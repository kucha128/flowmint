//! End-to-end: a wss:// client through the proxy with **MITM 解密** has its
//! frames relayed, captured, AND rewritten by an intercept hook.
//!
//! 拓扑：client --TLS--> 代理(MITM 解密) --TLS--> 上游 ws echo。
//! 客户端先 CONNECT，再在隧道里做 TLS（用不校验证书的 client config 接受 MITM leaf），
//! 然后升级 wss。代理解密后按帧 relay，并可被 WS 钩子改写。

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use flowmint_model::{CaptureId, Clock, EventKind, Flow, NetworkEvent, PayloadRef, RedactionState};
use flowmint_proxy_http::{
    serve, ws, Decision, FlowSink, InterceptHook, InterceptMessage, MitmConfig, ProxyContext,
    WsDecision,
};
use flowmint_tls::{insecure_upstream_client_config, server_config_for_host, CertAuthority};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// 把客户端发出的文本帧改成固定内容，验证 wss 帧可被拦截改写。
struct WsRewrite;
impl InterceptHook for WsRewrite {
    fn enabled(&self) -> bool {
        true
    }
    fn intercept<'a>(
        &'a self,
        _msg: InterceptMessage,
    ) -> Pin<Box<dyn Future<Output = Decision> + Send + 'a>> {
        Box::pin(async { Decision::Continue })
    }
    fn intercept_ws(&self, outgoing: bool, opcode: u8, _payload: &[u8]) -> WsDecision {
        if outgoing && opcode == 0x1 {
            WsDecision::Modify(b"MITM-REWRITTEN".to_vec())
        } else {
            WsDecision::Forward
        }
    }
}

struct TestSink {
    events: Mutex<Vec<NetworkEvent>>,
}
impl FlowSink for TestSink {
    fn upsert_flow(&self, _f: Flow) {}
    fn record_event(&self, e: NetworkEvent) {
        self.events.lock().unwrap().push(e);
    }
    fn put_payload(&self, b: &[u8], _r: RedactionState) -> Option<PayloadRef> {
        Some(PayloadRef {
            sha256: "test".into(),
            length: b.len() as u64,
            redaction: RedactionState::None,
            locator: "test".into(),
        })
    }
}

/// ws echo over 任意流（明文或 TLS）：读完握手头 → 回 101 → 逐帧原样回显。
async fn ws_echo<S: AsyncRead + AsyncWrite + Unpin>(mut s: S) {
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    loop {
        match s.read(&mut b).await {
            Ok(0) | Err(_) => return,
            Ok(_) => head.push(b[0]),
        }
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let _ = s
        .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: dummy\r\n\r\n")
        .await;
    let _ = s.flush().await;
    while let Ok(Some(frame)) = ws::read_frame(&mut s).await {
        let echo = ws::Frame {
            fin: true,
            opcode: frame.opcode,
            masked: false,
            payload: frame.payload,
        };
        if s.write_all(&ws::encode_frame(&echo, None)).await.is_err() {
            break;
        }
        let _ = s.flush().await;
        if echo.opcode == ws::Opcode::Close {
            break;
        }
    }
}

/// 上游 TLS ws echo 服务：TLS 终止后跑 ws echo。
async fn tls_ws_echo_server(listener: TcpListener, ca: Arc<CertAuthority>) {
    let cfg = server_config_for_host(ca, "localhost").unwrap();
    let acceptor = TlsAcceptor::from(cfg);
    loop {
        let Ok((sock, _)) = listener.accept().await else {
            return;
        };
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            if let Ok(tls) = acceptor.accept(sock).await {
                ws_echo(tls).await;
            }
        });
    }
}

fn masked_text(payload: &[u8]) -> Vec<u8> {
    ws::encode_frame(
        &ws::Frame {
            fin: true,
            opcode: ws::Opcode::Text,
            masked: true,
            payload: payload.to_vec(),
        },
        Some([1, 2, 3, 4]),
    )
}

async fn read_head<S: AsyncRead + Unpin>(s: &mut S) -> Vec<u8> {
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    loop {
        let n = s.read(&mut b).await.unwrap();
        assert_ne!(n, 0, "eof before head complete");
        head.push(b[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    head
}

#[tokio::test]
async fn wss_frames_relayed_captured_and_rewritten_through_mitm() {
    let ca = Arc::new(CertAuthority::bundled_default().unwrap());

    // 上游 TLS ws echo。
    let up_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_port = up_listener.local_addr().unwrap().port();
    tokio::spawn(tls_ws_echo_server(up_listener, ca.clone()));

    // MITM 代理（挂 WS 改写钩子）。
    let sink = Arc::new(TestSink {
        events: Mutex::new(Vec::new()),
    });
    let ctx = ProxyContext {
        sink: sink.clone(),
        capture_id: CaptureId::new(),
        clock: Clock::start_now(),
        mitm: Some(Arc::new(MitmConfig {
            ca: ca.clone(),
            client_config: insecure_upstream_client_config().unwrap(),
        })),
        hook: Some(Arc::new(WsRewrite)),
        upstream_proxy: None,
        proxy_port: 0,
        ca_pem: None,
        ca_der: None,
        disconnects: None,
    };
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    tokio::spawn(serve(proxy_listener, ctx));

    // 客户端：CONNECT → 隧道内 TLS（不校验，接受 MITM leaf）→ wss 升级。
    let mut raw = TcpStream::connect(proxy_addr).await.unwrap();
    raw.write_all(
        format!("CONNECT localhost:{up_port} HTTP/1.1\r\nHost: localhost:{up_port}\r\n\r\n")
            .as_bytes(),
    )
    .await
    .unwrap();
    raw.flush().await.unwrap();
    let connect_resp = read_head(&mut raw).await;
    assert!(
        String::from_utf8_lossy(&connect_resp).contains("200"),
        "CONNECT not established: {:?}",
        String::from_utf8_lossy(&connect_resp)
    );

    let connector = TlsConnector::from(insecure_upstream_client_config().unwrap());
    let server_name = ServerName::try_from("localhost").unwrap();
    let mut tls = connector.connect(server_name, raw).await.unwrap();

    tls.write_all(
        b"GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
    )
    .await
    .unwrap();
    tls.flush().await.unwrap();
    let up_head = read_head(&mut tls).await;
    assert!(
        String::from_utf8_lossy(&up_head).contains("101"),
        "no 101: {:?}",
        String::from_utf8_lossy(&up_head)
    );

    // 发文本帧；钩子应把它改成 MITM-REWRITTEN，echo 原样回传。
    tls.write_all(&masked_text(b"hello")).await.unwrap();
    tls.flush().await.unwrap();
    let echoed = ws::read_frame(&mut tls).await.unwrap().unwrap();
    assert_eq!(
        echoed.payload, b"MITM-REWRITTEN",
        "wss frame should be rewritten by the WS hook"
    );

    // 代理应记录到 wss 帧事件（安全标记）。
    tokio::time::sleep(Duration::from_millis(150)).await;
    let events = sink.events.lock().unwrap();
    let ws_frames = events
        .iter()
        .filter(|e| matches!(e.kind, EventKind::WebSocketFrame))
        .count();
    assert!(
        ws_frames >= 2,
        "expected >=2 wss frame events, got {ws_frames}"
    );
}
