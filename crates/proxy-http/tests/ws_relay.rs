//! End-to-end: a ws:// client through the proxy has its frames relayed AND
//! captured as WebSocketFrame events.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use std::future::Future;
use std::pin::Pin;

use flowmint_model::{CaptureId, Clock, EventKind, Flow, NetworkEvent, PayloadRef, RedactionState};
use flowmint_proxy_http::{
    serve, ws, Decision, DisconnectHub, FlowSink, InterceptHook, InterceptMessage, ProxyContext,
    WsDecision,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// 测试用 WS 拦截钩子：把客户端发出的 text 帧改成固定内容，或断开。
struct WsHook {
    close: bool,
}
impl InterceptHook for WsHook {
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
            if self.close {
                WsDecision::Close
            } else {
                WsDecision::Modify(b"MODIFIED".to_vec())
            }
        } else {
            WsDecision::Forward
        }
    }
}

struct TestSink {
    events: Mutex<Vec<NetworkEvent>>,
    flows: Mutex<Vec<Flow>>,
}

impl TestSink {
    fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            flows: Mutex::new(Vec::new()),
        }
    }
    /// 返回首个 WebSocket flow 的 id（用于主动断开测试）。
    fn ws_flow_id(&self) -> Option<String> {
        self.flows
            .lock()
            .unwrap()
            .iter()
            .find(|f| f.l7.as_deref() == Some("websocket"))
            .map(|f| f.flow_id.to_string())
    }
}

impl FlowSink for TestSink {
    fn upsert_flow(&self, f: Flow) {
        self.flows.lock().unwrap().push(f);
    }
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

/// Minimal WebSocket echo server: canned 101 handshake, then echoes frames.
async fn ws_echo_server(listener: TcpListener) {
    loop {
        let Ok((mut sock, _)) = listener.accept().await else {
            return;
        };
        tokio::spawn(async move {
            // Drain the request head.
            let mut head = Vec::new();
            let mut b = [0u8; 1];
            loop {
                match sock.read(&mut b).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => head.push(b[0]),
                }
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let _ = sock
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: dummy\r\n\r\n")
                .await;
            let _ = sock.flush().await;

            while let Ok(Some(frame)) = ws::read_frame(&mut sock).await {
                let echo = ws::Frame {
                    fin: true,
                    opcode: frame.opcode,
                    masked: false,
                    payload: frame.payload,
                };
                if sock
                    .write_all(&ws::encode_frame(&echo, None))
                    .await
                    .is_err()
                {
                    break;
                }
                let _ = sock.flush().await;
                if echo.opcode == ws::Opcode::Close {
                    break;
                }
            }
        });
    }
}

#[tokio::test]
async fn ws_frames_are_captured_through_proxy() {
    // Echo server on a random port.
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    tokio::spawn(ws_echo_server(echo_listener));

    // Proxy on a random port.
    let sink = Arc::new(TestSink::new());
    let ctx = ProxyContext {
        sink: sink.clone(),
        capture_id: CaptureId::new(),
        clock: Clock::start_now(),
        mitm: None,
        hook: None,
        upstream_proxy: None,
        proxy_port: 0,
        ca_pem: None,
        ca_der: None,
        disconnects: None,
    };
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    tokio::spawn(serve(proxy_listener, ctx));

    // Client → proxy, absolute-form ws upgrade.
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let req = format!(
        "GET http://{echo_addr}/ws HTTP/1.1\r\nHost: {echo_addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    client.write_all(req.as_bytes()).await.unwrap();
    client.flush().await.unwrap();

    // Read the 101 head.
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    loop {
        let n = client.read(&mut b).await.unwrap();
        assert_ne!(n, 0, "eof before 101");
        head.push(b[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    assert!(
        String::from_utf8_lossy(&head).contains("101"),
        "expected 101, got {:?}",
        String::from_utf8_lossy(&head)
    );

    // Send a masked text frame; expect it echoed back.
    let frame = ws::Frame {
        fin: true,
        opcode: ws::Opcode::Text,
        masked: true,
        payload: b"ping".to_vec(),
    };
    client
        .write_all(&ws::encode_frame(&frame, Some([9, 8, 7, 6])))
        .await
        .unwrap();
    client.flush().await.unwrap();

    let echoed = ws::read_frame(&mut client).await.unwrap().unwrap();
    assert_eq!(echoed.payload, b"ping");

    // Let the proxy record.
    tokio::time::sleep(Duration::from_millis(150)).await;
    let events = sink.events.lock().unwrap();
    let ws_frames = events
        .iter()
        .filter(|e| matches!(e.kind, EventKind::WebSocketFrame))
        .count();
    assert!(
        ws_frames >= 2,
        "expected >=2 WebSocketFrame events, got {ws_frames}"
    );
    assert!(
        events
            .iter()
            .any(|e| e.attributes.get("ws.opcode").and_then(|v| v.as_str()) == Some("text")),
        "expected a text frame event"
    );
}

/// 起 echo 服务 + 代理（可挂拦截钩子），完成 ws 升级，返回已升级的客户端连接。
async fn ws_upgrade(hook: Option<Arc<dyn InterceptHook>>) -> TcpStream {
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    tokio::spawn(ws_echo_server(echo_listener));

    let sink = Arc::new(TestSink::new());
    let ctx = ProxyContext {
        sink,
        capture_id: CaptureId::new(),
        clock: Clock::start_now(),
        mitm: None,
        hook,
        upstream_proxy: None,
        proxy_port: 0,
        ca_pem: None,
        ca_der: None,
        disconnects: None,
    };
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    tokio::spawn(serve(proxy_listener, ctx));

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let req = format!(
        "GET http://{echo_addr}/ws HTTP/1.1\r\nHost: {echo_addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    client.write_all(req.as_bytes()).await.unwrap();
    client.flush().await.unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    loop {
        let n = client.read(&mut b).await.unwrap();
        assert_ne!(n, 0, "eof before 101");
        head.push(b[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    client
}

fn text_frame(payload: &[u8]) -> Vec<u8> {
    ws::encode_frame(
        &ws::Frame {
            fin: true,
            opcode: ws::Opcode::Text,
            masked: true,
            payload: payload.to_vec(),
        },
        Some([9, 8, 7, 6]),
    )
}

#[tokio::test]
async fn ws_frame_modified_by_hook() {
    let mut client = ws_upgrade(Some(Arc::new(WsHook { close: false }))).await;
    client.write_all(&text_frame(b"ping")).await.unwrap();
    client.flush().await.unwrap();
    // 客户端发的 text 帧被钩子改成 "MODIFIED"，echo 原样回传。
    let echoed = ws::read_frame(&mut client).await.unwrap().unwrap();
    assert_eq!(echoed.payload, b"MODIFIED");
}

#[tokio::test]
async fn ws_closed_by_hook() {
    let mut client = ws_upgrade(Some(Arc::new(WsHook { close: true }))).await;
    client.write_all(&text_frame(b"ping")).await.unwrap();
    client.flush().await.unwrap();
    // 钩子返回 Close：代理向上游发 close 并断开；客户端最终读到 Close 帧或 EOF。
    match ws::read_frame(&mut client).await {
        Ok(Some(f)) => assert_eq!(f.opcode, ws::Opcode::Close),
        Ok(None) | Err(_) => {} // EOF / 断开也算成功
    }
}

/// echo 服务变体：把收到的握手请求头存入 `sink`，供测试断言（如剥离压缩扩展）。
async fn ws_echo_server_capturing(listener: TcpListener, sink: Arc<Mutex<Vec<u8>>>) {
    let Ok((mut sock, _)) = listener.accept().await else {
        return;
    };
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    loop {
        match sock.read(&mut b).await {
            Ok(0) | Err(_) => return,
            Ok(_) => head.push(b[0]),
        }
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    *sink.lock().unwrap() = head;
    let _ = sock
        .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: dummy\r\n\r\n")
        .await;
    let _ = sock.flush().await;
    while let Ok(Some(frame)) = ws::read_frame(&mut sock).await {
        let echo = ws::Frame {
            fin: true,
            opcode: frame.opcode,
            masked: false,
            payload: frame.payload,
        };
        if sock
            .write_all(&ws::encode_frame(&echo, None))
            .await
            .is_err()
        {
            break;
        }
        let _ = sock.flush().await;
    }
}

/// 代理转发 ws 升级握手时应剥离 `Sec-WebSocket-Extensions`（permessage-deflate），
/// 避免协商压缩扩展导致压缩帧无法逐帧改写/转发。
#[tokio::test]
async fn ws_upgrade_strips_permessage_deflate() {
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    let captured = Arc::new(Mutex::new(Vec::<u8>::new()));
    tokio::spawn(ws_echo_server_capturing(echo_listener, captured.clone()));

    let sink = Arc::new(TestSink::new());
    let ctx = ProxyContext {
        sink,
        capture_id: CaptureId::new(),
        clock: Clock::start_now(),
        mitm: None,
        hook: None,
        upstream_proxy: None,
        proxy_port: 0,
        ca_pem: None,
        ca_der: None,
        disconnects: None,
    };
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    tokio::spawn(serve(proxy_listener, ctx));

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    // 客户端 offer permessage-deflate。
    let req = format!(
        "GET http://{echo_addr}/ws HTTP/1.1\r\nHost: {echo_addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZQ==\r\nSec-WebSocket-Extensions: permessage-deflate\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    client.write_all(req.as_bytes()).await.unwrap();
    client.flush().await.unwrap();
    let mut b = [0u8; 1];
    let mut head = Vec::new();
    loop {
        let n = client.read(&mut b).await.unwrap();
        assert_ne!(n, 0);
        head.push(b[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    // 上游收到的握手头不应含压缩扩展。
    let forwarded = String::from_utf8_lossy(&captured.lock().unwrap()).to_lowercase();
    assert!(
        !forwarded.contains("sec-websocket-extensions"),
        "forwarded handshake should not carry Sec-WebSocket-Extensions:\n{forwarded}"
    );
    assert!(!forwarded.contains("permessage-deflate"));
}

/// 桌面「主动断开」：通过 DisconnectHub 按 flow_id 断开一个进行中的 ws 会话，
/// 客户端随即读到 EOF。
#[tokio::test]
async fn ws_disconnected_by_hub() {
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    tokio::spawn(ws_echo_server(echo_listener));

    let sink = Arc::new(TestSink::new());
    let hub = Arc::new(DisconnectHub::new());
    let ctx = ProxyContext {
        sink: sink.clone(),
        capture_id: CaptureId::new(),
        clock: Clock::start_now(),
        mitm: None,
        hook: None,
        upstream_proxy: None,
        proxy_port: 0,
        ca_pem: None,
        ca_der: None,
        disconnects: Some(hub.clone()),
    };
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    tokio::spawn(serve(proxy_listener, ctx));

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let req = format!(
        "GET http://{echo_addr}/ws HTTP/1.1\r\nHost: {echo_addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    client.write_all(req.as_bytes()).await.unwrap();
    client.flush().await.unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    loop {
        let n = client.read(&mut b).await.unwrap();
        assert_ne!(n, 0, "eof before 101");
        head.push(b[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    // 一来一回，确认帧正常流动 + relay 已注册到 hub。
    client.write_all(&text_frame(b"ping")).await.unwrap();
    client.flush().await.unwrap();
    assert_eq!(
        ws::read_frame(&mut client).await.unwrap().unwrap().payload,
        b"ping"
    );

    // 找到 ws flow_id 并主动断开。
    let flow_id = {
        let mut id = None;
        for _ in 0..50 {
            if let Some(f) = sink.ws_flow_id() {
                id = Some(f);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        id.expect("no websocket flow recorded")
    };
    assert!(hub.disconnect(&flow_id), "flow should be live");

    // 断开后客户端读到 EOF（0 字节）。
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
        .await
        .expect("read timed out — connection not closed")
        .unwrap();
    assert_eq!(n, 0, "expected EOF after disconnect, got {n} bytes");

    // 未知 flow_id 返回 false。
    assert!(!hub.disconnect("flow_does_not_exist"));
}
