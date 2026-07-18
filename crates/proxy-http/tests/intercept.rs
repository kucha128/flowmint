//! 端到端：拦截钩子修改请求与响应，断言修改真正生效
//! （源站收到改后的请求，客户端收到改后的响应）。

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use flowmint_model::{CaptureId, Clock, Flow, NetworkEvent, PayloadRef, RedactionState};
use flowmint_proxy_http::http::{parse_head, read_body, read_head_bytes};
use flowmint_proxy_http::{
    serve, Decision, Edit, FlowSink, InterceptHook, InterceptMessage, ProxyContext,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

struct NullSink;
impl FlowSink for NullSink {
    fn upsert_flow(&self, _f: Flow) {}
    fn record_event(&self, _e: NetworkEvent) {}
    fn put_payload(&self, _b: &[u8], _r: RedactionState) -> Option<PayloadRef> {
        None
    }
}

/// 请求：加一个头 + 改 body；响应：改 body。
struct TestHook;
impl InterceptHook for TestHook {
    fn enabled(&self) -> bool {
        true
    }
    fn intercept<'a>(
        &'a self,
        msg: InterceptMessage,
    ) -> Pin<Box<dyn Future<Output = Decision> + Send + 'a>> {
        Box::pin(async move {
            if msg.is_response {
                Decision::Modify(Edit {
                    status: msg.status,
                    headers: msg.headers,
                    body: b"MODIFIED-RESPONSE".to_vec(),
                })
            } else {
                let mut headers = msg.headers;
                headers.push(("X-Injected".into(), "yes".into()));
                Decision::Modify(Edit { status: None, headers, body: b"MODIFIED-REQUEST".to_vec() })
            }
        })
    }
}

#[tokio::test]
async fn breakpoint_modifies_request_and_response() {
    // 源站：记录收到的请求，返回固定响应。
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_port = origin.local_addr().unwrap().port();
    let recorded = Arc::new(Mutex::new(String::new()));
    let rec = recorded.clone();
    tokio::spawn(async move {
        let (sock, _) = origin.accept().await.unwrap();
        let (r, mut w) = sock.into_split();
        let mut reader = BufReader::new(r);
        let head = read_head_bytes(&mut reader).await.unwrap();
        let parsed = parse_head(&head).unwrap();
        let body = read_body(&mut reader, &parsed, false).await.unwrap();
        *rec.lock().unwrap() =
            String::from_utf8_lossy(&head).into_owned() + &String::from_utf8_lossy(&body);
        let _ = w
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nORIGINAL")
            .await;
    });

    // 带拦截钩子的代理。
    let ctx = ProxyContext {
        sink: Arc::new(NullSink),
        capture_id: CaptureId::new(),
        clock: Clock::start_now(),
        mitm: None,
        hook: Some(Arc::new(TestHook)),
        upstream_proxy: None,
        proxy_port: 0,
        ca_pem: None,
        ca_der: None,
    };
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    tokio::spawn(serve(proxy, ctx));

    // 客户端经代理发请求。
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let req = format!(
        "POST http://127.0.0.1:{origin_port}/x HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nContent-Length: 7\r\n\r\nORIGREQ"
    );
    client.write_all(req.as_bytes()).await.unwrap();
    let mut resp = Vec::new();
    client.read_to_end(&mut resp).await.unwrap();
    let resp = String::from_utf8_lossy(&resp);

    // 源站应收到"改后的请求"。
    let got = recorded.lock().unwrap().clone();
    assert!(got.contains("X-Injected: yes"), "源站未收到注入的请求头: {got}");
    assert!(got.contains("MODIFIED-REQUEST"), "源站未收到改后的请求体: {got}");

    // 客户端应收到"改后的响应"。
    assert!(resp.contains("MODIFIED-RESPONSE"), "客户端未收到改后的响应: {resp}");
}
