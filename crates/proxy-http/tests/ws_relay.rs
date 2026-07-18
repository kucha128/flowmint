//! End-to-end: a ws:// client through the proxy has its frames relayed AND
//! captured as WebSocketFrame events.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use flowmint_model::{CaptureId, Clock, EventKind, Flow, NetworkEvent, PayloadRef, RedactionState};
use flowmint_proxy_http::{serve, ws, FlowSink, ProxyContext};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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

/// Minimal WebSocket echo server: canned 101 handshake, then echoes frames.
async fn ws_echo_server(listener: TcpListener) {
    loop {
        let Ok((mut sock, _)) = listener.accept().await else { return };
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
                let echo = ws::Frame { fin: true, opcode: frame.opcode, masked: false, payload: frame.payload };
                if sock.write_all(&ws::encode_frame(&echo, None)).await.is_err() {
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
    let sink = Arc::new(TestSink { events: Mutex::new(Vec::new()) });
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
    assert!(String::from_utf8_lossy(&head).contains("101"), "expected 101, got {:?}", String::from_utf8_lossy(&head));

    // Send a masked text frame; expect it echoed back.
    let frame = ws::Frame { fin: true, opcode: ws::Opcode::Text, masked: true, payload: b"ping".to_vec() };
    client.write_all(&ws::encode_frame(&frame, Some([9, 8, 7, 6]))).await.unwrap();
    client.flush().await.unwrap();

    let echoed = ws::read_frame(&mut client).await.unwrap().unwrap();
    assert_eq!(echoed.payload, b"ping");

    // Let the proxy record.
    tokio::time::sleep(Duration::from_millis(150)).await;
    let events = sink.events.lock().unwrap();
    let ws_frames = events.iter().filter(|e| matches!(e.kind, EventKind::WebSocketFrame)).count();
    assert!(ws_frames >= 2, "expected >=2 WebSocketFrame events, got {ws_frames}");
    assert!(
        events.iter().any(|e| e.attributes.get("ws.opcode").and_then(|v| v.as_str()) == Some("text")),
        "expected a text frame event"
    );
}
