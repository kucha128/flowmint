//! 直接访问代理端口时，返回落地页与可下载的 CA 证书（对标 Fiddler）。

use std::sync::Arc;

use flowmint_model::{CaptureId, Clock, Flow, NetworkEvent, PayloadRef, RedactionState};
use flowmint_proxy_http::{serve, FlowSink, ProxyContext};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct NullSink;
impl FlowSink for NullSink {
    fn upsert_flow(&self, _f: Flow) {}
    fn record_event(&self, _e: NetworkEvent) {}
    fn put_payload(&self, _b: &[u8], _r: RedactionState) -> Option<PayloadRef> {
        None
    }
}

const CA_PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIB-test\n-----END CERTIFICATE-----\n";
const CA_DER: &[u8] = &[0x30, 0x82, 0x01, 0x02, 0xde, 0xad, 0xbe, 0xef];

async fn get(addr: std::net::SocketAddr, target: &str) -> String {
    let mut c = TcpStream::connect(addr).await.unwrap();
    // origin 形式，模拟浏览器直接打开 http://127.0.0.1:port/...
    let req = format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    c.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    c.read_to_end(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf).into_owned()
}

#[tokio::test]
async fn landing_page_and_cert_download() {
    let ctx = ProxyContext {
        sink: Arc::new(NullSink),
        capture_id: CaptureId::new(),
        clock: Clock::start_now(),
        mitm: None,
        hook: None,
        upstream_proxy: None,
        proxy_port: 0,
        ca_pem: Some(Arc::from(CA_PEM)),
        ca_der: Some(Arc::from(CA_DER)),
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(listener, ctx));

    // 落地页：含品牌、各平台引导、两种下载链接
    let root = get(addr, "/").await;
    assert!(root.starts_with("HTTP/1.1 200"), "落地页应 200：{root}");
    assert!(root.contains("text/html"), "应是 HTML");
    assert!(root.contains("FlowMint"), "应含品牌名");
    assert!(
        root.contains("/cert.crt") && root.contains("/cert.cer"),
        "应有 crt 与 cer 下载链接"
    );
    assert!(
        root.contains("Windows") && root.contains("iOS"),
        "应有各平台安装引导"
    );

    // PEM 证书下载（Windows/macOS/Android）
    let pem = get(addr, "/cert.crt").await;
    assert!(pem.starts_with("HTTP/1.1 200"), "crt 应 200：{pem}");
    assert!(
        pem.contains("attachment; filename=\"flowmint-ca.crt\""),
        "应是 .crt 附件"
    );
    assert!(pem.contains("BEGIN CERTIFICATE"), "应返回 PEM 内容");

    // DER 证书下载（iOS）
    let der = get(addr, "/cert.cer").await;
    assert!(der.starts_with("HTTP/1.1 200"), "cer 应 200：{der}");
    assert!(
        der.contains("attachment; filename=\"flowmint-ca.cer\""),
        "应是 .cer 附件"
    );

    // 裸 /cert 仍返回 PEM（向后兼容）
    let bare = get(addr, "/cert").await;
    assert!(bare.contains("BEGIN CERTIFICATE"), "/cert 应仍返回 PEM");

    // 未知路径 404
    let missing = get(addr, "/nope").await;
    assert!(
        missing.starts_with("HTTP/1.1 404"),
        "未知路径应 404：{missing}"
    );
}
