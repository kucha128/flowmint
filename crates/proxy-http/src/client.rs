//! 最小 HTTP(S) 客户端：发送一条请求并读回响应。
//!
//! 供"重放/构造器（Composer）"使用——把捕获的请求编辑后重新发出。复用本 crate
//! 的 HTTP 解析，不引入额外 HTTP 库。

use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::http::{parse_head, read_body, read_head_bytes};

pub struct SendResult {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// 发送一条请求到 `host:port`，返回响应。`https` 为 true 时必须提供 `tls_config`。
#[allow(clippy::too_many_arguments)]
pub async fn send_request(
    method: &str,
    host: &str,
    port: u16,
    path: &str,
    https: bool,
    headers: &[(String, String)],
    body: &[u8],
    tls_config: Option<Arc<ClientConfig>>,
) -> std::io::Result<SendResult> {
    let tcp = TcpStream::connect((host, port)).await?;
    let _ = tcp.set_nodelay(true);
    if https {
        let cfg = tls_config
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "https 需要 TLS 配置"))?;
        let connector = TlsConnector::from(cfg);
        let name = ServerName::try_from(host.to_string())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "非法主机名"))?;
        let tls = connector.connect(name, tcp).await?;
        exchange(tls, method, host, path, headers, body).await
    } else {
        exchange(tcp, method, host, path, headers, body).await
    }
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    method: &str,
    host: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> std::io::Result<SendResult> {
    stream.write_all(&build_request(method, host, path, headers, body)).await?;
    stream.flush().await?;

    let mut reader = BufReader::new(stream);
    let head_bytes = read_head_bytes(&mut reader).await?;
    let head = parse_head(&head_bytes);
    let (status, resp_headers) = match &head {
        Some(h) => (h.start_line.1.parse().unwrap_or(0), h.headers.clone()),
        None => (0, Vec::new()),
    };
    let resp_body = match &head {
        Some(h) => read_body(&mut reader, h, true).await.unwrap_or_default(),
        None => Vec::new(),
    };
    Ok(SendResult { status, headers: resp_headers, body: resp_body })
}

fn build_request(method: &str, host: &str, path: &str, headers: &[(String, String)], body: &[u8]) -> Vec<u8> {
    let mut out = format!("{method} {path} HTTP/1.1\r\n").into_bytes();
    let mut has_host = false;
    for (k, v) in headers {
        let lk = k.to_ascii_lowercase();
        // 长度/连接类头由我们自己控制，避免与实际不一致。
        if matches!(lk.as_str(), "connection" | "content-length" | "proxy-connection" | "transfer-encoding") {
            continue;
        }
        if lk == "host" {
            has_host = true;
        }
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    if !has_host {
        out.extend_from_slice(format!("Host: {host}\r\n").as_bytes());
    }
    if !body.is_empty() {
        out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    }
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn sends_and_reads_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await; // 读掉请求
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
                .await;
        });

        let r = send_request("GET", "127.0.0.1", addr.port(), "/x", false, &[], b"", None).await.unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"hello");
    }
}
