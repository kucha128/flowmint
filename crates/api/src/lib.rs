//! 本地 API 网关（设计 §5）：面向脚本/外部工具的 loopback JSON/REST 只读模型。
//!
//! 安全（设计 §12）：仅监听 loopback，除 `/` 与 `/health` 外每个路由都要求
//! 每次启动随机生成的 bearer token。（mTLS/RBAC 属于远程受管模式，不在本地服务内。）

use std::net::SocketAddr;
use std::sync::Arc;

use flowmint_engine::Engine;
use flowmint_storage::SearchFilter;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tracing::debug;

/// A running API server's bind address and access token.
pub struct ApiHandle {
    pub bind: SocketAddr,
    pub token: String,
}

struct Ctx {
    engine: Engine,
    token: String,
}

/// Bind and serve the API on `bind` (loopback). Returns only on fatal error.
/// Prints nothing; the caller reports the token.
pub async fn serve(engine: Engine, bind: SocketAddr, token: String) -> std::io::Result<()> {
    let listener = TcpListener::bind(bind).await?;
    let ctx = Arc::new(Ctx { engine, token });
    debug!(%bind, "api listening");
    loop {
        let (stream, _peer) = listener.accept().await?;
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let _ = handle(stream, ctx).await;
        });
    }
}

/// Generate a random-enough loopback token.
pub fn new_token() -> String {
    uuid::Uuid::now_v7().simple().to_string()
}

async fn handle(mut stream: tokio::net::TcpStream, ctx: Arc<Ctx>) -> std::io::Result<()> {
    let mut buf = BufReader::new(&mut stream);
    let (method, path, headers) = match read_request(&mut buf).await? {
        Some(v) => v,
        None => return Ok(()),
    };

    let (status, body) = route(&ctx, &method, &path, &headers);
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(resp.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

fn route(ctx: &Ctx, method: &str, path: &str, headers: &[(String, String)]) -> (&'static str, String) {
    let (path_only, query) = match path.split_once('?') {
        Some((p, q)) => (p, q),
        None => (path, ""),
    };

    if method == "GET" && path_only == "/" {
        return ("200 OK", json!({
            "service": "flowmint-api",
            "version": env!("CARGO_PKG_VERSION"),
            "endpoints": ["/health", "/captures", "/flows", "/flows/{id}", "/flows/{id}/events"],
        }).to_string());
    }
    if method == "GET" && path_only == "/health" {
        return ("200 OK", json!({ "status": "ok", "version": env!("CARGO_PKG_VERSION") }).to_string());
    }

    // Auth for everything else.
    if !authorized(ctx, headers) {
        return ("401 Unauthorized", json!({ "error": "missing or invalid bearer token" }).to_string());
    }

    match (method, path_only) {
        ("GET", "/captures") => match ctx.engine.list_captures() {
            Ok(caps) => ok(json!(caps
                .iter()
                .map(|c| json!({ "capture_id": c.capture_id, "started_ms": c.started_ms, "label": c.label }))
                .collect::<Vec<_>>())),
            Err(e) => err_500(e),
        },
        ("GET", "/flows") => {
            let host = query_param(query, "host");
            let limit = query_param(query, "limit").and_then(|v| v.parse().ok()).unwrap_or(100);
            match ctx.engine.search_flows(&SearchFilter { host, capture_id: None, limit }) {
                Ok(flows) => ok(serde_json::to_value(&flows).unwrap_or(json!([]))),
                Err(e) => err_500(e),
            }
        }
        ("GET", p) if p.starts_with("/flows/") => {
            let rest = &p["/flows/".len()..];
            if let Some(id) = rest.strip_suffix("/events") {
                match ctx.engine.events_for_flow(id) {
                    Ok(events) => ok(serde_json::to_value(&events).unwrap_or(json!([]))),
                    Err(e) => err_500(e),
                }
            } else {
                match ctx.engine.get_flow(rest) {
                    Ok(Some(flow)) => ok(serde_json::to_value(&flow).unwrap_or(json!({}))),
                    Ok(None) => ("404 Not Found", json!({ "error": "flow not found" }).to_string()),
                    Err(e) => err_500(e),
                }
            }
        }
        _ => ("404 Not Found", json!({ "error": "no such route" }).to_string()),
    }
}

fn authorized(ctx: &Ctx, headers: &[(String, String)]) -> bool {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
        .map(|(_, v)| v.trim() == format!("Bearer {}", ctx.token))
        .unwrap_or(false)
}

fn ok(v: serde_json::Value) -> (&'static str, String) {
    ("200 OK", v.to_string())
}

fn err_500(e: anyhow::Error) -> (&'static str, String) {
    ("500 Internal Server Error", json!({ "error": e.to_string() }).to_string())
}

fn query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        if k == key {
            Some(v.replace('+', " "))
        } else {
            None
        }
    })
}

async fn read_request<R: tokio::io::AsyncRead + Unpin>(
    r: &mut R,
) -> std::io::Result<Option<(String, String, Vec<(String, String)>)>> {
    // Read until end of headers.
    let mut data = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = r.read(&mut byte).await?;
        if n == 0 {
            break;
        }
        data.push(byte[0]);
        if data.ends_with(b"\r\n\r\n") {
            break;
        }
        if data.len() > 32 * 1024 {
            break;
        }
    }
    let text = String::from_utf8_lossy(&data);
    let mut lines = text.split("\r\n");
    let Some(start) = lines.next() else { return Ok(None) };
    let mut parts = start.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("/").to_string();
    let headers = lines
        .filter(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string())))
        .collect();
    Ok(Some((method, path, headers)))
}
