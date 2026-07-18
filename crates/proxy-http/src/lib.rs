//! Explicit HTTP proxy capture adapter (design §7.1, §7.2).
//!
//! - **Plain HTTP** (`GET http://host/…`): forwarded to origin; captured as
//!   canonical events with full headers and bodies.
//! - **CONNECT, tunnel mode** (default): a blind TCP relay; only tunnel
//!   metadata is recorded — no TLS interception (design §7.2).
//! - **CONNECT, MITM mode** (opt-in per profile): the client TLS is terminated
//!   with an on-demand leaf from the profile CA, a real TLS connection is made
//!   upstream, and the decrypted HTTP is captured as sub-flows of the tunnel.
//!   WebSocket upgrades are detected and relayed (frame capture: see `ws`).

pub mod client;
pub mod decode;
pub mod http;
pub mod intercept;
pub mod procinfo;
pub mod ws;

pub use intercept::{Decision, Edit, InterceptHook, InterceptMessage, WsDecision};

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use flowmint_model::{
    CaptureId, Clock, Direction, Endpoint, EventKind, EvidenceRef, Flow, FlowId, NetworkEvent,
    PayloadRef, ProtocolStack, RedactionState, TlsInfo,
};
use flowmint_tls::CertAuthority;
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{debug, warn};

use crate::http::{
    parse_absolute_target, parse_connect_target, parse_head, read_body, read_head_bytes, Head,
};

const ADAPTER: &str = "proxy-http";

/// Opt-in HTTPS interception config for a capture profile (design §7.2).
///
/// Holds the profile CA (leaves are minted per CONNECT target, so SNI-less
/// clients work) and the upstream TLS client config.
pub struct MitmConfig {
    pub ca: Arc<CertAuthority>,
    pub client_config: Arc<ClientConfig>,
}

/// Where captured flows/events/payloads are written. Implemented by the engine.
pub trait FlowSink: Send + Sync + 'static {
    fn upsert_flow(&self, flow: Flow);
    fn record_event(&self, event: NetworkEvent);
    fn put_payload(&self, bytes: &[u8], redaction: RedactionState) -> Option<PayloadRef>;
}

pub struct ProxyContext<S: FlowSink> {
    pub sink: Arc<S>,
    pub capture_id: CaptureId,
    pub clock: Clock,
    /// `None` = tunnel-only (no decryption). `Some` = MITM enabled.
    pub mitm: Option<Arc<MitmConfig>>,
    /// 断点拦截钩子（`None` 表示不拦截）。
    pub hook: Option<Arc<dyn InterceptHook>>,
    /// 上游代理 `host:port`（`None` 表示直连）。设置后所有出站流量经它转发。
    pub upstream_proxy: Option<Arc<str>>,
    /// 代理自身监听端口（用于识别"直接访问代理"的请求，服务落地页/证书下载）。
    pub proxy_port: u16,
    /// profile CA 的 PEM 文本（供落地页下载：Windows/macOS/Android 用 `.crt`）。
    pub ca_pem: Option<Arc<str>>,
    /// profile CA 的 DER 字节（供落地页下载：iOS 用 `.cer`）。
    pub ca_der: Option<Arc<[u8]>>,
}

impl<S: FlowSink> Clone for ProxyContext<S> {
    fn clone(&self) -> Self {
        Self {
            sink: self.sink.clone(),
            capture_id: self.capture_id.clone(),
            clock: self.clock,
            mitm: self.mitm.clone(),
            hook: self.hook.clone(),
            upstream_proxy: self.upstream_proxy.clone(),
            proxy_port: self.proxy_port,
            ca_pem: self.ca_pem.clone(),
            ca_der: self.ca_der.clone(),
        }
    }
}

/// Bind an explicit HTTP proxy on `bind` (expected loopback) and serve until the
/// task is cancelled.
pub async fn run<S: FlowSink>(bind: SocketAddr, ctx: ProxyContext<S>) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(bind).await?;
    serve(listener, ctx).await
}

/// Serve on an already-bound listener (used by tests that need the OS-assigned
/// port).
pub async fn serve<S: FlowSink>(
    listener: tokio::net::TcpListener,
    ctx: ProxyContext<S>,
) -> std::io::Result<()> {
    debug!(mitm = ctx.mitm.is_some(), "http capture proxy listening");
    loop {
        let (stream, peer) = listener.accept().await?;
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, peer, ctx).await {
                debug!(%peer, error = %e, "connection ended with error");
            }
        });
    }
}

async fn handle_conn<S: FlowSink>(
    stream: TcpStream,
    peer: SocketAddr,
    ctx: ProxyContext<S>,
) -> std::io::Result<()> {
    let _ = stream.set_nodelay(true);
    let mut buf = BufReader::new(stream);

    let head_bytes = read_head_bytes(&mut buf).await?;
    if head_bytes.is_empty() {
        return Ok(());
    }
    let head = match parse_head(&head_bytes) {
        Some(h) => h,
        None => {
            let _ = buf.into_inner().write_all(bad_request()).await;
            return Ok(());
        }
    };

    let method = head.start_line.0.to_ascii_uppercase();
    // 直接访问代理端口（origin 形式，如浏览器打开 http://127.0.0.1:8888/）→ 落地页/证书下载。
    if method != "CONNECT" && head.start_line.1.starts_with('/') {
        return serve_local_page(buf.into_inner(), &head.start_line.1, &ctx).await;
    }
    if method == "CONNECT" {
        match ctx.mitm.clone() {
            Some(mitm) => handle_connect_mitm(buf, peer, &head, ctx, mitm).await,
            None => handle_connect_tunnel(buf, peer, &head, ctx).await,
        }
    } else {
        handle_plain(buf, peer, head, ctx).await
    }
}

/// Plain absolute-form HTTP proxying (one exchange, then close).
async fn handle_plain<S: FlowSink>(
    mut buf: BufReader<TcpStream>,
    peer: SocketAddr,
    head: Head,
    ctx: ProxyContext<S>,
) -> std::io::Result<()> {
    let Some((host, port, path)) = parse_absolute_target(&head.start_line.1) else {
        let _ = buf.into_inner().write_all(bad_request()).await;
        return Ok(());
    };
    let req_body = read_body(&mut buf, &head, false).await.unwrap_or_default();
    let mut client = buf.into_inner();

    // 通过代理访问代理自身（绝对形式，如浏览器配了代理再打开 http://127.0.0.1:8888/）→ 落地页。
    if port == ctx.proxy_port && is_loopback_host(&host) {
        return serve_local_page(client, &path, &ctx).await;
    }

    let upstream = match dial_upstream(ctx.upstream_proxy.as_deref(), &host, port, false).await {
        Ok(s) => s,
        Err(e) => {
            warn!(%host, port, error = %e, "upstream connect failed");
            let _ = client.write_all(bad_gateway()).await;
            return Ok(());
        }
    };

    // WebSocket (ws://) upgrade: relay frames instead of a single exchange.
    if is_ws_upgrade(&head) {
        return relay_plain_ws(client, upstream, head, path, host, port, peer, ctx).await;
    }

    let method = head.start_line.0.clone();
    let url = format!("http://{host}:{port}{path}");
    // 经上游代理时请求行须用绝对形式（GET http://host/path），直连时用 origin 形式。
    let req_target = if ctx.upstream_proxy.is_some() {
        url.clone()
    } else {
        path.clone()
    };

    // 请求断点（转发前）。
    let Some((req_headers, req_body)) =
        request_breakpoint(&ctx, &method, &url, head.headers.clone(), req_body).await
    else {
        return Ok(()); // 丢弃
    };

    let (status, resp_headers, resp_body) =
        match http_exchange(upstream, &method, &req_headers, &req_target, &req_body).await {
            Ok(v) => v,
            Err(e) => {
                warn!(%host, error = %e, "upstream exchange failed");
                let _ = client.write_all(bad_gateway()).await;
                return Ok(());
            }
        };

    // 响应断点（回传前）。
    let Some((status, resp_headers, resp_body)) =
        response_breakpoint(&ctx, &method, &url, status, resp_headers, resp_body).await
    else {
        return Ok(()); // 丢弃
    };

    let client_ep = client_endpoint(peer);
    let server_ep = server_endpoint(&host, port);
    capture_exchange(
        &ctx,
        &client_ep,
        &server_ep,
        &host,
        &path,
        &method,
        &req_headers,
        &req_body,
        status,
        &resp_headers,
        &resp_body,
        false,
        None,
    );

    client
        .write_all(&build_client_response(
            status.unwrap_or(0),
            &resp_headers,
            &resp_body,
            false,
        ))
        .await?;
    client.flush().await?;
    Ok(())
}

/// CONNECT tunnel without interception: record metadata, blind-relay bytes.
async fn handle_connect_tunnel<S: FlowSink>(
    buf: BufReader<TcpStream>,
    peer: SocketAddr,
    head: &Head,
    ctx: ProxyContext<S>,
) -> std::io::Result<()> {
    let Some((host, port)) = parse_connect_target(&head.start_line.1) else {
        let _ = buf.into_inner().write_all(bad_request()).await;
        return Ok(());
    };
    let mut client = buf.into_inner();
    let upstream = match dial_upstream(ctx.upstream_proxy.as_deref(), &host, port, true).await {
        Ok(s) => s,
        Err(e) => {
            warn!(%host, port, error = %e, "CONNECT upstream failed");
            let _ = client.write_all(bad_gateway()).await;
            return Ok(());
        }
    };
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    client.flush().await?;

    let client_ep = client_endpoint(peer);
    let server_ep = server_endpoint(&host, port);
    let flow_id = FlowId::new();
    let mut flow = Flow::opened(
        flow_id.clone(),
        ctx.capture_id.clone(),
        client_ep.clone(),
        server_ep.clone(),
        ctx.clock.stamp().wall_unix_ms,
    );
    flow.l7 = Some("connect".into());
    flow.secure = true; // CONNECT 隧道即加密（未解密）的 HTTPS
    ctx.sink.upsert_flow(flow);
    let mut open_ev = mk_event(
        &ctx,
        &flow_id,
        0,
        Direction::ClientToServer,
        EventKind::FlowOpened,
        client_ep.clone(),
        server_ep.clone(),
        pstack("connect", None),
    );
    open_ev.attributes.insert("tunnel".into(), true.into());
    open_ev.attributes.insert("decrypted".into(), false.into());
    ctx.sink.record_event(open_ev);

    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut ur, mut uw) = tokio::io::split(upstream);
    let c2s = tokio::io::copy(&mut cr, &mut uw);
    let s2c = tokio::io::copy(&mut ur, &mut cw);
    let _ = tokio::join!(c2s, s2c);

    ctx.sink.record_event(mk_event(
        &ctx,
        &flow_id,
        1,
        Direction::Unspecified,
        EventKind::FlowClosed,
        server_ep,
        client_ep,
        pstack("connect", None),
    ));
    Ok(())
}

/// CONNECT with MITM: terminate client TLS with a minted leaf, connect upstream
/// TLS, capture decrypted HTTP as sub-flows. Requests here are origin-form.
async fn handle_connect_mitm<S: FlowSink>(
    buf: BufReader<TcpStream>,
    peer: SocketAddr,
    head: &Head,
    ctx: ProxyContext<S>,
    mitm: Arc<MitmConfig>,
) -> std::io::Result<()> {
    let Some((host, port)) = parse_connect_target(&head.start_line.1) else {
        let _ = buf.into_inner().write_all(bad_request()).await;
        return Ok(());
    };
    let mut client = buf.into_inner();
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    client.flush().await?;

    // Terminate the client's TLS with a leaf minted for the CONNECT target.
    // Minting per-host means SNI-less clients (schannel + IP literals) still get
    // a matching cert.
    let server_config = match flowmint_tls::server_config_for_host(mitm.ca.clone(), &host) {
        Ok(c) => c,
        Err(e) => {
            warn!(%host, error = %e, "building MITM server config failed");
            return Ok(());
        }
    };
    let acceptor = TlsAcceptor::from(server_config);
    let tls_client = match acceptor.accept(client).await {
        Ok(s) => s,
        Err(e) => {
            debug!(%host, error = %e, "client TLS handshake failed");
            return Ok(());
        }
    };

    // Parent "tunnel" flow; each request/response is a child sub-flow.
    let client_ep = client_endpoint(peer);
    let server_ep = server_endpoint(&host, port);
    let tunnel_id = FlowId::new();
    let mut tunnel = Flow::opened(
        tunnel_id.clone(),
        ctx.capture_id.clone(),
        client_ep.clone(),
        server_ep.clone(),
        ctx.clock.stamp().wall_unix_ms,
    );
    tunnel.l7 = Some("tls".into());
    tunnel.secure = true;
    ctx.sink.upsert_flow(tunnel);

    let (cr, mut cw) = tokio::io::split(tls_client);
    let mut client_reader = BufReader::new(cr);

    loop {
        let req_bytes = read_head_bytes(&mut client_reader).await?;
        if req_bytes.is_empty() {
            break; // client closed the tunnel
        }
        let Some(req_head) = parse_head(&req_bytes) else {
            break;
        };
        let path = req_head.start_line.1.clone();
        let req_body = read_body(&mut client_reader, &req_head, false)
            .await
            .unwrap_or_default();
        let method = req_head.start_line.0.clone();
        let url = format!("https://{host}:{port}{path}");

        // 请求断点（转发前）。丢弃则关闭隧道。
        let Some((req_headers, req_body)) =
            request_breakpoint(&ctx, &method, &url, req_head.headers.clone(), req_body).await
        else {
            break;
        };

        // 连接真实上游 TLS。
        let connector = TlsConnector::from(mitm.client_config.clone());
        let server_name = match ServerName::try_from(host.clone()) {
            Ok(n) => n,
            Err(_) => break,
        };
        let up_tcp = match dial_upstream(ctx.upstream_proxy.as_deref(), &host, port, true).await {
            Ok(s) => s,
            Err(e) => {
                warn!(%host, error = %e, "MITM upstream connect failed");
                let _ = cw.write_all(bad_gateway()).await;
                break;
            }
        };
        let up_tls = match connector.connect(server_name, up_tcp).await {
            Ok(s) => s,
            Err(e) => {
                warn!(%host, error = %e, "MITM upstream TLS failed");
                let _ = cw.write_all(bad_gateway()).await;
                break;
            }
        };

        let (status, resp_headers, resp_body) =
            match http_exchange(up_tls, &method, &req_headers, &path, &req_body).await {
                Ok(v) => v,
                Err(e) => {
                    warn!(%host, error = %e, "MITM exchange failed");
                    let _ = cw.write_all(bad_gateway()).await;
                    break;
                }
            };

        // 101 升级结束 HTTP 循环（wss 帧捕获后续），不做响应断点。
        let is_upgrade = status == Some(101);
        let (status, resp_headers, resp_body) = if is_upgrade {
            (status, resp_headers, resp_body)
        } else {
            match response_breakpoint(&ctx, &method, &url, status, resp_headers, resp_body).await {
                Some(v) => v,
                None => break,
            }
        };

        capture_exchange(
            &ctx,
            &client_ep,
            &server_ep,
            &host,
            &path,
            &method,
            &req_headers,
            &req_body,
            status,
            &resp_headers,
            &resp_body,
            true,
            Some(&tunnel_id),
        );

        cw.write_all(&build_client_response(
            status.unwrap_or(0),
            &resp_headers,
            &resp_body,
            !is_upgrade,
        ))
        .await?;
        cw.flush().await?;
        if is_upgrade {
            break;
        }
    }
    Ok(())
}

/// Perform one upstream HTTP exchange over an arbitrary (plain or TLS) stream.
/// 返回 (status, 响应头, 响应体)。
async fn http_exchange<U: AsyncRead + AsyncWrite + Unpin>(
    mut up: U,
    method: &str,
    headers: &[(String, String)],
    path: &str,
    body: &[u8],
) -> std::io::Result<(Option<u16>, Vec<(String, String)>, Vec<u8>)> {
    up.write_all(&build_upstream_request(method, headers, path, body))
        .await?;
    up.flush().await?;
    let mut reader = BufReader::new(up);
    let resp_bytes = read_head_bytes(&mut reader).await?;
    let resp_head = parse_head(&resp_bytes);
    let (status, resp_headers) = match &resp_head {
        Some(h) => (h.start_line.1.parse().ok(), h.headers.clone()),
        None => (None, Vec::new()),
    };
    let resp_body = match &resp_head {
        Some(h) => read_body(&mut reader, h, true).await.unwrap_or_default(),
        None => Vec::new(),
    };
    Ok((status, resp_headers, resp_body))
}

/// 经上游代理建隧道：发 `CONNECT host:port`，读到 2xx 后返回裸 TCP 流（供 TLS/盲转发）。
async fn proxy_connect(proxy: &str, host: &str, port: u16) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect(proxy).await?;
    let _ = s.set_nodelay(true);
    let req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n");
    s.write_all(req.as_bytes()).await?;
    s.flush().await?;
    let head = read_head_direct(&mut s).await?;
    let ok = head
        .split(|&b| b == b' ')
        .nth(1)
        .and_then(|c| std::str::from_utf8(c).ok())
        .is_some_and(|c| c.starts_with('2'));
    if ok {
        Ok(s)
    } else {
        Err(std::io::Error::other("上游代理 CONNECT 被拒绝"))
    }
}

/// 连接上游：直连或经上游代理。`tunnel=true` 时经上游代理要先 CONNECT 建裸隧道
/// （用于 HTTPS MITM/盲转发）；`false` 时是明文 HTTP，直接连到上游代理再发绝对形式请求。
async fn dial_upstream(
    proxy: Option<&str>,
    host: &str,
    port: u16,
    tunnel: bool,
) -> std::io::Result<TcpStream> {
    match proxy {
        Some(p) if tunnel => proxy_connect(p, host, port).await,
        Some(p) => {
            let s = TcpStream::connect(p).await?;
            let _ = s.set_nodelay(true);
            Ok(s)
        }
        None => {
            let s = TcpStream::connect((host, port)).await?;
            let _ = s.set_nodelay(true);
            Ok(s)
        }
    }
}

fn is_ws_upgrade(head: &Head) -> bool {
    head.get("upgrade")
        .map(|u| u.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
}

/// Read an HTTP head directly off a stream (byte-at-a-time) so no bytes past the
/// blank line are buffered — the stream stays positioned for WS frames.
async fn read_head_direct<S: AsyncRead + Unpin>(s: &mut S) -> std::io::Result<Vec<u8>> {
    let mut data = Vec::new();
    let mut b = [0u8; 1];
    loop {
        let n = s.read(&mut b).await?;
        if n == 0 {
            break;
        }
        data.push(b[0]);
        if data.ends_with(b"\r\n\r\n") || data.len() > 32 * 1024 {
            break;
        }
    }
    Ok(data)
}

/// Origin-form upgrade request that preserves Upgrade/Connection/Sec-WebSocket-*.
fn build_upgrade_request(head: &Head, path: &str) -> Vec<u8> {
    let mut out = format!("{} {} HTTP/1.1\r\n", head.start_line.0, path).into_bytes();
    for (k, v) in &head.headers {
        if k.eq_ignore_ascii_case("proxy-connection") {
            continue;
        }
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// Relay a ws:// upgrade: forward the handshake, then pump frames both ways,
/// recording each as a `WebSocketFrame` event (design §3 WS row).
#[allow(clippy::too_many_arguments)]
async fn relay_plain_ws<S: FlowSink>(
    mut client: TcpStream,
    mut upstream: TcpStream,
    head: Head,
    path: String,
    host: String,
    port: u16,
    peer: SocketAddr,
    ctx: ProxyContext<S>,
) -> std::io::Result<()> {
    // 经上游代理时握手请求行也要用绝对形式。
    let target = if ctx.upstream_proxy.is_some() {
        format!("http://{host}:{port}{path}")
    } else {
        path.clone()
    };
    upstream
        .write_all(&build_upgrade_request(&head, &target))
        .await?;
    upstream.flush().await?;
    let up_head_bytes = read_head_direct(&mut upstream).await?;
    let up_head = parse_head(&up_head_bytes);
    let status = up_head
        .as_ref()
        .and_then(|h| h.start_line.1.parse::<u16>().ok());

    // Forward the response head verbatim (keeps Sec-WebSocket-Accept etc.).
    client.write_all(&up_head_bytes).await?;
    client.flush().await?;

    if status != Some(101) {
        // Server declined the upgrade: blind-relay whatever follows.
        let (mut cr, mut cw) = tokio::io::split(client);
        let (mut ur, mut uw) = tokio::io::split(upstream);
        let _ = tokio::join!(
            tokio::io::copy(&mut cr, &mut uw),
            tokio::io::copy(&mut ur, &mut cw)
        );
        return Ok(());
    }

    let client_ep = client_endpoint(peer);
    let server_ep = server_endpoint(&host, port);
    let flow_id = capture_ws_open(
        &ctx,
        &client_ep,
        &server_ep,
        &host,
        &path,
        &head,
        up_head.as_ref(),
        None,
    );

    let (cr, cw) = tokio::io::split(client);
    let (ur, uw) = tokio::io::split(upstream);
    let seq = Arc::new(AtomicU64::new(2));
    let c2s = pump_ws(
        cr,
        uw,
        Some([0x21, 0x43, 0x65, 0x87]),
        Direction::ClientToServer,
        ctx.clone(),
        flow_id.clone(),
        seq.clone(),
        client_ep.clone(),
        server_ep.clone(),
        None,
    );
    let s2c = pump_ws(
        ur,
        cw,
        None,
        Direction::ServerToClient,
        ctx.clone(),
        flow_id.clone(),
        seq.clone(),
        server_ep,
        client_ep,
        None,
    );
    let _ = tokio::join!(c2s, s2c);
    Ok(())
}

/// Pump WebSocket frames from `from` to `to`, recording each. `mask` re-masks
/// for client→server frames (None for server→client).
#[allow(clippy::too_many_arguments)]
async fn pump_ws<S, R, W>(
    mut from: R,
    mut to: W,
    mask: Option<[u8; 4]>,
    direction: Direction,
    ctx: ProxyContext<S>,
    flow_id: FlowId,
    seq: Arc<AtomicU64>,
    src: Endpoint,
    dst: Endpoint,
    tls: Option<TlsInfo>,
) where
    S: FlowSink,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let frame = match ws::read_frame(&mut from).await {
            Ok(Some(f)) => f,
            _ => break,
        };
        let s = seq.fetch_add(1, Ordering::Relaxed);
        let mut ev = mk_event(
            &ctx,
            &flow_id,
            s,
            direction,
            EventKind::WebSocketFrame,
            src.clone(),
            dst.clone(),
            pstack("websocket", tls.clone()),
        );
        ev.attributes
            .insert("ws.opcode".into(), frame.opcode.as_str().into());
        ev.attributes.insert("ws.fin".into(), frame.fin.into());
        ev.attributes
            .insert("ws.length".into(), (frame.payload.len() as i64).into());
        if matches!(frame.opcode, ws::Opcode::Text | ws::Opcode::Binary)
            && !frame.payload.is_empty()
        {
            ev.payload = ctx.sink.put_payload(&frame.payload, RedactionState::None);
        }
        ctx.sink.record_event(ev);

        // 帧拦截：转发前调钩子，可改 payload / 丢帧 / 断开。
        let mut frame = frame;
        if let Some(hook) = &ctx.hook {
            if hook.enabled() {
                let outgoing = direction == Direction::ClientToServer;
                match hook.intercept_ws(outgoing, frame.opcode.as_u8(), &frame.payload) {
                    WsDecision::Forward => {}
                    WsDecision::Modify(p) => frame.payload = p,
                    WsDecision::Drop => continue, // 不转发这一帧
                    WsDecision::Close => {
                        let close = ws::Frame {
                            fin: true,
                            opcode: ws::Opcode::Close,
                            masked: false,
                            payload: Vec::new(),
                        };
                        let _ = to.write_all(&ws::encode_frame(&close, mask)).await;
                        let _ = to.flush().await;
                        break;
                    }
                }
            }
        }

        let bytes = ws::encode_frame(&frame, mask);
        if to.write_all(&bytes).await.is_err() {
            break;
        }
        let _ = to.flush().await;
        if frame.opcode == ws::Opcode::Close {
            break;
        }
    }
}

/// Create the flow + handshake events for an opened WebSocket. Returns its id.
#[allow(clippy::too_many_arguments)]
fn capture_ws_open<S: FlowSink>(
    ctx: &ProxyContext<S>,
    client_ep: &Endpoint,
    server_ep: &Endpoint,
    host: &str,
    path: &str,
    req_head: &Head,
    resp_head: Option<&Head>,
    tls: Option<TlsInfo>,
) -> FlowId {
    let flow_id = FlowId::new();
    let mut flow = Flow::opened(
        flow_id.clone(),
        ctx.capture_id.clone(),
        client_ep.clone(),
        server_ep.clone(),
        ctx.clock.stamp().wall_unix_ms,
    );
    flow.l7 = Some("websocket".into());
    flow.method = Some("GET".into());
    flow.path = Some(path.to_string());
    flow.status = Some(101);
    flow.secure = tls.is_some();
    ctx.sink.upsert_flow(flow);

    let stack = pstack("websocket", tls);
    let mut req_ev = mk_event(
        ctx,
        &flow_id,
        0,
        Direction::ClientToServer,
        EventKind::HttpRequestHeaders,
        client_ep.clone(),
        server_ep.clone(),
        stack.clone(),
    );
    req_ev.attributes.insert("http.method".into(), "GET".into());
    req_ev.attributes.insert("http.host".into(), host.into());
    req_ev.attributes.insert("http.path".into(), path.into());
    req_ev
        .attributes
        .insert("http.request_headers".into(), headers_json(req_head));
    ctx.sink.record_event(req_ev);

    let mut resp_ev = mk_event(
        ctx,
        &flow_id,
        1,
        Direction::ServerToClient,
        EventKind::HttpResponseHeaders,
        server_ep.clone(),
        client_ep.clone(),
        stack,
    );
    resp_ev
        .attributes
        .insert("http.status".into(), 101i64.into());
    if let Some(h) = resp_head {
        resp_ev
            .attributes
            .insert("http.response_headers".into(), headers_json(h));
    }
    ctx.sink.record_event(resp_ev);
    flow_id
}

/// Build flow + request/response events for one HTTP exchange.
#[allow(clippy::too_many_arguments)]
fn capture_exchange<S: FlowSink>(
    ctx: &ProxyContext<S>,
    client_ep: &Endpoint,
    server_ep: &Endpoint,
    host: &str,
    path: &str,
    method: &str,
    req_headers: &[(String, String)],
    req_body: &[u8],
    status: Option<u16>,
    resp_headers: &[(String, String)],
    resp_body: &[u8],
    tls: bool,
    parent: Option<&FlowId>,
) {
    let method = method.to_ascii_uppercase();
    let tls_info = tls.then(|| TlsInfo {
        sni: Some(host.to_string()),
        alpn: None,
        version: None,
        decrypted: true,
    });

    let flow_id = FlowId::new();
    let mut flow = Flow::opened(
        flow_id.clone(),
        ctx.capture_id.clone(),
        client_ep.clone(),
        server_ep.clone(),
        ctx.clock.stamp().wall_unix_ms,
    );
    flow.parent_flow_id = parent.cloned();
    flow.l7 = Some("http/1.1".into());
    flow.method = Some(method.clone());
    flow.path = Some(path.to_string());
    flow.status = status;
    flow.content_type = resp_headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.split(';').next().unwrap_or(v).trim().to_string());
    flow.secure = tls;
    flow.resp_body_size = Some(resp_body.len() as u64);
    flow.closed_at_ms = Some(ctx.clock.stamp().wall_unix_ms);
    ctx.sink.upsert_flow(flow);

    let stack = pstack("http/1.1", tls_info);

    let mut req_ev = mk_event(
        ctx,
        &flow_id,
        0,
        Direction::ClientToServer,
        EventKind::HttpRequestHeaders,
        client_ep.clone(),
        server_ep.clone(),
        stack.clone(),
    );
    req_ev
        .attributes
        .insert("http.method".into(), method.into());
    req_ev.attributes.insert("http.host".into(), host.into());
    req_ev.attributes.insert("http.path".into(), path.into());
    req_ev
        .attributes
        .insert("http.request_headers".into(), headers_json_of(req_headers));
    if !req_body.is_empty() {
        req_ev.payload = ctx.sink.put_payload(req_body, RedactionState::None);
    }
    ctx.sink.record_event(req_ev);

    let mut resp_ev = mk_event(
        ctx,
        &flow_id,
        1,
        Direction::ServerToClient,
        EventKind::HttpResponseHeaders,
        server_ep.clone(),
        client_ep.clone(),
        stack,
    );
    if let Some(s) = status {
        resp_ev
            .attributes
            .insert("http.status".into(), (s as i64).into());
    }
    resp_ev.attributes.insert(
        "http.response_headers".into(),
        headers_json_of(resp_headers),
    );
    if !resp_body.is_empty() {
        resp_ev.payload = ctx.sink.put_payload(resp_body, RedactionState::None);
    }
    ctx.sink.record_event(resp_ev);
}

fn headers_json(head: &Head) -> serde_json::Value {
    headers_json_of(&head.headers)
}

fn headers_json_of(headers: &[(String, String)]) -> serde_json::Value {
    serde_json::Value::Array(
        headers
            .iter()
            .map(|(k, v)| serde_json::json!({ "name": k, "value": v }))
            .collect(),
    )
}

/// 请求断点：转发前调用钩子。返回最终 (headers, body)；`None` 表示丢弃。
async fn request_breakpoint<S: FlowSink>(
    ctx: &ProxyContext<S>,
    method: &str,
    url: &str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
) -> Option<(Vec<(String, String)>, Vec<u8>)> {
    let Some(hook) = &ctx.hook else {
        return Some((headers, body));
    };
    if !hook.enabled() {
        return Some((headers, body));
    }
    // 给回调解压后的明文 body（按 Content-Encoding），改包侧无需自己解压/压缩。
    let plain = decode::decode_body(header_value(&headers, "content-encoding").as_deref(), &body);
    let msg = InterceptMessage {
        is_response: false,
        method: method.to_string(),
        url: url.to_string(),
        status: None,
        headers: headers.clone(),
        body: plain,
    };
    match hook.intercept(msg).await {
        Decision::Continue => Some((headers, body)), // 未改：原样（压缩）转发
        Decision::Modify(e) => {
            let (headers, body) = reencode_edit(header_value(&headers, "content-encoding"), e);
            Some((headers, body))
        }
        Decision::Drop => None,
    }
}

/// 改包后的 body 是明文：若原来有可识别的 `Content-Encoding` 就按它**重新压缩**、保留该头；
/// 否则（identity/未知）去掉该头、用明文。
fn reencode_edit(orig_encoding: Option<String>, mut e: Edit) -> (Vec<(String, String)>, Vec<u8>) {
    match orig_encoding
        .as_deref()
        .and_then(|enc| decode::encode_body(enc, &e.body))
    {
        Some(compressed) => (e.headers, compressed), // 保留 Content-Encoding
        None => {
            strip_content_encoding(&mut e.headers);
            (e.headers, e.body)
        }
    }
}

/// 取某个头的值（大小写不敏感）。
fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

/// 去掉 Content-Encoding 头（body 改成明文后调用）。
fn strip_content_encoding(headers: &mut Vec<(String, String)>) {
    headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-encoding"));
}

/// 响应断点：回传前调用钩子。返回最终 (status, headers, body)；`None` 表示丢弃。
async fn response_breakpoint<S: FlowSink>(
    ctx: &ProxyContext<S>,
    method: &str,
    url: &str,
    status: Option<u16>,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
) -> Option<(Option<u16>, Vec<(String, String)>, Vec<u8>)> {
    let Some(hook) = &ctx.hook else {
        return Some((status, headers, body));
    };
    if !hook.enabled() {
        return Some((status, headers, body));
    }
    // 给回调解压后的明文 body（按 Content-Encoding），改包侧无需自己解压/压缩。
    let plain = decode::decode_body(header_value(&headers, "content-encoding").as_deref(), &body);
    let msg = InterceptMessage {
        is_response: true,
        method: method.to_string(),
        url: url.to_string(),
        status,
        headers: headers.clone(),
        body: plain,
    };
    match hook.intercept(msg).await {
        Decision::Continue => Some((status, headers, body)), // 未改：原样（压缩）转发
        Decision::Modify(e) => {
            let st = e.status.or(status);
            let (headers, body) = reencode_edit(header_value(&headers, "content-encoding"), e);
            Some((st, headers, body))
        }
        Decision::Drop => None,
    }
}

fn is_loopback_host(host: &str) -> bool {
    host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

/// 服务代理自身的落地页（对标 Fiddler）：`/` 显示各平台安装引导与下载入口，
/// `.crt`（PEM，Windows/macOS/Android）/ `.cer`（DER，iOS）下载 CA 证书。
async fn serve_local_page<S: FlowSink>(
    mut stream: TcpStream,
    target: &str,
    ctx: &ProxyContext<S>,
) -> std::io::Result<()> {
    let path = target.split(['?', '#']).next().unwrap_or(target);

    // DER（iOS）：.cer / .der
    let is_der = matches!(
        path,
        "/cert.cer" | "/cert.der" | "/ca.cer" | "/root.cer" | "/flowmint-ca.cer"
    );
    // PEM（Windows/macOS/Android）：.crt / .pem 以及裸 /cert
    let is_pem = matches!(
        path,
        "/cert" | "/cert.crt" | "/cert.pem" | "/ca" | "/ca.crt" | "/ca.pem" | "/flowmint-ca.crt"
    );

    let resp = if is_der {
        match &ctx.ca_der {
            Some(der) => http_response(
                200,
                "application/x-x509-ca-cert",
                Some("flowmint-ca.cer"),
                der,
            ),
            None => http_response(
                503,
                "text/plain; charset=utf-8",
                None,
                "CA 尚未就绪".as_bytes(),
            ),
        }
    } else if is_pem {
        match &ctx.ca_pem {
            Some(pem) => http_response(
                200,
                "application/x-x509-ca-cert",
                Some("flowmint-ca.crt"),
                pem.as_bytes(),
            ),
            None => http_response(
                503,
                "text/plain; charset=utf-8",
                None,
                "CA 尚未就绪".as_bytes(),
            ),
        }
    } else if path == "/" {
        http_response(
            200,
            "text/html; charset=utf-8",
            None,
            LANDING_HTML.as_bytes(),
        )
    } else {
        let body = "404 Not Found — 访问 / 查看 FlowMint 证书下载页";
        http_response(404, "text/plain; charset=utf-8", None, body.as_bytes())
    };
    stream.write_all(&resp).await?;
    stream.flush().await
}

/// 组装一个 `Connection: close` 的 HTTP/1.1 响应字节。
fn http_response(status: u16, content_type: &str, filename: Option<&str>, body: &[u8]) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        503 => "Service Unavailable",
        _ => "",
    };
    let mut out =
        format!("HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\n").into_bytes();
    if let Some(name) = filename {
        out.extend_from_slice(
            format!("Content-Disposition: attachment; filename=\"{name}\"\r\n").as_bytes(),
        );
    }
    out.extend_from_slice(
        format!(
            "Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    );
    out.extend_from_slice(body);
    out
}

/// 落地页 HTML（自包含、内联样式与脚本）：两种格式下载 + 各平台安装引导 tab。
const LANDING_HTML: &str = r#"<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FlowMint 抓包证书</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body { margin:0; font:15px/1.65 system-ui,"Segoe UI",Roboto,sans-serif; background:#0f1115; color:#e6e9ef;
    display:flex; align-items:flex-start; justify-content:center; padding:32px 16px; min-height:100vh; }
  .card { width:100%; max-width:600px; padding:28px 32px; background:#161922; border:1px solid #262b36; border-radius:14px; }
  h1 { margin:0 0 4px; font-size:22px; } h1 span { color:#5b8cff; }
  p.sub { color:#8b93a4; margin:4px 0 18px; }
  .dl { display:flex; flex-wrap:wrap; gap:10px; margin-bottom:8px; }
  a.btn { display:inline-block; padding:11px 18px; background:#5b8cff; color:#fff; text-decoration:none;
    border-radius:8px; font-weight:600; }
  a.btn.alt { background:#1c2029; color:#e6e9ef; border:1px solid #2f3542; }
  .hint { color:#8b93a4; font-size:13px; margin:2px 0 20px; }
  .tabs { display:flex; gap:4px; border-bottom:1px solid #262b36; margin-bottom:14px; flex-wrap:wrap; }
  .tab { padding:8px 14px; cursor:pointer; color:#8b93a4; border-bottom:2px solid transparent; margin-bottom:-1px; }
  .tab.active { color:#e6e9ef; border-bottom-color:#5b8cff; }
  .panel { display:none; } .panel.active { display:block; }
  ol { color:#c9cede; padding-left:20px; margin:6px 0; } li { margin:5px 0; }
  b.warn { color:#d29922; }
  code { background:#1c2029; padding:1px 6px; border-radius:5px; font-family:ui-monospace,Consolas,monospace; font-size:13px; }
  .foot { color:#8b93a4; font-size:13px; margin-top:20px; border-top:1px solid #262b36; padding-top:14px;
    text-wrap:pretty; }
</style></head>
<body><div class="card">
  <h1>Flow<span>Mint</span> 抓包证书</h1>
  <p class="sub">要解密 HTTPS，请在本设备安装并信任下面的 CA 根证书。</p>

  <div class="dl">
    <a class="btn" href="/cert.crt" download="flowmint-ca.crt">⬇ Windows / macOS / Android (.crt)</a>
    <a class="btn alt" href="/cert.cer" download="flowmint-ca.cer">⬇ iOS / iPadOS (.cer)</a>
  </div>
  <div class="hint">下载后，按你的系统在下面选对应的安装步骤。</div>

  <div class="tabs">
    <div class="tab active" data-t="win">Windows</div>
    <div class="tab" data-t="mac">macOS</div>
    <div class="tab" data-t="and">Android</div>
    <div class="tab" data-t="ios">iOS / iPadOS</div>
  </div>

  <div class="panel active" id="win">
    <ol>
      <li>下载 <code>flowmint-ca.crt</code> 并双击。</li>
      <li>点“安装证书”→ 存储位置选 <b>当前用户</b>（或本地计算机）。</li>
      <li>选择 <b>“将所有的证书都放入下列存储”</b> → 浏览 → <b>“受信任的根证书颁发机构”</b>。</li>
      <li>下一步 → 完成，弹出安全警告点“是”。</li>
    </ol>
  </div>
  <div class="panel" id="mac">
    <ol>
      <li>下载 <code>flowmint-ca.crt</code> 并双击，导入到 <b>“登录”</b> 钥匙串。</li>
      <li>打开“钥匙串访问”，找到 <code>FlowMint Local CA</code>，双击它。</li>
      <li>展开“信任”，把 <b>“使用此证书时”</b> 设为 <b>“始终信任”</b>，关闭窗口输入密码确认。</li>
    </ol>
  </div>
  <div class="panel" id="and">
    <ol>
      <li>下载 <code>flowmint-ca.crt</code>。</li>
      <li>设置 → 安全 →（加密与凭据）→ <b>安装证书</b> → <b>CA 证书</b> → 选择该文件。</li>
      <li><b class="warn">注意：</b>Android 7+ 起，只有浏览器等会信任用户安装的 CA；<b>多数 App 默认不信任用户证书</b>（需 App 自身允许，或已 root 装入系统证书库）。</li>
    </ol>
  </div>
  <div class="panel" id="ios">
    <ol>
      <li>用上方 <b>iOS (.cer)</b> 按钮下载，允许“下载描述文件”。</li>
      <li>设置 → 通用 → <b>VPN与设备管理</b> → 安装刚下载的 FlowMint 描述文件。</li>
      <li>再到 设置 → 通用 → 关于本机 → <b>证书信任设置</b>，为 FlowMint 打开 <b>“完全信任”</b>（这一步不做则 HTTPS 仍握手失败）。</li>
    </ol>
  </div>

  <div class="foot">装好后在 FlowMint 设置里开启 <b>解密 HTTPS (MITM)</b>，即可看到明文。</div>
</div>
<script>
  document.querySelectorAll('.tab').forEach(function(t){
    t.addEventListener('click', function(){
      document.querySelectorAll('.tab').forEach(function(x){x.classList.remove('active')});
      document.querySelectorAll('.panel').forEach(function(x){x.classList.remove('active')});
      t.classList.add('active');
      document.getElementById(t.getAttribute('data-t')).classList.add('active');
    });
  });
</script>
</body></html>"#;

fn client_endpoint(peer: SocketAddr) -> Endpoint {
    // 按源端口反查发起进程（本机 loopback 客户端；查不到则留空）。
    let (process_pid, process_name) = match procinfo::resolve_by_local_port(peer.port()) {
        Some((pid, name)) => (Some(pid), Some(name)),
        None => (None, None),
    };
    Endpoint {
        ip: Some(peer.ip().to_string()),
        port: peer.port(),
        process_name,
        process_pid,
        ..Default::default()
    }
}

fn server_endpoint(host: &str, port: u16) -> Endpoint {
    Endpoint {
        host: Some(host.to_string()),
        port,
        ..Default::default()
    }
}

fn pstack(l7: &str, tls: Option<TlsInfo>) -> ProtocolStack {
    ProtocolStack {
        l4: "tcp".into(),
        tls,
        l7: Some(l7.to_string()),
    }
}

fn mk_event<S: FlowSink>(
    ctx: &ProxyContext<S>,
    flow_id: &FlowId,
    sequence: u64,
    direction: Direction,
    kind: EventKind,
    source: Endpoint,
    destination: Endpoint,
    protocol_stack: ProtocolStack,
) -> NetworkEvent {
    let mut ev = NetworkEvent::new(
        ctx.capture_id.clone(),
        flow_id.clone(),
        sequence,
        ctx.clock.stamp(),
        direction,
        kind,
    );
    ev.source = source;
    ev.destination = destination;
    ev.protocol_stack = protocol_stack;
    ev.evidence = EvidenceRef {
        adapter: ADAPTER.into(),
        decoder_version: None,
    };
    ev
}

fn build_upstream_request(
    method: &str,
    headers: &[(String, String)],
    path: &str,
    body: &[u8],
) -> Vec<u8> {
    let mut out = format!("{method} {path} HTTP/1.1\r\n").into_bytes();
    for (k, v) in headers {
        if is_hop_by_hop(k) || k.eq_ignore_ascii_case("content-length") {
            continue;
        }
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    if !body.is_empty() {
        out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    }
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    out.extend_from_slice(body);
    out
}

fn build_client_response(
    status: u16,
    headers: &[(String, String)],
    body: &[u8],
    keep_alive: bool,
) -> Vec<u8> {
    // 空 reason 短语（"HTTP/1.1 200 \r\n"）合法，客户端可接受。
    let mut out = format!("HTTP/1.1 {status} \r\n").into_bytes();
    for (k, v) in headers {
        if is_hop_by_hop(k)
            || k.eq_ignore_ascii_case("content-length")
            || k.eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    let conn = if keep_alive { "keep-alive" } else { "close" };
    out.extend_from_slice(format!("Connection: {conn}\r\n\r\n").as_bytes());
    out.extend_from_slice(body);
    out
}

fn is_hop_by_hop(name: &str) -> bool {
    const HOP: [&str; 8] = [
        "connection",
        "proxy-connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "upgrade",
    ];
    HOP.iter().any(|h| name.eq_ignore_ascii_case(h))
}

fn bad_request() -> &'static [u8] {
    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
}

fn bad_gateway() -> &'static [u8] {
    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
}
