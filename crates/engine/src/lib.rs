//! FlowMint engine (design §5.1): the process that owns capture lifecycle and
//! wires adapters to storage. In the full architecture this also holds the
//! control plane, authorization and the MITM CA; this MVP slice covers capture
//! profiles + the explicit HTTP proxy + query passthroughs.

mod breakpoint;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use flowmint_model::{
    CaptureId, Clock, Direction, Endpoint, EventKind, EvidenceRef, Flow, FlowId, NetworkEvent,
    PayloadRef, ProtocolStack, RedactionState, TlsInfo,
};
use flowmint_proxy_http::{FlowSink, MitmConfig, ProxyContext};
use flowmint_storage::{SearchFilter, Store};
use tokio::sync::broadcast;
use tracing::warn;

/// Adapts the (single-writer) [`Store`] to the proxy's [`FlowSink`], serializing
/// writes behind a mutex. Writes never `await` while holding the lock. It also
/// broadcasts each upserted flow so a live UI can update in real time.
pub struct StoreSink {
    store: Arc<Mutex<Store>>,
    live: broadcast::Sender<Flow>,
}

impl FlowSink for StoreSink {
    fn upsert_flow(&self, flow: Flow) {
        if let Err(e) = self.store.lock().unwrap().upsert_flow(&flow) {
            warn!(error = %e, "upsert_flow failed");
        }
        let _ = self.live.send(flow); // ignore if no subscribers
    }

    fn record_event(&self, event: NetworkEvent) {
        if let Err(e) = self.store.lock().unwrap().insert_event(&event) {
            warn!(error = %e, "record_event failed");
        }
    }

    fn put_payload(&self, bytes: &[u8], redaction: RedactionState) -> Option<PayloadRef> {
        match self.store.lock().unwrap().put_payload(bytes, redaction) {
            Ok(r) => Some(r),
            Err(e) => {
                warn!(error = %e, "put_payload failed");
                None
            }
        }
    }
}

/// Top-level engine handle. Cheap to clone (shares the store).
#[derive(Clone)]
pub struct Engine {
    store: Arc<Mutex<Store>>,
    root: PathBuf,
    live: broadcast::Sender<Flow>,
    interceptor: Arc<breakpoint::Interceptor>,
    /// 手动请求（重放/构造器）归属的 capture，首次发送时惰性创建。
    manual_capture: Arc<Mutex<Option<CaptureId>>>,
}

impl Engine {
    /// Open (creating if needed) an engine backed by a store at `data_dir`.
    pub fn open(data_dir: impl AsRef<Path>) -> Result<Self> {
        let root = data_dir.as_ref().to_path_buf();
        let store = Store::open(&root)?;
        let (live, _) = broadcast::channel(4096);
        Ok(Self {
            store: Arc::new(Mutex::new(store)),
            root,
            live,
            interceptor: Arc::new(breakpoint::Interceptor::new()),
            manual_capture: Arc::new(Mutex::new(None)),
        })
    }

    // --- 断点改包（design §9 Breakpoint Editor）------------------------

    /// 配置断点：开关、主机过滤（URL 子串）、是否也拦截响应。
    pub fn set_breakpoints(
        &self,
        enabled: bool,
        host_filter: Option<String>,
        break_response: bool,
    ) {
        self.interceptor.set(enabled, host_filter, break_response);
    }

    /// 界面对某挂起消息的决定。action：continue / modify / drop。
    pub fn resume_breakpoint(
        &self,
        id: u64,
        action: &str,
        status: Option<u16>,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) {
        self.interceptor.resume(id, action, status, headers, body);
    }

    /// 订阅"挂起消息"广播（界面据此弹出拦截编辑器）。
    pub fn subscribe_breakpoints(&self) -> broadcast::Receiver<serde_json::Value> {
        self.interceptor.subscribe()
    }

    /// Subscribe to live flow updates (each capture upsert). Used by the desktop
    /// UI to render sessions as they arrive.
    pub fn subscribe(&self) -> broadcast::Receiver<Flow> {
        self.live.subscribe()
    }

    /// Directory holding this profile's CA (design §7.2). Created on demand.
    fn ca_dir(&self) -> PathBuf {
        self.root.join("ca")
    }

    /// Ensure the profile CA exists; return (ca.pem path, PEM text) for the user
    /// to install/trust. MITM is never enabled implicitly by this.
    pub fn ensure_ca(&self) -> Result<(PathBuf, String)> {
        let ca = flowmint_tls::CertAuthority::load_or_create(self.ca_dir())?;
        Ok((self.ca_dir().join("ca.pem"), ca.ca_pem().to_string()))
    }

    /// 当前生效的 CA：`use_default=true` 用内置默认共享 CA（⚠️ 公开私钥、仅测试），
    /// 否则用本机生成的 CA。抓包/安装/下载证书都以它为准。
    pub fn active_ca(&self, use_default: bool) -> Result<Arc<flowmint_tls::CertAuthority>> {
        Ok(Arc::new(if use_default {
            flowmint_tls::CertAuthority::bundled_default()?
        } else {
            flowmint_tls::CertAuthority::load_or_create(self.ca_dir())?
        }))
    }

    /// 当前生效 CA 的 PEM（供安装/下载）。
    pub fn active_ca_pem(&self, use_default: bool) -> Result<String> {
        Ok(self.active_ca(use_default)?.ca_pem().to_string())
    }

    /// Start an explicit HTTP capture bound to `bind` (should be loopback).
    /// When `mitm` is true, HTTPS is intercepted using the profile CA (design
    /// §7.2). Runs until the returned future is dropped/cancelled.
    pub async fn run_http_capture(
        &self,
        bind: SocketAddr,
        label: Option<String>,
        mitm: bool,
        insecure_upstream: bool,
        upstream_proxy: Option<String>,
        use_default_ca: bool,
    ) -> Result<()> {
        let clock = Clock::start_now();
        let capture_id = flowmint_model::CaptureId::new();
        let started_ms = clock.stamp().wall_unix_ms;
        self.store.lock().unwrap().insert_capture(
            capture_id.as_str(),
            started_ms,
            label.as_deref(),
        )?;

        // 无论是否 MITM 都备好 CA（生成很廉价），落地页要用它下载证书。
        let ca = self.active_ca(use_default_ca)?;
        let ca_pem: Arc<str> = Arc::from(ca.ca_pem());
        let ca_der: Arc<[u8]> = Arc::from(ca.ca_der());

        let mitm_cfg = if mitm {
            let client_config = if insecure_upstream {
                warn!("insecure upstream TLS verification enabled (test profiles only)");
                flowmint_tls::insecure_upstream_client_config()?
            } else {
                flowmint_tls::upstream_client_config()?
            };
            Some(Arc::new(MitmConfig {
                ca: ca.clone(),
                client_config,
            }))
        } else {
            None
        };

        let ctx = ProxyContext {
            sink: Arc::new(StoreSink {
                store: self.store.clone(),
                live: self.live.clone(),
            }),
            capture_id,
            clock,
            mitm: mitm_cfg,
            hook: Some(self.interceptor.clone() as Arc<dyn flowmint_proxy_http::InterceptHook>),
            upstream_proxy: upstream_proxy.map(Arc::from),
            proxy_port: bind.port(),
            ca_pem: Some(ca_pem),
            ca_der: Some(ca_der),
        };
        flowmint_proxy_http::run(bind, ctx).await?;
        Ok(())
    }

    // --- read model (design §5: Query & Evidence Service) ----------------

    pub fn list_captures(&self) -> Result<Vec<flowmint_storage::CaptureRow>> {
        Ok(self.store.lock().unwrap().list_captures()?)
    }

    pub fn search_flows(&self, filter: &SearchFilter) -> Result<Vec<Flow>> {
        Ok(self.store.lock().unwrap().search_flows(filter)?)
    }

    /// 清空所有已捕获数据（flows/events + chunk 磁盘文件）。UI 的"清空存储"用它。
    pub fn clear_storage(&self) -> Result<()> {
        self.store.lock().unwrap().clear()?;
        *self.manual_capture.lock().unwrap() = None; // captures 已删，重放需重建
        Ok(())
    }

    pub fn get_flow(&self, flow_id: &str) -> Result<Option<Flow>> {
        Ok(self.store.lock().unwrap().get_flow(flow_id)?)
    }

    pub fn events_for_flow(&self, flow_id: &str) -> Result<Vec<NetworkEvent>> {
        Ok(self.store.lock().unwrap().events_for_flow(flow_id)?)
    }

    pub fn get_payload(&self, payload: &PayloadRef) -> Result<Vec<u8>> {
        Ok(self.store.lock().unwrap().get_payload(payload)?)
    }

    /// Rich flow detail for the inspector: flow + each event's headers and
    /// decoded body (text when UTF-8, else a hex preview + `is_binary`). Bodies
    /// are capped for display.
    pub fn flow_detail(&self, flow_id: &str) -> Result<Option<serde_json::Value>> {
        use serde_json::json;
        const MAX_BODY: usize = 2 * 1024 * 1024;
        let Some(flow) = self.get_flow(flow_id)? else {
            return Ok(None);
        };
        let mut events = Vec::new();
        for ev in self.events_for_flow(flow_id)? {
            let headers = ev
                .attributes
                .get("http.request_headers")
                .or_else(|| ev.attributes.get("http.response_headers"))
                .cloned()
                .unwrap_or_else(|| json!([]));
            let (body, body_size, is_binary) = match &ev.payload {
                Some(p) => {
                    // 存的是压缩后的原始字节；按 Content-Encoding 解压后再判定文本/二进制，
                    // 否则 gzip/br 的 HTML/JS/JSON 都会被当成二进制只能看 Hex。
                    let raw = self.get_payload(p).unwrap_or_default();
                    let enc = content_encoding(&headers);
                    let bytes = flowmint_proxy_http::decode::decode_body(enc.as_deref(), &raw);
                    let shown = &bytes[..bytes.len().min(MAX_BODY)];
                    match std::str::from_utf8(shown) {
                        Ok(s) => (json!(s), bytes.len(), false),
                        Err(_) => {
                            let hex: String = shown.iter().map(|b| format!("{b:02x}")).collect();
                            (json!(hex), bytes.len(), true)
                        }
                    }
                }
                None => (serde_json::Value::Null, 0, false),
            };
            events.push(json!({
                "event_id": ev.event_id.as_str(),
                "kind": format!("{:?}", ev.kind),
                "direction": format!("{:?}", ev.direction),
                "sequence": ev.sequence,
                "headers": headers,
                "body": body,
                "body_size": body_size,
                "is_binary": is_binary,
                "ws_opcode": ev.attributes.get("ws.opcode"),
                "tls": ev.protocol_stack.tls,
            }));
        }
        Ok(Some(
            json!({ "flow": serde_json::to_value(&flow)?, "events": events }),
        ))
    }

    /// 发送一条请求（重放 / 构造器）。解析 URL，按需建 TLS，返回响应 JSON。
    pub async fn send_request(
        &self,
        method: &str,
        url: &str,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        insecure: bool,
    ) -> Result<serde_json::Value> {
        use serde_json::json;
        let (https, host, port, path) = parse_url(url)?;
        let tls_config = if https {
            Some(if insecure {
                flowmint_tls::insecure_upstream_client_config()?
            } else {
                flowmint_tls::upstream_client_config()?
            })
        } else {
            None
        };
        let r = flowmint_proxy_http::client::send_request(
            method, &host, port, &path, https, &headers, &body, tls_config,
        )
        .await?;
        // 把这次手动发送也记入抓包列表（写库 + 广播），与代理抓到的流量并列。
        self.record_manual_send(
            method,
            &host,
            port,
            &path,
            https,
            &headers,
            &body,
            Some(r.status),
            &r.headers,
            &r.body,
        );
        // 与检查器一致：按响应头的 Content-Encoding 解压后再判定文本/二进制。
        let enc = r
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-encoding"))
            .map(|(_, v)| v.clone());
        let body = flowmint_proxy_http::decode::decode_body(enc.as_deref(), &r.body);
        let (body_val, is_binary) = match std::str::from_utf8(&body) {
            Ok(s) => (json!(s), false),
            Err(_) => (
                json!(body.iter().map(|b| format!("{b:02x}")).collect::<String>()),
                true,
            ),
        };
        Ok(json!({
            "status": r.status,
            "headers": r.headers,
            "body": body_val,
            "is_binary": is_binary,
            "body_size": body.len(),
        }))
    }

    /// 惰性获取"手动请求/重放"专用 capture 的 id（首次调用时创建并写库）。
    fn manual_capture_id(&self) -> Result<CaptureId> {
        let mut guard = self.manual_capture.lock().unwrap();
        if let Some(c) = guard.as_ref() {
            return Ok(c.clone());
        }
        let id = CaptureId::new();
        let now = Clock::start_now().stamp().wall_unix_ms;
        self.store
            .lock()
            .unwrap()
            .insert_capture(id.as_str(), now, Some("手动请求/重放"))?;
        *guard = Some(id.clone());
        Ok(id)
    }

    /// 把一次手动发送记录成一条 http/1.1 flow（请求头 + 响应头两条事件），
    /// 写库并广播，使其像代理抓到的流量一样出现在会话列表与检查器里。
    #[allow(clippy::too_many_arguments)]
    fn record_manual_send(
        &self,
        method: &str,
        host: &str,
        port: u16,
        path: &str,
        https: bool,
        req_headers: &[(String, String)],
        req_body: &[u8],
        status: Option<u16>,
        resp_headers: &[(String, String)],
        resp_body: &[u8],
    ) {
        let capture_id = match self.manual_capture_id() {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "manual capture 创建失败，跳过记录");
                return;
            }
        };
        let clock = Clock::start_now();
        let sink = StoreSink {
            store: self.store.clone(),
            live: self.live.clone(),
        };

        let client_ep = Endpoint {
            ip: Some("127.0.0.1".into()),
            port: 0,
            ..Default::default()
        };
        let server_ep = Endpoint {
            host: Some(host.to_string()),
            port,
            ..Default::default()
        };
        let tls_info = https.then(|| TlsInfo {
            sni: Some(host.to_string()),
            alpn: None,
            version: None,
            decrypted: true,
        });

        let flow_id = FlowId::new();
        let mut flow = Flow::opened(
            flow_id.clone(),
            capture_id.clone(),
            client_ep.clone(),
            server_ep.clone(),
            clock.stamp().wall_unix_ms,
        );
        flow.l7 = Some("http/1.1".into());
        flow.method = Some(method.to_string());
        flow.path = Some(path.to_string());
        flow.status = status;
        flow.content_type = resp_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.split(';').next().unwrap_or(v).trim().to_string());
        flow.secure = https;
        flow.resp_body_size = Some(resp_body.len() as u64);
        flow.closed_at_ms = Some(clock.stamp().wall_unix_ms);
        sink.upsert_flow(flow);

        let stack = ProtocolStack {
            l4: "tcp".into(),
            tls: tls_info,
            l7: Some("http/1.1".into()),
        };
        let evidence = EvidenceRef {
            adapter: "composer".into(),
            decoder_version: None,
        };

        let mut req_ev = NetworkEvent::new(
            capture_id.clone(),
            flow_id.clone(),
            0,
            clock.stamp(),
            Direction::ClientToServer,
            EventKind::HttpRequestHeaders,
        );
        req_ev.source = client_ep.clone();
        req_ev.destination = server_ep.clone();
        req_ev.protocol_stack = stack.clone();
        req_ev.evidence = evidence.clone();
        req_ev
            .attributes
            .insert("http.method".into(), method.into());
        req_ev.attributes.insert("http.host".into(), host.into());
        req_ev.attributes.insert("http.path".into(), path.into());
        req_ev
            .attributes
            .insert("http.request_headers".into(), headers_json(req_headers));
        if !req_body.is_empty() {
            req_ev.payload = sink.put_payload(req_body, RedactionState::None);
        }
        sink.record_event(req_ev);

        let mut resp_ev = NetworkEvent::new(
            capture_id,
            flow_id,
            1,
            clock.stamp(),
            Direction::ServerToClient,
            EventKind::HttpResponseHeaders,
        );
        resp_ev.source = server_ep;
        resp_ev.destination = client_ep;
        resp_ev.protocol_stack = stack;
        resp_ev.evidence = evidence;
        if let Some(s) = status {
            resp_ev
                .attributes
                .insert("http.status".into(), (s as i64).into());
        }
        resp_ev
            .attributes
            .insert("http.response_headers".into(), headers_json(resp_headers));
        if !resp_body.is_empty() {
            resp_ev.payload = sink.put_payload(resp_body, RedactionState::None);
        }
        sink.record_event(resp_ev);
    }

    // --- rule replay (design §9.1 step 3) --------------------------------

    /// Reconstruct an [`HttpExchange`] from a captured HTTP flow, pulling
    /// headers off the events and bodies from the chunk store.
    pub fn exchange_for_flow(&self, flow_id: &str) -> Result<Option<flowmint_rules::HttpExchange>> {
        use flowmint_model::EventKind;
        let Some(flow) = self.get_flow(flow_id)? else {
            return Ok(None);
        };
        let mut ex = flowmint_rules::HttpExchange::request(
            flow.method.as_deref().unwrap_or("GET"),
            flow.host.as_deref().unwrap_or(""),
            flow.path.as_deref().unwrap_or("/"),
        );
        ex.status = flow.status;
        for ev in self.events_for_flow(flow_id)? {
            match ev.kind {
                EventKind::HttpRequestHeaders => {
                    ex.req_headers = headers_from_event(&ev, "http.request_headers");
                    if let Some(p) = &ev.payload {
                        ex.req_body = self.get_payload(p)?;
                    }
                }
                EventKind::HttpResponseHeaders => {
                    ex.resp_headers = headers_from_event(&ev, "http.response_headers");
                    if let Some(p) = &ev.payload {
                        ex.resp_body = self.get_payload(p)?;
                    }
                }
                _ => {}
            }
        }
        Ok(Some(ex))
    }

    /// Export captured HTTP flows to a HAR 1.2 file. Returns the entry count.
    pub fn export_har(&self, out: &Path, host: Option<&str>) -> Result<usize> {
        use flowmint_model::EventKind;
        use serde_json::{json, Value};
        use time::{format_description::well_known::Rfc3339, OffsetDateTime};

        let flows = self.search_flows(&SearchFilter {
            host: host.map(|s| s.to_string()),
            capture_id: None,
            limit: 1_000_000,
        })?;

        let iso = |ms: i64| -> String {
            OffsetDateTime::from_unix_timestamp_nanos((ms as i128) * 1_000_000)
                .ok()
                .and_then(|dt| dt.format(&Rfc3339).ok())
                .unwrap_or_else(|| "1970-01-01T00:00:00Z".into())
        };
        let headers_of = |ev: Option<&NetworkEvent>, key: &str| -> Value {
            ev.and_then(|e| e.attributes.get(key))
                .filter(|v| v.is_array())
                .cloned()
                .unwrap_or_else(|| json!([]))
        };

        let mut entries = Vec::new();
        for flow in &flows {
            if flow.l7.as_deref() != Some("http/1.1") {
                continue;
            }
            let events = self.events_for_flow(flow.flow_id.as_str())?;
            let req = events
                .iter()
                .find(|e| matches!(e.kind, EventKind::HttpRequestHeaders));
            let resp = events
                .iter()
                .find(|e| matches!(e.kind, EventKind::HttpResponseHeaders));
            // 导出 HAR 时把 body 按 Content-Encoding 解压，text 字段才是可读原文。
            let decode = |e: Option<&NetworkEvent>, key: &str| -> Vec<u8> {
                let raw = e
                    .and_then(|e| e.payload.as_ref())
                    .and_then(|p| self.get_payload(p).ok())
                    .unwrap_or_default();
                let enc = e.and_then(|e| {
                    headers_from_event(e, key)
                        .into_iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case("content-encoding"))
                        .map(|(_, v)| v)
                });
                flowmint_proxy_http::decode::decode_body(enc.as_deref(), &raw)
            };
            let req_body = decode(req, "http.request_headers");
            let resp_body = decode(resp, "http.response_headers");

            let tls = req
                .map(|e| {
                    e.protocol_stack
                        .tls
                        .as_ref()
                        .map(|t| t.decrypted)
                        .unwrap_or(false)
                })
                .unwrap_or(false);
            let scheme = if tls { "https" } else { "http" };
            let default_port = if tls { 443 } else { 80 };
            let host_s = flow.host.as_deref().unwrap_or("");
            let authority = if flow.server.port == 0 || flow.server.port == default_port {
                host_s.to_string()
            } else {
                format!("{host_s}:{}", flow.server.port)
            };

            let mut request = json!({
                "method": flow.method.as_deref().unwrap_or("GET"),
                "url": format!("{scheme}://{authority}{}", flow.path.as_deref().unwrap_or("/")),
                "httpVersion": "HTTP/1.1", "cookies": [], "queryString": [],
                "headers": headers_of(req, "http.request_headers"),
                "headersSize": -1, "bodySize": req_body.len() as i64,
            });
            if !req_body.is_empty() {
                request["postData"] = json!({ "mimeType": "application/octet-stream", "text": String::from_utf8_lossy(&req_body) });
            }
            entries.push(json!({
                "startedDateTime": iso(flow.opened_at_ms), "time": 0,
                "request": request,
                "response": {
                    "status": flow.status.unwrap_or(0), "statusText": "", "httpVersion": "HTTP/1.1",
                    "cookies": [], "headers": headers_of(resp, "http.response_headers"),
                    "content": { "size": resp_body.len() as i64, "mimeType": "", "text": String::from_utf8_lossy(&resp_body) },
                    "redirectURL": "", "headersSize": -1, "bodySize": resp_body.len() as i64,
                },
                "cache": {}, "timings": { "send": 0, "wait": 0, "receive": 0 },
            }));
        }

        let har = json!({ "log": { "version": "1.2", "creator": { "name": "FlowMint", "version": env!("CARGO_PKG_VERSION") }, "entries": entries } });
        std::fs::write(out, serde_json::to_vec_pretty(&har)?)?;
        Ok(entries.len())
    }

    /// Offline replay: apply `rule` to the recorded exchange for `flow_id` and
    /// return the decision + structured before/after diff. Never re-sends.
    pub fn replay_rule_on_flow(
        &self,
        flow_id: &str,
        rule: &flowmint_model::Rule,
    ) -> Result<Option<(flowmint_rules::Decision, Vec<flowmint_rules::Change>)>> {
        let Some(before) = self.exchange_for_flow(flow_id)? else {
            return Ok(None);
        };
        let mut after = before.clone();
        let decision = flowmint_rules::apply(rule, &mut after);
        let changes = flowmint_rules::diff(&before, &after);
        Ok(Some((decision, changes)))
    }
}

/// 解析 URL 为 (是否 https, 主机, 端口, 路径)。
fn parse_url(url: &str) -> Result<(bool, String, u16, String)> {
    let (https, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        anyhow::bail!("URL 必须以 http:// 或 https:// 开头");
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let default_port = if https { 443 } else { 80 };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(default_port)),
        None => (authority.to_string(), default_port),
    };
    if host.is_empty() {
        anyhow::bail!("URL 缺少主机");
    }
    Ok((https, host, port, path.to_string()))
}

/// 把头列表编码成 `[{name,value}]` JSON（与代理抓包一致的形状）。
fn headers_json(headers: &[(String, String)]) -> serde_json::Value {
    serde_json::Value::Array(
        headers
            .iter()
            .map(|(k, v)| serde_json::json!({ "name": k, "value": v }))
            .collect(),
    )
}

/// 从 `[{name,value}]` 头数组 JSON 中取 `Content-Encoding`（大小写不敏感）。
fn content_encoding(headers: &serde_json::Value) -> Option<String> {
    let items = headers.as_array()?;
    items.iter().find_map(|it| {
        let name = it.get("name")?.as_str()?;
        name.eq_ignore_ascii_case("content-encoding")
            .then(|| it.get("value")?.as_str().map(str::to_string))?
    })
}

/// Parse a stored `[{name,value}]` header array off an event attribute.
fn headers_from_event(ev: &NetworkEvent, key: &str) -> Vec<(String, String)> {
    match ev.attributes.get(key) {
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(|it| {
                let name = it.get("name")?.as_str()?.to_string();
                let value = it.get("value")?.as_str()?.to_string();
                Some((name, value))
            })
            .collect(),
        _ => Vec::new(),
    }
}
