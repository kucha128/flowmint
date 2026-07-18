//! FlowMint 稳定 C ABI 核心（设计 §11）。
//!
//! 把抓包引擎 + 回调以 C 接口暴露，供 C/C++/C#/Go/Java/Python/易语言等通过薄绑定
//! 复用同一份实现（规则/抓包逻辑只写一份，避免多语言重复与漂移）。
//!
//! 使用方式（回调式嵌入）：
//!   fm_context_new -> fm_bind_port -> fm_set_http_callback -> fm_start
//! 回调在工作线程触发，通过 `fm_http_event_*` 读取事件字段（仅回调期间有效）。
//!
//! 两类回调：
//! - **观察**（`fm_set_http_callback`）：请求/响应完成后回传方法/URL/主机/状态/Body，只读。
//! - **拦截改包**（`fm_set_intercept_callback`）：请求转发前、响应回传前**在途**触发，
//!   可用 `fm_intercept_set_*` 改写 Body/状态码/头，或返回丢弃，实现真正的改包。
//! WebSocket/TCP/UDP 回调为后续阶段。

use std::collections::HashMap;
use std::ffi::{c_char, c_void, CStr, CString};
use std::future::Future;
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::ptr;
use std::slice;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use flowmint_model::{CaptureId, Clock, EventKind, Flow, NetworkEvent, PayloadRef, RedactionState};
use flowmint_proxy_http::{
    Decision, Edit, FlowSink, InterceptHook, InterceptMessage, MitmConfig, ProxyContext,
};
use flowmint_tls::CertAuthority;
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;

/// HTTP 事件回调：`ev` 仅在回调期间有效，`user` 为注册时传入的用户指针。
pub type FmHttpCallback = extern "C" fn(ev: *const FmHttpEvent, user: *mut c_void);

/// 回调目标。裸指针的线程安全由调用方负责（回调式嵌入）。
#[derive(Clone, Copy)]
struct CallbackTarget {
    cb: Option<FmHttpCallback>,
    user: *mut c_void,
}
unsafe impl Send for CallbackTarget {}
unsafe impl Sync for CallbackTarget {}

/// 传给 C 回调的一次 HTTP 事件快照。
pub struct FmHttpEvent {
    kind: i32, // 0 = 请求, 1 = 响应
    method: CString,
    url: CString,
    host: CString,
    status: i32, // 响应状态码；请求为 -1
    body: Vec<u8>,
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// 把抓包事件转成回调的 `FlowSink`。不落盘，只在内存缓存 Body 以随事件回传。
struct FfiSink {
    target: CallbackTarget,
    bodies: Mutex<HashMap<String, Vec<u8>>>, // put_payload 返回的 key -> 字节
    requests: Mutex<HashMap<String, ReqInfo>>, // flow_id -> 请求信息（供响应回调拼 URL）
}

struct ReqInfo {
    method: String,
    host: String,
    path: String,
    https: bool,
}

impl FfiSink {
    fn body_of(&self, event: &NetworkEvent) -> Vec<u8> {
        match &event.payload {
            Some(p) => self.bodies.lock().unwrap().remove(&p.sha256).unwrap_or_default(),
            None => Vec::new(),
        }
    }
}

impl FlowSink for FfiSink {
    fn upsert_flow(&self, _flow: Flow) {}

    fn put_payload(&self, bytes: &[u8], _redaction: RedactionState) -> Option<PayloadRef> {
        // 用自增 id 作为 key（也放进 PayloadRef.sha256，record_event 据此取回）。
        let key = NEXT_ID.fetch_add(1, Ordering::Relaxed).to_string();
        self.bodies.lock().unwrap().insert(key.clone(), bytes.to_vec());
        Some(PayloadRef { sha256: key, length: bytes.len() as u64, redaction: RedactionState::None, locator: String::new() })
    }

    fn record_event(&self, event: NetworkEvent) {
        let Some(cb) = self.target.cb else { return };
        let user = self.target.user;
        let https = event.protocol_stack.tls.as_ref().map(|t| t.decrypted).unwrap_or(false);

        match event.kind {
            EventKind::HttpRequestHeaders => {
                let method = attr(&event, "http.method");
                let host = attr(&event, "http.host");
                let path = attr(&event, "http.path");
                self.requests.lock().unwrap().insert(
                    event.flow_id.to_string(),
                    ReqInfo { method: method.clone(), host: host.clone(), path: path.clone(), https },
                );
                let url = format!("{}://{host}{path}", if https { "https" } else { "http" });
                fire(cb, user, 0, &method, &url, &host, -1, &self.body_of(&event));
            }
            EventKind::HttpResponseHeaders => {
                let status = event.attributes.get("http.status").and_then(|v| v.as_i64()).unwrap_or(-1) as i32;
                let (method, url, host) = match self.requests.lock().unwrap().remove(&event.flow_id.to_string()) {
                    Some(ri) => {
                        let scheme = if ri.https { "https" } else { "http" };
                        (ri.method, format!("{scheme}://{}{}", ri.host, ri.path), ri.host)
                    }
                    None => (String::new(), String::new(), String::new()),
                };
                fire(cb, user, 1, &method, &url, &host, status, &self.body_of(&event));
            }
            _ => {}
        }
    }
}

fn attr(event: &NetworkEvent, key: &str) -> String {
    event.attributes.get(key).and_then(|v| v.as_str()).unwrap_or_default().to_string()
}

#[allow(clippy::too_many_arguments)]
fn fire(cb: FmHttpCallback, user: *mut c_void, kind: i32, method: &str, url: &str, host: &str, status: i32, body: &[u8]) {
    let ev = FmHttpEvent {
        kind,
        method: cstr(method),
        url: cstr(url),
        host: cstr(host),
        status,
        body: body.to_vec(),
    };
    cb(&ev as *const FmHttpEvent, user);
}

fn cstr(s: &str) -> CString {
    CString::new(s).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// 拦截改包（在途修改请求/响应）
// ---------------------------------------------------------------------------

/// 拦截回调：在途给一次请求或响应，返回动作码
/// （0=放行 / 1=修改并放行 / 2=丢弃）。回调内用 `fm_intercept_set_*` 写改动。
pub type FmInterceptCallback = extern "C" fn(msg: *mut FmInterceptMsg, user: *mut c_void) -> i32;

#[derive(Clone, Copy)]
struct InterceptTarget {
    cb: Option<FmInterceptCallback>,
    user: *mut c_void,
}
unsafe impl Send for InterceptTarget {}
unsafe impl Sync for InterceptTarget {}

/// 传给拦截回调的可写消息：读原始字段，写改动，返回时合成决策。
pub struct FmInterceptMsg {
    is_response: bool,
    method: CString,
    url: CString,
    status: i32, // 响应状态码；请求为 -1
    orig_headers: Vec<(String, String)>,
    body: Vec<u8>,
    // 改动：
    new_body: Option<Vec<u8>>,
    new_status: Option<u16>,
    header_sets: Vec<(String, String)>,
}

impl FmInterceptMsg {
    fn from_msg(msg: InterceptMessage) -> Self {
        Self {
            is_response: msg.is_response,
            method: cstr(&msg.method),
            url: cstr(&msg.url),
            status: msg.status.map(|s| s as i32).unwrap_or(-1),
            orig_headers: msg.headers,
            body: msg.body,
            new_body: None,
            new_status: None,
            header_sets: Vec::new(),
        }
    }

    /// 按回调返回的动作码合成最终决策。
    fn into_decision(self, action: i32) -> Decision {
        match action {
            2 => Decision::Drop,
            1 => {
                let mut headers = self.orig_headers;
                for (name, value) in self.header_sets {
                    match headers.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case(&name)) {
                        Some(h) => h.1 = value,
                        None => headers.push((name, value)),
                    }
                }
                let status = self
                    .new_status
                    .or(if self.is_response && self.status >= 0 { Some(self.status as u16) } else { None });
                Decision::Modify(Edit { status, headers, body: self.new_body.unwrap_or(self.body) })
            }
            _ => Decision::Continue,
        }
    }
}

/// 把 C 拦截回调适配成代理的 `InterceptHook`。回调同步执行于代理工作线程。
struct FfiInterceptHook {
    cb: FmInterceptCallback,
    user: *mut c_void,
}
unsafe impl Send for FfiInterceptHook {}
unsafe impl Sync for FfiInterceptHook {}

impl InterceptHook for FfiInterceptHook {
    fn enabled(&self) -> bool {
        true
    }

    fn intercept<'a>(
        &'a self,
        msg: InterceptMessage,
    ) -> Pin<Box<dyn Future<Output = Decision> + Send + 'a>> {
        Box::pin(async move {
            let mut m = FmInterceptMsg::from_msg(msg);
            let action = (self.cb)(&mut m as *mut FmInterceptMsg, self.user);
            m.into_decision(action)
        })
    }
}

/// 注册拦截改包回调（传 NULL 清除）。必须在 `fm_start` 之前调用。
#[no_mangle]
pub unsafe extern "C" fn fm_set_intercept_callback(
    ctx: *mut FmContext,
    cb: Option<FmInterceptCallback>,
    user: *mut c_void,
) {
    if let Some(c) = ctx.as_mut() {
        c.intercept = InterceptTarget { cb, user };
    }
}

/// 是否响应（1）还是请求（0）。
#[no_mangle]
pub unsafe extern "C" fn fm_intercept_is_response(msg: *const FmInterceptMsg) -> i32 {
    msg.as_ref().map(|m| m.is_response as i32).unwrap_or(0)
}

#[no_mangle]
pub unsafe extern "C" fn fm_intercept_method(msg: *const FmInterceptMsg) -> *const c_char {
    msg.as_ref().map(|m| m.method.as_ptr()).unwrap_or(ptr::null())
}

#[no_mangle]
pub unsafe extern "C" fn fm_intercept_url(msg: *const FmInterceptMsg) -> *const c_char {
    msg.as_ref().map(|m| m.url.as_ptr()).unwrap_or(ptr::null())
}

/// 响应状态码；请求为 -1。
#[no_mangle]
pub unsafe extern "C" fn fm_intercept_status(msg: *const FmInterceptMsg) -> i32 {
    msg.as_ref().map(|m| m.status).unwrap_or(-1)
}

/// 当前（原始）Body 指针 + 长度；指针仅在回调期间有效。
#[no_mangle]
pub unsafe extern "C" fn fm_intercept_body(
    msg: *const FmInterceptMsg,
    out_len: *mut usize,
) -> *const u8 {
    match msg.as_ref() {
        Some(m) => {
            if !out_len.is_null() {
                *out_len = m.body.len();
            }
            m.body.as_ptr()
        }
        None => {
            if !out_len.is_null() {
                *out_len = 0;
            }
            ptr::null()
        }
    }
}

/// 改写 Body（拷贝 `len` 字节）。需回调返回 1 才生效。
#[no_mangle]
pub unsafe extern "C" fn fm_intercept_set_body(msg: *mut FmInterceptMsg, data: *const u8, len: usize) {
    if let Some(m) = msg.as_mut() {
        let bytes = if data.is_null() || len == 0 { Vec::new() } else { slice::from_raw_parts(data, len).to_vec() };
        m.new_body = Some(bytes);
    }
}

/// 改写响应状态码（仅响应有效）。需回调返回 1 才生效。
#[no_mangle]
pub unsafe extern "C" fn fm_intercept_set_status(msg: *mut FmInterceptMsg, status: i32) {
    if let Some(m) = msg.as_mut() {
        if (0..=599).contains(&status) {
            m.new_status = Some(status as u16);
        }
    }
}

/// 设置/替换一个头（同名替换，否则追加）。需回调返回 1 才生效。
/// # Safety: `name`/`value` 为有效 NUL 结尾字符串。
#[no_mangle]
pub unsafe extern "C" fn fm_intercept_set_header(
    msg: *mut FmInterceptMsg,
    name: *const c_char,
    value: *const c_char,
) {
    let (Some(m), false, false) = (msg.as_mut(), name.is_null(), value.is_null()) else { return };
    if let (Ok(n), Ok(v)) = (CStr::from_ptr(name).to_str(), CStr::from_ptr(value).to_str()) {
        m.header_sets.push((n.to_string(), v.to_string()));
    }
}

// ---------------------------------------------------------------------------
// 上下文与生命周期
// ---------------------------------------------------------------------------

/// 一个抓包实例。不透明句柄，由 C 侧持有。
pub struct FmContext {
    port: u16,
    mitm: bool,
    insecure_upstream: bool,
    data_dir: String,
    target: CallbackTarget,
    intercept: InterceptTarget,
    runtime: Option<Runtime>,
    handle: Option<JoinHandle<std::io::Result<()>>>,
    error: CString,
}

impl FmContext {
    fn set_error(&mut self, msg: impl AsRef<str>) {
        self.error = cstr(msg.as_ref());
    }
}

#[no_mangle]
pub extern "C" fn fm_context_new() -> *mut FmContext {
    Box::into_raw(Box::new(FmContext {
        port: 8888,
        mitm: false,
        insecure_upstream: false,
        data_dir: "flowmint-data".to_string(),
        target: CallbackTarget { cb: None, user: ptr::null_mut() },
        intercept: InterceptTarget { cb: None, user: ptr::null_mut() },
        runtime: None,
        handle: None,
        error: CString::default(),
    }))
}

/// # Safety: `ctx` 必须是 `fm_context_new` 返回且尚未释放的指针。
#[no_mangle]
pub unsafe extern "C" fn fm_context_free(ctx: *mut FmContext) {
    if ctx.is_null() {
        return;
    }
    fm_stop(ctx);
    drop(Box::from_raw(ctx));
}

#[no_mangle]
pub unsafe extern "C" fn fm_bind_port(ctx: *mut FmContext, port: u16) {
    if let Some(c) = ctx.as_mut() {
        c.port = port;
    }
}

#[no_mangle]
pub unsafe extern "C" fn fm_set_mitm(ctx: *mut FmContext, mitm: bool, insecure_upstream: bool) {
    if let Some(c) = ctx.as_mut() {
        c.mitm = mitm;
        c.insecure_upstream = insecure_upstream;
    }
}

/// # Safety: `dir` 必须是有效的以 NUL 结尾的 UTF-8 字符串。
#[no_mangle]
pub unsafe extern "C" fn fm_set_data_dir(ctx: *mut FmContext, dir: *const c_char) {
    if let (Some(c), false) = (ctx.as_mut(), dir.is_null()) {
        if let Ok(s) = CStr::from_ptr(dir).to_str() {
            c.data_dir = s.to_string();
        }
    }
}

/// 注册 HTTP 回调（传 NULL 清除）。必须在 `fm_start` 之前调用。
#[no_mangle]
pub unsafe extern "C" fn fm_set_http_callback(ctx: *mut FmContext, cb: Option<FmHttpCallback>, user: *mut c_void) {
    if let Some(c) = ctx.as_mut() {
        c.target = CallbackTarget { cb, user };
    }
}

/// 启动抓包代理。成功返回 true；失败返回 false，用 `fm_last_error` 取错误。
#[no_mangle]
pub unsafe extern "C" fn fm_start(ctx: *mut FmContext) -> bool {
    let Some(c) = ctx.as_mut() else { return false };

    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            c.set_error(format!("创建运行时失败: {e}"));
            return false;
        }
    };

    let bind: SocketAddr = ([127, 0, 0, 1], c.port).into();
    let listener = match rt.block_on(TcpListener::bind(bind)) {
        Ok(l) => l,
        Err(e) => {
            c.set_error(format!("绑定端口 {} 失败: {e}", c.port));
            return false;
        }
    };

    let mitm = if c.mitm {
        match build_mitm(&c.data_dir, c.insecure_upstream) {
            Ok(m) => Some(Arc::new(m)),
            Err(e) => {
                c.set_error(format!("初始化 MITM 失败: {e}"));
                return false;
            }
        }
    } else {
        None
    };

    let sink = Arc::new(FfiSink {
        target: c.target,
        bodies: Mutex::new(HashMap::new()),
        requests: Mutex::new(HashMap::new()),
    });
    let hook: Option<Arc<dyn InterceptHook>> = match c.intercept.cb {
        Some(cb) => Some(Arc::new(FfiInterceptHook { cb, user: c.intercept.user })),
        None => None,
    };
    let pctx = ProxyContext { sink, capture_id: CaptureId::new(), clock: Clock::start_now(), mitm, hook, upstream_proxy: None, proxy_port: 0, ca_pem: None, ca_der: None };
    let handle = rt.spawn(flowmint_proxy_http::serve(listener, pctx));

    c.runtime = Some(rt);
    c.handle = Some(handle);
    true
}

/// 停止抓包（可再次 `fm_start`）。
#[no_mangle]
pub unsafe extern "C" fn fm_stop(ctx: *mut FmContext) {
    if let Some(c) = ctx.as_mut() {
        if let Some(h) = c.handle.take() {
            h.abort();
        }
        if let Some(rt) = c.runtime.take() {
            rt.shutdown_background();
        }
    }
}

/// 最近一次错误信息（以 NUL 结尾）；无错误时为空串。
#[no_mangle]
pub unsafe extern "C" fn fm_last_error(ctx: *mut FmContext) -> *const c_char {
    match ctx.as_ref() {
        Some(c) => c.error.as_ptr(),
        None => c"invalid context".as_ptr(),
    }
}

/// 导出本实例 profile 的 MITM CA 到 `out_path`。成功返回 true。
#[no_mangle]
pub unsafe extern "C" fn fm_export_ca(ctx: *mut FmContext, out_path: *const c_char) -> bool {
    let Some(c) = ctx.as_mut() else { return false };
    if out_path.is_null() {
        return false;
    }
    let Ok(path) = CStr::from_ptr(out_path).to_str() else { return false };
    match CertAuthority::load_or_create(Path::new(&c.data_dir).join("ca")) {
        Ok(ca) => std::fs::write(path, ca.ca_pem()).is_ok(),
        Err(e) => {
            c.set_error(format!("导出 CA 失败: {e}"));
            false
        }
    }
}

/// SDK 版本（以 NUL 结尾）。
#[no_mangle]
pub extern "C" fn fm_version() -> *const c_char {
    c"0.1.0".as_ptr()
}

fn build_mitm(data_dir: &str, insecure: bool) -> Result<MitmConfig, flowmint_tls::TlsError> {
    let ca = Arc::new(CertAuthority::load_or_create(Path::new(data_dir).join("ca"))?);
    let client_config = if insecure {
        flowmint_tls::insecure_upstream_client_config()?
    } else {
        flowmint_tls::upstream_client_config()?
    };
    Ok(MitmConfig { ca, client_config })
}

// ---------------------------------------------------------------------------
// 事件 getter（仅在回调期间有效）
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn fm_http_event_type(ev: *const FmHttpEvent) -> i32 {
    ev.as_ref().map(|e| e.kind).unwrap_or(-1)
}

#[no_mangle]
pub unsafe extern "C" fn fm_http_event_method(ev: *const FmHttpEvent) -> *const c_char {
    ev.as_ref().map(|e| e.method.as_ptr()).unwrap_or(ptr::null())
}

#[no_mangle]
pub unsafe extern "C" fn fm_http_event_url(ev: *const FmHttpEvent) -> *const c_char {
    ev.as_ref().map(|e| e.url.as_ptr()).unwrap_or(ptr::null())
}

#[no_mangle]
pub unsafe extern "C" fn fm_http_event_host(ev: *const FmHttpEvent) -> *const c_char {
    ev.as_ref().map(|e| e.host.as_ptr()).unwrap_or(ptr::null())
}

#[no_mangle]
pub unsafe extern "C" fn fm_http_event_status(ev: *const FmHttpEvent) -> i32 {
    ev.as_ref().map(|e| e.status).unwrap_or(-1)
}

/// 返回 Body 指针并写出长度；指针仅在回调期间有效。
#[no_mangle]
pub unsafe extern "C" fn fm_http_event_body(ev: *const FmHttpEvent, out_len: *mut usize) -> *const u8 {
    match ev.as_ref() {
        Some(e) => {
            if !out_len.is_null() {
                *out_len = e.body.len();
            }
            e.body.as_ptr()
        }
        None => {
            if !out_len.is_null() {
                *out_len = 0;
            }
            ptr::null()
        }
    }
}
