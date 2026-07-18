//! 断点拦截器：实现 proxy-http 的 `InterceptHook`。
//!
//! 命中断点时：登记一个挂起项、通过广播把消息推给界面、异步等待界面的决定
//! （放行 / 修改放行 / 丢弃），再返回给代理。关闭断点或超时则直接放行。

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use flowmint_proxy_http::{Decision, Edit, InterceptHook, InterceptMessage};
use serde_json::json;
use tokio::sync::{broadcast, oneshot};

pub struct Interceptor {
    enabled: AtomicBool,
    break_response: AtomicBool,
    host_filter: Mutex<Option<String>>,
    pending: Mutex<HashMap<u64, oneshot::Sender<Decision>>>,
    paused_tx: broadcast::Sender<serde_json::Value>,
    next_id: AtomicU64,
}

impl Interceptor {
    pub fn new() -> Self {
        let (paused_tx, _) = broadcast::channel(256);
        Self {
            enabled: AtomicBool::new(false),
            break_response: AtomicBool::new(false),
            host_filter: Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
            paused_tx,
            next_id: AtomicU64::new(1),
        }
    }

    /// 订阅"挂起消息"事件（界面据此弹出编辑器）。
    pub fn subscribe(&self) -> broadcast::Receiver<serde_json::Value> {
        self.paused_tx.subscribe()
    }

    /// 配置断点：开关、主机过滤（URL 子串，空为不过滤）、是否也拦截响应。
    pub fn set(&self, enabled: bool, host_filter: Option<String>, break_response: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
        self.break_response.store(break_response, Ordering::Relaxed);
        *self.host_filter.lock().unwrap() = host_filter.filter(|s| !s.is_empty());
        if !enabled {
            // 关闭时放行所有挂起项，避免连接卡死。
            for (_, tx) in self.pending.lock().unwrap().drain() {
                let _ = tx.send(Decision::Continue);
            }
        }
    }

    /// 界面对某挂起消息的决定。action：continue / modify / drop。
    pub fn resume(
        &self,
        id: u64,
        action: &str,
        status: Option<u16>,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) {
        let decision = match action {
            "drop" => Decision::Drop,
            "modify" => Decision::Modify(Edit { status, headers, body }),
            _ => Decision::Continue,
        };
        if let Some(tx) = self.pending.lock().unwrap().remove(&id) {
            let _ = tx.send(decision);
        }
    }

    async fn do_intercept(&self, msg: InterceptMessage) -> Decision {
        if !self.enabled.load(Ordering::Relaxed) {
            return Decision::Continue;
        }
        if msg.is_response && !self.break_response.load(Ordering::Relaxed) {
            return Decision::Continue;
        }
        if let Some(h) = self.host_filter.lock().unwrap().as_ref() {
            if !msg.url.contains(h.as_str()) {
                return Decision::Continue;
            }
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id, tx);

        let is_binary = std::str::from_utf8(&msg.body).is_err();
        let ev = json!({
            "id": id,
            "is_response": msg.is_response,
            "method": msg.method,
            "url": msg.url,
            "status": msg.status,
            "headers": msg.headers.iter().map(|(k, v)| json!({ "name": k, "value": v })).collect::<Vec<_>>(),
            "body": if is_binary { String::new() } else { String::from_utf8_lossy(&msg.body).into_owned() },
            "is_binary": is_binary,
        });
        let _ = self.paused_tx.send(ev);

        // 等界面决定；5 分钟超时则放行（避免连接永久挂起）。
        match tokio::time::timeout(Duration::from_secs(300), rx).await {
            Ok(Ok(d)) => d,
            _ => {
                self.pending.lock().unwrap().remove(&id);
                Decision::Continue
            }
        }
    }
}

impl Default for Interceptor {
    fn default() -> Self {
        Self::new()
    }
}

impl InterceptHook for Interceptor {
    fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    fn intercept<'a>(
        &'a self,
        msg: InterceptMessage,
    ) -> Pin<Box<dyn Future<Output = Decision> + Send + 'a>> {
        Box::pin(self.do_intercept(msg))
    }
}
