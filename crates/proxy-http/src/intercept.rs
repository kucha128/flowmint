//! 断点拦截：代理在"请求转发前 / 响应回传前"调用钩子，允许暂停、修改或丢弃。
//!
//! 钩子是异步的（可长时间等待界面决策）。为使其 `dyn` 兼容，`intercept` 返回一个
//! 装箱的 Future 而非用 `async fn`。引擎实现该钩子（见 `flowmint-engine`）。

use std::future::Future;
use std::pin::Pin;

/// 拦截到的一条消息（请求或响应）。
pub struct InterceptMessage {
    pub is_response: bool,
    /// 请求方法（响应消息里为对应请求的方法）。
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// 用户对拦截消息的决定。
pub enum Decision {
    /// 原样放行。
    Continue,
    /// 用修改后的内容放行。
    Modify(Edit),
    /// 丢弃（断开连接）。
    Drop,
}

/// 修改后的消息内容。
pub struct Edit {
    /// 响应状态码（请求时忽略）。
    pub status: Option<u16>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// 代理调用的拦截钩子。返回装箱 Future 以便 `Arc<dyn InterceptHook>`。
pub trait InterceptHook: Send + Sync + 'static {
    /// 断点是否开启。关闭时代理直接放行、不构造消息（零开销）。
    fn enabled(&self) -> bool;

    fn intercept<'a>(
        &'a self,
        msg: InterceptMessage,
    ) -> Pin<Box<dyn Future<Output = Decision> + Send + 'a>>;
}
