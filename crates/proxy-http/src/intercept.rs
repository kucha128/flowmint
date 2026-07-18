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
    /// 已按 `Content-Encoding` 解压的明文 Body。改写后代理会按原编码重新压缩、保留该头。
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

/// 对一帧 WebSocket 消息的决定。
pub enum WsDecision {
    /// 原样转发。
    Forward,
    /// 用新 payload 转发。
    Modify(Vec<u8>),
    /// 丢弃这一帧（不转发，连接继续）。
    Drop,
    /// 主动断开这个 WebSocket 连接。
    Close,
}

/// 代理调用的拦截钩子。返回装箱 Future 以便 `Arc<dyn InterceptHook>`。
pub trait InterceptHook: Send + Sync + 'static {
    /// 断点是否开启。关闭时代理直接放行、不构造消息（零开销）。
    fn enabled(&self) -> bool;

    fn intercept<'a>(
        &'a self,
        msg: InterceptMessage,
    ) -> Pin<Box<dyn Future<Output = Decision> + Send + 'a>>;

    /// 拦截一帧 WebSocket 消息（转发前调用，同步）。`outgoing` = 客户端→服务器方向；
    /// `opcode`：1=text, 2=binary, 8=close, 9=ping, 10=pong。默认放行。
    fn intercept_ws(&self, outgoing: bool, opcode: u8, payload: &[u8]) -> WsDecision {
        let _ = (outgoing, opcode, payload);
        WsDecision::Forward
    }
}
