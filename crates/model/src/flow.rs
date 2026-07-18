//! Flow — a first-class object (design §3.2, §15.1).
//!
//! A flow aggregates the events of one logical connection (or one HTTP
//! request/response exchange over a shared tunnel). It carries the denormalized
//! fields the Session Explorer and CLI search on, so listing 100k flows never
//! has to open payloads (design §6.1).

use serde::{Deserialize, Serialize};

use crate::event::Endpoint;
use crate::ids::{CaptureId, FlowId};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Flow {
    pub flow_id: FlowId,
    pub capture_id: CaptureId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_flow_id: Option<FlowId>,
    pub client: Endpoint,
    pub server: Endpoint,
    /// Denormalized host for fast filtering (SNI / Host header / CONNECT target).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub l7: Option<String>,
    pub opened_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_at_ms: Option<i64>,
    /// Denormalized HTTP summary fields, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// 响应的 Content-Type（会话列表列用）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// 是否经 TLS（HTTPS / WSS）——会话列表用它区分 http/https。
    #[serde(default)]
    pub secure: bool,
    /// 响应体字节数（会话列表 size 列用；不含头）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resp_body_size: Option<u64>,
}

impl Flow {
    pub fn opened(
        flow_id: FlowId,
        capture_id: CaptureId,
        client: Endpoint,
        server: Endpoint,
        opened_at_ms: i64,
    ) -> Self {
        let host = server.host.clone();
        Self {
            flow_id,
            capture_id,
            parent_flow_id: None,
            client,
            server,
            host,
            l7: None,
            opened_at_ms,
            closed_at_ms: None,
            method: None,
            path: None,
            status: None,
            content_type: None,
            secure: false,
            resp_body_size: None,
        }
    }
}
