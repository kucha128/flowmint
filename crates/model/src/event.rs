//! Canonical, append-only network event model (design §6).
//!
//! Every adapter (proxy, SDK hook, TUN, PCAP import) normalizes into
//! [`NetworkEvent`]. Events are immutable once written; mutations are expressed
//! as *new* `RuleDecision` / `MutationApplied` events rather than in-place edits.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::ids::{CaptureId, EventId, FlowId};

/// Direction of a datum relative to the observed flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    ClientToServer,
    ServerToClient,
    Unspecified,
}

/// Minimal event taxonomy (design §6). Extended incrementally per protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    FlowOpened,
    TlsHandshake,
    HttpRequestHeaders,
    HttpRequestBodyChunk,
    HttpResponseHeaders,
    HttpResponseBodyChunk,
    WebSocketFrame,
    TcpDataChunk,
    UdpDatagram,
    DnsMessage,
    FlowClosed,
    RuleDecision,
    MutationApplied,
    Diagnostic,
}

/// Wall-clock + monotonic timestamp. We keep both so ordering survives clock
/// adjustments while still being human-anchorable (design §6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observed {
    /// UTC wall-clock, milliseconds since the Unix epoch.
    pub wall_unix_ms: i64,
    /// Monotonic offset in nanoseconds from the capture's start instant.
    pub monotonic_offset_ns: u64,
}

/// A network peer. Any field may be unknown depending on the adapter's vantage.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_pid: Option<u32>,
}

/// Observed TLS parameters (design §7.2). Populated once a handshake is seen;
/// `decrypted` records whether content was actually made visible, not merely
/// whether TLS was present.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub decrypted: bool,
}

/// The protocol layering observed for the flow at the time of the event.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolStack {
    /// L4 transport, e.g. "tcp" or "udp".
    pub l4: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsInfo>,
    /// L7 application protocol, e.g. "http/1.1", "websocket", "connect".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub l7: Option<String>,
}

/// Whether a payload has been redacted, and how (design §10.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionState {
    /// Stored verbatim.
    None,
    /// Sensitive spans masked before storage.
    Partial,
    /// Only metadata retained; body dropped.
    Dropped,
}

/// Reference to a payload held in the chunk store. Events never inline bodies
/// (design §6.1) — list/MCP reads must not auto-fetch full payloads.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadRef {
    /// SHA-256 of the *stored* bytes, lowercase hex.
    pub sha256: String,
    /// Length in bytes of the stored payload.
    pub length: u64,
    pub redaction: RedactionState,
    /// Opaque storage locator resolved by the storage layer.
    pub locator: String,
}

/// Outcome of an attempted decode/enrichment pass.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum DecodeStatus {
    #[default]
    NotAttempted,
    Decoded {
        decoder: String,
        version: String,
    },
    Failed {
        decoder: String,
        reason: String,
    },
}

/// Provenance of an event: which adapter produced it and with what code version
/// (design §6, §10.3 — every AI answer must trace back to evidence).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRef {
    pub adapter: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoder_version: Option<String>,
}

/// The one canonical event. Mirrors the `NetworkEvent` protobuf message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub event_id: EventId,
    pub capture_id: CaptureId,
    pub flow_id: FlowId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_flow_id: Option<FlowId>,
    pub sequence: u64,
    pub observed_at: Observed,
    pub direction: Direction,
    pub kind: EventKind,
    pub source: Endpoint,
    pub destination: Endpoint,
    pub protocol_stack: ProtocolStack,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<PayloadRef>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    pub decode_status: DecodeStatus,
    pub evidence: EvidenceRef,
}

impl NetworkEvent {
    /// Convenience constructor for the common fields; callers fill the rest.
    pub fn new(
        capture_id: CaptureId,
        flow_id: FlowId,
        sequence: u64,
        observed_at: Observed,
        direction: Direction,
        kind: EventKind,
    ) -> Self {
        Self {
            event_id: EventId::new(),
            capture_id,
            flow_id,
            parent_flow_id: None,
            sequence,
            observed_at,
            direction,
            kind,
            source: Endpoint::default(),
            destination: Endpoint::default(),
            protocol_stack: ProtocolStack::default(),
            payload: None,
            attributes: BTreeMap::new(),
            decode_status: DecodeStatus::NotAttempted,
            evidence: EvidenceRef::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_roundtrips_through_json() {
        let mut ev = NetworkEvent::new(
            CaptureId::new(),
            FlowId::new(),
            0,
            Observed {
                wall_unix_ms: 1_700_000_000_000,
                monotonic_offset_ns: 42,
            },
            Direction::ClientToServer,
            EventKind::HttpRequestHeaders,
        );
        ev.attributes.insert("http.method".into(), "GET".into());
        ev.attributes
            .insert("http.path".into(), "/v1/profile".into());

        let json = serde_json::to_string(&ev).unwrap();
        let back: NetworkEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
        assert_eq!(back.attributes.get("http.method").unwrap(), "GET");
    }
}
