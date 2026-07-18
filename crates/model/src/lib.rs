//! `flowmint-model` — the canonical data contract shared by every FlowMint
//! component (engine, storage, SDK, CLI, MCP).
//!
//! Design references: §6 (event model), §3.3/§8 (Rule IR).

pub mod clock;
pub mod error;
pub mod event;
pub mod flow;
pub mod ids;
pub mod rule;

pub use clock::Clock;
pub use error::{ModelError, Result};
pub use event::{
    DecodeStatus, Direction, Endpoint, EventKind, EvidenceRef, NetworkEvent, Observed, PayloadRef,
    ProtocolStack, RedactionState, TlsInfo,
};
pub use flow::Flow;
pub use ids::{CaptureId, EventId, FlowId};
pub use rule::{Action, Fallback, Limits, Match, PatchOp, Rule, Scope};
