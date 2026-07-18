//! Read-only MCP tool surface (design §10.2–§10.4).
//!
//! Strongly-typed, least-privilege query tools over captured evidence. Every
//! tool is read-only, forces redaction, and returns an envelope carrying
//! `evidence_ids`, the redaction policy version, confidence and unknowns — so
//! an AI answer can always be traced back to specific events (design §10.3).
//!
//! Act-tier tools (draft_rule, replay, execute_approved_action) are NOT here:
//! by design they require an approval workflow and are added behind that gate.

pub mod redact;
pub mod server;

use flowmint_engine::Engine;
use flowmint_model::EventKind;
use flowmint_storage::SearchFilter;
use redact::Redactor;
use serde_json::{json, Value};
use thiserror::Error;

/// Max bytes any single payload-range read returns (design §10.4 quotas).
const PAYLOAD_RANGE_CAP: usize = 64 * 1024;

#[derive(Debug, Error)]
pub enum McpError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error(transparent)]
    Engine(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, McpError>;

/// The read-only tool provider. Wraps an [`Engine`]; holds no write capability.
pub struct Mcp {
    engine: Engine,
    redactor: Redactor,
}

impl Mcp {
    pub fn new(engine: Engine) -> Self {
        Self { engine, redactor: Redactor::default() }
    }

    fn envelope(&self, data: Value, evidence_ids: Vec<String>) -> Value {
        json!({
            "data": data,
            "evidence_ids": evidence_ids,
            "redaction_policy": self.redactor.policy_version(),
            "confidence": "observed",
            "unknowns": [],
        })
    }

    /// `flowmint_list_captures` — discover available captures (design §10.3).
    pub fn list_captures(&self) -> Result<Value> {
        let caps = self.engine.list_captures()?;
        let data: Vec<Value> = caps
            .iter()
            .map(|c| json!({ "capture_id": c.capture_id, "started_ms": c.started_ms, "label": c.label }))
            .collect();
        Ok(self.envelope(json!(data), vec![]))
    }

    /// `flowmint_search_flows` — metadata + minimal evidence, never bodies.
    pub fn search_flows(&self, host: Option<String>, limit: usize) -> Result<Value> {
        let flows = self
            .engine
            .search_flows(&SearchFilter { host, capture_id: None, limit })?;
        let data: Vec<Value> = flows
            .iter()
            .map(|f| {
                json!({
                    "flow_id": f.flow_id.as_str(),
                    "method": f.method,
                    "host": f.host,
                    "path": f.path,
                    "status": f.status,
                    "l7": f.l7,
                })
            })
            .collect();
        let evidence = flows.iter().map(|f| f.flow_id.to_string()).collect();
        Ok(self.envelope(json!(data), evidence))
    }

    /// `flowmint_get_flow` — redacted flow detail with event metadata. Bodies
    /// are referenced (sha/length) but not inlined (design §6.1).
    pub fn get_flow(&self, flow_id: &str) -> Result<Value> {
        let flow = self
            .engine
            .get_flow(flow_id)?
            .ok_or_else(|| McpError::NotFound(flow_id.into()))?;
        let events = self.engine.events_for_flow(flow_id)?;

        let mut evidence = Vec::new();
        let ev_json: Vec<Value> = events
            .iter()
            .map(|e| {
                evidence.push(e.event_id.to_string());
                let headers = e
                    .attributes
                    .get("http.request_headers")
                    .or_else(|| e.attributes.get("http.response_headers"))
                    .map(|v| self.redact_headers(v));
                json!({
                    "event_id": e.event_id.as_str(),
                    "kind": format!("{:?}", e.kind),
                    "direction": format!("{:?}", e.direction),
                    "headers": headers,
                    "payload": e.payload.as_ref().map(|p| json!({ "sha256": p.sha256, "length": p.length })),
                })
            })
            .collect();

        let flow_json = json!({
            "flow_id": flow.flow_id.as_str(),
            "parent_flow_id": flow.parent_flow_id.as_ref().map(|f| f.to_string()),
            "host": flow.host,
            "method": flow.method,
            "path": flow.path,
            "status": flow.status,
            "l7": flow.l7,
        });
        Ok(self.envelope(json!({ "flow": flow_json, "events": ev_json }), evidence))
    }

    /// `flowmint_get_payload_range` — a capped, redacted slice of one body.
    pub fn get_payload_range(
        &self,
        flow_id: &str,
        which: &str,
        offset: usize,
        length: usize,
    ) -> Result<Value> {
        let kind = match which {
            "request" => EventKind::HttpRequestHeaders,
            _ => EventKind::HttpResponseHeaders,
        };
        let events = self.engine.events_for_flow(flow_id)?;
        let ev = events
            .iter()
            .find(|e| e.kind == kind && e.payload.is_some())
            .ok_or_else(|| McpError::NotFound(format!("{which} payload for {flow_id}")))?;
        let payload = ev.payload.as_ref().unwrap();
        let bytes = self.engine.get_payload(payload)?;

        let start = offset.min(bytes.len());
        let end = (start + length.min(PAYLOAD_RANGE_CAP)).min(bytes.len());
        let slice = &bytes[start..end];
        let text = self.redactor.text(&String::from_utf8_lossy(slice));

        Ok(self.envelope(
            json!({
                "which": which,
                "total_length": bytes.len(),
                "offset": start,
                "returned": end - start,
                "truncated": end < bytes.len(),
                "text": text,
            }),
            vec![ev.event_id.to_string()],
        ))
    }

    /// `flowmint_compare_flows` — structured, redacted diff between two flows.
    pub fn compare_flows(&self, a: &str, b: &str) -> Result<Value> {
        let ex_a = self
            .engine
            .exchange_for_flow(a)?
            .ok_or_else(|| McpError::NotFound(a.into()))?;
        let ex_b = self
            .engine
            .exchange_for_flow(b)?
            .ok_or_else(|| McpError::NotFound(b.into()))?;
        let changes = flowmint_rules::diff(&ex_a, &ex_b);
        let data: Vec<Value> = changes
            .iter()
            .map(|c| {
                json!({
                    "location": c.location,
                    "before": c.before.as_ref().map(|s| self.redactor.text(s)),
                    "after": c.after.as_ref().map(|s| self.redactor.text(s)),
                })
            })
            .collect();

        let mut evidence: Vec<String> = self
            .engine
            .events_for_flow(a)?
            .iter()
            .map(|e| e.event_id.to_string())
            .collect();
        evidence.extend(self.engine.events_for_flow(b)?.iter().map(|e| e.event_id.to_string()));
        Ok(self.envelope(json!(data), evidence))
    }

    /// Redact a stored `[{name,value}]` header array.
    fn redact_headers(&self, value: &Value) -> Value {
        match value {
            Value::Array(items) => Value::Array(
                items
                    .iter()
                    .map(|it| {
                        let name = it.get("name").and_then(|v| v.as_str()).unwrap_or("");
                        let val = it.get("value").and_then(|v| v.as_str()).unwrap_or("");
                        json!({ "name": name, "value": self.redactor.header_value(name, val) })
                    })
                    .collect(),
            ),
            _ => Value::Null,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_captures_is_read_only_envelope() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open(dir.path()).unwrap();
        let mcp = Mcp::new(engine);
        let out = mcp.list_captures().unwrap();
        assert_eq!(out["redaction_policy"], "default-v1");
        assert!(out["data"].is_array());
        assert!(out["evidence_ids"].is_array());
    }
}
