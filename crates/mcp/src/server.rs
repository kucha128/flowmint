//! Minimal MCP stdio server (design §10.3): newline-delimited JSON-RPC 2.0 over
//! stdin/stdout, exposing only the read-only tools. No port is opened; a client
//! spawns this as a subprocess. (Streamable-HTTP transport, bound to 127.0.0.1,
//! is an additional transport added later.)

use std::io::{self, BufRead, Write};

use flowmint_engine::Engine;
use serde_json::{json, Value};

use crate::Mcp;

/// Serve the read-only tool surface over stdio until stdin closes.
pub fn serve_stdio(engine: Engine) -> io::Result<()> {
    let mcp = Mcp::new(engine);
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let Ok(req) = serde_json::from_str::<Value>(&line) else { continue };
        let id = req.get("id").cloned();
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");

        let response = match method {
            "initialize" => Some(ok(id, json!({
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "flowmint-mcp", "version": env!("CARGO_PKG_VERSION") },
            }))),
            "notifications/initialized" | "notifications/cancelled" => None,
            "tools/list" => Some(ok(id, json!({ "tools": tool_specs() }))),
            "tools/call" => {
                let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
                let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
                let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
                match dispatch(&mcp, name, &args) {
                    Ok(data) => Some(ok(id, json!({
                        "content": [ { "type": "text", "text": serde_json::to_string(&data).unwrap_or_default() } ],
                        "isError": false,
                    }))),
                    Err(e) => Some(err(id, -32000, &e.to_string())),
                }
            }
            _ => id.as_ref().map(|_| err(id.clone(), -32601, "method not found")),
        };

        if let Some(resp) = response {
            writeln!(stdout, "{resp}")?;
            stdout.flush()?;
        }
    }
    Ok(())
}

fn dispatch(mcp: &Mcp, name: &str, args: &Value) -> crate::Result<Value> {
    let s = |k: &str| args.get(k).and_then(|v| v.as_str()).map(|s| s.to_string());
    let n = |k: &str| args.get(k).and_then(|v| v.as_u64()).map(|v| v as usize);
    match name {
        "flowmint_list_captures" => mcp.list_captures(),
        "flowmint_search_flows" => mcp.search_flows(s("host"), n("limit").unwrap_or(50)),
        "flowmint_get_flow" => {
            mcp.get_flow(&s("flow_id").ok_or_else(|| crate::McpError::NotFound("flow_id required".into()))?)
        }
        "flowmint_get_payload_range" => mcp.get_payload_range(
            &s("flow_id").ok_or_else(|| crate::McpError::NotFound("flow_id required".into()))?,
            &s("which").unwrap_or_else(|| "response".into()),
            n("offset").unwrap_or(0),
            n("length").unwrap_or(4096),
        ),
        "flowmint_compare_flows" => mcp.compare_flows(
            &s("a").ok_or_else(|| crate::McpError::NotFound("a required".into()))?,
            &s("b").ok_or_else(|| crate::McpError::NotFound("b required".into()))?,
        ),
        other => Err(crate::McpError::NotFound(format!("unknown tool {other}"))),
    }
}

/// Tool schemas advertised via `tools/list` (design §10.3 — strongly typed).
pub fn tool_specs() -> Value {
    json!([
        {
            "name": "flowmint_list_captures",
            "description": "List available capture sessions.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "flowmint_search_flows",
            "description": "Search flows by host substring; returns redacted metadata, never bodies.",
            "inputSchema": { "type": "object", "properties": {
                "host": { "type": "string" }, "limit": { "type": "integer" } } }
        },
        {
            "name": "flowmint_get_flow",
            "description": "Get one flow with redacted headers and event metadata (no bodies).",
            "inputSchema": { "type": "object", "required": ["flow_id"], "properties": {
                "flow_id": { "type": "string" } } }
        },
        {
            "name": "flowmint_get_payload_range",
            "description": "Return a capped, redacted slice of a request/response body.",
            "inputSchema": { "type": "object", "required": ["flow_id"], "properties": {
                "flow_id": { "type": "string" },
                "which": { "type": "string", "enum": ["request", "response"] },
                "offset": { "type": "integer" }, "length": { "type": "integer" } } }
        },
        {
            "name": "flowmint_compare_flows",
            "description": "Structured, redacted diff between two flows.",
            "inputSchema": { "type": "object", "required": ["a", "b"], "properties": {
                "a": { "type": "string" }, "b": { "type": "string" } } }
        }
    ])
}

fn ok(id: Option<Value>, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id.unwrap_or(Value::Null), "result": result })
}

fn err(id: Option<Value>, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id.unwrap_or(Value::Null), "error": { "code": code, "message": message } })
}
