//! Rule IR executor (design §3.3, §8) — the shared engine that GUI, SDK, CLI and
//! CI all run so a rule verified in one place behaves identically everywhere.
//!
//! Operates on an in-memory [`HttpExchange`] (built from a captured flow for
//! offline replay, or from a live request in the SDK). Matching + mutation are
//! deterministic and produce a [`Decision`] plus a structured [`Change`] diff.

use flowmint_model::{Action, Rule};
use serde::Serialize;
use serde_json::Value;

/// A request/response pair the executor matches and mutates.
#[derive(Debug, Clone)]
pub struct HttpExchange {
    pub method: String,
    pub host: String,
    pub path: String,
    pub req_headers: Vec<(String, String)>,
    pub req_body: Vec<u8>,
    pub status: Option<u16>,
    pub resp_headers: Vec<(String, String)>,
    pub resp_body: Vec<u8>,
}

impl HttpExchange {
    pub fn request(method: &str, host: &str, path: &str) -> Self {
        Self {
            method: method.into(),
            host: host.into(),
            path: path.into(),
            req_headers: vec![],
            req_body: vec![],
            status: None,
            resp_headers: vec![],
            resp_body: vec![],
        }
    }
}

const REDACTED: &str = "***REDACTED***";

/// Result of evaluating a rule against an exchange.
#[derive(Debug, Default, Clone, Serialize)]
pub struct Decision {
    pub rule_id: String,
    pub matched: bool,
    pub actions_applied: Vec<String>,
    pub tags: Vec<String>,
    pub redacted: Vec<String>,
    pub delay_ms: u64,
    pub short_circuit: Option<SyntheticResponse>,
    /// Non-fatal issues (e.g. a body that would not parse as JSON). A rule with
    /// `fallback: pass_through` records these instead of failing the exchange.
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyntheticResponse {
    pub status: u16,
    pub body: String,
}

/// A single before/after change produced by a mutation.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Change {
    pub location: String,
    pub before: Option<String>,
    pub after: Option<String>,
}

/// True if `rule.match` selects `ex`.
pub fn matches(rule: &Rule, ex: &HttpExchange) -> bool {
    let m = &rule.r#match;
    if let Some(p) = &m.protocol {
        if !p.eq_ignore_ascii_case("http") && !p.eq_ignore_ascii_case("https") {
            return false;
        }
    }
    if let Some(h) = &m.host {
        if !h.eq_ignore_ascii_case(&ex.host) {
            return false;
        }
    }
    if let Some(meth) = &m.method {
        if !meth.eq_ignore_ascii_case(&ex.method) {
            return false;
        }
    }
    if let Some(path) = &m.path {
        if path != &ex.path {
            return false;
        }
    }
    if let Some(prefix) = &m.path_prefix {
        if !ex.path.starts_with(prefix) {
            return false;
        }
    }
    true
}

/// Apply `rule` to `ex` in place, returning a [`Decision`]. If the rule does not
/// match, `ex` is untouched and `matched` is false.
pub fn apply(rule: &Rule, ex: &mut HttpExchange) -> Decision {
    let mut d = Decision {
        rule_id: rule.id.clone(),
        ..Default::default()
    };
    if !matches(rule, ex) {
        return d;
    }
    d.matched = true;

    for action in &rule.actions {
        match action {
            Action::Observe => d.actions_applied.push("observe".into()),
            Action::Record => d.actions_applied.push("record".into()),
            Action::Breakpoint => d.actions_applied.push("breakpoint".into()),
            Action::Tag { labels } => {
                d.actions_applied.push("tag".into());
                d.tags.extend(labels.clone());
            }
            Action::Delay { milliseconds } => {
                d.actions_applied.push("delay".into());
                d.delay_ms += *milliseconds;
            }
            Action::Redact { fields } => {
                d.actions_applied.push("redact".into());
                for f in fields {
                    if redact_header(&mut ex.req_headers, f)
                        || redact_header(&mut ex.resp_headers, f)
                    {
                        d.redacted.push(f.clone());
                    }
                }
            }
            Action::Respond { status, body } => {
                d.actions_applied.push("respond".into());
                d.short_circuit = Some(SyntheticResponse {
                    status: *status,
                    body: body.clone(),
                });
                ex.status = Some(*status);
                ex.resp_body = body.clone().into_bytes();
            }
            Action::JsonPatch { target, operations } => {
                d.actions_applied.push("json_patch".into());
                let is_request = target.contains("request");
                let body = if is_request {
                    &ex.req_body
                } else {
                    &ex.resp_body
                };
                if body.len() as u64 > rule.limits.max_body_bytes {
                    d.errors
                        .push(format!("{target}: body exceeds max_body_bytes"));
                    continue;
                }
                match serde_json::from_slice::<Value>(body) {
                    Ok(mut root) => {
                        for op in operations {
                            if let Err(e) =
                                apply_patch_op(&mut root, &op.op, &op.path, op.value.clone())
                            {
                                d.errors.push(format!("{target} {}: {e}", op.path));
                            }
                        }
                        let out = serde_json::to_vec(&root).unwrap_or_default();
                        if is_request {
                            ex.req_body = out;
                        } else {
                            ex.resp_body = out;
                        }
                    }
                    Err(e) => d.errors.push(format!("{target}: not JSON ({e})")),
                }
            }
        }
    }
    d
}

fn redact_header(headers: &mut [(String, String)], field: &str) -> bool {
    let mut hit = false;
    for (k, v) in headers.iter_mut() {
        if k.eq_ignore_ascii_case(field) {
            *v = REDACTED.to_string();
            hit = true;
        }
    }
    hit
}

/// Apply one JSON patch op (subset of RFC 6902: replace/add/remove).
fn apply_patch_op(
    root: &mut Value,
    op: &str,
    pointer: &str,
    value: Option<Value>,
) -> Result<(), String> {
    match op {
        "replace" => {
            let target = root.pointer_mut(pointer).ok_or("path not found")?;
            *target = value.ok_or("replace requires a value")?;
            Ok(())
        }
        "add" => {
            let (parent_ptr, key) = split_pointer(pointer)?;
            let value = value.ok_or("add requires a value")?;
            let parent = root.pointer_mut(&parent_ptr).ok_or("parent not found")?;
            match parent {
                Value::Object(map) => {
                    map.insert(key, value);
                    Ok(())
                }
                Value::Array(arr) => {
                    if key == "-" {
                        arr.push(value);
                    } else {
                        let idx: usize = key.parse().map_err(|_| "bad array index")?;
                        if idx > arr.len() {
                            return Err("index out of range".into());
                        }
                        arr.insert(idx, value);
                    }
                    Ok(())
                }
                _ => Err("parent is not a container".into()),
            }
        }
        "remove" => {
            let (parent_ptr, key) = split_pointer(pointer)?;
            let parent = root.pointer_mut(&parent_ptr).ok_or("parent not found")?;
            match parent {
                Value::Object(map) => {
                    map.remove(&key).ok_or("key not found")?;
                    Ok(())
                }
                Value::Array(arr) => {
                    let idx: usize = key.parse().map_err(|_| "bad array index")?;
                    if idx >= arr.len() {
                        return Err("index out of range".into());
                    }
                    arr.remove(idx);
                    Ok(())
                }
                _ => Err("parent is not a container".into()),
            }
        }
        other => Err(format!("unsupported op '{other}'")),
    }
}

fn split_pointer(pointer: &str) -> Result<(String, String), String> {
    let idx = pointer.rfind('/').ok_or("invalid pointer")?;
    let parent = pointer[..idx].to_string();
    let key = pointer[idx + 1..].replace("~1", "/").replace("~0", "~");
    Ok((parent, key))
}

/// Structured before/after diff of two exchanges (design §9.1 step 3).
pub fn diff(before: &HttpExchange, after: &HttpExchange) -> Vec<Change> {
    let mut changes = Vec::new();

    if before.status != after.status {
        changes.push(Change {
            location: "response.status".into(),
            before: before.status.map(|s| s.to_string()),
            after: after.status.map(|s| s.to_string()),
        });
    }
    diff_headers(
        "request.headers",
        &before.req_headers,
        &after.req_headers,
        &mut changes,
    );
    diff_headers(
        "response.headers",
        &before.resp_headers,
        &after.resp_headers,
        &mut changes,
    );
    diff_body(
        "request.body",
        &before.req_body,
        &after.req_body,
        &mut changes,
    );
    diff_body(
        "response.body",
        &before.resp_body,
        &after.resp_body,
        &mut changes,
    );
    changes
}

fn diff_headers(
    prefix: &str,
    before: &[(String, String)],
    after: &[(String, String)],
    out: &mut Vec<Change>,
) {
    for (k, bv) in before {
        let av = after
            .iter()
            .find(|(ak, _)| ak.eq_ignore_ascii_case(k))
            .map(|(_, v)| v);
        match av {
            Some(av) if av != bv => out.push(Change {
                location: format!("{prefix}.{k}"),
                before: Some(bv.clone()),
                after: Some(av.clone()),
            }),
            _ => {}
        }
    }
}

fn diff_body(prefix: &str, before: &[u8], after: &[u8], out: &mut Vec<Change>) {
    if before == after {
        return;
    }
    match (
        serde_json::from_slice::<Value>(before),
        serde_json::from_slice::<Value>(after),
    ) {
        (Ok(b), Ok(a)) => diff_json(prefix, &b, &a, out),
        _ => out.push(Change {
            location: prefix.into(),
            before: Some(format!("{} bytes", before.len())),
            after: Some(format!("{} bytes", after.len())),
        }),
    }
}

fn diff_json(path: &str, before: &Value, after: &Value, out: &mut Vec<Change>) {
    if before == after {
        return;
    }
    match (before, after) {
        (Value::Object(b), Value::Object(a)) => {
            let mut keys: Vec<&String> = b.keys().chain(a.keys()).collect();
            keys.sort();
            keys.dedup();
            for k in keys {
                let child = format!("{path}/{k}");
                match (b.get(k), a.get(k)) {
                    (Some(bv), Some(av)) => diff_json(&child, bv, av, out),
                    (Some(bv), None) => out.push(Change {
                        location: child,
                        before: Some(bv.to_string()),
                        after: None,
                    }),
                    (None, Some(av)) => out.push(Change {
                        location: child,
                        before: None,
                        after: Some(av.to_string()),
                    }),
                    (None, None) => {}
                }
            }
        }
        _ => out.push(Change {
            location: path.into(),
            before: Some(before.to_string()),
            after: Some(after.to_string()),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowmint_model::rule::{Match, PatchOp};
    use flowmint_model::{Action, Rule};

    fn base_rule() -> Rule {
        Rule {
            id: "r1".into(),
            name: "test".into(),
            version: "1.0.0".into(),
            r#match: Match {
                host: Some("api.example.test".into()),
                method: Some("GET".into()),
                path: Some("/v1/profile".into()),
                ..Default::default()
            },
            actions: vec![],
            limits: Default::default(),
            scope: Default::default(),
            fallback: Default::default(),
            audit_label: None,
        }
    }

    fn profile_exchange() -> HttpExchange {
        let mut ex = HttpExchange::request("GET", "api.example.test", "/v1/profile");
        ex.req_headers
            .push(("Authorization".into(), "Bearer abc".into()));
        ex.status = Some(200);
        ex.resp_body = br#"{"features":{"experimental":false},"name":"a"}"#.to_vec();
        ex
    }

    #[test]
    fn json_patch_replace_and_redact_match_design_example() {
        let mut rule = base_rule();
        rule.actions = vec![
            Action::Redact {
                fields: vec!["authorization".into()],
            },
            Action::JsonPatch {
                target: "response.body".into(),
                operations: vec![PatchOp {
                    op: "replace".into(),
                    path: "/features/experimental".into(),
                    value: Some(serde_json::json!(true)),
                }],
            },
        ];

        let before = profile_exchange();
        let mut after = before.clone();
        let d = apply(&rule, &mut after);

        assert!(d.matched);
        assert_eq!(d.redacted, vec!["authorization"]);
        assert!(d.errors.is_empty());

        let body: Value = serde_json::from_slice(&after.resp_body).unwrap();
        assert_eq!(body["features"]["experimental"], serde_json::json!(true));
        assert_eq!(after.req_headers[0].1, REDACTED);

        let changes = diff(&before, &after);
        assert!(changes
            .iter()
            .any(|c| c.location == "response.body/features/experimental"
                && c.after.as_deref() == Some("true")));
        assert!(changes
            .iter()
            .any(|c| c.location == "request.headers.Authorization"));
    }

    #[test]
    fn non_matching_rule_is_inert() {
        let rule = base_rule();
        let mut ex = HttpExchange::request("POST", "other.test", "/x");
        let d = apply(&rule, &mut ex);
        assert!(!d.matched);
    }

    #[test]
    fn respond_short_circuits() {
        let mut rule = base_rule();
        rule.actions = vec![Action::Respond {
            status: 503,
            body: "{\"down\":true}".into(),
        }];
        let mut ex = profile_exchange();
        let d = apply(&rule, &mut ex);
        assert_eq!(d.short_circuit.as_ref().unwrap().status, 503);
        assert_eq!(ex.status, Some(503));
    }

    #[test]
    fn bad_json_records_error_not_panic() {
        let mut rule = base_rule();
        rule.actions = vec![Action::JsonPatch {
            target: "response.body".into(),
            operations: vec![PatchOp {
                op: "replace".into(),
                path: "/x".into(),
                value: Some(serde_json::json!(1)),
            }],
        }];
        let mut ex = profile_exchange();
        ex.resp_body = b"not json".to_vec();
        let d = apply(&rule, &mut ex);
        assert!(!d.errors.is_empty());
    }
}
