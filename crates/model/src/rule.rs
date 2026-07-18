//! Rule IR — the shared contract across GUI, SDK and CI (design §3.3).
//!
//! This is the *intermediate representation*: GUI forms, AI drafts, SDK
//! middleware and CLI replay all compile/map onto this single shape. The MVP
//! defines the schema and (de)serialization; the executor lives in the `rules`
//! crate (added in a later milestone).
//!
//! NOTE: design §3.3 and §8 currently show two YAML dialects
//! (`match/actions/...` vs `when/then/...`). This type is the canonical one;
//! the §8 form should be treated as sugar that lowers onto it.

use serde::{Deserialize, Serialize};

/// A versioned, verifiable, explainable declarative rule.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    #[serde(default)]
    pub name: String,
    pub version: String,
    pub r#match: Match,
    #[serde(default)]
    pub actions: Vec<Action>,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub scope: Scope,
    #[serde(default = "Fallback::default")]
    pub fallback: Fallback,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_label: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Match {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_prefix: Option<String>,
}

/// Rule actions (design §3.3 / §8). Serialized as an externally-tagged enum so
/// the YAML/JSON reads like `{ redact: {...} }`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Observe,
    Tag { labels: Vec<String> },
    Redact { fields: Vec<String> },
    Delay { milliseconds: u64 },
    Respond { status: u16, body: String },
    /// RFC6902-style patch applied to a JSON body (`response.body` /
    /// `request.body`), per the design §3.3 example.
    JsonPatch { target: String, operations: Vec<PatchOp> },
    Breakpoint,
    Record,
}

/// A single JSON patch operation (subset of RFC 6902).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PatchOp {
    /// "replace" | "add" | "remove".
    pub op: String,
    /// JSON Pointer (RFC 6901), e.g. `/features/experimental`.
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Limits {
    pub max_body_bytes: u64,
    pub timeout_ms: u64,
}

impl Default for Limits {
    fn default() -> Self {
        // Conservative defaults; a rule that omits limits still cannot run away.
        Self { max_body_bytes: 1 << 20, timeout_ms: 50 }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Scope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_hosts: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Fallback {
    #[default]
    PassThrough,
    Abort,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_design_example_shape() {
        let json = r#"{
            "id": "rewrite-profile-for-development",
            "version": "1.0.0",
            "match": { "protocol": "http", "host": "api.example.test", "method": "GET", "path": "/v1/profile" },
            "actions": [ { "redact": { "fields": ["authorization"] } } ],
            "limits": { "max_body_bytes": 1048576, "timeout_ms": 20 },
            "scope": { "environment": "development", "allow_hosts": ["api.example.test"] },
            "fallback": "pass_through",
            "audit_label": "development-feature-test"
        }"#;
        let rule: Rule = serde_json::from_str(json).unwrap();
        assert_eq!(rule.id, "rewrite-profile-for-development");
        assert_eq!(rule.r#match.host.as_deref(), Some("api.example.test"));
        assert_eq!(rule.limits.timeout_ms, 20);
    }
}
