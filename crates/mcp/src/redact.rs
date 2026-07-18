//! Default data-minimization / redaction policy (design §10.4).
//!
//! Applied to everything the AI surface returns. Sensitive header values are
//! masked by name; bodies and free text are scanned for tokens, emails and
//! phone numbers. Organizations can extend this with their own regex/dictionary
//! policy — the `policy_version` string travels with every response so a reader
//! knows exactly what masking was in force.

use regex::Regex;

const SENSITIVE_HEADERS: [&str; 8] = [
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-csrf-token",
];

pub const MASK: &str = "***REDACTED***";

pub struct Redactor {
    policy_version: String,
    jwt: Regex,
    email: Regex,
    bearer: Regex,
    phone: Regex,
}

impl Default for Redactor {
    fn default() -> Self {
        Self {
            policy_version: "default-v1".into(),
            jwt: Regex::new(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+").unwrap(),
            email: Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}").unwrap(),
            bearer: Regex::new(r"(?i)bearer\s+[A-Za-z0-9._\-]+").unwrap(),
            phone: Regex::new(r"\+?\d[\d\s\-]{7,}\d").unwrap(),
        }
    }
}

impl Redactor {
    pub fn policy_version(&self) -> &str {
        &self.policy_version
    }

    /// True if a header value should be fully masked by its name.
    pub fn is_sensitive_header(&self, name: &str) -> bool {
        SENSITIVE_HEADERS
            .iter()
            .any(|h| name.eq_ignore_ascii_case(h))
    }

    /// Mask a single header value if the name is sensitive.
    pub fn header_value(&self, name: &str, value: &str) -> String {
        if self.is_sensitive_header(name) {
            MASK.to_string()
        } else {
            self.text(value)
        }
    }

    /// Scan free text for tokens/PII and mask them.
    pub fn text(&self, input: &str) -> String {
        let s = self.jwt.replace_all(input, MASK);
        let s = self.bearer.replace_all(&s, MASK);
        let s = self.email.replace_all(&s, MASK);
        let s = self.phone.replace_all(&s, MASK);
        s.into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_sensitive_headers_and_tokens() {
        let r = Redactor::default();
        assert_eq!(r.header_value("Authorization", "Bearer abc"), MASK);
        assert_eq!(r.header_value("Cookie", "sid=1"), MASK);
        assert_eq!(
            r.header_value("Accept", "application/json"),
            "application/json"
        );

        let body = r.text(r#"{"email":"a@b.com","jwt":"eyJhbGc.eyJzdWI.sig"}"#);
        assert!(body.contains(MASK));
        assert!(!body.contains("a@b.com"));
        assert!(!body.contains("eyJhbGc"));
    }
}
