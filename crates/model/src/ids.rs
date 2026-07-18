//! Stable identifiers.
//!
//! Per design §6, stable IDs use time-ordered UUIDs (UUIDv7). These sort
//! lexicographically in creation order, which keeps SQLite indexes and event
//! logs naturally append-ordered without a separate sequence column.

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

macro_rules! id_type {
    ($name:ident, $prefix:literal) => {
        #[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Mint a new time-ordered id.
            pub fn new() -> Self {
                Self(format!("{}_{}", $prefix, Uuid::now_v7().simple()))
            }

            /// Wrap an already-formatted id string (e.g. read from storage).
            pub fn from_string(s: impl Into<String>) -> Self {
                Self(s.into())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }

        impl From<String> for $name {
            fn from(s: String) -> Self {
                Self(s)
            }
        }
    };
}

id_type!(CaptureId, "cap");
id_type!(FlowId, "flow");
id_type!(EventId, "evt");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_prefixed_and_ordered() {
        let a = EventId::new();
        let b = EventId::new();
        assert!(a.as_str().starts_with("evt_"));
        // UUIDv7 is time-ordered, so a monotonically-later id sorts after.
        assert!(a.as_str() <= b.as_str());
    }
}
