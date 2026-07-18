//! Shared error taxonomy.
//!
//! Kept deliberately small in the MVP; crates map their internal failures onto
//! these variants so the CLI / API surface a stable set of categories.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ModelError {
    #[error("invalid endpoint: {0}")]
    InvalidEndpoint(String),

    #[error("payload exceeds configured limit: {actual} > {limit} bytes")]
    PayloadTooLarge { actual: u64, limit: u64 },

    #[error("serialization failed: {0}")]
    Serde(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, ModelError>;
