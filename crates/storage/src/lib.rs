//! Storage: a SQLite metadata index plus a content-addressed chunk store
//! (design §6.1).
//!
//! - **Index** (`index.sqlite`): one row per flow and per event, with the full
//!   object as JSON plus a few denormalized columns to filter/sort on. Listing
//!   never touches payloads.
//! - **Chunk store** (`chunks/<ab>/<sha256>`): payload bytes keyed by SHA-256,
//!   so identical bodies are stored once. Chunking into 1–4 MiB pieces (design
//!   §6.1) is a later optimization; today each payload is one content-addressed
//!   blob. The `.fma` archive format is layered on top in a later milestone.

use std::fs;
use std::path::{Path, PathBuf};

use flowmint_model::{Flow, NetworkEvent, PayloadRef, RedactionState};
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("payload not found for locator {0}")]
    PayloadMissing(String),
}

pub type Result<T> = std::result::Result<T, StorageError>;

/// A capture session row (design §5 control plane).
#[derive(Debug, Clone)]
pub struct CaptureRow {
    pub capture_id: String,
    pub started_ms: i64,
    pub label: Option<String>,
}

/// Filter for flow search (design §9 Session Explorer / §15.5 CLI).
#[derive(Debug, Default, Clone)]
pub struct SearchFilter {
    pub host: Option<String>,
    pub capture_id: Option<String>,
    pub limit: usize,
}

impl SearchFilter {
    fn effective_limit(&self) -> i64 {
        if self.limit == 0 {
            1000
        } else {
            self.limit as i64
        }
    }
}

pub struct Store {
    conn: Connection,
    root: PathBuf,
}

impl Store {
    /// Open (creating if needed) a store rooted at `root`.
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("chunks"))?;
        let conn = Connection::open(root.join("index.sqlite"))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let store = Self { conn, root };
        store.migrate()?;
        Ok(store)
    }

    /// 清空所有已捕获数据：删空 flows/events/captures，并清空 chunk 存储。
    pub fn clear(&self) -> Result<()> {
        self.conn.execute_batch("DELETE FROM events; DELETE FROM flows; DELETE FROM captures;")?;
        let chunks = self.root.join("chunks");
        if chunks.exists() {
            fs::remove_dir_all(&chunks)?;
        }
        fs::create_dir_all(&chunks)?;
        Ok(())
    }

    fn migrate(&self) -> Result<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS captures (
                capture_id  TEXT PRIMARY KEY,
                started_ms  INTEGER NOT NULL,
                label       TEXT
            );

            CREATE TABLE IF NOT EXISTS flows (
                flow_id     TEXT PRIMARY KEY,
                capture_id  TEXT NOT NULL,
                host        TEXT,
                opened_ms   INTEGER NOT NULL,
                json        TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_flows_capture ON flows(capture_id);
            CREATE INDEX IF NOT EXISTS idx_flows_host    ON flows(host);
            CREATE INDEX IF NOT EXISTS idx_flows_opened  ON flows(opened_ms);

            CREATE TABLE IF NOT EXISTS events (
                event_id    TEXT PRIMARY KEY,
                flow_id     TEXT NOT NULL,
                capture_id  TEXT NOT NULL,
                sequence    INTEGER NOT NULL,
                wall_ms     INTEGER NOT NULL,
                kind        TEXT NOT NULL,
                json        TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_flow ON events(flow_id, sequence);
            "#,
        )?;
        Ok(())
    }

    // --- chunk store -----------------------------------------------------

    /// Store payload bytes content-addressed; returns a [`PayloadRef`].
    /// Idempotent: identical bytes reuse the same file.
    pub fn put_payload(&self, bytes: &[u8], redaction: RedactionState) -> Result<PayloadRef> {
        let sha = hex::encode(Sha256::digest(bytes));
        let (dir, locator) = self.chunk_paths(&sha);
        if !dir.join(&sha).exists() {
            fs::create_dir_all(&dir)?;
            // write-to-temp then rename would be ideal; kept simple for the MVP.
            fs::write(dir.join(&sha), bytes)?;
        }
        Ok(PayloadRef {
            sha256: sha,
            length: bytes.len() as u64,
            redaction,
            locator,
        })
    }

    pub fn get_payload(&self, payload: &PayloadRef) -> Result<Vec<u8>> {
        let path = self.root.join(&payload.locator);
        fs::read(&path).map_err(|_| StorageError::PayloadMissing(payload.locator.clone()))
    }

    fn chunk_paths(&self, sha: &str) -> (PathBuf, String) {
        let prefix = &sha[0..2];
        let dir = self.root.join("chunks").join(prefix);
        let locator = format!("chunks/{prefix}/{sha}");
        (dir, locator)
    }

    // --- index writes ----------------------------------------------------

    pub fn list_captures(&self) -> Result<Vec<CaptureRow>> {
        let mut stmt = self
            .conn
            .prepare("SELECT capture_id, started_ms, label FROM captures ORDER BY started_ms DESC")?;
        let rows = stmt.query_map([], |row| {
            Ok(CaptureRow {
                capture_id: row.get(0)?,
                started_ms: row.get(1)?,
                label: row.get(2)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn insert_capture(&self, capture_id: &str, started_ms: i64, label: Option<&str>) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO captures (capture_id, started_ms, label) VALUES (?1, ?2, ?3)",
            params![capture_id, started_ms, label],
        )?;
        Ok(())
    }

    pub fn upsert_flow(&self, flow: &Flow) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO flows (flow_id, capture_id, host, opened_ms, json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                flow.flow_id.as_str(),
                flow.capture_id.as_str(),
                flow.host,
                flow.opened_at_ms,
                serde_json::to_string(flow)?,
            ],
        )?;
        Ok(())
    }

    pub fn insert_event(&self, event: &NetworkEvent) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO events (event_id, flow_id, capture_id, sequence, wall_ms, kind, json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                event.event_id.as_str(),
                event.flow_id.as_str(),
                event.capture_id.as_str(),
                event.sequence as i64,
                event.observed_at.wall_unix_ms,
                serde_json::to_string(&event.kind)?.trim_matches('"'),
                serde_json::to_string(event)?,
            ],
        )?;
        Ok(())
    }

    // --- queries ---------------------------------------------------------

    pub fn search_flows(&self, filter: &SearchFilter) -> Result<Vec<Flow>> {
        let mut sql = String::from("SELECT json FROM flows WHERE 1=1");
        if filter.host.is_some() {
            sql.push_str(" AND host LIKE :host");
        }
        if filter.capture_id.is_some() {
            sql.push_str(" AND capture_id = :cap");
        }
        sql.push_str(" ORDER BY opened_ms ASC LIMIT :lim");

        let host_pat = filter.host.as_ref().map(|h| format!("%{h}%"));
        let lim = filter.effective_limit();

        let mut named: Vec<(&str, &dyn rusqlite::ToSql)> = Vec::new();
        if let Some(h) = &host_pat {
            named.push((":host", h));
        }
        if let Some(c) = &filter.capture_id {
            named.push((":cap", c));
        }
        named.push((":lim", &lim));

        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(named.as_slice(), |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(serde_json::from_str::<Flow>(&r?)?);
        }
        Ok(out)
    }

    pub fn get_flow(&self, flow_id: &str) -> Result<Option<Flow>> {
        let mut stmt = self.conn.prepare("SELECT json FROM flows WHERE flow_id = ?1")?;
        let mut rows = stmt.query(params![flow_id])?;
        match rows.next()? {
            Some(row) => Ok(Some(serde_json::from_str::<Flow>(&row.get::<_, String>(0)?)?)),
            None => Ok(None),
        }
    }

    pub fn events_for_flow(&self, flow_id: &str) -> Result<Vec<NetworkEvent>> {
        let mut stmt = self
            .conn
            .prepare("SELECT json FROM events WHERE flow_id = ?1 ORDER BY sequence ASC")?;
        let rows = stmt.query_map(params![flow_id], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(serde_json::from_str::<NetworkEvent>(&r?)?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowmint_model::{CaptureId, Endpoint, FlowId};

    fn endpoint(host: &str, port: u16) -> Endpoint {
        Endpoint { host: Some(host.into()), ip: None, port, process_name: None, process_pid: None }
    }

    #[test]
    fn payload_is_content_addressed_and_deduped() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let a = store.put_payload(b"hello", RedactionState::None).unwrap();
        let b = store.put_payload(b"hello", RedactionState::None).unwrap();
        assert_eq!(a.sha256, b.sha256);
        assert_eq!(store.get_payload(&a).unwrap(), b"hello");
    }

    #[test]
    fn flow_search_filters_by_host() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let cap = CaptureId::new();
        store.insert_capture(cap.as_str(), 0, Some("t")).unwrap();

        let f1 = Flow::opened(FlowId::new(), cap.clone(), endpoint("client", 1), endpoint("example.com", 80), 10);
        let f2 = Flow::opened(FlowId::new(), cap.clone(), endpoint("client", 2), endpoint("other.test", 80), 20);
        store.upsert_flow(&f1).unwrap();
        store.upsert_flow(&f2).unwrap();

        let hits = store
            .search_flows(&SearchFilter { host: Some("example".into()), capture_id: None, limit: 10 })
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].host.as_deref(), Some("example.com"));
    }
}
