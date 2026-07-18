//! Capture clock: pairs a monotonic anchor with wall-clock time so every event
//! carries both (design §6).

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::event::Observed;

/// Cheap to clone (holds a `Copy` `Instant`). One clock per capture, anchored at
/// capture start.
#[derive(Clone, Copy)]
pub struct Clock {
    start: Instant,
}

impl Clock {
    pub fn start_now() -> Self {
        Self { start: Instant::now() }
    }

    /// Stamp "now" relative to this clock's start.
    pub fn stamp(&self) -> Observed {
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        Observed {
            wall_unix_ms: wall,
            monotonic_offset_ns: self.start.elapsed().as_nanos() as u64,
        }
    }
}

impl Default for Clock {
    fn default() -> Self {
        Self::start_now()
    }
}
