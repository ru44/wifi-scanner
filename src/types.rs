//! Shared data types passed between the scanner, the benchmark, the report,
//! and the platform backend.

use std::time::Duration;

/// A Wi-Fi network as seen by a scan.
pub struct Network {
    pub ssid: String,
    /// Signal strength from 0 to 100.
    pub signal: u8,
    pub security: String,
}

/// Result of a single connection attempt during a benchmark run.
pub struct Attempt {
    pub ok: bool,
    pub elapsed: Duration,
    /// One-line summary from nmcli (stdout on success, stderr on failure).
    pub detail: String,
    /// True if the attempt was killed by the per-attempt timeout.
    pub timed_out: bool,
}

/// One recorded benchmark attempt: everything the report and CSV output need.
pub(crate) struct BenchRow {
    pub(crate) attempt_idx: usize,
    pub(crate) round: usize,
    pub(crate) ssid: String,
    pub(crate) crowd: usize,
    pub(crate) elapsed: Duration,
    pub(crate) ok: bool,
    pub(crate) timed_out: bool,
    pub(crate) detail: String,
}
