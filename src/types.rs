//! Shared data types passed between the scanner, the analysis modes, the
//! benchmark, the report, and the platform backend.

use std::time::Duration;

/// A single access point as seen by a scan (one entry per BSSID).
pub struct Network {
    pub ssid: String,
    /// Hardware address of the radio (unique per AP; an SSID may have many).
    pub bssid: String,
    /// Signal quality from 0 to 100, as NetworkManager reports it.
    pub signal: u8,
    pub security: String,
    /// Operating mode, e.g. "Infra" or "Mesh".
    pub mode: String,
    pub channel: u32,
    pub freq_mhz: u32,
    /// Channel width in MHz (20/40/80/160); 0 if unknown.
    pub bandwidth_mhz: u32,
    /// Advertised maximum rate in Mbit/s; 0 if unknown.
    pub rate_mbps: u32,
}

impl Network {
    pub fn band(&self) -> Band {
        Band::from_freq(self.freq_mhz)
    }

    /// Approximate dBm from NetworkManager's 0–100 quality figure.
    ///
    /// NM's percentage is itself derived from the radio's dBm reading; this
    /// inverts the common linear mapping (−100 dBm → 0 %, −50 dBm → 100 %).
    /// It is a guide only — for the *connected* AP, `link` mode reports the
    /// true dBm straight from the driver.
    pub fn approx_dbm(&self) -> i32 {
        i32::from(self.signal) / 2 - 100
    }
}

/// The three Wi-Fi bands, derived from a channel's centre frequency.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Band {
    TwoFour,
    Five,
    Six,
    Unknown,
}

impl Band {
    pub fn from_freq(mhz: u32) -> Band {
        match mhz {
            2400..=2500 => Band::TwoFour,
            4900..=5895 => Band::Five,
            5925..=7125 => Band::Six,
            _ => Band::Unknown,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Band::TwoFour => "2.4 GHz",
            Band::Five => "5 GHz",
            Band::Six => "6 GHz",
            Band::Unknown => "?",
        }
    }
}

/// A plain-language quality word for a dBm reading (same scale everywhere).
pub fn rssi_label(dbm: i32) -> &'static str {
    match dbm {
        d if d >= -50 => "excellent",
        d if d >= -60 => "very good",
        d if d >= -67 => "good",
        d if d >= -70 => "okay",
        d if d >= -80 => "weak",
        _ => "very weak",
    }
}

/// A best-effort snapshot of the active Wi-Fi link's health. Every field is
/// optional because the backend gathers what the driver will give it and
/// leaves the rest blank rather than failing.
#[derive(Default)]
pub struct LinkInfo {
    pub device: String,
    pub ssid: Option<String>,
    pub bssid: Option<String>,
    pub signal_dbm: Option<i32>,
    pub freq_mhz: Option<u32>,
    pub channel: Option<u32>,
    pub width_mhz: Option<u32>,
    pub txpower_dbm: Option<f64>,
    pub rx_bitrate: Option<String>,
    pub tx_bitrate: Option<String>,
    /// Human-readable PHY generation, e.g. "Wi-Fi 6 (802.11ax)".
    pub phy: Option<&'static str>,
    pub tx_packets: Option<u64>,
    pub tx_retries: Option<u64>,
    pub beacon_loss: Option<u64>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn band_from_frequency() {
        assert_eq!(Band::from_freq(2437), Band::TwoFour);
        assert_eq!(Band::from_freq(5560), Band::Five);
        assert_eq!(Band::from_freq(6135), Band::Six);
        assert_eq!(Band::from_freq(0), Band::Unknown);
    }

    #[test]
    fn approx_dbm_maps_quality_linearly() {
        let net = |signal| Network {
            ssid: String::new(),
            bssid: String::new(),
            signal,
            security: String::new(),
            mode: String::new(),
            channel: 0,
            freq_mhz: 0,
            bandwidth_mhz: 0,
            rate_mbps: 0,
        };
        assert_eq!(net(100).approx_dbm(), -50);
        assert_eq!(net(0).approx_dbm(), -100);
        assert_eq!(net(50).approx_dbm(), -75);
    }

    #[test]
    fn rssi_label_covers_the_scale() {
        assert_eq!(rssi_label(-40), "excellent");
        assert_eq!(rssi_label(-65), "good");
        assert_eq!(rssi_label(-72), "weak");
        assert_eq!(rssi_label(-90), "very weak");
    }
}
