//! `link` mode: report the health of the *active* Wi-Fi connection, read
//! straight from the driver via `iw` (true dBm, negotiated rate, PHY, width,
//! TX power, retries). Answers "why does my connection feel the way it does".

use std::process::ExitCode;

use crate::json;
use crate::platform;
use crate::types::{LinkInfo, rssi_label};

pub(crate) fn cmd_link(args: &[String]) -> ExitCode {
    let mut as_json = false;
    for arg in args {
        match arg.as_str() {
            "--json" => as_json = true,
            other => {
                eprintln!("Error: unknown link option: {other}");
                return ExitCode::FAILURE;
            }
        }
    }

    match platform::link_info() {
        Some(info) if as_json => print_json(&info),
        Some(info) => print_report(&info),
        None if as_json => println!("{{\"connected\": false}}"),
        None => println!("No active Wi-Fi link (not connected, or no Wi-Fi device found)."),
    }
    ExitCode::SUCCESS
}

/// tx retries as a percentage of all tx frames, if both counters are present.
fn retry_pct(info: &LinkInfo) -> Option<f64> {
    match (info.tx_packets, info.tx_retries) {
        (Some(pkts), Some(retries)) if pkts + retries > 0 => {
            Some(retries as f64 / (pkts + retries) as f64 * 100.0)
        }
        _ => None,
    }
}

fn print_report(info: &LinkInfo) {
    println!();
    println!("── Wi-Fi link ──────────────────────────────────────────────");

    let name = info.ssid.as_deref().unwrap_or("(unknown)");
    match &info.bssid {
        Some(bssid) => println!("  Network:    {name}  ({bssid})"),
        None => println!("  Network:    {name}"),
    }
    println!("  Device:     {}", info.device);

    if let Some(dbm) = info.signal_dbm {
        println!("  Signal:     {dbm} dBm ({})", rssi_label(dbm));
    }
    if let Some(freq) = info.freq_mhz {
        let chan = info.channel.map_or(String::new(), |c| format!("ch {c}, "));
        let width = info
            .width_mhz
            .map_or(String::new(), |w| format!(", {w} MHz wide"));
        println!("  Channel:    {chan}{freq} MHz{width}");
    }
    if let Some(phy) = info.phy {
        println!("  PHY:        {phy}");
    }
    if let Some(tx) = info.txpower_dbm {
        println!("  TX power:   {tx:.1} dBm");
    }
    if let Some(rx) = &info.rx_bitrate {
        println!("  RX rate:    {rx}");
    }
    if let Some(tx) = &info.tx_bitrate {
        println!("  TX rate:    {tx}");
    }
    if let Some(pct) = retry_pct(info) {
        println!(
            "  TX retry:   {pct:.1}%  ({} retries / {} frames)",
            info.tx_retries.unwrap_or(0),
            info.tx_packets.unwrap_or(0) + info.tx_retries.unwrap_or(0),
        );
    }
    if let Some(loss) = info.beacon_loss {
        println!("  Beacon loss: {loss}");
    }
    println!("────────────────────────────────────────────────────────────");
}

fn print_json(info: &LinkInfo) {
    println!("{{");
    println!("  \"connected\": true,");
    println!("  \"device\": {},", json::quote(&info.device));
    println!("  \"ssid\": {},", json::opt_str(info.ssid.as_deref()));
    println!("  \"bssid\": {},", json::opt_str(info.bssid.as_deref()));
    println!("  \"signal_dbm\": {},", json::num(info.signal_dbm));
    println!("  \"freq_mhz\": {},", json::num(info.freq_mhz));
    println!("  \"channel\": {},", json::num(info.channel));
    println!("  \"width_mhz\": {},", json::num(info.width_mhz));
    println!("  \"txpower_dbm\": {},", json::num(info.txpower_dbm));
    println!("  \"phy\": {},", json::opt_str(info.phy));
    println!("  \"rx_bitrate\": {},", json::opt_str(info.rx_bitrate.as_deref()));
    println!("  \"tx_bitrate\": {},", json::opt_str(info.tx_bitrate.as_deref()));
    println!("  \"tx_packets\": {},", json::num(info.tx_packets));
    println!("  \"tx_retries\": {},", json::num(info.tx_retries));
    println!("  \"tx_retry_pct\": {},", json::num(retry_pct(info).map(|p| format!("{p:.2}"))));
    println!("  \"beacon_loss\": {}", json::num(info.beacon_loss));
    println!("}}");
}
