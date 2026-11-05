//! `scan` mode: list nearby networks, strongest first, and record their names
//! to the allow-list file for a later benchmark.

use std::env;
use std::fs;
use std::process::ExitCode;

use crate::SSID_FILE;
use crate::json;
use crate::netlist::{printable_name, strongest_per_name};
use crate::platform;
use crate::types::{Network, rssi_label};

pub(crate) fn cmd_scan(args: &[String]) -> ExitCode {
    let mut as_json = false;
    for arg in args {
        match arg.as_str() {
            "--json" => as_json = true,
            other => {
                eprintln!("Error: unknown scan option: {other}");
                return ExitCode::FAILURE;
            }
        }
    }

    if !as_json {
        eprintln!("Scanning for Wi-Fi networks...");
    }

    let raw = match platform::scan() {
        Ok(networks) => networks,
        Err(message) => {
            eprintln!("Error: {message}");
            return ExitCode::FAILURE;
        }
    };

    // `--json` is a lossless feed: every access point, one record per BSSID
    // (so roaming — one name on several radios — is visible downstream). The
    // human table below instead collapses to the strongest per name.
    if as_json {
        let mut all = raw;
        for n in &mut all {
            n.ssid = printable_name(&n.ssid);
        }
        print_json(&all);
        return ExitCode::SUCCESS;
    }

    let networks = strongest_per_name(raw);

    if networks.is_empty() {
        println!("No Wi-Fi networks found. Is Wi-Fi turned on?");
        return ExitCode::SUCCESS;
    }

    print_table(&networks);
    save_allowlist(&networks)
}

fn print_table(networks: &[Network]) {
    println!("Nearby Wi-Fi networks:\n");
    println!(
        "{:<32} {:<7} {:>4} {:>6} {:>18}  {}",
        "SSID", "Band", "Chan", "Width", "Signal", "Security"
    );
    for n in networks {
        let dbm = n.approx_dbm();
        let width = if n.bandwidth_mhz > 0 {
            format!("{}MHz", n.bandwidth_mhz)
        } else {
            "-".to_string()
        };
        println!(
            "{:<32} {:<7} {:>4} {:>6} {:>3}% (~{:>4} dBm)  {}",
            truncate(&n.ssid, 32),
            n.band().label(),
            n.channel,
            width,
            n.signal,
            dbm,
            n.security,
        );
    }
    if let Some(strongest) = networks.first() {
        println!(
            "\nStrongest: {} — {} ({}), ~{} dBm.",
            strongest.ssid,
            rssi_label(strongest.approx_dbm()),
            strongest.band().label(),
            strongest.approx_dbm(),
        );
    }
    println!("(dBm is approximate; run `wifi-scanner link` for the real figure once connected.)");
}

fn save_allowlist(networks: &[Network]) -> ExitCode {
    let path = env::var("LAB_SSID_FILE").unwrap_or_else(|_| SSID_FILE.to_string());
    let contents = networks
        .iter()
        .map(|network| network.ssid.as_str())
        .collect::<Vec<_>>()
        .join("\n");

    match fs::write(&path, format!("{contents}\n")) {
        Ok(()) => {
            println!("\nSaved {} network(s) to {path}", networks.len());
            println!("Only keep networks you own or administer in this file —");
            println!("`wifi-scanner bench` will refuse to run against anything else.");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("\nFailed to save networks to {path}: {error}");
            ExitCode::FAILURE
        }
    }
}

fn print_json(networks: &[Network]) {
    println!("[");
    for (i, n) in networks.iter().enumerate() {
        let comma = if i + 1 < networks.len() { "," } else { "" };
        println!(
            "  {{\"ssid\": {}, \"bssid\": {}, \"mode\": {}, \"band\": {}, \"channel\": {}, \
             \"freq_mhz\": {}, \"bandwidth_mhz\": {}, \"rate_mbps\": {}, \
             \"signal_pct\": {}, \"signal_dbm_approx\": {}, \"security\": {}}}{}",
            json::quote(&n.ssid),
            json::quote(&n.bssid),
            json::quote(&n.mode),
            json::quote(n.band().label()),
            n.channel,
            n.freq_mhz,
            n.bandwidth_mhz,
            n.rate_mbps,
            n.signal,
            n.approx_dbm(),
            json::quote(&n.security),
            comma,
        );
    }
    println!("]");
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}
