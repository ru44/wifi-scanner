//! `scan` mode: list nearby networks, strongest first, and record their names
//! to the allow-list file for a later benchmark.

use std::env;
use std::fs;
use std::process::ExitCode;

use crate::SSID_FILE;
use crate::netlist::strongest_per_name;
use crate::platform;

pub(crate) fn cmd_scan() -> ExitCode {
    eprintln!("Scanning for Wi-Fi networks...");

    let networks = match platform::scan() {
        Ok(networks) => strongest_per_name(networks),
        Err(message) => {
            eprintln!("Error: {message}");
            return ExitCode::FAILURE;
        }
    };

    if networks.is_empty() {
        println!("No Wi-Fi networks found. Is Wi-Fi turned on?");
        return ExitCode::SUCCESS;
    }

    println!("Nearby Wi-Fi networks:\n");
    for network in &networks {
        println!(
            "{:<35} Signal: {:>3}%  Security: {}",
            network.ssid, network.signal, network.security
        );
    }

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
        }
        Err(error) => {
            eprintln!("\nFailed to save networks to {path}: {error}");
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}
