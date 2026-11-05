//! Leaving the machine in an honest, documented final state once a benchmark
//! run has finished.

use std::collections::HashMap;

use crate::ATTEMPT_TIMEOUT;
use crate::netlist::strongest_per_name;
use crate::platform;

/// Ends the run on a benchmark-verified SSID when possible, forgets every
/// allow-list profile except the one we are connected to, and prints an
/// honest final-state block.
///
/// "Verified" means *this run's* attempts authenticated the network. Being
/// in the allow-list is not enough: `scan` writes every visible SSID to the
/// file, including open networks (printers in DIRECT-* mode, cafés) that
/// `nmcli` will happily "authenticate" without using the password at all.
///
/// When `leave_disconnected` is set, lab profiles are removed and the run
/// exits offline instead of finishing connected.
pub(crate) fn finalize(
    leave_disconnected: bool,
    allow_list: &[String],
    succeeded: &[String],
    password: &str,
    delivery: platform::PasswordDelivery,
) {
    if leave_disconnected {
        for ssid in allow_list {
            platform::cleanup(ssid);
        }
        let active = platform::active_connection().ok().flatten();
        print_final_disconnected(active);
        return;
    }

    // If we're not already on a benchmark-verified SSID, try to get there.
    ensure_benchmark_connected(succeeded, password, delivery);

    // Forget every allow-list profile except the one we're currently on.
    // The active connection is preserved; every other lab network the bench
    // may have touched (or that was already stored) is removed.
    let active = platform::active_connection().ok().flatten();
    let active_ssid = active.as_ref().map(|(s, _)| s.as_str());
    for ssid in allow_list {
        if Some(ssid.as_str()) != active_ssid {
            platform::cleanup(ssid);
        }
    }

    let active = platform::active_connection().ok().flatten();
    let security = security_map();
    print_final_state(allow_list, succeeded, active, &security);
}

/// If NetworkManager is not on a benchmark-verified SSID, walk the successes
/// in order and connect to the first one that takes. Targets that went
/// offline during the run are skipped with a warning.
fn ensure_benchmark_connected(
    succeeded: &[String],
    password: &str,
    delivery: platform::PasswordDelivery,
) {
    let on_verified = || {
        platform::active_connection()
            .ok()
            .flatten()
            .map_or(false, |(s, _)| succeeded.iter().any(|x| x == &s))
    };

    if on_verified() {
        return;
    }

    for target in succeeded {
        eprintln!("  Reconnecting to benchmark-verified `{target}` …");
        let attempt = platform::connect(target, password, ATTEMPT_TIMEOUT, delivery);
        if attempt.ok && on_verified() {
            return;
        }
        if !attempt.ok {
            eprintln!("  ⚠ Could not reconnect to `{target}`: {}", attempt.detail);
        }
    }
}

/// Best-effort map of SSID → security string from nmcli's current view.
/// Triggers a rescan, which can take a couple of seconds; called once.
fn security_map() -> HashMap<String, String> {
    match platform::scan() {
        Ok(networks) => strongest_per_name(networks)
            .into_iter()
            .map(|n| (n.ssid, n.security))
            .collect(),
        Err(_) => HashMap::new(),
    }
}

fn print_final_state(
    allow_list: &[String],
    succeeded: &[String],
    active: Option<(String, String)>,
    security: &HashMap<String, String>,
) {
    println!();
    println!("── Final state ─────────────────────────────────────────────");
    match active {
        Some((ssid, device)) => {
            let is_verified = succeeded.iter().any(|s| s == &ssid);
            let in_allow_list = allow_list.iter().any(|s| s == &ssid);
            let security_str = security.get(&ssid).map(String::as_str);

            if is_verified {
                match security_str {
                    Some("Open") => {
                        println!("  ⚠ Connected to `{ssid}` (device {device}).");
                        println!("    This network is OPEN. Your password was not");
                        println!("    actually verified during the benchmark.");
                    }
                    Some(_) => {
                        println!(
                            "  ✔ Connected to authorized lab network: {ssid} (device {device})"
                        );
                        println!("    (benchmark authenticated this network during the run)");
                    }
                    None => {
                        println!("  ✔ Connected to `{ssid}` (device {device}).");
                        println!("    Benchmark authenticated this network, but its");
                        println!("    security could not be re-checked right now.");
                    }
                }
            } else if in_allow_list {
                println!("  ⚠ Connected to `{ssid}` (device {device}).");
                println!("    It is in the allow-list, but the benchmark did NOT");
                println!("    authenticate it. NetworkManager auto-reconnected.");
                if succeeded.is_empty() {
                    println!("    No benchmark attempt succeeded at all.");
                } else {
                    println!("    Benchmark succeeded on: {}", succeeded.join(", "));
                    println!("    (but could not reconnect; targets may be offline).");
                }
            } else {
                println!("  ⚠ Connected to `{ssid}` (device {device}).");
                println!("    This network is NOT in the allow-list and was not tested.");
                if !succeeded.is_empty() {
                    println!("    Benchmark succeeded on: {}", succeeded.join(", "));
                }
            }
        }
        None => {
            println!("  ⚠ Not connected to any Wi-Fi network.");
            if succeeded.is_empty() {
                println!("    No benchmark attempt succeeded, so there is nothing to");
                println!("    reconnect to.");
            } else {
                println!("    Benchmark succeeded on: {}", succeeded.join(", "));
                println!("    but reconnecting to it failed (target may be offline).");
            }
        }
    }
    println!("────────────────────────────────────────────────────────────");
}

fn print_final_disconnected(active: Option<(String, String)>) {
    println!();
    println!("── Final state ─────────────────────────────────────────────");
    match active {
        None => {
            println!("  ✔ Not connected to any Wi-Fi network.");
            println!("    (--leave-disconnected: allow-list profiles removed.)");
        }
        Some((ssid, device)) => {
            println!("  ⚠ Still connected to `{ssid}` (device {device}).");
            println!("    It is not in the allow-list, so --leave-disconnected did");
            println!("    not disconnect from it. Run `nmcli device disconnect {device}`");
            println!("    if you want to drop that connection too.");
        }
    }
    println!("────────────────────────────────────────────────────────────");
}
