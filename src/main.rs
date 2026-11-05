//! Wi-Fi scanner — authorized-lab benchmark & RF study tool
//!
//! Modes:
//!   wifi-scanner scan     list nearby networks (band/channel/width/signal),
//!                         strongest first, and write their names to
//!                         `lab-ssids.txt`. `--json` for machine output.
//!   wifi-scanner analyze  study the airspace from one scan: band split,
//!                         channel congestion with a recommended 2.4 GHz
//!                         channel, security posture, and roaming (multi-AP)
//!                         networks. `--json` for machine output.
//!   wifi-scanner link     health of the *active* connection, read from the
//!                         driver: true dBm, negotiated rate, PHY generation,
//!                         channel width, TX power, retries. `--json` too.
//!   wifi-scanner monitor  re-scan on an interval and watch each AP's signal
//!                         as a sparkline, flagging APs that appear/vanish.
//!                         `--interval SECS`, `--rounds N`, `--csv PATH`.
//!   wifi-scanner bench    time connection attempts against the SSIDs listed in
//!                         `lab-ssids.txt` using a password you supply.
//!
//! What this tool does *not* do: it does not discover, guess, or crack
//! passwords. It takes a password you already know and measures how long
//! each allow-listed network takes to authenticate it, plus how many
//! access points were visible at the time (the "crowd" covariate).
//!
//! Consent and final state:
//!   `bench` refuses to run unless you either type `allow`
//!   on an interactive terminal, or pass `--authorized`. It also finishes
//!   with a connected Wi-Fi interface whenever a benchmark-verified SSID is
//!   reachable, prints the live `nmcli` connection state, and forgets every
//!   allow-listed profile except the one it is currently connected to.
//!   Pass `--leave-disconnected` to clean up and exit offline instead.
//!
//! Bench options:
//!   --repeats N           repeat the allowlist N times (default: 1)
//!   --csv PATH            write one row per attempt to PATH
//!   --no-shuffle          keep SSID order instead of shuffling each round
//!   --authorized          assert you own/administer the listed networks;
//!                         skips the interactive consent prompt
//!   --leave-disconnected  remove lab profiles and exit offline instead of
//!                         finishing connected
//!   --password-argv       pass the password on nmcli's argv instead of
//!                         stdin. Visible in `ps` and journald; use only if
//!                         `--ask` mode does not work on your system.
//!
//! The code is split into focused modules:
//!   types      shared data types (Network, Band, LinkInfo, Attempt, BenchRow)
//!   netlist    shaping a raw scan into a clean, printable list
//!   json       zero-dependency JSON escaping for `--json` output
//!   scan       the `scan` command
//!   analyze    the `analyze` command (airspace study)
//!   link       the `link` command (active-connection health)
//!   monitor    the `monitor` command (signal over time)
//!   bench      the `bench` command and its run loop
//!   allowlist  reading the SSID allow-list and prompting for the password
//!   report     the end-of-run report and its statistics
//!   csv_out    per-attempt CSV output
//!   finalize   leaving the machine in an honest final state
//!   linux      the NetworkManager (`nmcli`) + `iw` backend

use std::env;
use std::process::ExitCode;
use std::time::Duration;

#[cfg(not(target_os = "linux"))]
compile_error!("wifi-scanner now supports Linux only.");

mod allowlist;
mod analyze;
mod bench;
mod csv_out;
mod finalize;
mod json;
mod link;
mod linux;
mod monitor;
mod netlist;
mod report;
mod scan;
mod types;

use linux as platform;

/// Default allow-list path; override with the `LAB_SSID_FILE` env var.
const SSID_FILE: &str = "lab-ssids.txt";
/// Per-attempt timeout: a benchmark must not hang on a stuck association.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let rest = args.get(1..).unwrap_or(&[]);
    match args.first().map(String::as_str) {
        None | Some("scan") => scan::cmd_scan(rest),
        Some("analyze") => analyze::cmd_analyze(rest),
        Some("link") => link::cmd_link(rest),
        Some("monitor") => monitor::cmd_monitor(rest),
        Some("bench") => bench::cmd_bench(rest),
        Some("-h" | "--help" | "help") => {
            print_usage();
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("Unknown command: {other}\n");
            print_usage();
            ExitCode::FAILURE
        }
    }
}

fn print_usage() {
    eprintln!("Usage: wifi-scanner <command> [options]\n");
    eprintln!("Commands:");
    eprintln!("  scan      [--json]            list nearby networks, save names to lab-ssids.txt");
    eprintln!("  analyze   [--json]            band/channel/security/roaming study of the airspace");
    eprintln!("  link      [--json]            health of the active connection (true dBm, rate, PHY)");
    eprintln!("  monitor   [--interval SECS] [--rounds N] [--csv PATH]");
    eprintln!("                                watch signal over time as sparklines");
    eprintln!("  bench     [--repeats N] [--csv PATH] [--no-shuffle] [--authorized]");
    eprintln!("            [--leave-disconnected] [--password-argv]");
    eprintln!("                                time known-password auth against lab-ssids.txt");
}
