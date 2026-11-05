//! Wi-Fi scanner — authorized-lab benchmark
//!
//! Modes:
//!   wifi-scanner scan    list nearby networks, strongest first, and write
//!                        their names to `lab-ssids.txt`
//!   wifi-scanner bench   time connection attempts against the SSIDs listed in
//!                        `lab-ssids.txt` using a password you supply.
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
//!   types      shared data types (Network, Attempt, BenchRow)
//!   netlist    shaping a raw scan into a clean, printable list
//!   scan       the `scan` command
//!   bench      the `bench` command and its run loop
//!   allowlist  reading the SSID allow-list and prompting for the password
//!   report     the end-of-run report and its statistics
//!   csv_out    per-attempt CSV output
//!   finalize   leaving the machine in an honest final state
//!   linux      the NetworkManager (`nmcli`) backend

use std::env;
use std::process::ExitCode;
use std::time::Duration;

#[cfg(not(target_os = "linux"))]
compile_error!("wifi-scanner now supports Linux only.");

mod allowlist;
mod bench;
mod csv_out;
mod finalize;
mod linux;
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
    match args.first().map(String::as_str) {
        None | Some("scan") => scan::cmd_scan(),
        Some("bench") => bench::cmd_bench(&args[1..]),
        Some(other) => {
            eprintln!("Unknown command: {other}");
            eprintln!(
                "Usage: wifi-scanner [scan|bench [--repeats N] [--csv PATH] \
                 [--no-shuffle] [--authorized] [--leave-disconnected] \
                 [--password-argv]]"
            );
            ExitCode::FAILURE
        }
    }
}
