//! `bench` mode: take a *known* password and time how long each allow-listed
//! Wi-Fi network takes to authenticate it, alongside the visible-AP "crowd"
//! covariate. It never discovers, guesses, or cracks a password.

use std::fs::File;
use std::io::{self, BufWriter, IsTerminal, Write};
use std::process::ExitCode;
use std::time::Instant;

use crate::ATTEMPT_TIMEOUT;
use crate::allowlist::{prompt_password, read_allowlist};
use crate::csv_out::write_csv_row;
use crate::finalize::finalize;
use crate::platform;
use crate::report::print_report;
use crate::types::BenchRow;

#[derive(Default)]
pub(crate) struct BenchOptions {
    repeats: usize,
    csv_path: Option<String>,
    shuffle: bool,
    authorized: bool,
    leave_disconnected: bool,
    password_via_argv: bool,
}

fn parse_bench_args(args: &[String]) -> Result<BenchOptions, String> {
    let mut opts = BenchOptions {
        repeats: 1,
        shuffle: true,
        ..BenchOptions::default()
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--repeats" => {
                i += 1;
                let value = args.get(i).ok_or("--repeats needs a value")?;
                let n: usize = value
                    .parse()
                    .map_err(|_| format!("invalid --repeats value: {value}"))?;
                if n == 0 {
                    return Err("--repeats must be at least 1".to_string());
                }
                opts.repeats = n;
            }
            "--csv" => {
                i += 1;
                opts.csv_path = Some(args.get(i).ok_or("--csv needs a path")?.clone());
            }
            "--no-shuffle" => opts.shuffle = false,
            "--authorized" => opts.authorized = true,
            "--leave-disconnected" => opts.leave_disconnected = true,
            "--password-argv" => opts.password_via_argv = true,
            other => return Err(format!("unknown bench option: {other}")),
        }
        i += 1;
    }
    Ok(opts)
}

pub(crate) fn cmd_bench(args: &[String]) -> ExitCode {
    let opts = match parse_bench_args(args) {
        Ok(opts) => opts,
        Err(message) => {
            eprintln!("Error: {message}");
            return ExitCode::FAILURE;
        }
    };
    match run_bench(opts) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("Error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run_bench(opts: BenchOptions) -> Result<(), String> {
    print_banner();

    let ssids = read_allowlist()?;

    // Consent gate — refuse to run if we cannot establish that the operator
    // owns or is authorized to test the listed networks.
    if !opts.authorized {
        confirm_authorized()?;
    }

    match platform::crowd() {
        Ok(count) => eprintln!("Visible access points right now (crowd size): {count}"),
        Err(message) => eprintln!("Warning: could not sample crowd size ({message}); continuing."),
    }

    let password = prompt_password()?;

    let delivery = if opts.password_via_argv {
        platform::PasswordDelivery::Argv
    } else {
        platform::PasswordDelivery::Stdin
    };

    let total_attempts = ssids.len() * opts.repeats;
    println!();
    println!(
        "Testing {} network(s) x {} repeat(s) = {} attempt(s), timeout {}s each:",
        ssids.len(),
        opts.repeats,
        total_attempts,
        ATTEMPT_TIMEOUT.as_secs()
    );
    println!();

    let mut csv_writer = match &opts.csv_path {
        Some(path) => {
            let file = File::create(path).map_err(|e| format!("could not create {path}: {e}"))?;
            let mut writer = BufWriter::new(file);
            writeln!(
                writer,
                "attempt_idx,round,ssid,crowd,elapsed_ms,ok,timed_out,detail"
            )
            .map_err(|e| format!("could not write CSV header: {e}"))?;
            Some(writer)
        }
        None => None,
    };

    let mut rows: Vec<BenchRow> = Vec::with_capacity(total_attempts);
    let overall = Instant::now();
    let mut attempt_idx = 0;

    for round in 0..opts.repeats {
        let mut order: Vec<String> = ssids.clone();
        if opts.shuffle {
            shuffle(&mut order);
        }

        for ssid in &order {
            platform::cleanup(ssid);

            let crowd = platform::crowd().unwrap_or(0);

            print!(
                "  [{:>3}/{}] round {}  {:<35} crowd {:>3} ... ",
                attempt_idx + 1,
                total_attempts,
                round + 1,
                ssid,
                crowd
            );
            io::stdout().flush().map_err(|e| e.to_string())?;

            let attempt = platform::connect(ssid, &password, ATTEMPT_TIMEOUT, delivery);
            println!(
                "{}  {:>8.2} ms  {}",
                if attempt.ok { "OK  " } else { "FAIL" },
                attempt.elapsed.as_secs_f64() * 1000.0,
                attempt.detail
            );

            let row = BenchRow {
                attempt_idx,
                round: round + 1,
                ssid: ssid.clone(),
                crowd,
                elapsed: attempt.elapsed,
                ok: attempt.ok,
                timed_out: attempt.timed_out,
                detail: attempt.detail,
            };

            if let Some(writer) = csv_writer.as_mut() {
                write_csv_row(writer, &row)
                    .and_then(|()| writer.flush())
                    .map_err(|e| format!("could not write CSV: {e}"))?;
            }

            rows.push(row);
            attempt_idx += 1;
        }
    }

    let total = overall.elapsed();

    print_report(&rows, total);

    // SSIDs the benchmark actually authenticated, dedup'd, in first-success order.
    let mut succeeded: Vec<String> = Vec::new();
    for row in &rows {
        if row.ok && !succeeded.contains(&row.ssid) {
            succeeded.push(row.ssid.clone());
        }
    }

    finalize(
        opts.leave_disconnected,
        &ssids,
        &succeeded,
        &password,
        delivery,
    );

    Ok(())
}

fn print_banner() {
    eprintln!();
    eprintln!("─────────────────────────────────────────────────────────────────");
    eprintln!("  wifi-scanner · authorized-lab benchmark");
    eprintln!();
    eprintln!("  This tool takes a *known* password and times how long each");
    eprintln!("  allow-listed Wi-Fi network takes to authenticate it.");
    eprintln!();
    eprintln!("  It does NOT discover, guess, or crack passwords, and it");
    eprintln!("  refuses to run without acknowledgement that you own or");
    eprintln!("  administer every network in lab-ssids.txt.");
    eprintln!("─────────────────────────────────────────────────────────────────");
    eprintln!();
}

/// Requires an interactive acknowledgement, or the `--authorized` flag.
fn confirm_authorized() -> Result<(), String> {
    if !io::stdin().is_terminal() {
        return Err(
            "refusing to run without explicit authorization: pass --authorized \
             if you own or administer every network in lab-ssids.txt"
                .to_string(),
        );
    }
    eprintln!(
        "Only continue if you own or are authorized to test every network in the allow-list."
    );
    eprint!("Type exactly `allow` to proceed: ");
    io::stderr().flush().map_err(|e| e.to_string())?;
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    if line.trim() != "allow" {
        return Err("authorization not confirmed; aborting".to_string());
    }
    Ok(())
}

fn shuffle<T>(items: &mut [T]) {
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E37_79B9_7F4A_7C15);
    let mut state = seed | 1;
    for i in (1..items.len()).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let j = (state % (i as u64 + 1)) as usize;
        items.swap(i, j);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shuffle_is_a_permutation() {
        let mut items = vec![1, 2, 3, 4, 5, 6, 7, 8];
        shuffle(&mut items);
        items.sort();
        assert_eq!(items, [1, 2, 3, 4, 5, 6, 7, 8]);
    }
}
