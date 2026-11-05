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
//!   `bench` refuses to run unless you either type `I own these networks`
//!   on an interactive terminal, or pass `--authorized`. It also, by
//!   default, finishes with a connected Wi-Fi interface on a network from
//!   your allow-list and prints the live `nmcli` connection state so it is
//!   unambiguous which network the tool is on. Pass `--leave-disconnected`
//!   to clean up and exit offline instead.
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

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::env;
use std::fs;
use std::fs::File;
use std::io::{self, BufWriter, IsTerminal, Write};
use std::process::ExitCode;
use std::time::{Duration, Instant};

#[cfg(not(target_os = "linux"))]
compile_error!("wifi-scanner now supports Linux only.");

mod linux;
use linux as platform;

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

const SSID_FILE: &str = "lab-ssids.txt";
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(20);

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None | Some("scan") => cmd_scan(),
        Some("bench") => cmd_bench(&args[1..]),
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

// --- scan mode ------------------------------------------------------------

fn cmd_scan() -> ExitCode {
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

// --- bench mode -----------------------------------------------------------

#[derive(Default)]
struct BenchOptions {
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

fn cmd_bench(args: &[String]) -> ExitCode {
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

struct BenchRow {
    attempt_idx: usize,
    round: usize,
    ssid: String,
    crowd: usize,
    elapsed: Duration,
    ok: bool,
    timed_out: bool,
    detail: String,
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

    let first_success_ssid: Option<String> =
        rows.iter().find(|r| r.ok).map(|r| r.ssid.clone());

    if opts.leave_disconnected {
        for row in &rows {
            if row.ok {
                platform::cleanup(&row.ssid);
            }
        }
        print_final_disconnected();
    } else {
        report_final_connection(&ssids, first_success_ssid.as_deref(), &password, delivery);
    }

    Ok(())
}

// --- clarity / safety helpers --------------------------------------------

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
    eprint!("Type exactly `I own these networks` to proceed: ");
    io::stderr().flush().map_err(|e| e.to_string())?;
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    if line.trim() != "I own these networks" {
        return Err("authorization not confirmed; aborting".to_string());
    }
    Ok(())
}

fn print_final_disconnected() {
    println!();
    println!("── Final state ─────────────────────────────────────────────");
    println!("  Cleaned up and left disconnected (--leave-disconnected).");
    println!("────────────────────────────────────────────────────────────");
}

/// Ensures the process ends on an allow-listed network and prints the live
/// `nmcli` connection state, so the tool's final state is unambiguous.
fn report_final_connection(
    ssids: &[String],
    first_success: Option<&str>,
    password: &str,
    delivery: platform::PasswordDelivery,
) {
    println!();
    println!("── Final state ─────────────────────────────────────────────");

    let mut connected_to_allowlisted = false;
    match platform::active_connection() {
        Ok(Some((ssid, device))) => {
            if ssids.iter().any(|s| s == &ssid) {
                println!("  ✔ Connected to authorized lab network: {ssid} (device {device})");
                connected_to_allowlisted = true;
            } else {
                println!("  Connected to {ssid} (device {device}); not in the allow-list.");
            }
        }
        Ok(None) => {}
        Err(e) => println!("  ⚠ Could not read active connection: {e}"),
    }

    if !connected_to_allowlisted {
        if let Some(target) = first_success {
            println!("  Reconnecting to allow-listed `{target}` to leave a clear end state…");
            let attempt = platform::connect(target, password, ATTEMPT_TIMEOUT, delivery);
            if attempt.ok {
                match platform::active_connection() {
                    Ok(Some((ssid, device))) => {
                        println!(
                            "  ✔ Connected to authorized lab network: {ssid} (device {device})"
                        );
                    }
                    _ => println!("  ✔ Reconnected to `{target}` (could not confirm device)"),
                }
            } else {
                println!("  ⚠ Could not reconnect to `{target}`: {}", attempt.detail);
            }
        } else {
            println!("  ⚠ No successful attempt to reconnect to; leaving the connection as-is.");
        }
    }

    println!("────────────────────────────────────────────────────────────");
}

// --- CSV output ----------------------------------------------------------

fn write_csv_row(writer: &mut BufWriter<File>, row: &BenchRow) -> io::Result<()> {
    writeln!(
        writer,
        "{},{},{},{},{:.2},{},{},{}",
        row.attempt_idx,
        row.round,
        csv_escape(&row.ssid),
        row.crowd,
        row.elapsed.as_secs_f64() * 1000.0,
        row.ok,
        row.timed_out,
        csv_escape(&row.detail),
    )
}

fn csv_escape(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

// --- report --------------------------------------------------------------

fn print_report(rows: &[BenchRow], total: Duration) {
    let attempts = rows.len();
    let successes = rows.iter().filter(|r| r.ok).count();
    let timeouts = rows.iter().filter(|r| r.timed_out).count();

    let elapsed_values: Vec<Duration> = rows.iter().map(|r| r.elapsed).collect();
    let median_ms = median(&elapsed_values)
        .map(|d| d.as_secs_f64() * 1000.0)
        .unwrap_or(0.0);
    let p90_ms = percentile(&elapsed_values, 0.90)
        .map(|d| d.as_secs_f64() * 1000.0)
        .unwrap_or(0.0);
    let throughput = attempts as f64 / total.as_secs_f64().max(f64::MIN_POSITIVE);

    println!();
    println!("Attempts:        {attempts}");
    println!("Succeeded:       {successes}");
    println!("Timed out:       {timeouts}");
    println!("Total wall time: {:.2} s", total.as_secs_f64());
    println!("Throughput:      {throughput:.2} attempts/sec");
    println!("Median latency:  {median_ms:.2} ms");
    println!("p90 latency:     {p90_ms:.2} ms");

    if let Some((elapsed, ssid)) = time_to_first_success(rows) {
        println!(
            "Time to first success: {:.2} s (found {ssid})",
            elapsed.as_secs_f64()
        );
    } else {
        println!("Time to first success: never (no attempt succeeded)");
    }

    let mut by_ssid: HashMap<&str, Vec<&BenchRow>> = HashMap::new();
    for row in rows {
        by_ssid.entry(row.ssid.as_str()).or_default().push(row);
    }
    let mut ssids: Vec<&&str> = by_ssid.keys().collect();
    ssids.sort();

    println!();
    println!("Per-network summary:");
    println!(
        "  {:<35} {:>8} {:>8} {:>10} {:>10} {:>8}",
        "SSID", "attempts", "ok", "median ms", "p90 ms", "timeouts"
    );
    for ssid in ssids {
        let group = &by_ssid[*ssid];
        let ok = group.iter().filter(|r| r.ok).count();
        let timeouts = group.iter().filter(|r| r.timed_out).count();
        let mut times: Vec<Duration> = group.iter().map(|r| r.elapsed).collect();
        times.sort();
        let median = median(&times)
            .map(|d| d.as_secs_f64() * 1000.0)
            .unwrap_or(0.0);
        let p90 = percentile(&times, 0.90)
            .map(|d| d.as_secs_f64() * 1000.0)
            .unwrap_or(0.0);
        println!(
            "  {:<35} {:>8} {:>8} {:>10.2} {:>10.2} {:>8}",
            ssid,
            group.len(),
            ok,
            median,
            p90,
            timeouts
        );
    }
}

fn time_to_first_success(rows: &[BenchRow]) -> Option<(Duration, &str)> {
    let mut cumulative = Duration::ZERO;
    for row in rows {
        cumulative += row.elapsed;
        if row.ok {
            return Some((cumulative, &row.ssid));
        }
    }
    None
}

fn median(values: &[Duration]) -> Option<Duration> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort();
    Some(sorted[sorted.len() / 2])
}

fn percentile(values: &[Duration], p: f64) -> Option<Duration> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort();
    let rank = ((sorted.len() - 1) as f64 * p).round() as usize;
    Some(sorted[rank])
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

// --- allow-list and password ---------------------------------------------

fn read_allowlist() -> Result<Vec<String>, String> {
    let path = env::var("LAB_SSID_FILE").unwrap_or_else(|_| SSID_FILE.to_string());
    let text = fs::read_to_string(&path).map_err(|e| {
        format!(
            "could not read {path}: {e}\n\
             Create it with one SSID per line, e.g.:\n  MyLabAP\n  MyLabAP-5G"
        )
    })?;
    let ssids = parse_ssid_file(&text);
    if ssids.is_empty() {
        return Err(format!("{path} lists no SSIDs"));
    }
    Ok(ssids)
}

fn parse_ssid_file(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect()
}

fn prompt_password() -> Result<String, String> {
    if io::stdin().is_terminal() {
        eprintln!("Enter the known lab password (visible as you type):");
        print!("> ");
        io::stdout().flush().map_err(|e| e.to_string())?;
    }
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    let password = line.trim_end_matches(['\r', '\n']).to_string();
    if password.is_empty() {
        return Err("empty password".to_string());
    }
    Ok(password)
}

// --- shared helpers ------------------------------------------------------

fn strongest_per_name(networks: Vec<Network>) -> Vec<Network> {
    let mut strongest: HashMap<String, Network> = HashMap::new();
    for mut network in networks {
        network.ssid = printable_name(&network.ssid);
        if network.ssid.is_empty() {
            continue;
        }
        match strongest.entry(network.ssid.clone()) {
            Entry::Occupied(mut current) => {
                if network.signal > current.get().signal {
                    current.insert(network);
                }
            }
            Entry::Vacant(slot) => {
                slot.insert(network);
            }
        }
    }
    let mut result: Vec<Network> = strongest.into_values().collect();
    result.sort_by(|a, b| b.signal.cmp(&a.signal).then_with(|| a.ssid.cmp(&b.ssid)));
    result
}

fn printable_name(name: &str) -> String {
    name.chars()
        .filter(|c| *c != '\0')
        .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn network(ssid: &str, signal: u8) -> Network {
        Network {
            ssid: ssid.to_string(),
            signal,
            security: "WPA2".to_string(),
        }
    }

    fn names(networks: &[Network]) -> Vec<&str> {
        networks.iter().map(|n| n.ssid.as_str()).collect()
    }

    fn row(ssid: &str, ms: u64, ok: bool) -> BenchRow {
        BenchRow {
            attempt_idx: 0,
            round: 1,
            ssid: ssid.to_string(),
            crowd: 0,
            elapsed: Duration::from_millis(ms),
            ok,
            timed_out: false,
            detail: String::new(),
        }
    }

    #[test]
    fn keeps_the_strongest_access_point_for_each_name() {
        let result = strongest_per_name(vec![
            network("Cafe", 40),
            network("Cafe", 90),
            network("Cafe", 60),
        ]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].signal, 90);
    }

    #[test]
    fn sorts_strongest_first_then_by_name() {
        let result = strongest_per_name(vec![
            network("Weak", 10),
            network("Zed", 80),
            network("Alpha", 80),
        ]);
        assert_eq!(names(&result), ["Alpha", "Zed", "Weak"]);
    }

    #[test]
    fn drops_hidden_networks() {
        let result = strongest_per_name(vec![network("", 90), network("\0\0\0\0", 90)]);
        assert!(result.is_empty());
    }

    #[test]
    fn neutralises_terminal_escape_sequences() {
        assert_eq!(printable_name("\u{1b}[2JCafe\n"), "\u{FFFD}[2JCafe\u{FFFD}");
    }

    #[test]
    fn leaves_spaces_and_non_ascii_alone() {
        assert_eq!(printable_name(" مقهى Café "), " مقهى Café ");
    }

    #[test]
    fn parses_ssid_file_skipping_blanks_and_comments() {
        let text = "# lab APs\n\nMyLabAP\n  MyLabAP-5G  \n#MyLabAP-6G\n";
        assert_eq!(parse_ssid_file(text), ["MyLabAP", "MyLabAP-5G"]);
    }

    #[test]
    fn csv_escape_quotes_special_characters() {
        assert_eq!(csv_escape("plain"), "plain");
        assert_eq!(csv_escape("with,comma"), "\"with,comma\"");
        assert_eq!(csv_escape("with\"quote"), "\"with\"\"quote\"");
        assert_eq!(csv_escape("multi\nline"), "\"multi\nline\"");
    }

    #[test]
    fn median_returns_upper_middle_for_even_lengths() {
        let values = vec![
            Duration::from_millis(400),
            Duration::from_millis(100),
            Duration::from_millis(300),
            Duration::from_millis(200),
        ];
        assert_eq!(median(&values), Some(Duration::from_millis(300)));
    }

    #[test]
    fn percentile_p90_of_ten_values_is_ninth_smallest() {
        let values: Vec<Duration> = (1..=10).map(Duration::from_millis).collect();
        assert_eq!(percentile(&values, 0.9), Some(Duration::from_millis(9)));
    }

    #[test]
    fn shuffle_is_a_permutation() {
        let mut items = vec![1, 2, 3, 4, 5, 6, 7, 8];
        shuffle(&mut items);
        items.sort();
        assert_eq!(items, [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn time_to_first_success_accumulates_until_the_first_ok() {
        let rows = vec![
            row("A", 100, false),
            row("B", 200, true),
            row("C", 300, false),
        ];
        let (elapsed, ssid) = time_to_first_success(&rows).unwrap();
        assert_eq!(elapsed, Duration::from_millis(300));
        assert_eq!(ssid, "B");
    }

    #[test]
    fn time_to_first_success_is_none_when_nothing_succeeds() {
        let rows = vec![row("A", 100, false), row("B", 200, false)];
        assert!(time_to_first_success(&rows).is_none());
    }
}