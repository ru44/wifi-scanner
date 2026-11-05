//! `monitor` mode: re-scan on an interval and watch each AP's signal move
//! over time as a sparkline, flagging access points that appear or vanish.
//! Useful for mapping coverage as you walk, or spotting interference.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io::{self, BufWriter, IsTerminal, Write};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use crate::csv_out::csv_escape;
use crate::interrupt;
use crate::netlist::printable_name;
use crate::platform;
use crate::types::{Band, Network, rssi_label};

/// Samples kept per AP for the sparkline.
const HISTORY: usize = 24;
/// dBm window the sparkline is scaled across.
const DBM_MIN: i32 = -90;
const DBM_MAX: i32 = -30;
const LEVELS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

struct Options {
    interval: Duration,
    rounds: u64,
    csv_path: Option<String>,
}

struct Track {
    ssid: String,
    band: Band,
    channel: u32,
    dbm: i32,
    signal: u8,
    history: VecDeque<i32>,
}

pub(crate) fn cmd_monitor(args: &[String]) -> ExitCode {
    let opts = match parse_args(args) {
        Ok(opts) => opts,
        Err(message) => {
            eprintln!("Error: {message}");
            return ExitCode::FAILURE;
        }
    };
    match run(opts) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("Error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn parse_args(args: &[String]) -> Result<Options, String> {
    let mut interval = 3u64;
    let mut rounds = 0u64; // 0 = run until interrupted
    let mut csv_path = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--interval" => {
                i += 1;
                let v = args.get(i).ok_or("--interval needs a value (seconds)")?;
                interval = v.parse().map_err(|_| format!("invalid --interval: {v}"))?;
                if interval == 0 {
                    return Err("--interval must be at least 1 second".to_string());
                }
            }
            "--rounds" => {
                i += 1;
                let v = args.get(i).ok_or("--rounds needs a value")?;
                rounds = v.parse().map_err(|_| format!("invalid --rounds: {v}"))?;
            }
            "--csv" => {
                i += 1;
                csv_path = Some(args.get(i).ok_or("--csv needs a path")?.clone());
            }
            other => return Err(format!("unknown monitor option: {other}")),
        }
        i += 1;
    }
    Ok(Options {
        interval: Duration::from_secs(interval),
        rounds,
        csv_path,
    })
}

fn run(opts: Options) -> Result<(), String> {
    let mut tracks: HashMap<String, Track> = HashMap::new();
    let mut previous: HashSet<String> = HashSet::new();

    let mut csv = match &opts.csv_path {
        Some(path) => {
            let file = File::create(path).map_err(|e| format!("could not create {path}: {e}"))?;
            let mut w = BufWriter::new(file);
            writeln!(w, "round,bssid,ssid,band,channel,signal_dbm,signal_pct")
                .map_err(|e| format!("could not write CSV header: {e}"))?;
            Some(w)
        }
        None => None,
    };

    // Ctrl-C stops the loop after the current round rather than killing the
    // process mid-render; a second Ctrl-C force-quits.
    interrupt::install();
    let started = Instant::now();

    let mut round = 0u64;
    loop {
        round += 1;

        let mut networks = match platform::scan() {
            Ok(networks) => networks,
            // A scan interrupted by Ctrl-C is a clean stop, not an error.
            Err(_) if interrupt::interrupted() => break,
            Err(message) => return Err(message),
        };
        for n in &mut networks {
            n.ssid = printable_name(&n.ssid);
        }

        let current: HashSet<String> = networks.iter().map(|n| n.bssid.clone()).collect();
        let appeared: Vec<&Network> = networks
            .iter()
            .filter(|n| !previous.is_empty() && !previous.contains(&n.bssid))
            .collect();
        let vanished: Vec<String> = previous.difference(&current).cloned().collect();

        for n in &networks {
            update_track(&mut tracks, n);
            if let Some(w) = csv.as_mut() {
                write_csv(w, round, n).map_err(|e| format!("could not write CSV: {e}"))?;
            }
        }
        if let Some(w) = csv.as_mut() {
            w.flush().map_err(|e| format!("could not flush CSV: {e}"))?;
        }

        render(round, &opts, &networks, &tracks, &appeared, &vanished);

        previous = current;
        if interrupt::interrupted() {
            break;
        }
        if opts.rounds != 0 && round >= opts.rounds {
            break;
        }
        interrupt::sleep_or_interrupt(opts.interval);
        if interrupt::interrupted() {
            break;
        }
    }

    print_summary(round, started.elapsed(), tracks.len(), &opts);
    Ok(())
}

fn print_summary(rounds: u64, elapsed: Duration, aps_seen: usize, opts: &Options) {
    println!();
    if interrupt::interrupted() {
        println!(
            "Stopped (Ctrl-C) after {rounds} round(s) over {}s; {aps_seen} access point(s) seen.",
            elapsed.as_secs()
        );
    } else {
        println!(
            "Done: {rounds} round(s) over {}s; {aps_seen} access point(s) seen.",
            elapsed.as_secs()
        );
    }
    if let Some(path) = &opts.csv_path {
        println!("Samples written to {path}.");
    }
}

fn update_track(tracks: &mut HashMap<String, Track>, n: &Network) {
    let dbm = n.approx_dbm();
    let track = tracks.entry(n.bssid.clone()).or_insert_with(|| Track {
        ssid: n.ssid.clone(),
        band: n.band(),
        channel: n.channel,
        dbm,
        signal: n.signal,
        history: VecDeque::with_capacity(HISTORY),
    });
    track.ssid = n.ssid.clone();
    track.band = n.band();
    track.channel = n.channel;
    track.dbm = dbm;
    track.signal = n.signal;
    if track.history.len() == HISTORY {
        track.history.pop_front();
    }
    track.history.push_back(dbm);
}

fn render(
    round: u64,
    opts: &Options,
    networks: &[Network],
    tracks: &HashMap<String, Track>,
    appeared: &[&Network],
    vanished: &[String],
) {
    let interactive = io::stdout().is_terminal();
    if interactive {
        // Clear screen and move cursor home for an in-place live view.
        print!("\x1b[2J\x1b[H");
    }

    let stop = if opts.rounds == 0 {
        "Ctrl-C to stop (again to force)".to_string()
    } else {
        format!("round {round}/{}", opts.rounds)
    };
    println!(
        "wifi-scanner monitor · {} AP(s) · every {}s · {}",
        networks.len(),
        opts.interval.as_secs(),
        stop,
    );
    println!(
        "{:<28} {:<7} {:>4} {:>8}  {:<24} {}",
        "SSID", "Band", "Chan", "Signal", "Trend", "Quality"
    );

    let mut rows: Vec<&Track> = networks
        .iter()
        .filter_map(|n| tracks.get(&n.bssid))
        .collect();
    rows.sort_by(|a, b| b.dbm.cmp(&a.dbm));

    for t in rows {
        println!(
            "{:<28} {:<7} {:>4} {:>5} dBm  {:<24} {}",
            trunc(&t.ssid, 28),
            t.band.label(),
            t.channel,
            t.dbm,
            sparkline(&t.history),
            rssi_label(t.dbm),
        );
    }

    for n in appeared {
        println!("  + appeared: {} ({} dBm, {})", n.ssid, n.approx_dbm(), n.band().label());
    }
    for bssid in vanished {
        println!("  - vanished: {bssid}");
    }
}

fn sparkline(history: &VecDeque<i32>) -> String {
    history
        .iter()
        .map(|&dbm| {
            let clamped = dbm.clamp(DBM_MIN, DBM_MAX);
            let span = (DBM_MAX - DBM_MIN) as f64;
            let idx = ((clamped - DBM_MIN) as f64 / span * (LEVELS.len() - 1) as f64).round();
            LEVELS[idx as usize]
        })
        .collect()
}

fn write_csv(w: &mut BufWriter<File>, round: u64, n: &Network) -> io::Result<()> {
    writeln!(
        w,
        "{},{},{},{},{},{},{}",
        round,
        csv_escape(&n.bssid),
        csv_escape(&n.ssid),
        csv_escape(n.band().label()),
        n.channel,
        n.approx_dbm(),
        n.signal,
    )
}

fn trunc(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparkline_scales_across_the_window() {
        let mut h = VecDeque::new();
        h.push_back(-90); // floor -> lowest
        h.push_back(-30); // ceiling -> highest
        h.push_back(-200); // below floor, clamps
        let s: Vec<char> = sparkline(&h).chars().collect();
        assert_eq!(s[0], '▁');
        assert_eq!(s[1], '█');
        assert_eq!(s[2], '▁');
    }
}
