//! The end-of-run report and the summary statistics behind it.

use std::collections::HashMap;
use std::time::Duration;

use crate::types::BenchRow;

pub(crate) fn print_report(rows: &[BenchRow], total: Duration) {
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

#[cfg(test)]
mod tests {
    use super::*;

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
