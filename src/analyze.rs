//! `analyze` mode: turn one scan into a picture of the airspace — band split,
//! channel congestion, security posture, and roaming (multi-AP) networks.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::process::ExitCode;

use crate::json;
use crate::netlist::printable_name;
use crate::platform;
use crate::types::{Band, Network};

/// Non-overlapping 2.4 GHz channels; a scan is busiest around these.
const CLEAN_24: [u32; 3] = [1, 6, 11];

pub(crate) fn cmd_analyze(args: &[String]) -> ExitCode {
    let mut as_json = false;
    for arg in args {
        match arg.as_str() {
            "--json" => as_json = true,
            other => {
                eprintln!("Error: unknown analyze option: {other}");
                return ExitCode::FAILURE;
            }
        }
    }

    if !as_json {
        eprintln!("Scanning and analyzing the airspace...");
    }

    let mut networks = match platform::scan() {
        Ok(networks) => networks,
        Err(message) => {
            eprintln!("Error: {message}");
            return ExitCode::FAILURE;
        }
    };
    for n in &mut networks {
        n.ssid = printable_name(&n.ssid);
    }

    if networks.is_empty() {
        if as_json {
            println!("{{\"ap_count\": 0}}");
        } else {
            println!("No access points visible. Is Wi-Fi turned on?");
        }
        return ExitCode::SUCCESS;
    }

    if as_json {
        print_json(&networks);
    } else {
        print_report(&networks);
    }
    ExitCode::SUCCESS
}

// --- computations --------------------------------------------------------

fn band_counts(networks: &[Network]) -> BTreeMap<Band, usize> {
    let mut counts = BTreeMap::new();
    for n in networks {
        *counts.entry(n.band()).or_insert(0) += 1;
    }
    counts
}

fn channel_counts(networks: &[Network], band: Band) -> BTreeMap<u32, usize> {
    let mut counts = BTreeMap::new();
    for n in networks.iter().filter(|n| n.band() == band && n.channel > 0) {
        *counts.entry(n.channel).or_insert(0) += 1;
    }
    counts
}

/// Best of channels 1/6/11, counting any AP within ±4 channels as overlapping
/// load. Ties go to the lower channel. `None` if nothing is on 2.4 GHz.
fn recommend_24(networks: &[Network]) -> Option<u32> {
    if !networks.iter().any(|n| n.band() == Band::TwoFour) {
        return None;
    }
    CLEAN_24
        .iter()
        .min_by_key(|&&c| overlap_load(networks, c))
        .copied()
}

fn overlap_load(networks: &[Network], channel: u32) -> usize {
    networks
        .iter()
        .filter(|n| n.band() == Band::TwoFour && n.channel > 0)
        .filter(|n| n.channel.abs_diff(channel) <= 4)
        .count()
}

#[derive(Default)]
struct Posture {
    open: usize,
    wep: usize,
    wpa1: usize,
    wpa2: usize,
    wpa3: usize,
    enterprise: usize,
}

fn posture(networks: &[Network]) -> Posture {
    let mut p = Posture::default();
    for n in networks {
        let s = n.security.as_str();
        if s == "Open" {
            p.open += 1;
        }
        if s.contains("WEP") {
            p.wep += 1;
        }
        if s.contains("WPA3") || s.contains("SAE") {
            p.wpa3 += 1;
        }
        if s.contains("WPA2") {
            p.wpa2 += 1;
        }
        if s.contains("WPA1") {
            p.wpa1 += 1;
        }
        if s.contains("802.1X") {
            p.enterprise += 1;
        }
    }
    p
}

/// SSIDs seen on more than one BSSID, with a "band chN" tag per radio.
fn roaming(networks: &[Network]) -> Vec<(String, Vec<String>)> {
    let mut by_name: HashMap<&str, Vec<&Network>> = HashMap::new();
    for n in networks {
        if !n.ssid.is_empty() {
            by_name.entry(n.ssid.as_str()).or_default().push(n);
        }
    }
    let mut groups: Vec<(String, Vec<String>)> = by_name
        .into_iter()
        .filter_map(|(ssid, mut aps)| {
            let distinct: std::collections::HashSet<&str> =
                aps.iter().map(|n| n.bssid.as_str()).collect();
            if distinct.len() < 2 {
                return None;
            }
            aps.sort_by(|a, b| a.freq_mhz.cmp(&b.freq_mhz).then(a.channel.cmp(&b.channel)));
            let placements = aps
                .iter()
                .map(|n| format!("{} ch{}", n.band().label(), n.channel))
                .collect();
            Some((ssid.to_string(), placements))
        })
        .collect();
    groups.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(&b.0)));
    groups
}

fn distinct_ssids(networks: &[Network]) -> usize {
    networks
        .iter()
        .filter(|n| !n.ssid.is_empty())
        .map(|n| n.ssid.as_str())
        .collect::<std::collections::HashSet<_>>()
        .len()
}

// --- text report ---------------------------------------------------------

fn print_report(networks: &[Network]) {
    println!();
    println!("══ Airspace analysis ═══════════════════════════════════════");
    println!(
        "{} access points · {} distinct network name(s)",
        networks.len(),
        distinct_ssids(networks),
    );

    println!("\nBands in use:");
    for (band, count) in band_counts(networks) {
        println!("  {:<8} {:>3}  {}", band.label(), count, bar(count));
    }

    print_channels(networks, Band::TwoFour, "2.4 GHz");
    if let Some(ch) = recommend_24(networks) {
        println!(
            "  → Least-congested 2.4 GHz channel: {ch} (of the non-overlapping 1/6/11).",
        );
    }
    print_channels(networks, Band::Five, "5 GHz");
    print_channels(networks, Band::Six, "6 GHz");

    print_posture(networks);
    print_roaming(networks);
    println!("════════════════════════════════════════════════════════════");
}

fn print_channels(networks: &[Network], band: Band, title: &str) {
    let counts = channel_counts(networks, band);
    if counts.is_empty() {
        return;
    }
    println!("\nChannel use on {title}:");
    for (channel, count) in counts {
        println!("  ch{:>3}  {:>2}  {}", channel, count, bar(count));
    }
}

fn print_posture(networks: &[Network]) {
    let p = posture(networks);
    let modern = p.wpa2 + p.wpa3;
    println!("\nSecurity posture:");
    print_posture_line("WPA3 (SAE)", p.wpa3, "");
    print_posture_line("WPA2", p.wpa2, "");
    print_posture_line("WPA (WPA1)", p.wpa1, if p.wpa1 > 0 { "⚠ legacy" } else { "" });
    print_posture_line("Enterprise (802.1X)", p.enterprise, "needs a username too");
    print_posture_line("WEP", p.wep, if p.wep > 0 { "⚠ broken, avoid" } else { "" });
    print_posture_line("Open", p.open, if p.open > 0 { "⚠ no encryption" } else { "" });
    println!(
        "  {modern} of {} AP(s) use modern encryption (WPA2/WPA3).",
        networks.len()
    );
}

fn print_posture_line(label: &str, count: usize, note: &str) {
    if note.is_empty() {
        println!("  {label:<22} {count:>3}");
    } else {
        println!("  {label:<22} {count:>3}   {note}");
    }
}

fn print_roaming(networks: &[Network]) {
    let groups = roaming(networks);
    if groups.is_empty() {
        return;
    }
    println!("\nRoaming / multi-AP networks (one name, several radios):");
    for (ssid, placements) in groups {
        println!(
            "  {:<28} {} radios · {}",
            trunc(&ssid, 28),
            placements.len(),
            placements.join(", "),
        );
    }
}

fn bar(count: usize) -> String {
    "█".repeat(count.min(40))
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

// --- json report ---------------------------------------------------------

fn print_json(networks: &[Network]) {
    let bands: Vec<String> = band_counts(networks)
        .into_iter()
        .map(|(b, c)| format!("{}: {}", json::quote(b.label()), c))
        .collect();

    let mut channels: Vec<String> = Vec::new();
    for band in [Band::TwoFour, Band::Five, Band::Six] {
        for (channel, count) in channel_counts(networks, band) {
            channels.push(format!(
                "{{\"band\": {}, \"channel\": {}, \"count\": {}}}",
                json::quote(band.label()),
                channel,
                count
            ));
        }
    }

    let p = posture(networks);
    let roaming_json: Vec<String> = roaming(networks)
        .into_iter()
        .map(|(ssid, placements)| {
            let places: Vec<String> = placements.iter().map(|s| json::quote(s)).collect();
            format!(
                "{{\"ssid\": {}, \"radios\": {}, \"placements\": [{}]}}",
                json::quote(&ssid),
                placements.len(),
                places.join(", ")
            )
        })
        .collect();

    println!("{{");
    println!("  \"ap_count\": {},", networks.len());
    println!("  \"ssid_count\": {},", distinct_ssids(networks));
    println!("  \"bands\": {{{}}},", bands.join(", "));
    println!("  \"channels\": [{}],", channels.join(", "));
    println!(
        "  \"recommended_24ghz_channel\": {},",
        json::num(recommend_24(networks))
    );
    println!(
        "  \"security\": {{\"open\": {}, \"wep\": {}, \"wpa1\": {}, \"wpa2\": {}, \
         \"wpa3\": {}, \"enterprise\": {}}},",
        p.open, p.wep, p.wpa1, p.wpa2, p.wpa3, p.enterprise
    );
    println!("  \"roaming\": [{}]", roaming_json.join(", "));
    println!("}}");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(ssid: &str, bssid: &str, channel: u32, freq: u32, security: &str) -> Network {
        Network {
            ssid: ssid.to_string(),
            bssid: bssid.to_string(),
            signal: 60,
            security: security.to_string(),
            mode: "Infra".to_string(),
            channel,
            freq_mhz: freq,
            bandwidth_mhz: 20,
            rate_mbps: 0,
        }
    }

    fn sample() -> Vec<Network> {
        vec![
            net("A", "aa", 1, 2412, "WPA2"),
            net("A", "bb", 11, 2462, "WPA2"),       // A roams: 2 radios
            net("B", "cc", 6, 2437, "Open"),
            net("C", "dd", 6, 2437, "WPA2 WPA3"),
            net("D", "ee", 36, 5180, "WPA2 802.1X"),
        ]
    }

    #[test]
    fn counts_bands() {
        let counts = band_counts(&sample());
        assert_eq!(counts[&Band::TwoFour], 4);
        assert_eq!(counts[&Band::Five], 1);
    }

    #[test]
    fn recommends_the_clearest_24_channel() {
        // ch1 has 1 AP nearby, ch6 has 2, ch11 has 1 -> ties on 1 and 11,
        // lower wins -> channel 1.
        assert_eq!(recommend_24(&sample()), Some(1));
    }

    #[test]
    fn posture_classifies_each_mode() {
        let p = posture(&sample());
        assert_eq!(p.open, 1);
        assert_eq!(p.wpa2, 4); // both A radios, C, and D all advertise WPA2
        assert_eq!(p.wpa3, 1);
        assert_eq!(p.enterprise, 1);
        assert_eq!(p.wep, 0);
    }

    #[test]
    fn roaming_finds_multi_bssid_names() {
        let groups = roaming(&sample());
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].0, "A");
        assert_eq!(groups[0].1.len(), 2);
    }

    #[test]
    fn distinct_ssids_ignores_duplicates() {
        assert_eq!(distinct_ssids(&sample()), 4);
    }
}
