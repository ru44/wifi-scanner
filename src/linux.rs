//! Linux backend: asks NetworkManager through `nmcli`, and reads live link
//! health through `iw`.

use std::io::{ErrorKind, Write};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::types::{Attempt, LinkInfo, Network};

/// How the password reaches nmcli. `Stdin` (via `--ask`) keeps it off argv;
/// `Argv` is the legacy path, visible to `ps` and in journald.
#[derive(Copy, Clone)]
pub enum PasswordDelivery {
    Stdin,
    Argv,
}

/// Fields requested from `nmcli dev wifi list`, in the order parsed below.
const SCAN_FIELDS: &str = "SSID,BSSID,MODE,CHAN,FREQ,BANDWIDTH,RATE,SIGNAL,SECURITY";

pub fn scan() -> Result<Vec<Network>, String> {
    // NetworkManager refuses a forced rescan right after another scan, and may
    // refuse it by policy. Its cached list is still good enough, so fall back.
    let mut output = nmcli_list("yes")?;
    if !output.status.success() {
        output = nmcli_list("auto")?;
    }
    if !output.status.success() {
        let reason = String::from_utf8_lossy(&output.stderr);
        let reason = reason.trim().trim_start_matches("Error: ");
        return Err(format!("nmcli failed: {reason}"));
    }
    Ok(parse(&String::from_utf8_lossy(&output.stdout)))
}

fn nmcli_list(rescan: &str) -> Result<Output, String> {
    Command::new("nmcli")
        .args(["-t", "-f", SCAN_FIELDS])
        .args(["dev", "wifi", "list", "--rescan", rescan])
        .output()
        .map_err(map_spawn_error)
}

/// Number of access points in nmcli's cached list. Never triggers a scan, so
/// it is cheap enough to call before every attempt; the cache is refreshed by
/// the connect attempt itself.
pub fn crowd() -> Result<usize, String> {
    let output = Command::new("nmcli")
        .args(["-t", "-f", "SSID", "dev", "wifi", "list", "--rescan", "no"])
        .output()
        .map_err(map_spawn_error)?;
    if !output.status.success() {
        let reason = String::from_utf8_lossy(&output.stderr);
        return Err(format!("nmcli failed: {}", reason.trim()));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.is_empty())
        .count())
}

/// Returns (connection name, device) for the first active Wi-Fi connection,
/// if any.
pub fn active_connection() -> Result<Option<(String, String)>, String> {
    let output = Command::new("nmcli")
        .args([
            "-t",
            "-f",
            "NAME,TYPE,DEVICE",
            "connection",
            "show",
            "--active",
        ])
        .output()
        .map_err(map_spawn_error)?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(parse_active))
}

fn parse_active(line: &str) -> Option<(String, String)> {
    let fields = split_fields(line);
    if fields.len() >= 3 && fields[1] == "802-11-wireless" {
        Some((fields[0].clone(), fields[2].clone()))
    } else {
        None
    }
}

/// Best-effort tear-down of any connection and profile named after `ssid`.
/// Called before each attempt so nmcli prompts for the password again, and
/// at the end so we do not leave a stored profile behind for networks the
/// benchmark did not authenticate.
pub fn cleanup(ssid: &str) {
    // nmcli refuses to delete an active profile, so bring it down first.
    let _ = Command::new("nmcli")
        .args(["connection", "down", "id", ssid])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let _ = Command::new("nmcli")
        .args(["connection", "delete", "id", ssid])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// One timed connection attempt against `ssid`.
pub fn connect(
    ssid: &str,
    password: &str,
    timeout: Duration,
    delivery: PasswordDelivery,
) -> Attempt {
    let start = Instant::now();
    let result = match delivery {
        PasswordDelivery::Stdin => try_connect_stdin(ssid, password, timeout),
        PasswordDelivery::Argv => try_connect_argv(ssid, password, timeout),
    };
    match result {
        Ok(output) => Attempt {
            ok: output.status.success(),
            elapsed: start.elapsed(),
            detail: summarize(&output),
            timed_out: false,
        },
        Err(error) => Attempt {
            ok: false,
            elapsed: start.elapsed(),
            timed_out: error.starts_with("timed out"),
            detail: error,
        },
    }
}

fn try_connect_stdin(ssid: &str, password: &str, timeout: Duration) -> Result<Output, String> {
    let mut cmd = Command::new("nmcli");
    cmd.args(["--ask", "device", "wifi", "connect", ssid]);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(map_spawn_error)?;

    // Feed the password on stdin. Ignore write errors: nmcli may already have
    // consumed what it needs, or exited; wait_with_timeout surfaces real
    // failures.
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(password.as_bytes());
        let _ = stdin.write_all(b"\n");
        // stdin dropped here, closing the pipe.
    }

    wait_with_timeout(child, timeout)
}

fn try_connect_argv(ssid: &str, password: &str, timeout: Duration) -> Result<Output, String> {
    let mut cmd = Command::new("nmcli");
    cmd.args(["device", "wifi", "connect", ssid, "password", password]);
    // Keep nmcli from inheriting stdin and blocking on a polkit prompt.
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = cmd.spawn().map_err(map_spawn_error)?;
    wait_with_timeout(child, timeout)
}

fn map_spawn_error(error: std::io::Error) -> String {
    match error.kind() {
        ErrorKind::NotFound => {
            "nmcli was not found. On Linux this tool needs NetworkManager.".to_string()
        }
        _ => format!("could not run nmcli: {error}"),
    }
}

fn summarize(output: &Output) -> String {
    let text = if output.status.success() {
        String::from_utf8_lossy(&output.stdout).into_owned()
    } else {
        String::from_utf8_lossy(&output.stderr).into_owned()
    };
    summarize_text(&text)
}

fn summarize_text(text: &str) -> String {
    text.lines()
        .map(strip_ask_prompt)
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("")
        .to_string()
}

/// `nmcli --ask` writes "Password (key): " to stderr without a trailing
/// newline, so the prompt and the first error share a line. Strip the prompt
/// so CSV consumers see just the message.
fn strip_ask_prompt(line: &str) -> &str {
    if line.starts_with("Password (") {
        if let Some(idx) = line.find("): ") {
            return &line[idx + 3..];
        }
    }
    line
}

/// Spawns the command and kills it if it outlives `timeout`. `nmcli` can hang
/// on a polkit prompt or a stuck association, and a benchmark must not hang.
///
/// nmcli's output is a couple of lines, so the pipe buffer will not fill
/// before it exits and a `try_wait` poll loop is safe here.
fn wait_with_timeout(mut child: Child, timeout: Duration) -> Result<Output, String> {
    let start = Instant::now();
    loop {
        match child
            .try_wait()
            .map_err(|e| format!("could not wait for nmcli: {e}"))?
        {
            Some(_) => break,
            None => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("timed out after {}s", timeout.as_secs()));
                }
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
    child
        .wait_with_output()
        .map_err(|e| format!("could not read nmcli output: {e}"))
}

// --- scan parsing --------------------------------------------------------

fn parse(output: &str) -> Vec<Network> {
    output.lines().filter_map(parse_line).collect()
}

fn parse_line(line: &str) -> Option<Network> {
    let fields = split_fields(line);
    let [ssid, bssid, mode, chan, freq, bandwidth, rate, signal, security] = fields.as_slice()
    else {
        return None;
    };
    Some(Network {
        ssid: ssid.clone(),
        bssid: bssid.clone(),
        mode: mode.clone(),
        channel: chan.parse().unwrap_or(0),
        freq_mhz: leading_u32(freq),
        bandwidth_mhz: leading_u32(bandwidth),
        rate_mbps: leading_u32(rate),
        signal: signal.parse().ok()?,
        security: if security.is_empty() {
            "Open".to_string()
        } else {
            security.clone()
        },
    })
}

/// First whitespace-separated integer in `s` (e.g. "2437 MHz" -> 2437).
fn leading_u32(s: &str) -> u32 {
    s.split_whitespace()
        .next()
        .and_then(|t| t.parse().ok())
        .unwrap_or(0)
}

fn split_fields(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => field.extend(chars.next()),
            ':' => fields.push(std::mem::take(&mut field)),
            _ => field.push(c),
        }
    }
    fields.push(field);
    fields
}

// --- live link health (iw) ----------------------------------------------

/// First `managed` (station-mode) Wi-Fi interface reported by `iw dev`.
pub fn wifi_device() -> Option<String> {
    let output = Command::new("iw").arg("dev").output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(parse_wifi_device(&String::from_utf8_lossy(&output.stdout))?)
}

fn parse_wifi_device(text: &str) -> Option<String> {
    let mut current: Option<String> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed.strip_prefix("Interface ") {
            current = Some(name.trim().to_string());
        } else if trimmed == "type managed" {
            if let Some(name) = current.take() {
                return Some(name);
            }
        }
    }
    None
}

/// Best-effort health snapshot of the active link. `None` means no Wi-Fi
/// device, or the device is not currently associated.
pub fn link_info() -> Option<LinkInfo> {
    let device = wifi_device()?;

    let link = iw(&device, &["link"])?;
    if link.trim_start().starts_with("Not connected") {
        return None;
    }

    let mut info = LinkInfo {
        device: device.clone(),
        ..LinkInfo::default()
    };
    parse_iw_link(&link, &mut info);

    if let Some(text) = iw(&device, &["info"]) {
        parse_iw_info(&text, &mut info);
    }
    if let Some(text) = iw(&device, &["station", "dump"]) {
        parse_station_dump(&text, &mut info);
    }
    Some(info)
}

fn iw(device: &str, args: &[&str]) -> Option<String> {
    let output = Command::new("iw")
        .arg("dev")
        .arg(device)
        .args(args)
        .output()
        .ok()?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        None
    }
}

fn parse_iw_link(text: &str, info: &mut LinkInfo) {
    if let Some(first) = text.lines().next() {
        // "Connected to aa:bb:.. (on wlp0s20f3)"
        info.bssid = first
            .trim()
            .strip_prefix("Connected to ")
            .and_then(|rest| rest.split_whitespace().next())
            .map(str::to_string);
    }
    for line in text.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("SSID:") {
            info.ssid = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("freq:") {
            info.freq_mhz = v.trim().split('.').next().and_then(|t| t.parse().ok());
        } else if let Some(v) = line.strip_prefix("signal:") {
            info.signal_dbm = leading_i32(v.trim());
        } else if let Some(v) = line.strip_prefix("rx bitrate:") {
            let v = v.trim().to_string();
            info.phy = info.phy.or_else(|| phy_generation(&v));
            info.rx_bitrate = Some(v);
        } else if let Some(v) = line.strip_prefix("tx bitrate:") {
            let v = v.trim().to_string();
            info.phy = info.phy.or_else(|| phy_generation(&v));
            info.tx_bitrate = Some(v);
        }
    }
}

fn parse_iw_info(text: &str, info: &mut LinkInfo) {
    for line in text.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("channel ") {
            // "112 (5560 MHz), width: 80 MHz, center1: 5530 MHz"
            info.channel = leading_u32_opt(v);
            if let Some(w) = v.split("width:").nth(1) {
                info.width_mhz = leading_u32_opt(w.trim());
            }
        } else if let Some(v) = line.strip_prefix("txpower ") {
            info.txpower_dbm = v.trim().split_whitespace().next().and_then(|t| t.parse().ok());
        }
    }
}

fn parse_station_dump(text: &str, info: &mut LinkInfo) {
    for line in text.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("tx packets:") {
            info.tx_packets = v.trim().parse().ok();
        } else if let Some(v) = line.strip_prefix("tx retries:") {
            info.tx_retries = v.trim().parse().ok();
        } else if let Some(v) = line.strip_prefix("beacon loss:") {
            info.beacon_loss = v.trim().parse().ok();
        } else if info.signal_dbm.is_none() {
            if let Some(v) = line.strip_prefix("signal avg:") {
                info.signal_dbm = leading_i32(v.trim());
            }
        }
    }
}

/// Maps an `iw` bitrate line to a Wi-Fi generation by its modulation token.
/// `iw` tags the rate with the modulation: `EHT-MCS` (be), `HE-MCS` (ax),
/// `VHT-MCS` (ac), a bare `MCS` (n), or nothing at all (legacy a/b/g).
fn phy_generation(bitrate_line: &str) -> Option<&'static str> {
    if bitrate_line.contains("EHT") {
        Some("Wi-Fi 7 (802.11be)")
    } else if bitrate_line.contains("HE") {
        Some("Wi-Fi 6 (802.11ax)")
    } else if bitrate_line.contains("VHT") {
        Some("Wi-Fi 5 (802.11ac)")
    } else if bitrate_line.contains("MCS") {
        Some("Wi-Fi 4 (802.11n)")
    } else {
        None
    }
}

fn leading_i32(s: &str) -> Option<i32> {
    s.split_whitespace().next().and_then(|t| t.parse().ok())
}

fn leading_u32_opt(s: &str) -> Option<u32> {
    s.split_whitespace().next().and_then(|t| t.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(line: &str) -> Network {
        parse_line(line).expect("line should parse")
    }

    const RICH: &str =
        r"Cafe Guest:AA\:BB\:CC\:DD\:EE\:FF:Infra:6:2437 MHz:20 MHz:130 Mbit/s:72:WPA2";

    #[test]
    fn reads_a_full_line() {
        let n = one(RICH);
        assert_eq!(n.ssid, "Cafe Guest");
        assert_eq!(n.bssid, "AA:BB:CC:DD:EE:FF");
        assert_eq!(n.mode, "Infra");
        assert_eq!(n.channel, 6);
        assert_eq!(n.freq_mhz, 2437);
        assert_eq!(n.band(), crate::types::Band::TwoFour);
        assert_eq!(n.bandwidth_mhz, 20);
        assert_eq!(n.rate_mbps, 130);
        assert_eq!(n.signal, 72);
        assert_eq!(n.security, "WPA2");
    }

    #[test]
    fn reads_a_5ghz_line() {
        let n = one(r"ZAIN5G:30\:AA\:BB\:CC\:DC\:0E:Infra:112:5560 MHz:80 MHz:1170 Mbit/s:51:WPA2");
        assert_eq!(n.channel, 112);
        assert_eq!(n.freq_mhz, 5560);
        assert_eq!(n.band(), crate::types::Band::Five);
        assert_eq!(n.bandwidth_mhz, 80);
    }

    #[test]
    fn keeps_escaped_colons_in_the_name() {
        assert_eq!(
            one(r"Cafe\:Guest:AA\:BB\:CC\:DD\:EE\:FF:Infra:6:2437 MHz:20 MHz:130 Mbit/s:72:WPA2")
                .ssid,
            "Cafe:Guest"
        );
    }

    #[test]
    fn keeps_non_ascii_names() {
        assert_eq!(
            one(r"مقهى:AA\:BB\:CC\:DD\:EE\:FF:Infra:6:2437 MHz:20 MHz:130 Mbit/s:72:WPA2").ssid,
            "مقهى"
        );
    }

    #[test]
    fn empty_security_means_open() {
        assert_eq!(
            one(r"Free:AA\:BB\:CC\:DD\:EE\:FF:Infra:6:2437 MHz:20 MHz:65 Mbit/s:72:").security,
            "Open"
        );
    }

    #[test]
    fn keeps_multiple_security_modes() {
        assert_eq!(
            one(r"Cafe:AA\:BB\:CC\:DD\:EE\:FF:Infra:6:2437 MHz:20 MHz:65 Mbit/s:72:WPA2 WPA3")
                .security,
            "WPA2 WPA3"
        );
    }

    #[test]
    fn skips_malformed_lines() {
        assert!(parse_line("").is_none());
        assert!(parse_line("only-a-name").is_none());
        assert!(parse_line("too:few:fields").is_none());
        assert!(
            parse_line(r"Cafe:AA\:BB:Infra:x:2437 MHz:20 MHz:65 Mbit/s:not-a-number:WPA2").is_none()
        );
    }

    #[test]
    fn strips_ask_prompt_from_summary() {
        let text = "Password (802-11-wireless-security.psk): Error: Connection activation failed\n";
        assert_eq!(summarize_text(text), "Error: Connection activation failed");
    }

    #[test]
    fn summary_skips_a_prompt_only_line() {
        let text = "Password (802-11-wireless-security.psk): \nError: nope\n";
        assert_eq!(summarize_text(text), "Error: nope");
    }

    #[test]
    fn summary_passes_through_plain_text() {
        assert_eq!(
            summarize_text("Device 'wlan0' successfully activated.\n"),
            "Device 'wlan0' successfully activated."
        );
    }

    #[test]
    fn parse_active_picks_first_wifi_connection() {
        assert_eq!(
            parse_active("MyLabAP:802-11-wireless:wlan0"),
            Some(("MyLabAP".to_string(), "wlan0".to_string()))
        );
    }

    #[test]
    fn parse_active_ignores_non_wifi_lines() {
        assert_eq!(parse_active("eth0:802-3-ethernet:enp3s0"), None);
        assert_eq!(parse_active("too:few"), None);
    }

    #[test]
    fn finds_managed_interface() {
        let text = "phy#2\n\tUnnamed/non-netdev interface\n\t\ttype P2P-device\n\
                    \tInterface wlp0s20f3\n\t\tifindex 69\n\t\ttype managed\n";
        assert_eq!(parse_wifi_device(text), Some("wlp0s20f3".to_string()));
    }

    #[test]
    fn parses_iw_link_block() {
        let text = "Connected to aa:bb:cc:dd:ee:ff (on wlp0s20f3)\n\
                    \tSSID: ZAIN5G_4EDC10\n\tfreq: 5560.0\n\tsignal: -70 dBm\n\
                    \trx bitrate: 324.2 MBit/s 80MHz HE-MCS 6 HE-NSS 1\n\
                    \ttx bitrate: 432.3 MBit/s 80MHz HE-MCS 4 HE-NSS 2\n";
        let mut info = LinkInfo::default();
        parse_iw_link(text, &mut info);
        assert_eq!(info.bssid.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(info.ssid.as_deref(), Some("ZAIN5G_4EDC10"));
        assert_eq!(info.freq_mhz, Some(5560));
        assert_eq!(info.signal_dbm, Some(-70));
        assert_eq!(info.phy, Some("Wi-Fi 6 (802.11ax)"));
        assert!(info.tx_bitrate.as_deref().unwrap().starts_with("432.3"));
    }

    #[test]
    fn parses_iw_info_channel_and_power() {
        let text = "Interface wlp0s20f3\n\ttype managed\n\
                    \tchannel 112 (5560 MHz), width: 80 MHz, center1: 5530 MHz\n\
                    \ttxpower 22.00 dBm\n";
        let mut info = LinkInfo::default();
        parse_iw_info(text, &mut info);
        assert_eq!(info.channel, Some(112));
        assert_eq!(info.width_mhz, Some(80));
        assert_eq!(info.txpower_dbm, Some(22.0));
    }

    #[test]
    fn parses_station_dump_counters() {
        let text = "Station aa:bb:cc:dd:ee:ff (on wlp0s20f3)\n\
                    \ttx packets:\t64333\n\ttx retries:\t10930\n\tbeacon loss:\t0\n\
                    \tsignal avg:\t-71 dBm\n";
        let mut info = LinkInfo::default();
        parse_station_dump(text, &mut info);
        assert_eq!(info.tx_packets, Some(64333));
        assert_eq!(info.tx_retries, Some(10930));
        assert_eq!(info.beacon_loss, Some(0));
        // signal avg fills in only because link signal was absent here
        assert_eq!(info.signal_dbm, Some(-71));
    }

    #[test]
    fn phy_generation_from_modulation() {
        assert_eq!(phy_generation("432 MBit/s 80MHz HE-MCS 4"), Some("Wi-Fi 6 (802.11ax)"));
        assert_eq!(phy_generation("433 MBit/s VHT-MCS 9"), Some("Wi-Fi 5 (802.11ac)"));
        assert_eq!(phy_generation("150 MBit/s MCS 7 40MHz"), Some("Wi-Fi 4 (802.11n)"));
        assert_eq!(phy_generation("54.0 MBit/s"), None);
    }
}
