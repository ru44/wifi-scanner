//! Linux: asks NetworkManager through `nmcli`.

use std::io::{ErrorKind, Write};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::types::{Attempt, Network};

/// How the password reaches nmcli. `Stdin` (via `--ask`) keeps it off argv;
/// `Argv` is the legacy path, visible to `ps` and in journald.
#[derive(Copy, Clone)]
pub enum PasswordDelivery {
    Stdin,
    Argv,
}

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
        .args(["-t", "-f", "SSID,SIGNAL,SECURITY"])
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

fn try_connect_stdin(
    ssid: &str,
    password: &str,
    timeout: Duration,
) -> Result<Output, String> {
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

fn try_connect_argv(
    ssid: &str,
    password: &str,
    timeout: Duration,
) -> Result<Output, String> {
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

fn parse(output: &str) -> Vec<Network> {
    output.lines().filter_map(parse_line).collect()
}

fn parse_line(line: &str) -> Option<Network> {
    let fields = split_fields(line);
    let [ssid, signal, security] = fields.as_slice() else {
        return None;
    };
    Some(Network {
        ssid: ssid.clone(),
        signal: signal.parse().ok()?,
        security: if security.is_empty() {
            "Open".to_string()
        } else {
            security.clone()
        },
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn one(line: &str) -> Network {
        parse_line(line).expect("line should parse")
    }

    #[test]
    fn reads_a_plain_line() {
        let network = one("Cafe Guest:72:WPA2");
        assert_eq!(network.ssid, "Cafe Guest");
        assert_eq!(network.signal, 72);
        assert_eq!(network.security, "WPA2");
    }

    #[test]
    fn keeps_escaped_colons_in_the_name() {
        assert_eq!(one(r"Cafe\:Guest:72:WPA2").ssid, "Cafe:Guest");
        assert_eq!(one(r"AA\:BB\:CC:50:WPA2").ssid, "AA:BB:CC");
    }

    #[test]
    fn keeps_escaped_backslashes_in_the_name() {
        assert_eq!(one(r"back\\slash:72:WPA2").ssid, r"back\slash");
    }

    #[test]
    fn keeps_non_ascii_names() {
        assert_eq!(one("مقهى:72:WPA2").ssid, "مقهى");
    }

    #[test]
    fn empty_security_means_open() {
        assert_eq!(one("Free:72:").security, "Open");
    }

    #[test]
    fn keeps_multiple_security_modes() {
        assert_eq!(one("Cafe:72:WPA1 WPA2").security, "WPA1 WPA2");
    }

    #[test]
    fn skips_malformed_lines() {
        assert!(parse_line("").is_none());
        assert!(parse_line("only-a-name").is_none());
        assert!(parse_line("Cafe:not-a-number:WPA2").is_none());
        assert!(parse_line("too:many:fields:here").is_none());
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
}