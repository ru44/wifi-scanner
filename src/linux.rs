//! Linux: asks NetworkManager through `nmcli`.

use std::io::ErrorKind;
use std::process::{Command, Output};

use crate::Network;

pub fn scan() -> Result<Vec<Network>, String> {
    // NetworkManager refuses a forced rescan right after another scan, and may
    // refuse it by policy. Its cached list is still good enough, so fall back.
    let mut output = nmcli("yes")?;
    if !output.status.success() {
        output = nmcli("auto")?;
    }
    if !output.status.success() {
        let reason = String::from_utf8_lossy(&output.stderr);
        let reason = reason.trim().trim_start_matches("Error: ");
        return Err(format!("nmcli failed: {reason}"));
    }
    Ok(parse(&String::from_utf8_lossy(&output.stdout)))
}

fn nmcli(rescan: &str) -> Result<Output, String> {
    Command::new("nmcli")
        .args(["-t", "-f", "SSID,SIGNAL,SECURITY"])
        .args(["dev", "wifi", "list", "--rescan", rescan])
        .output()
        .map_err(|error| match error.kind() {
            ErrorKind::NotFound => {
                "nmcli was not found. On Linux this tool needs NetworkManager.".to_string()
            }
            _ => format!("could not run nmcli: {error}"),
        })
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

/// Splits one line of `nmcli -t` output. Fields are separated by `:`, and any
/// `:` or `\` inside a value is escaped with a backslash.
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
}
