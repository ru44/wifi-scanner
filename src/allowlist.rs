//! Reading the SSID allow-list and prompting for the known lab password.

use std::env;
use std::fs;
use std::io::{self, IsTerminal, Write};

use crate::SSID_FILE;

pub(crate) fn read_allowlist() -> Result<Vec<String>, String> {
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

pub(crate) fn prompt_password() -> Result<String, String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ssid_file_skipping_blanks_and_comments() {
        let text = "# lab APs\n\nMyLabAP\n  MyLabAP-5G  \n#MyLabAP-6G\n";
        assert_eq!(parse_ssid_file(text), ["MyLabAP", "MyLabAP-5G"]);
    }
}
