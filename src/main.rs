//! Lists nearby Wi-Fi networks, strongest first, on Linux, macOS and Windows.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::process::ExitCode;

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
compile_error!("wifi-scanner only supports Linux, macOS and Windows.");

#[cfg_attr(target_os = "linux", path = "linux.rs")]
#[cfg_attr(target_os = "macos", path = "macos.rs")]
#[cfg_attr(target_os = "windows", path = "windows.rs")]
mod platform;

pub struct Network {
    pub ssid: String,
    /// Signal strength from 0 to 100.
    pub signal: u8,
    pub security: String,
}

fn main() -> ExitCode {
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
    ExitCode::SUCCESS
}

/// Keeps one entry per name, since a network often has several access points,
/// and orders them strongest first. Networks with no name are dropped.
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

/// Anyone nearby can broadcast any bytes as a network name, including escape
/// sequences that would act on the terminal, so control characters are replaced.
/// Hidden networks may broadcast a name made only of zero bytes, so those go.
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
}
