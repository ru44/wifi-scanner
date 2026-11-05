//! Shaping a raw scan into a clean list: one entry per name, strongest first,
//! with names made safe to print.

use std::collections::HashMap;
use std::collections::hash_map::Entry;

use crate::types::Network;

/// Collapses a scan to one entry per name — the strongest sighting of each —
/// sorted strongest first, then by name. Hidden/blank names are dropped.
pub(crate) fn strongest_per_name(networks: Vec<Network>) -> Vec<Network> {
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

/// Replaces control characters with the Unicode replacement character and
/// drops NULs, so a hostile SSID cannot drive the terminal when printed.
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
