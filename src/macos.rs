//! macOS: CoreWLAN. Apple removed the `airport` tool in macOS 14.4 and hides
//! network names from programs without Location permission, which only an app
//! bundle can hold. See `scripts/bundle-macos.sh`.

use std::thread;
use std::time::{Duration, Instant};

use objc2_core_location::{CLAuthorizationStatus, CLLocationManager};
use objc2_core_wlan::{CWNetwork, CWSecurity, CWWiFiClient};
use objc2_foundation::{NSBundle, NSDate, NSRunLoop};

use crate::Network;

const PERMISSION_TIMEOUT: Duration = Duration::from_secs(120);
const SCAN_ATTEMPTS: u32 = 3;
const SCAN_RETRY_DELAY: Duration = Duration::from_secs(1);

const ENABLE_LOCATION: &str = "Open System Settings > Privacy & Security > Location Services, \
    turn on Location Services and WifiScanner, then run this again.";

/// Strongest first, because a network can report several modes at once. Uses
/// the same names as `nmcli`, so the output reads the same on every OS.
const SECURITY_LABELS: &[(CWSecurity, &str)] = &[
    (CWSecurity::WPA3Enterprise, "WPA3 802.1X"),
    (CWSecurity::WPA3Personal, "WPA3"),
    (CWSecurity::WPA3Transition, "WPA2 WPA3"),
    (CWSecurity::WPA2Enterprise, "WPA2 802.1X"),
    (CWSecurity::WPA2Personal, "WPA2"),
    (CWSecurity::WPAEnterpriseMixed, "WPA1 WPA2 802.1X"),
    (CWSecurity::WPAPersonalMixed, "WPA1 WPA2"),
    (CWSecurity::WPAEnterprise, "WPA1 802.1X"),
    (CWSecurity::WPAPersonal, "WPA1"),
    (CWSecurity::Enterprise, "802.1X"),
    (CWSecurity::Personal, "Personal"),
    (CWSecurity::DynamicWEP, "WEP 802.1X"),
    (CWSecurity::WEP, "WEP"),
    (CWSecurity::OWE, "OWE"),
    (CWSecurity::OWETransition, "OWE"),
    (CWSecurity::None, "Open"),
];

pub fn scan() -> Result<Vec<Network>, String> {
    if NSBundle::mainBundle().bundleIdentifier().is_none() {
        return Err(
            "on macOS this must run from inside its app bundle, or the network names stay \
             hidden. Run scripts/bundle-macos.sh and follow what it prints."
                .to_string(),
        );
    }
    require_location_permission()?;

    let interface = unsafe { CWWiFiClient::sharedWiFiClient().interface() }
        .ok_or("no Wi-Fi interface found.")?;
    if !unsafe { interface.powerOn() } {
        return Err("Wi-Fi is turned off.".to_string());
    }

    // Scans sometimes come back with every name missing and then work when
    // repeated. Hidden networks have no name either, so only an all-empty
    // result is suspicious.
    for attempt in 0..SCAN_ATTEMPTS {
        if attempt > 0 {
            thread::sleep(SCAN_RETRY_DELAY);
        }
        let found = unsafe { interface.scanForNetworksWithName_error(None) }
            .map_err(|error| format!("Wi-Fi scan failed: {}", error.localizedDescription()))?;
        let named: Vec<Network> = found.iter().filter_map(|n| to_network(&n)).collect();
        if !named.is_empty() || found.count() == 0 {
            return Ok(named);
        }
    }
    Err(format!(
        "macOS found networks but hid their names, which usually means Location permission \
         is missing or this build's signature was not accepted. {ENABLE_LOCATION}"
    ))
}

/// Polls instead of using a delegate because this only needs the final answer.
/// The run loop has to keep turning for the manager to receive status updates.
fn require_location_permission() -> Result<(), String> {
    let manager = unsafe { CLLocationManager::new() };
    let run_loop = NSRunLoop::currentRunLoop();
    let deadline = Instant::now() + PERMISSION_TIMEOUT;
    let mut requested = false;

    loop {
        let status = unsafe { manager.authorizationStatus() };
        if status == CLAuthorizationStatus::AuthorizedAlways
            || status == CLAuthorizationStatus::AuthorizedWhenInUse
        {
            return Ok(());
        }
        if status != CLAuthorizationStatus::NotDetermined {
            return Err(format!(
                "macOS denied Location permission. {ENABLE_LOCATION}"
            ));
        }
        if !requested {
            eprintln!("Waiting for you to allow Location access in the macOS prompt...");
            unsafe { manager.requestAlwaysAuthorization() };
            requested = true;
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for Location permission. {ENABLE_LOCATION}"
            ));
        }
        run_loop.runUntilDate(&NSDate::dateWithTimeIntervalSinceNow(0.2));
    }
}

fn to_network(network: &CWNetwork) -> Option<Network> {
    let ssid = unsafe { network.ssid() }?.to_string();
    let label = SECURITY_LABELS
        .iter()
        .find(|(mode, _)| unsafe { network.supportsSecurity(*mode) })
        .map_or("Unknown", |(_, label)| label);
    Some(Network {
        ssid,
        signal: signal_percent(unsafe { network.rssiValue() }),
        security: label.to_string(),
    })
}

/// CoreWLAN reports dBm. This is the common linear scale that also matches how
/// Windows describes its quality value: -100 dBm is 0% and -50 dBm is 100%.
fn signal_percent(rssi: isize) -> u8 {
    (rssi.saturating_add(100).saturating_mul(2)).clamp(0, 100) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_dbm_to_percent() {
        assert_eq!(signal_percent(-50), 100);
        assert_eq!(signal_percent(-75), 50);
        assert_eq!(signal_percent(-100), 0);
    }

    #[test]
    fn clamps_out_of_range_signal() {
        assert_eq!(signal_percent(-20), 100);
        assert_eq!(signal_percent(-120), 0);
        assert_eq!(signal_percent(isize::MIN), 0);
        assert_eq!(signal_percent(isize::MAX), 100);
    }
}
