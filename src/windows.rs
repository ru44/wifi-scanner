//! Windows: the Native Wifi API. `netsh` is avoided on purpose, because its
//! output is translated into the system language and is awkward to parse.

use std::io;
use std::ptr;
use std::slice;
use std::thread;
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_NDIS_DOT11_POWER_STATE_INVALID, ERROR_SERVICE_NOT_ACTIVE,
    ERROR_SUCCESS, HANDLE,
};
use windows_sys::Win32::NetworkManagement::WiFi::{
    DOT11_AUTH_ALGO_80211_OPEN, DOT11_AUTH_ALGO_80211_SHARED_KEY, DOT11_AUTH_ALGO_OWE,
    DOT11_AUTH_ALGO_RSNA, DOT11_AUTH_ALGO_RSNA_PSK, DOT11_AUTH_ALGO_WPA, DOT11_AUTH_ALGO_WPA_NONE,
    DOT11_AUTH_ALGO_WPA_PSK, DOT11_AUTH_ALGO_WPA3_ENT, DOT11_AUTH_ALGO_WPA3_ENT_192,
    DOT11_AUTH_ALGO_WPA3_SAE, DOT11_AUTH_ALGORITHM, WLAN_API_VERSION_2_0, WLAN_AVAILABLE_NETWORK,
    WLAN_AVAILABLE_NETWORK_LIST, WLAN_INTERFACE_INFO, WLAN_INTERFACE_INFO_LIST, WlanCloseHandle,
    WlanEnumInterfaces, WlanFreeMemory, WlanGetAvailableNetworkList, WlanOpenHandle, WlanScan,
};
use windows_sys::core::GUID;

use crate::Network;

/// `WlanScan` returns immediately, and its documentation gives drivers 4 seconds
/// to finish, which is also the timeout it recommends for callers.
const SCAN_WAIT: Duration = Duration::from_secs(4);

struct Client(HANDLE);

impl Drop for Client {
    fn drop(&mut self) {
        unsafe { WlanCloseHandle(self.0, ptr::null()) };
    }
}

/// A list allocated by the WLAN API, freed when dropped.
struct WlanList<T>(*mut T);

impl<T> Drop for WlanList<T> {
    fn drop(&mut self) {
        unsafe { WlanFreeMemory(self.0.cast()) };
    }
}

pub fn scan() -> Result<Vec<Network>, String> {
    let client = open_client()?;
    let adapters = adapter_guids(&client)?;
    if adapters.is_empty() {
        return Err("no Wi-Fi adapter found.".to_string());
    }

    for adapter in &adapters {
        let status = unsafe { WlanScan(client.0, adapter, ptr::null(), ptr::null(), ptr::null()) };
        // Permission applies to every adapter, so there is no point continuing.
        // Other failures, such as the radio being off, are per adapter and show
        // up again when the list is read below.
        if status == ERROR_ACCESS_DENIED {
            return Err(describe_error(status));
        }
    }
    thread::sleep(SCAN_WAIT);

    let mut networks = Vec::new();
    let mut first_error = None;
    for adapter in &adapters {
        match list_networks(&client, adapter) {
            Ok(found) => networks.extend(found),
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    match first_error {
        Some(error) if networks.is_empty() => Err(error),
        _ => Ok(networks),
    }
}

fn open_client() -> Result<Client, String> {
    let mut negotiated_version = 0;
    let mut handle: HANDLE = ptr::null_mut();
    let status = unsafe {
        WlanOpenHandle(
            WLAN_API_VERSION_2_0,
            ptr::null(),
            &mut negotiated_version,
            &mut handle,
        )
    };
    check(status)?;
    Ok(Client(handle))
}

fn adapter_guids(client: &Client) -> Result<Vec<GUID>, String> {
    let mut raw: *mut WLAN_INTERFACE_INFO_LIST = ptr::null_mut();
    check(unsafe { WlanEnumInterfaces(client.0, ptr::null(), &mut raw) })?;
    let list = WlanList(raw);

    // The list's last field is a variable-length array declared with length 1.
    let interfaces = unsafe {
        let first = ptr::addr_of!((*list.0).InterfaceInfo).cast::<WLAN_INTERFACE_INFO>();
        slice::from_raw_parts(first, (*list.0).dwNumberOfItems as usize)
    };
    Ok(interfaces.iter().map(|info| info.InterfaceGuid).collect())
}

fn list_networks(client: &Client, adapter: &GUID) -> Result<Vec<Network>, String> {
    let mut raw: *mut WLAN_AVAILABLE_NETWORK_LIST = ptr::null_mut();
    check(unsafe { WlanGetAvailableNetworkList(client.0, adapter, 0, ptr::null(), &mut raw) })?;
    let list = WlanList(raw);

    // The list's last field is a variable-length array declared with length 1.
    let entries = unsafe {
        let first = ptr::addr_of!((*list.0).Network).cast::<WLAN_AVAILABLE_NETWORK>();
        slice::from_raw_parts(first, (*list.0).dwNumberOfItems as usize)
    };
    Ok(entries.iter().map(to_network).collect())
}

fn to_network(entry: &WLAN_AVAILABLE_NETWORK) -> Network {
    let ssid = &entry.dot11Ssid;
    let length = (ssid.uSSIDLength as usize).min(ssid.ucSSID.len());
    Network {
        ssid: String::from_utf8_lossy(&ssid.ucSSID[..length]).into_owned(),
        signal: entry.wlanSignalQuality.min(100) as u8,
        security: security_label(entry.bSecurityEnabled != 0, entry.dot11DefaultAuthAlgorithm)
            .to_string(),
    }
}

/// Uses the same names as `nmcli`, so the output reads the same on every OS.
fn security_label(security_enabled: bool, algorithm: DOT11_AUTH_ALGORITHM) -> &'static str {
    match algorithm {
        DOT11_AUTH_ALGO_80211_OPEN if !security_enabled => "Open",
        DOT11_AUTH_ALGO_80211_OPEN | DOT11_AUTH_ALGO_80211_SHARED_KEY => "WEP",
        DOT11_AUTH_ALGO_WPA => "WPA1 802.1X",
        DOT11_AUTH_ALGO_WPA_PSK | DOT11_AUTH_ALGO_WPA_NONE => "WPA1",
        DOT11_AUTH_ALGO_RSNA => "WPA2 802.1X",
        DOT11_AUTH_ALGO_RSNA_PSK => "WPA2",
        DOT11_AUTH_ALGO_WPA3_ENT | DOT11_AUTH_ALGO_WPA3_ENT_192 => "WPA3 802.1X",
        DOT11_AUTH_ALGO_WPA3_SAE => "WPA3",
        DOT11_AUTH_ALGO_OWE => "OWE",
        _ => "Unknown",
    }
}

fn check(status: u32) -> Result<(), String> {
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(describe_error(status))
    }
}

fn describe_error(status: u32) -> String {
    match status {
        ERROR_ACCESS_DENIED => "Windows blocked the Wi-Fi scan because it needs Location \
            permission. If a prompt appeared, allow it and run this again. Otherwise open \
            Settings > Privacy & security > Location (run: start ms-settings:privacy-location), \
            turn on Location services and \"Let desktop apps access your location\", then run \
            this again."
            .to_string(),
        ERROR_SERVICE_NOT_ACTIVE => {
            "the WLAN AutoConfig service is not running, or this PC has no Wi-Fi adapter."
                .to_string()
        }
        ERROR_NDIS_DOT11_POWER_STATE_INVALID => "Wi-Fi is turned off.".to_string(),
        _ => format!(
            "Wi-Fi scan failed: {}",
            io::Error::from_raw_os_error(status as i32)
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_network_without_security_is_open() {
        assert_eq!(security_label(false, DOT11_AUTH_ALGO_80211_OPEN), "Open");
    }

    #[test]
    fn open_auth_with_security_enabled_is_wep() {
        assert_eq!(security_label(true, DOT11_AUTH_ALGO_80211_OPEN), "WEP");
    }

    #[test]
    fn personal_and_enterprise_are_told_apart() {
        assert_eq!(security_label(true, DOT11_AUTH_ALGO_RSNA_PSK), "WPA2");
        assert_eq!(security_label(true, DOT11_AUTH_ALGO_RSNA), "WPA2 802.1X");
        assert_eq!(security_label(true, DOT11_AUTH_ALGO_WPA3_SAE), "WPA3");
    }

    #[test]
    fn network_name_stops_at_the_reported_length() {
        let mut entry = WLAN_AVAILABLE_NETWORK::default();
        entry.dot11Ssid.ucSSID[..6].copy_from_slice(b"Cafe!!");
        entry.dot11Ssid.uSSIDLength = 4;
        entry.wlanSignalQuality = 80;
        assert_eq!(to_network(&entry).ssid, "Cafe");
        assert_eq!(to_network(&entry).signal, 80);
    }

    #[test]
    fn an_oversized_name_length_does_not_read_past_the_buffer() {
        let mut entry = WLAN_AVAILABLE_NETWORK::default();
        entry.dot11Ssid.uSSIDLength = 500;
        assert_eq!(to_network(&entry).ssid.len(), 32);
    }
}
