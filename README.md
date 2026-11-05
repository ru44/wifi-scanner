# wifi-scanner

You have the Wi-Fi password, but nobody told you the network's name. This lists the networks around you, strongest first, so you can work out which one it is without having to ask again.

```
Nearby Wi-Fi networks:

Cafe_Guest                          Signal:  82%  Security: WPA2
Bakery-5G                           Signal:  64%  Security: WPA2 WPA3
Free_Airport_WiFi                   Signal:  41%  Security: Open
Office-Staff                        Signal:  30%  Security: WPA2 802.1X
```

The network you want often has one of the stronger signals, but nearby printers and phones can outrank it. Two kinds can be ruled out:

- **Open** networks don't use a password.
- **802.1X** networks need a username as well, so a password alone won't get you on.

The tool only reads the list of names your computer can already see. It doesn't connect to anything, try passwords or capture traffic.

## Get it

Download the file for your system from the [Releases](https://github.com/ru44/wifi-scanner/releases) page, or build it with [Rust](https://rustup.rs):

```sh
git clone https://github.com/ru44/wifi-scanner
cd wifi-scanner
cargo build --release
```

## Run it

### Linux

```sh
./wifi-scanner-linux-x86_64
```

You may need to run `chmod +x wifi-scanner-linux-x86_64` first. Requires NetworkManager (`nmcli`), which most desktop distributions include. Other setups, such as `iwd` on its own, aren't supported yet.

### Windows

```powershell
.\wifi-scanner-windows-x86_64.exe
```

- SmartScreen may warn you because the file isn't code signed. Choose **More info**, then **Run anyway**.
- Windows treats Wi-Fi scanning as location access, so it may ask for permission. If the scan is blocked, turn on Location services and **Let desktop apps access your location** in **Settings > Privacy & security > Location**.

### macOS

macOS only shows nearby network names to apps with Location permission, and only an app bundle can hold that permission, so there's a one-time setup. The app never reads your location.

1. Build the app:

   ```sh
   scripts/bundle-macos.sh
   ```

   If you downloaded the zip from Releases instead, unzip it and run `xattr -dr com.apple.quarantine WifiScanner.app`, because the app isn't notarized. The paths below are for a local build.

2. Open it once to get the permission prompt, and choose **Allow**:

   ```sh
   open -W target/WifiScanner.app
   ```

3. In **System Settings > Privacy & Security > Location Services**, check that **WifiScanner** is switched on.

4. Scan:

   ```sh
   target/WifiScanner.app/Contents/MacOS/wifi-scanner
   ```

If macOS still hides the names, it may not be accepting the ad hoc signature. Rebuilding with a Developer ID certificate should help:

```sh
CODESIGN_IDENTITY="Developer ID Application: Your Name" scripts/bundle-macos.sh
```

## Status

| System  | Status |
| ------- | ------ |
| Linux   | Tested with real Wi-Fi hardware |
| Windows | Compiles, not yet tested with real Wi-Fi hardware |
| macOS   | Compiles, not yet tested with real Wi-Fi hardware |

If you try it on Windows or macOS, please open an issue with your OS version and whether it worked.

## License

[MIT](LICENSE)
