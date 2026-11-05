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

## Requirements

Linux with NetworkManager (`nmcli`), which most desktop distributions include. Other setups, such as `iwd` on its own, aren't supported.

## Get it

 build it with [Rust](https://rustup.rs):

```sh
git clone https://github.com/ru44/wifi-scanner
cd wifi-scanner
cargo build --release
```

## Run it

```sh
./wifi-scanner-linux-x86_64
```

You may need to run `chmod +x wifi-scanner-linux-x86_64` first. A local build lands at `target/release/wifi-scanner`.

## License

[MIT](LICENSE)
