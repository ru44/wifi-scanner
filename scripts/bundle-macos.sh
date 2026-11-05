#!/bin/sh
# Builds target/WifiScanner.app. macOS only shows nearby network names to apps
# with Location permission, and only an app bundle can be granted that.
#
# Signs ad hoc by default, which needs no Apple account. To use a real identity:
#   CODESIGN_IDENTITY="Developer ID Application: Your Name" scripts/bundle-macos.sh
set -eu

cd "$(dirname "$0")/.."

cargo build --release

app=target/WifiScanner.app
rm -rf "$app"
mkdir -p "$app/Contents/MacOS"
cp macos/Info.plist "$app/Contents/Info.plist"
cp target/release/wifi-scanner "$app/Contents/MacOS/wifi-scanner"
codesign --force --sign "${CODESIGN_IDENTITY:--}" "$app"

cat <<EOF

Built $app

First run, to get the Location prompt:
  open -W $app

Allow it, then check that WifiScanner is switched on in
System Settings > Privacy & Security > Location Services.

After that, scan with:
  $app/Contents/MacOS/wifi-scanner
EOF
