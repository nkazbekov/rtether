#!/bin/sh
# Build RtetherBar.app (menu bar companion) into bar/build/.
set -e
cd "$(dirname "$0")"
APP=build/RtetherBar.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
swiftc -O -parse-as-library -target "$(uname -m)-apple-macos13.0" \
    -o "$APP/Contents/MacOS/RtetherBar" RtetherBar.swift
cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key><string>local.rtether.bar</string>
    <key>CFBundleName</key><string>RtetherBar</string>
    <key>CFBundleExecutable</key><string>RtetherBar</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>1.0</string>
    <key>LSMinimumSystemVersion</key><string>13.0</string>
    <key>LSUIElement</key><true/>
</dict>
</plist>
EOF
codesign --force --sign - "$APP"
echo "built $APP"
