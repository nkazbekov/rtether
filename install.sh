#!/bin/sh
# Install rtether as a launchd service that starts at boot.
# Usage: sudo ./install.sh   (build first, without sudo: ./build.sh)
set -e
cd "$(dirname "$0")"

[ "$(id -u)" -eq 0 ] || { echo "run with sudo: sudo $0"; exit 1; }
[ -x target/release/rtether ] || { echo "build first (without sudo): ./build.sh"; exit 1; }

LABEL=local.rtether
PLIST=/Library/LaunchDaemons/$LABEL.plist

# Stop whatever is running now: an older service and/or a foreground run.
launchctl bootout system/$LABEL 2>/dev/null || true
./target/release/rtether stop >/dev/null 2>&1 || true

install -d /usr/local/bin
install -m 755 target/release/rtether /usr/local/bin/rtether

cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/rtether</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/var/log/rtether.log</string>
    <key>StandardOutPath</key>
    <string>/var/log/rtether.log</string>
</dict>
</plist>
EOF
chown root:wheel "$PLIST"
chmod 644 "$PLIST"

# The log names apps and destinations: admins only. rtether keeps it under
# 1 MB itself (rotating to rtether.log.1).
touch /var/log/rtether.log
chown root:admin /var/log/rtether.log /var/log/rtether.log.1 2>/dev/null || true
chmod 640 /var/log/rtether.log /var/log/rtether.log.1 2>/dev/null || true

launchctl bootstrap system "$PLIST"
echo "rtether is installed and running in the background."

# Menu bar app (built by ./build.sh), started at every login.
if [ -d bar/build/RtetherBar.app ]; then
    BAR=/Library/LaunchAgents/local.rtether.bar.plist
    pkill -x RtetherBar 2>/dev/null || true
    rm -rf /Applications/RtetherBar.app
    cp -R bar/build/RtetherBar.app /Applications/
    # Root-owned: a login item for every user must not run code that one
    # user (or malware running as them) could replace.
    chown -R root:wheel /Applications/RtetherBar.app
    cat > "$BAR" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>local.rtether.bar</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Applications/RtetherBar.app/Contents/MacOS/RtetherBar</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>LimitLoadToSessionType</key>
    <string>Aqua</string>
</dict>
</plist>
EOF
    chown root:wheel "$BAR"
    chmod 644 "$BAR"
    if [ -n "$SUDO_USER" ]; then
        uid=$(id -u "$SUDO_USER")
        launchctl bootout gui/"$uid"/local.rtether.bar 2>/dev/null || true
        launchctl bootstrap gui/"$uid" "$BAR" || true
    fi
    echo "RtetherBar is in the menu bar and starts at login."
fi
echo "Turn on USB tethering on the phone to use it. Log: /var/log/rtether.log"
