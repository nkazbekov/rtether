#!/bin/sh
# Remove the rtether launchd service and binary, and restore normal networking.
# Usage: sudo ./uninstall.sh
cd "$(dirname "$0")"

[ "$(id -u)" -eq 0 ] || { echo "run with sudo: sudo $0"; exit 1; }

LABEL=local.rtether
launchctl bootout system/$LABEL 2>/dev/null
if [ -x /usr/local/bin/rtether ]; then
    /usr/local/bin/rtether stop
else
    printf 'remove State:/Network/Service/rtether/IPv4\nremove State:/Network/Service/rtether/DNS\n' | scutil
fi
rm -f /Library/LaunchDaemons/$LABEL.plist /usr/local/bin/rtether /var/run/rtether.pid

if [ -n "$SUDO_USER" ]; then
    launchctl bootout gui/"$(id -u "$SUDO_USER")"/local.rtether.bar 2>/dev/null
fi
pkill -x RtetherBar 2>/dev/null
rm -rf /Library/LaunchAgents/local.rtether.bar.plist /Applications/RtetherBar.app
echo "rtether and RtetherBar are uninstalled. (/var/log/rtether.log and your app settings are left in place.)"
