#!/bin/bash

# <bitbar.title>oh-my-privacy VPN Status</bitbar.title>
# <bitbar.version>v0.1.0</bitbar.version>
# <bitbar.author>Vardominator</bitbar.author>
# <bitbar.author.github>Vardominator</bitbar.author.github>
# <bitbar.desc>VPN privacy monitor - checks for IP, DNS, and routing leaks</bitbar.desc>
# <bitbar.image>https://github.com/Vardominator/oh-my-privacy/raw/main/assets/swiftbar-screenshot.png</bitbar.image>
# <bitbar.dependencies>bash,curl</bitbar.dependencies>
# <bitbar.abouturl>https://github.com/Vardominator/oh-my-privacy</bitbar.abouturl>

# <swiftbar.hideAbout>false</swiftbar.hideAbout>
# <swiftbar.hideRunInTerminal>false</swiftbar.hideRunInTerminal>
# <swiftbar.hideLastUpdated>false</swiftbar.hideLastUpdated>
# <swiftbar.hideDisablePlugin>false</swiftbar.hideDisablePlugin>
# <swiftbar.hideSwiftBar>false</swiftbar.hideSwiftBar>

# oh-my-privacy SwiftBar Plugin
# Displays VPN privacy status in the menu bar

set -o pipefail

# Find oh-my-privacy installation
OMP_BIN=""
for path in "/usr/local/bin/oh-my-privacy" "$HOME/.local/bin/oh-my-privacy" "/opt/homebrew/bin/oh-my-privacy"; do
    if [[ -x "$path" ]]; then
        OMP_BIN="$path"
        break
    fi
done

# Fallback: Check if running from repo directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -z "$OMP_BIN" && -x "$SCRIPT_DIR/../../bin/oh-my-privacy" ]]; then
    OMP_BIN="$SCRIPT_DIR/../../bin/oh-my-privacy"
fi

# Cache settings
CACHE_FILE="/tmp/oh-my-privacy-swiftbar-cache"
CACHE_TTL=30  # seconds

# Get routing info
get_route_interface() {
    netstat -rn 2>/dev/null | grep "^default" | head -1 | awk '{print $NF}'
}

# Check if interface is VPN
is_vpn_interface() {
    local iface="$1"
    [[ "$iface" =~ ^(utun|tun|ppp|wg|ipsec) ]]
}

# Get cached IP (reduces API calls)
get_cached_ip() {
    if [[ -f "$CACHE_FILE" ]]; then
        local cache_age=$(($(date +%s) - $(stat -f %m "$CACHE_FILE" 2>/dev/null || echo 0)))
        if [[ $cache_age -lt $CACHE_TTL ]]; then
            cat "$CACHE_FILE" 2>/dev/null
            return 0
        fi
    fi

    local ip
    ip=$(curl -s --max-time 3 --connect-timeout 2 ifconfig.me 2>/dev/null) || ip=""
    if [[ -n "$ip" ]]; then
        echo "$ip" > "$CACHE_FILE"
        echo "$ip"
    fi
}

# Get DNS resolver IP
get_dns_ip() {
    timeout 3 nslookup -type=txt o-o.myaddr.l.google.com ns1.google.com 2>/dev/null | \
        grep "text =" | sed 's/.*"\(.*\)".*/\1/' || echo ""
}

# Main status check
ROUTE_IFACE=$(get_route_interface)
[[ -z "$ROUTE_IFACE" ]] && ROUTE_IFACE="unknown"

LEAKS=0
ISSUES=""
NETWORK_ERROR=false

# Check 1: Traffic routing
if ! is_vpn_interface "$ROUTE_IFACE"; then
    ((LEAKS++))
    ISSUES="${ISSUES}Traffic via $ROUTE_IFACE (not VPN)\n"
fi

# Check 2: Public IP
IP=$(get_cached_ip)
if [[ -z "$IP" ]]; then
    NETWORK_ERROR=true
fi

# Check 3: DNS leak
DNS_IP=$(get_dns_ip)
if [[ -n "$DNS_IP" && -n "$IP" && "$DNS_IP" != "$IP" ]]; then
    ((LEAKS++))
    ISSUES="${ISSUES}DNS leak: $DNS_IP\n"
fi

# === Menu Bar Display ===

if $NETWORK_ERROR; then
    echo "🔌 | color=orange"
elif [[ $LEAKS -eq 0 ]]; then
    echo "🛡️ | color=green"
else
    echo "⚠️ $LEAKS | color=red"
fi

echo "---"

# Status section
if $NETWORK_ERROR; then
    echo "⚠️ Network Check Failed | color=orange"
    echo "   Cannot verify VPN status"
elif [[ $LEAKS -eq 0 ]]; then
    echo "✅ VPN Protected | color=green"
else
    echo "🚨 $LEAKS Leak(s) Detected | color=red"
    echo -e "$ISSUES" | while IFS= read -r line; do
        [[ -n "$line" ]] && echo "   • $line | color=red"
    done
fi

echo "---"

# Info section
if is_vpn_interface "$ROUTE_IFACE"; then
    echo "Route: $ROUTE_IFACE | color=green"
else
    echo "Route: $ROUTE_IFACE | color=red"
fi
echo "Public IP: ${IP:-Checking...}"
[[ -n "$DNS_IP" ]] && echo "DNS IP: $DNS_IP"

echo "---"

# Actions
if [[ -n "$OMP_BIN" ]]; then
    echo "Run Full Check | bash='$OMP_BIN' param1='--once' terminal=true"
    echo "Start Monitoring | bash='$OMP_BIN' terminal=true"
else
    echo "⚠️ oh-my-privacy not installed | color=orange"
    echo "Install: curl -sSL https://raw.githubusercontent.com/Vardominator/oh-my-privacy/main/install.sh | bash | terminal=false bash='/bin/echo' param1='Copy the install command'"
fi

echo "---"
echo "Refresh | refresh=true"
echo "---"
echo "ipleak.net | href=https://ipleak.net"
echo "browserleaks.com/webrtc | href=https://browserleaks.com/webrtc"
echo "---"
echo "oh-my-privacy on GitHub | href=https://github.com/Vardominator/oh-my-privacy"
