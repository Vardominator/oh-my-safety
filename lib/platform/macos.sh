#!/bin/bash
# oh-my-privacy - macOS platform module

# Send a macOS notification
send_notification() {
    local title="$1"
    local message="$2"
    local subtitle="${3:-}"

    local sound_arg=""
    if [[ "${OMP_NOTIFICATIONS_SOUND:-true}" == "true" ]]; then
        sound_arg='sound name "Basso"'
    fi

    if [[ -n "$subtitle" ]]; then
        osascript -e "display notification \"$message\" with title \"$title\" subtitle \"$subtitle\" $sound_arg" 2>/dev/null
    else
        osascript -e "display notification \"$message\" with title \"$title\" $sound_arg" 2>/dev/null
    fi
}

# Send a blocking alert dialog
send_alert() {
    local title="$1"
    local message="$2"

    osascript -e "display dialog \"$message\" with title \"$title\" with icon caution buttons {\"OK\"} default button \"OK\"" 2>/dev/null
}

# Get public IP address
get_public_ip() {
    curl -s --max-time 10 ifconfig.me 2>/dev/null || \
    curl -s --max-time 10 api.ipify.org 2>/dev/null || \
    curl -s --max-time 10 icanhazip.com 2>/dev/null
}

# Get DNS resolver IP via Google's service
get_dns_resolver_ip() {
    nslookup -type=txt o-o.myaddr.l.google.com ns1.google.com 2>/dev/null | \
        grep "text =" | \
        sed 's/.*"\(.*\)".*/\1/' | \
        head -1
}

# Get configured DNS servers
get_dns_servers() {
    scutil --dns 2>/dev/null | grep "nameserver\[[0-9]*\]" | sort -u | awk '{print $3}'
}

# Get VPN tunnel interfaces
get_vpn_interfaces() {
    ifconfig 2>/dev/null | grep -E "^(utun|tun|ppp|ipsec|wg)" | cut -d: -f1
}

# Check if interface is up and get its IP
get_interface_ip() {
    local iface="$1"
    ifconfig "$iface" 2>/dev/null | grep "inet " | awk '{print $2}'
}

# Get the default route interface
get_default_route_interface() {
    netstat -rn 2>/dev/null | grep "^default" | head -1 | awk '{print $NF}'
}

# Get the default route gateway
get_default_route_gateway() {
    netstat -rn 2>/dev/null | grep "^default" | head -1 | awk '{print $2}'
}

# Get full default route info
get_default_route() {
    netstat -rn 2>/dev/null | grep "^default" | head -1
}

# Check if interface is a VPN interface
is_vpn_interface() {
    local iface="$1"
    [[ "$iface" =~ ^(utun|tun|ppp|ipsec|wg) ]]
}

# Get IPv6 address (if any)
get_ipv6_address() {
    curl -s --max-time 5 https://api64.ipify.org 2>/dev/null
}

# Get all network interfaces with their IPs
get_all_interfaces() {
    ifconfig -l 2>/dev/null
}
