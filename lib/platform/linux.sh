#!/bin/bash
# oh-my-privacy - Linux platform module

# Send a Linux notification (requires libnotify or similar)
send_notification() {
    local title="$1"
    local message="$2"
    local subtitle="${3:-}"

    local full_message="$message"
    if [[ -n "$subtitle" ]]; then
        full_message="$subtitle\n$message"
    fi

    if command -v notify-send &>/dev/null; then
        notify-send "$title" "$full_message" --urgency=critical 2>/dev/null
    elif command -v zenity &>/dev/null; then
        zenity --notification --text="$title: $full_message" 2>/dev/null &
    elif command -v kdialog &>/dev/null; then
        kdialog --passivepopup "$full_message" 5 --title "$title" 2>/dev/null &
    else
        # Fallback to terminal bell and message
        echo -e "\a${title}: ${message}" >&2
    fi
}

# Send a blocking alert dialog
send_alert() {
    local title="$1"
    local message="$2"

    if command -v zenity &>/dev/null; then
        zenity --warning --title="$title" --text="$message" 2>/dev/null
    elif command -v kdialog &>/dev/null; then
        kdialog --sorry "$message" --title "$title" 2>/dev/null
    elif command -v xmessage &>/dev/null; then
        xmessage -center "$title: $message" 2>/dev/null
    else
        echo -e "\a${title}: ${message}" >&2
        read -r -p "Press Enter to continue..."
    fi
}

# Get public IP address
get_public_ip() {
    curl -s --max-time 10 ifconfig.me 2>/dev/null || \
    curl -s --max-time 10 api.ipify.org 2>/dev/null || \
    curl -s --max-time 10 icanhazip.com 2>/dev/null || \
    wget -qO- --timeout=10 ifconfig.me 2>/dev/null
}

# Get DNS resolver IP via Google's service
get_dns_resolver_ip() {
    if command -v nslookup &>/dev/null; then
        nslookup -type=txt o-o.myaddr.l.google.com ns1.google.com 2>/dev/null | \
            grep -E "(text|TXT)" | \
            sed 's/.*"\(.*\)".*/\1/' | \
            head -1
    elif command -v dig &>/dev/null; then
        dig +short txt o-o.myaddr.l.google.com @ns1.google.com 2>/dev/null | \
            tr -d '"' | \
            head -1
    fi
}

# Get configured DNS servers
get_dns_servers() {
    if [[ -f /etc/resolv.conf ]]; then
        grep "^nameserver" /etc/resolv.conf | awk '{print $2}'
    fi

    # Also check systemd-resolved if available
    if command -v resolvectl &>/dev/null; then
        resolvectl status 2>/dev/null | grep "DNS Servers" | awk '{print $3}'
    fi
}

# Get VPN tunnel interfaces
get_vpn_interfaces() {
    ip link show 2>/dev/null | grep -E "^[0-9]+: (tun|tap|wg|ppp)" | cut -d: -f2 | tr -d ' '
}

# Check if interface is up and get its IP
get_interface_ip() {
    local iface="$1"
    ip addr show "$iface" 2>/dev/null | grep "inet " | awk '{print $2}' | cut -d/ -f1
}

# Get the default route interface
get_default_route_interface() {
    ip route show default 2>/dev/null | head -1 | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}'
}

# Get the default route gateway
get_default_route_gateway() {
    ip route show default 2>/dev/null | head -1 | awk '{print $3}'
}

# Get full default route info
get_default_route() {
    ip route show default 2>/dev/null | head -1
}

# Check if interface is a VPN interface
is_vpn_interface() {
    local iface="$1"
    [[ "$iface" =~ ^(tun|tap|wg|ppp) ]]
}

# Get IPv6 address (if any)
get_ipv6_address() {
    curl -s --max-time 5 https://api64.ipify.org 2>/dev/null || \
    curl -s --max-time 5 https://v6.ident.me 2>/dev/null
}

# Get all network interfaces with their IPs
get_all_interfaces() {
    ip link show 2>/dev/null | grep -E "^[0-9]+:" | cut -d: -f2 | tr -d ' '
}
