#!/bin/bash
# oh-my-privacy - Windows/WSL platform module

# Detect if we're in WSL or native Windows (Git Bash, MSYS2, Cygwin)
_is_wsl() {
    grep -qi microsoft /proc/version 2>/dev/null
}

# Send a Windows notification via PowerShell
send_notification() {
    local title="$1"
    local message="$2"
    local subtitle="${3:-}"

    local full_message="$message"
    if [[ -n "$subtitle" ]]; then
        full_message="$subtitle - $message"
    fi

    if _is_wsl; then
        # WSL: Use PowerShell through wsl interop
        powershell.exe -Command "
            [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
            [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
            \$template = '<toast><visual><binding template=\"ToastText02\"><text id=\"1\">$title</text><text id=\"2\">$full_message</text></binding></visual></toast>'
            \$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
            \$xml.LoadXml(\$template)
            \$toast = [Windows.UI.Notifications.ToastNotification]::new(\$xml)
            [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('oh-my-privacy').Show(\$toast)
        " 2>/dev/null
    else
        # Native Windows: Direct PowerShell
        powershell -Command "
            Add-Type -AssemblyName System.Windows.Forms
            \$notification = New-Object System.Windows.Forms.NotifyIcon
            \$notification.Icon = [System.Drawing.SystemIcons]::Warning
            \$notification.BalloonTipTitle = '$title'
            \$notification.BalloonTipText = '$full_message'
            \$notification.Visible = \$true
            \$notification.ShowBalloonTip(5000)
        " 2>/dev/null
    fi
}

# Send a blocking alert dialog
send_alert() {
    local title="$1"
    local message="$2"

    if _is_wsl; then
        powershell.exe -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('$message', '$title', 'OK', 'Warning')" 2>/dev/null
    else
        powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('$message', '$title', 'OK', 'Warning')" 2>/dev/null
    fi
}

# Get public IP address
get_public_ip() {
    curl -s --max-time 10 ifconfig.me 2>/dev/null || \
    curl -s --max-time 10 api.ipify.org 2>/dev/null || \
    curl -s --max-time 10 icanhazip.com 2>/dev/null
}

# Get DNS resolver IP via Google's service
get_dns_resolver_ip() {
    if command -v nslookup &>/dev/null; then
        nslookup -type=txt o-o.myaddr.l.google.com ns1.google.com 2>/dev/null | \
            grep -E "(text|TXT)" | \
            sed 's/.*"\(.*\)".*/\1/' | \
            head -1
    fi
}

# Get configured DNS servers
get_dns_servers() {
    if _is_wsl; then
        # Get Windows DNS servers
        powershell.exe -Command "Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses" 2>/dev/null | tr -d '\r'
        # Also check WSL's resolv.conf
        [[ -f /etc/resolv.conf ]] && grep "^nameserver" /etc/resolv.conf | awk '{print $2}'
    else
        # Native Windows
        ipconfig /all 2>/dev/null | grep "DNS Servers" | awk -F: '{print $2}' | tr -d ' \r'
    fi
}

# Get VPN tunnel interfaces
get_vpn_interfaces() {
    if _is_wsl; then
        # Check both WSL and Windows interfaces
        ip link show 2>/dev/null | grep -E "^[0-9]+: (tun|tap|wg|ppp)" | cut -d: -f2 | tr -d ' '
        powershell.exe -Command "Get-NetAdapter | Where-Object {(\$_.InterfaceDescription -like '*VPN*') -or (\$_.InterfaceDescription -like '*TAP*') -or (\$_.InterfaceDescription -like '*TUN*')} | Select-Object -ExpandProperty Name" 2>/dev/null | tr -d '\r'
    else
        # Native Windows
        netsh interface show interface 2>/dev/null | grep -i "vpn\|tap\|tun" | awk '{print $NF}'
    fi
}

# Check if interface is up and get its IP
get_interface_ip() {
    local iface="$1"
    if _is_wsl && command -v ip &>/dev/null; then
        ip addr show "$iface" 2>/dev/null | grep "inet " | awk '{print $2}' | cut -d/ -f1
    else
        ipconfig 2>/dev/null | grep -A 5 "$iface" | grep "IPv4" | awk -F: '{print $2}' | tr -d ' \r'
    fi
}

# Get the default route interface
get_default_route_interface() {
    if _is_wsl && command -v ip &>/dev/null; then
        ip route show default 2>/dev/null | head -1 | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}'
    else
        route print 2>/dev/null | grep "0.0.0.0.*0.0.0.0" | head -1 | awk '{print $NF}'
    fi
}

# Get the default route gateway
get_default_route_gateway() {
    if _is_wsl && command -v ip &>/dev/null; then
        ip route show default 2>/dev/null | head -1 | awk '{print $3}'
    else
        route print 2>/dev/null | grep "0.0.0.0.*0.0.0.0" | head -1 | awk '{print $3}'
    fi
}

# Get full default route info
get_default_route() {
    if _is_wsl && command -v ip &>/dev/null; then
        ip route show default 2>/dev/null | head -1
    else
        route print 2>/dev/null | grep "0.0.0.0.*0.0.0.0" | head -1
    fi
}

# Check if interface is a VPN interface
is_vpn_interface() {
    local iface="$1"
    [[ "$iface" =~ ^(tun|tap|wg|ppp) ]] || [[ "$iface" =~ [Vv][Pp][Nn] ]]
}

# Get IPv6 address (if any)
get_ipv6_address() {
    curl -s --max-time 5 https://api64.ipify.org 2>/dev/null
}

# Get all network interfaces
get_all_interfaces() {
    if _is_wsl && command -v ip &>/dev/null; then
        ip link show 2>/dev/null | grep -E "^[0-9]+:" | cut -d: -f2 | tr -d ' '
    else
        ipconfig 2>/dev/null | grep "adapter" | sed 's/.*adapter //' | tr -d ':\r'
    fi
}
