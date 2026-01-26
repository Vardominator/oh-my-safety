#!/bin/bash
# oh-my-privacy - VPN Tunnel Check
# Verifies that VPN tunnel interfaces are active

CHECK_NAME="vpn-tunnel"
CHECK_DESCRIPTION="VPN Tunnel Interface Check"

check_vpn_tunnel() {
    echo ""
    echo "Step 4: VPN Tunnel Status"
    echo "-------------------------------------------"

    local interfaces
    interfaces=$(get_vpn_interfaces)

    if [[ -n "$interfaces" ]]; then
        echo "Active tunnel interfaces:"
        local found_active=false

        while IFS= read -r iface; do
            [[ -z "$iface" ]] && continue

            local ip
            ip=$(get_interface_ip "$iface")

            if [[ -n "$ip" ]]; then
                print_check_result "pass" "$iface: UP - $ip"
                found_active=true
            else
                print_check_result "pass" "$iface: UP"
                found_active=true
            fi
        done <<< "$interfaces"

        if $found_active; then
            return 0
        fi
    fi

    print_check_result "fail" "No VPN tunnel interfaces found"
    echo "  VPN may be disconnected"
    return 1
}
