#!/bin/bash
# oh-my-safety - VPN tunnel check
# Verifies that a VPN tunnel interface (utun/tun/wg/ppp/ipsec) is active.

CHECK_NAME="vpn-tunnel"
CHECK_DESCRIPTION="VPN tunnel interface"
CHECK_CATEGORY="privacy"
CHECK_PLATFORMS="all"
CHECK_SEVERITY="warn"
CHECK_CONTRACT="2"
CHECK_REQUIRES_NETWORK="false"
CHECK_DOC="docs/checks/privacy/vpn-tunnel.md"

check_vpn_tunnel() {
    local interfaces iface ip found=0
    interfaces="$(get_vpn_interfaces)"

    if [[ -n "$interfaces" ]]; then
        while IFS= read -r iface; do
            [[ -z "$iface" ]] && continue
            ip="$(get_interface_ip "$iface")"
            print_check_result pass "Tunnel interface $iface up${ip:+ ($ip)}"
            found=1
        done <<< "$interfaces"
    fi

    if [[ $found -eq 1 ]]; then
        CHECK_FINDING_SUMMARY="VPN tunnel active"
        return 0
    fi

    print_check_result warn "No VPN tunnel interfaces found — VPN may be disconnected"
    CHECK_FINDING_SUMMARY="No VPN tunnel interface"
    CHECK_RESULT_SEVERITY="warn"
    return 1
}
