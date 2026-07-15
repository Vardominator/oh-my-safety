#!/bin/bash
# oh-my-safety - Public IP address check
# Retrieves your public IP so you can confirm it's your VPN's, not your real one.

CHECK_NAME="ip-address"
CHECK_DESCRIPTION="Public IP address"
CHECK_CATEGORY="privacy"
CHECK_PLATFORMS="all"
CHECK_SEVERITY="warn"
CHECK_CONTRACT="2"
CHECK_REQUIRES_NETWORK="true"
CHECK_DOC="docs/checks/privacy/ip-address.md"

check_ip_address() {
    local ip
    ip="$(get_public_ip)"

    if [[ -n "$ip" ]]; then
        export OMS_PUBLIC_IP="$ip"
        print_check_result pass "Public IP: $ip"
        echo "  (this should be your VPN server's IP, not your real IP)"
        CHECK_FINDING_SUMMARY="Public IP $ip"
        return 0
    fi

    print_check_result warn "Could not retrieve public IP address"
    CHECK_FINDING_SUMMARY="Public IP unavailable"
    CHECK_RESULT_SEVERITY="warn"
    return 1
}
