#!/bin/bash
# oh-my-safety - IPv6 leak check
# Detects when IPv6 traffic escapes an IPv4-only VPN tunnel, exposing your IP.

CHECK_NAME="ipv6-leak"
CHECK_DESCRIPTION="IPv6 leak detection"
CHECK_CATEGORY="privacy"
CHECK_PLATFORMS="all"
CHECK_SEVERITY="warn"
CHECK_CONTRACT="2"
CHECK_REQUIRES_NETWORK="true"
CHECK_DOC="docs/checks/privacy/ipv6-leak.md"

check_ipv6_leak() {
    local ipv6 public_ip
    ipv6="$(get_ipv6_address)"

    if [[ -z "$ipv6" ]]; then
        print_check_result pass "IPv6 appears blocked or unavailable — no leak"
        CHECK_FINDING_SUMMARY="IPv6 blocked"
        return 0
    fi

    public_ip="${OMS_PUBLIC_IP:-}"
    [[ -z "$public_ip" ]] && public_ip="$(get_public_ip)"

    if [[ "$ipv6" == "$public_ip" ]]; then
        print_check_result pass "IPv6 matches IPv4 exit — no leak"
        CHECK_FINDING_SUMMARY="No IPv6 leak"
        return 0
    fi

    if [[ "$ipv6" == *:* ]]; then
        print_check_result warn "IPv6 leak detected: $ipv6"
        echo "  Your real IPv6 address may be exposed"
        CHECK_FINDING_SUMMARY="IPv6 leak $ipv6"
        CHECK_RESULT_SEVERITY="warn"
        return 1
    fi

    print_check_result pass "IPv6 traffic tunneled through VPN — no leak"
    CHECK_FINDING_SUMMARY="IPv6 tunneled"
    return 0
}
