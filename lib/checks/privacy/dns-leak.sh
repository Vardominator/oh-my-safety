#!/bin/bash
# oh-my-safety - DNS leak check
# Detects when DNS queries resolve outside your VPN tunnel (exposing browsing).

CHECK_NAME="dns-leak"
CHECK_DESCRIPTION="DNS leak detection"
CHECK_CATEGORY="privacy"
CHECK_PLATFORMS="all"
CHECK_SEVERITY="warn"
CHECK_CONTRACT="2"
CHECK_REQUIRES_NETWORK="true"
CHECK_DOC="docs/checks/privacy/dns-leak.md"

check_dns_leak() {
    local dns_ip public_ip
    dns_ip="$(get_dns_resolver_ip)"

    if [[ -z "$dns_ip" ]]; then
        print_check_result info "Could not determine DNS resolver IP (inconclusive)"
        CHECK_FINDING_SUMMARY="DNS resolver unknown"
        _dns_show_servers
        return 0
    fi

    public_ip="${OMS_PUBLIC_IP:-}"
    [[ -z "$public_ip" ]] && public_ip="$(get_public_ip)"

    if [[ -n "$public_ip" && "$dns_ip" == "$public_ip" ]]; then
        print_check_result pass "DNS resolver matches VPN IP — no leak"
        CHECK_FINDING_SUMMARY="No DNS leak"
        _dns_show_servers
        return 0
    fi

    print_check_result warn "DNS resolver IP ($dns_ip) differs from VPN IP (${public_ip:-unknown}) — possible leak"
    CHECK_FINDING_SUMMARY="DNS resolver $dns_ip differs from VPN IP"
    CHECK_RESULT_SEVERITY="warn"
    _dns_show_servers
    return 1
}

_dns_show_servers() {
    local servers
    servers="$(get_dns_servers)"
    if [[ -n "$servers" ]]; then
        echo "  Configured DNS servers:"
        printf '%s\n' "$servers" | head -6 | sed 's/^/    /'
    fi
}
