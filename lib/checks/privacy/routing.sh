#!/bin/bash
# oh-my-safety - Traffic routing check
# Verifies the default route goes through the VPN, so your traffic is protected.

CHECK_NAME="routing"
CHECK_DESCRIPTION="Default traffic routing"
CHECK_CATEGORY="privacy"
CHECK_PLATFORMS="all"
CHECK_SEVERITY="warn"
CHECK_CONTRACT="2"
CHECK_REQUIRES_NETWORK="false"
CHECK_DOC="docs/checks/privacy/routing.md"

check_routing() {
    local route
    route="$(get_default_route_interface)"

    if [[ -z "$route" ]]; then
        print_check_result warn "Could not determine the default route"
        CHECK_FINDING_SUMMARY="No default route"
        CHECK_RESULT_SEVERITY="warn"
        return 1
    fi

    if is_vpn_interface "$route"; then
        print_check_result pass "Default route via VPN ($route)"
        echo "  $(get_default_route)"
        CHECK_FINDING_SUMMARY="Default route via $route (VPN)"
        return 0
    fi

    print_check_result warn "Default route via $route — traffic may not be VPN-protected"
    echo "  $(get_default_route)"
    CHECK_FINDING_SUMMARY="Default route via $route (not VPN)"
    CHECK_RESULT_SEVERITY="warn"
    return 1
}

# Fast check used by the monitor loop's route-flip detection.
quick_routing_check() {
    is_vpn_interface "$(get_default_route_interface)"
}
