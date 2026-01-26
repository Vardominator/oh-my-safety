#!/bin/bash
# oh-my-privacy - Traffic Routing Check
# Verifies that default traffic is routed through the VPN

CHECK_NAME="routing"
CHECK_DESCRIPTION="Traffic Routing Check"

check_routing() {
    echo ""
    echo "Step 5: Traffic Routing"
    echo "-------------------------------------------"

    local route_iface
    route_iface=$(get_default_route_interface)

    if [[ -z "$route_iface" ]]; then
        print_check_result "fail" "Could not determine default route"
        return 1
    fi

    local default_route
    default_route=$(get_default_route)

    if is_vpn_interface "$route_iface"; then
        print_check_result "pass" "Default route goes through VPN ($route_iface)"
        echo "  $default_route"
        return 0
    else
        print_check_result "warn" "Default route: $route_iface (may not be VPN)"
        echo "  $default_route"
        echo "  Traffic may not be protected by VPN"
        return 1
    fi
}

# Quick routing check (for fast polling)
quick_routing_check() {
    local route_iface
    route_iface=$(get_default_route_interface)

    if is_vpn_interface "$route_iface"; then
        return 0
    else
        return 1
    fi
}
