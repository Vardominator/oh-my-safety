#!/bin/bash
# oh-my-privacy - DNS Leak Check
# Detects if DNS queries are leaking outside the VPN tunnel

CHECK_NAME="dns-leak"
CHECK_DESCRIPTION="DNS Leak Detection"

check_dns_leak() {
    echo ""
    echo "Step 2: DNS Leak Test"
    echo "-------------------------------------------"

    local dns_ip
    dns_ip=$(get_dns_resolver_ip)

    if [[ -n "$dns_ip" ]]; then
        echo "DNS resolver IP: $dns_ip"

        # Compare with public IP if available
        local public_ip="${OMP_PUBLIC_IP:-}"
        if [[ -z "$public_ip" ]]; then
            public_ip=$(get_public_ip)
        fi

        if [[ -n "$public_ip" && "$dns_ip" == "$public_ip" ]]; then
            print_check_result "pass" "DNS matches VPN IP - No leak detected"
            return 0
        else
            print_check_result "warn" "DNS IP differs from VPN IP - Check for potential leak"
            echo "  VPN IP: $public_ip"
            echo "  DNS IP: $dns_ip"
            return 1
        fi
    else
        print_check_result "warn" "Could not determine DNS resolver IP"
        return 0  # Not a definitive failure
    fi
}

# Additional check: Show configured DNS servers
check_dns_servers() {
    echo ""
    echo "Step 3: Configured DNS Servers"
    echo "-------------------------------------------"

    local servers
    servers=$(get_dns_servers)

    if [[ -n "$servers" ]]; then
        echo "$servers" | head -6
    else
        echo "No DNS servers found"
    fi

    return 0
}
