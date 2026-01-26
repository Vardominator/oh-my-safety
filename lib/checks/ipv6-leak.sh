#!/bin/bash
# oh-my-privacy - IPv6 Leak Check
# Detects if IPv6 traffic is leaking outside the VPN

CHECK_NAME="ipv6-leak"
CHECK_DESCRIPTION="IPv6 Leak Detection"

check_ipv6_leak() {
    echo ""
    echo "Step 6: IPv6 Leak Test"
    echo "-------------------------------------------"

    local ipv6
    ipv6=$(get_ipv6_address)

    if [[ -n "$ipv6" ]]; then
        # Get the IPv4 public IP for comparison
        local public_ip="${OMP_PUBLIC_IP:-}"
        if [[ -z "$public_ip" ]]; then
            public_ip=$(get_public_ip)
        fi

        if [[ "$ipv6" == "$public_ip" ]]; then
            print_check_result "pass" "IPv6 shows same IP as IPv4 - No leak"
            return 0
        else
            # Check if it looks like a real IPv6 address
            if [[ "$ipv6" =~ : ]]; then
                print_check_result "warn" "IPv6 leak detected: $ipv6"
                echo "  Your real IPv6 address may be exposed"
                return 1
            else
                # It returned an IPv4, which means IPv6 is likely tunneled
                print_check_result "pass" "IPv6 traffic tunneled through VPN"
                return 0
            fi
        fi
    else
        print_check_result "pass" "IPv6 appears blocked or unavailable - No leak"
        return 0
    fi
}
