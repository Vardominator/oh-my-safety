#!/bin/bash
# oh-my-privacy - IP Address Check
# Retrieves and displays the public IP address

# Check name and description
CHECK_NAME="ip-address"
CHECK_DESCRIPTION="Public IP Address Check"

# Run the IP address check
check_ip_address() {
    echo ""
    echo "Step 1: Public IP Address"
    echo "-------------------------------------------"

    local ip
    ip=$(get_public_ip)

    if [[ -n "$ip" ]]; then
        print_check_result "pass" "Your public IP: $ip"
        echo "(This should be your VPN server's IP, not your real IP)"

        # Export for use by other checks
        export OMP_PUBLIC_IP="$ip"
        return 0
    else
        print_check_result "fail" "Could not retrieve IP address"
        return 1
    fi
}
