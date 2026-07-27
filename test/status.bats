#!/usr/bin/env bats
# Status renderers for detailed/remediable last-scan state.

setup() {
    load test_helper
    _oms_setup
    source "$OMS_ROOT/lib/cmd/status.sh"
    load_config
    OMS_BIN="$OMS_ROOT/bin/oh-my-safety"
    export OMS_BIN
    STATUS_FIXTURE="$BATS_TEST_TMPDIR/last-scan.tsv"
    cat > "$STATUS_FIXTURE" <<EOF
schema	1
meta	timestamp	$(date -u '+%Y-%m-%dT%H:%M:%SZ')
meta	version	0.2.2
meta	platform	macos
meta	source	agent
meta	exit	1
meta	fda	true
result	security	hardening-posture	warn	warn	1 hardening issue(s)	Follow the exact fix, then recheck.	docs/checks/security/hardening-posture.md
result	security	network-exposure	warn	warn	1 new network listener(s)	Stop it if unexpected; otherwise accept it.	docs/checks/security/network-exposure.md
result	privacy	vpn-tunnel	ok	info	VPN tunnel active	Start or reconnect the VPN.	docs/checks/privacy/vpn-tunnel.md
detail	security	hardening-posture	⚠️  Application Firewall is disabled
detail	security	hardening-posture	  - fix: System Settings > Network > Firewall > On   [id: hard:firewall]
detail	security	network-exposure	⚠️  1 new network listener(s) detected
detail	security	network-exposure	  - NEW WAN listener: /usr/libexec/rapportd   [id: tcp|*|/usr/libexec/rapportd|wan]
EOF
}

@test "SwiftBar puts concrete warnings first and nests remediation" {
    run _status_swiftbar "$STATUS_FIXTURE"
    [ "$status" -eq 0 ]
    [[ "$output" == *"2 items need attention"* ]]
    [[ "$output" == *"⚠️ Firewall & hardening — Application Firewall is disabled"* ]]
    [[ "$output" == *"⚠️ Network exposure — NEW WAN listener: /usr/libexec/rapportd"* ]]
    [[ "$output" == *"--Suggested: Follow the exact fix, then recheck."* ]]
    [[ "$output" == *"--Recheck Firewall & hardening"* ]]
    [[ "$output" == *"Healthy checks (1)"* ]]
    [[ "$output" == *"--✓ VPN tunnel — VPN tunnel active"* ]]
    [[ "$output" == *"tcp¦*¦/usr/libexec/rapportd¦wan"* ]]
}

@test "JSON exposes remediation and exact detail arrays" {
    run _status_json "$STATUS_FIXTURE"
    [ "$status" -eq 0 ]
    printf '%s' "$output" | python3 -m json.tool >/dev/null
    [[ "$output" == *'"remediation":"Follow the exact fix, then recheck."'* ]]
    [[ "$output" == *'"details":["⚠️  Application Firewall is disabled"'* ]]
}

@test "human status includes an actionable details section" {
    run _status_human "$STATUS_FIXTURE"
    [ "$status" -eq 0 ]
    [[ "$output" == *"Actionable details"* ]]
    [[ "$output" == *"Application Firewall is disabled"* ]]
    [[ "$output" == *"Suggested action: Follow the exact fix, then recheck."* ]]
    [[ "$output" == *"Open remediation guide"* || "$output" == *"Guide: https://github.com/"* ]]
}
