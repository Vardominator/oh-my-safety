#!/usr/bin/env bats

setup() {
    load test_helper
    _oms_setup
    source "$OMS_ROOT/lib/cmd/status.sh"

    mkdir -p "$BATS_TEST_TMPDIR/mock-bin"
    export PATH="$BATS_TEST_TMPDIR/mock-bin:$PATH"
}

@test "scan age parses the portable UTC timestamp format" {
    local timestamp age
    timestamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

    run _scan_age "$timestamp"

    [ "$status" -eq 0 ]
    age="$output"
    [[ "$age" =~ ^[0-9]+$ ]]
    [ "$age" -lt 10 ]
}

@test "Linux status recognizes the packaged systemd user service" {
    cat > "$BATS_TEST_TMPDIR/mock-bin/systemctl" <<'EOF'
#!/bin/sh
if [ "$1" = "--user" ] && [ "$2" = "is-active" ]; then
    exit 0
fi
exit 1
EOF
    chmod +x "$BATS_TEST_TMPDIR/mock-bin/systemctl"
    detect_platform() { echo linux; }

    run _agent_manager
    [ "$status" -eq 0 ]
    [ "$output" = "systemd-user" ]

    run _agent_running
    [ "$status" -eq 0 ]
}
