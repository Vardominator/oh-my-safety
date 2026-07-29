#!/usr/bin/env bats

setup() {
    load test_helper
    _oms_setup

    export HOME="$BATS_TEST_TMPDIR/home"
    export OMS_BIN="$HOME/.local/bin/oh-my-safety"
    unset SNAP SNAP_INSTANCE_NAME
    mkdir -p "$HOME/.local/bin" "$BATS_TEST_TMPDIR/mock-bin"
    : > "$OMS_BIN"
    chmod +x "$OMS_BIN"

    export SYSTEMCTL_LOG="$BATS_TEST_TMPDIR/systemctl.log"
    cat > "$BATS_TEST_TMPDIR/mock-bin/systemctl" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$SYSTEMCTL_LOG"
if [ "$1" = "--user" ] && [ "$2" = "cat" ]; then
    exit 1
fi
if [ "$1" = "--user" ] && [ "$2" = "is-active" ]; then
    exit 1
fi
exit 0
EOF
    chmod +x "$BATS_TEST_TMPDIR/mock-bin/systemctl"
    export PATH="$BATS_TEST_TMPDIR/mock-bin:$PATH"

    detect_platform() { echo linux; }
    source "$OMS_ROOT/lib/cmd/install-agent.sh"
}

@test "manual Linux agent install creates and enables a systemd user unit" {
    run cmd_install_agent

    [ "$status" -eq 0 ]
    unit="$HOME/.config/systemd/user/oh-my-safety.service"
    [ -f "$unit" ]
    grep -Fq "ExecStart=\"$OMS_BIN\" monitor --quiet" "$unit"
    grep -Fq -- "--user daemon-reload" "$SYSTEMCTL_LOG"
    grep -Fq -- "--user enable --now oh-my-safety.service" "$SYSTEMCTL_LOG"
}

@test "manual Linux agent uninstall disables and removes its unit" {
    cmd_install_agent >/dev/null
    unit="$HOME/.config/systemd/user/oh-my-safety.service"
    [ -f "$unit" ]

    run cmd_uninstall_agent

    [ "$status" -eq 0 ]
    [ ! -f "$unit" ]
    grep -Fq -- "--user disable --now oh-my-safety.service" "$SYSTEMCTL_LOG"
}
