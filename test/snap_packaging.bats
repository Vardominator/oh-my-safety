#!/usr/bin/env bats

setup() {
    load test_helper
    _oms_setup

    SNAP_RECIPE="$OMS_ROOT/snap/snapcraft.yaml"
    SNAP_LAUNCHER="$OMS_ROOT/packaging/snap/oh-my-safety-launcher"
}

@test "snap metadata is classic, multi-arch, and needs no experimental daemon feature" {
    grep -Eq '^confinement:[[:space:]]+classic$' "$SNAP_RECIPE"
    grep -Eq '^platforms:$' "$SNAP_RECIPE"
    grep -Eq '^[[:space:]]+amd64:$' "$SNAP_RECIPE"
    grep -Eq '^[[:space:]]+arm64:$' "$SNAP_RECIPE"

    run grep -Eq '^[[:space:]]+(daemon|daemon-scope):' "$SNAP_RECIPE"
    [ "$status" -ne 0 ]
}

@test "snap version is adopted from the application source of truth" {
    grep -Eq '^adopt-info:[[:space:]]+oh-my-safety$' "$SNAP_RECIPE"
    run grep -Eq '^version:' "$SNAP_RECIPE"
    [ "$status" -ne 0 ]
    grep -Fq 'OMS_VERSION=' "$SNAP_RECIPE"
    grep -Fq 'craftctl set version=' "$SNAP_RECIPE"
}

@test "snap prime list follows the core24 merged-usr layout" {
    grep -Eq '^[[:space:]]+- usr/lib$' "$SNAP_RECIPE"
    grep -Eq '^[[:space:]]+- usr/sbin$' "$SNAP_RECIPE"

    run grep -Eq '^[[:space:]]+- (lib|lib64|sbin)$' "$SNAP_RECIPE"
    [ "$status" -ne 0 ]
}

@test "snap launcher pins helpers and durable private XDG paths" {
    fake_snap="$BATS_TEST_TMPDIR/snap"
    common="$BATS_TEST_TMPDIR/common"
    mkdir -p "$fake_snap/usr/bin" "$fake_snap/usr/lib/oh-my-safety/bin"

    cat > "$fake_snap/usr/bin/bash" <<'EOF'
#!/bin/sh
printf 'config=%s\n' "$XDG_CONFIG_HOME"
printf 'state=%s\n' "$XDG_STATE_HOME"
printf 'packaging=%s\n' "$OMS_PACKAGING"
printf 'path=%s\n' "$PATH"
printf 'target=%s\n' "$1"
printf 'arg=%s\n' "${2:-}"
EOF
    chmod +x "$fake_snap/usr/bin/bash"
    : > "$fake_snap/usr/lib/oh-my-safety/bin/oh-my-safety"
    chmod +x "$fake_snap/usr/lib/oh-my-safety/bin/oh-my-safety"

    run env SNAP="$fake_snap" SNAP_USER_COMMON="$common" "$SNAP_LAUNCHER" version

    [ "$status" -eq 0 ]
    [[ "$output" == *"config=$common/config"* ]]
    [[ "$output" == *"state=$common/state"* ]]
    [[ "$output" == *"packaging=snap"* ]]
    [[ "$output" == *"path=$fake_snap/usr/lib/oh-my-safety/bin:$fake_snap/usr/sbin:$fake_snap/usr/bin"* ]]
    [[ "$output" == *"target=$fake_snap/usr/lib/oh-my-safety/bin/oh-my-safety"* ]]
    [[ "$output" == *"arg=version"* ]]
    [ "$(_oms_test_file_mode "$common/config")" = "700" ]
    [ "$(_oms_test_file_mode "$common/state")" = "700" ]
}

@test "snap launcher rejects use outside the snap runtime" {
    run env -u SNAP -u SNAP_USER_COMMON "$SNAP_LAUNCHER" version

    [ "$status" -eq 70 ]
    [[ "$output" == *"snap runtime environment is unavailable"* ]]
}

@test "snap launcher forwards monitor mode to the packaged CLI" {
    fake_snap="$BATS_TEST_TMPDIR/snap"
    common="$BATS_TEST_TMPDIR/common"
    mkdir -p "$fake_snap/usr/bin" "$fake_snap/usr/lib/oh-my-safety/bin"

    cat > "$fake_snap/usr/bin/bash" <<'EOF'
#!/bin/sh
printf 'target=%s\n' "$1"
printf 'arg=%s\n' "${2:-}"
EOF
    chmod +x "$fake_snap/usr/bin/bash"
    : > "$fake_snap/usr/lib/oh-my-safety/bin/oh-my-safety"
    chmod +x "$fake_snap/usr/lib/oh-my-safety/bin/oh-my-safety"

    run env SNAP="$fake_snap" SNAP_USER_COMMON="$common" "$SNAP_LAUNCHER" monitor --quiet

    [ "$status" -eq 0 ]
    [[ "$output" == *"target=$fake_snap/usr/lib/oh-my-safety/bin/oh-my-safety"* ]]
    [[ "$output" == *"arg=monitor"* ]]
}

@test "status recognizes a legacy Snap-managed user monitor" {
    mkdir -p "$BATS_TEST_TMPDIR/mock-bin"
    cat > "$BATS_TEST_TMPDIR/mock-bin/systemctl" <<'EOF'
#!/bin/sh
case "$*" in
  "--user is-active --quiet snap.oh-my-safety.monitor.service") exit 0 ;;
  *) exit 1 ;;
esac
EOF
    chmod +x "$BATS_TEST_TMPDIR/mock-bin/systemctl"
    PATH="$BATS_TEST_TMPDIR/mock-bin:$PATH"
    export PATH
    detect_platform() { echo linux; }
    source "$OMS_ROOT/lib/cmd/status.sh"

    run _agent_running
    [ "$status" -eq 0 ]

    run _agent_manager
    [ "$status" -eq 0 ]
    [ "$output" = "snap" ]
}

@test "snap install-agent creates a refresh-stable systemd user service" {
    HOME="$BATS_TEST_TMPDIR/home"
    OMS_BIN="$BATS_TEST_TMPDIR/snap/usr/lib/oh-my-safety/bin/oh-my-safety"
    export HOME OMS_BIN
    mkdir -p "$BATS_TEST_TMPDIR/mock-bin"
    systemctl_log="$BATS_TEST_TMPDIR/systemctl.log"
    export systemctl_log
    cat > "$BATS_TEST_TMPDIR/mock-bin/systemctl" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"$systemctl_log"
case "$*" in
  "--user is-active --quiet snap.oh-my-safety.monitor.service") exit 1 ;;
  "--user cat oh-my-safety.service") exit 1 ;;
  *) exit 0 ;;
esac
EOF
    chmod +x "$BATS_TEST_TMPDIR/mock-bin/systemctl"
    PATH="$BATS_TEST_TMPDIR/mock-bin:$PATH"
    export PATH
    SNAP="$BATS_TEST_TMPDIR/snap"
    SNAP_INSTANCE_NAME="oh-my-safety"
    export SNAP SNAP_INSTANCE_NAME
    detect_platform() { echo linux; }
    source "$OMS_ROOT/lib/cmd/install-agent.sh"

    run cmd_install_agent

    [ "$status" -eq 0 ]
    unit="$HOME/.config/systemd/user/oh-my-safety.service"
    [ -f "$unit" ]
    grep -Fq 'ExecStart="/snap/bin/oh-my-safety" monitor --quiet' "$unit"
    grep -Fq -- "--user enable --now oh-my-safety.service" "$systemctl_log"
}

@test "snap install-agent refuses to replace a native user service" {
    HOME="$BATS_TEST_TMPDIR/home"
    OMS_BIN="$BATS_TEST_TMPDIR/snap/usr/lib/oh-my-safety/bin/oh-my-safety"
    export HOME OMS_BIN
    mkdir -p "$BATS_TEST_TMPDIR/mock-bin"
    cat > "$BATS_TEST_TMPDIR/mock-bin/systemctl" <<'EOF'
#!/bin/sh
case "$*" in
  "--user is-active --quiet snap.oh-my-safety.monitor.service") exit 1 ;;
  "--user cat oh-my-safety.service")
    printf '%s\n' 'ExecStart="/usr/bin/oh-my-safety" monitor --quiet'
    exit 0
    ;;
  *) exit 0 ;;
esac
EOF
    chmod +x "$BATS_TEST_TMPDIR/mock-bin/systemctl"
    PATH="$BATS_TEST_TMPDIR/mock-bin:$PATH"
    export PATH
    SNAP="$BATS_TEST_TMPDIR/snap"
    SNAP_INSTANCE_NAME="oh-my-safety"
    export SNAP SNAP_INSTANCE_NAME
    detect_platform() { echo linux; }
    source "$OMS_ROOT/lib/cmd/install-agent.sh"

    run cmd_install_agent

    [ "$status" -eq 1 ]
    [[ "$output" == *"non-Snap oh-my-safety user service is already installed"* ]]
    [ ! -e "$HOME/.config/systemd/user/oh-my-safety.service" ]
}

@test "snap uninstall-agent removes its user-owned service" {
    HOME="$BATS_TEST_TMPDIR/home"
    OMS_BIN="$BATS_TEST_TMPDIR/snap/usr/lib/oh-my-safety/bin/oh-my-safety"
    export HOME OMS_BIN
    mkdir -p "$HOME/.config/systemd/user" "$BATS_TEST_TMPDIR/mock-bin"
    printf '%s\n' '[Service]' \
        'ExecStart="/snap/bin/oh-my-safety" monitor --quiet' \
        >"$HOME/.config/systemd/user/oh-my-safety.service"

    cat > "$BATS_TEST_TMPDIR/mock-bin/systemctl" <<'EOF'
#!/bin/sh
exit 0
EOF
    chmod +x "$BATS_TEST_TMPDIR/mock-bin/systemctl"
    PATH="$BATS_TEST_TMPDIR/mock-bin:$PATH"
    export PATH
    SNAP="$BATS_TEST_TMPDIR/snap"
    SNAP_INSTANCE_NAME="oh-my-safety"
    export SNAP SNAP_INSTANCE_NAME
    detect_platform() { echo linux; }
    source "$OMS_ROOT/lib/cmd/install-agent.sh"

    run cmd_uninstall_agent

    [ "$status" -eq 0 ]
    [ ! -e "$HOME/.config/systemd/user/oh-my-safety.service" ]
}

@test "native install-agent refuses to compete with a legacy Snap monitor" {
    HOME="$BATS_TEST_TMPDIR/home"
    OMS_BIN="$HOME/.local/bin/oh-my-safety"
    export HOME OMS_BIN
    mkdir -p "$HOME/.local/bin" "$BATS_TEST_TMPDIR/mock-bin"
    : > "$OMS_BIN"
    chmod +x "$OMS_BIN"

    cat > "$BATS_TEST_TMPDIR/mock-bin/systemctl" <<'EOF'
#!/bin/sh
case "$*" in
  "--user is-active --quiet snap.oh-my-safety.monitor.service") exit 0 ;;
  *) exit 1 ;;
esac
EOF
    chmod +x "$BATS_TEST_TMPDIR/mock-bin/systemctl"
    PATH="$BATS_TEST_TMPDIR/mock-bin:$PATH"
    export PATH
    unset SNAP SNAP_INSTANCE_NAME
    detect_platform() { echo linux; }
    source "$OMS_ROOT/lib/cmd/install-agent.sh"

    run cmd_install_agent

    [ "$status" -eq 1 ]
    [[ "$output" == *"legacy Snap-managed monitor is still active"* ]]
    [ ! -e "$HOME/.config/systemd/user/oh-my-safety.service" ]
}
