#!/usr/bin/env bats

setup() {
    load test_helper
    _oms_setup

    export HOME="$BATS_TEST_TMPDIR/home"
    mkdir -p "$HOME" "$BATS_TEST_TMPDIR/mock-bin"
    export PATH="$BATS_TEST_TMPDIR/mock-bin:$PATH"

    # shellcheck source=/dev/null
    source "$OMS_ROOT/lib/platform/linux.sh"
    load_config
}

_mock_command() {
    local name="$1"
    shift
    {
        printf '#!/bin/sh\n'
        printf '%s\n' "$@"
    } > "$BATS_TEST_TMPDIR/mock-bin/$name"
    chmod +x "$BATS_TEST_TMPDIR/mock-bin/$name"
}

_mock_hardened_linux() {
    _mock_command findmnt 'printf "/dev/mapper/cryptroot\n"'
    _mock_command lsblk 'printf "crypt\npart\ndisk\n"'
    _mock_command ufw 'printf "Status: active\n"'
    _mock_command aa-status 'exit 0'
    _mock_command systemctl \
        'case "$1" in' \
        '  is-active) exit 1 ;;' \
        '  is-enabled) case "$3" in apt-daily-upgrade.timer) exit 0 ;; *) exit 1 ;; esac ;;' \
        'esac' \
        'exit 1'
}

@test "Linux hardening passes available controls and reports only coverage notes" {
    _mock_hardened_linux
    # shellcheck source=/dev/null
    source "$OMS_ROOT/lib/checks/security/linux-hardening-posture.sh"

    run check_linux_hardening_posture

    [ "$status" -eq 0 ]
    [[ "$output" == *"Linux hardening posture passed"* ]]
    [[ "$output" == *"Secure Boot is not measurable"* ]]
}

@test "Linux hardening flags an inactive host firewall" {
    _mock_hardened_linux
    _mock_command ufw 'printf "Status: inactive\n"'
    # shellcheck source=/dev/null
    source "$OMS_ROOT/lib/checks/security/linux-hardening-posture.sh"

    run check_linux_hardening_posture

    [ "$status" -eq 1 ]
    [[ "$output" == *"No active host firewall policy"* ]]
    [[ "$output" == *"[id: linux-hard:firewall]"* ]]
}

@test "Linux persistence creates a baseline then flags a new autostart file" {
    _mock_command systemctl 'exit 0'
    _mock_command crontab 'exit 1'
    mkdir -p "$HOME/.config/autostart"
    printf '%s\n' '[Desktop Entry]' 'Name=Known' > "$HOME/.config/autostart/known.desktop"
    # shellcheck source=/dev/null
    source "$OMS_ROOT/lib/checks/security/linux-persistence-scan.sh"

    run check_linux_persistence_scan
    [ "$status" -eq 0 ]
    [[ "$output" == *"Baseline recorded"* ]]

    printf '%s\n' '[Desktop Entry]' 'Name=Unexpected' > "$HOME/.config/autostart/unexpected.desktop"
    run check_linux_persistence_scan

    [ "$status" -eq 1 ]
    [[ "$output" == *"NEW persistence"* ]]
    [[ "$output" == *"unexpected.desktop"* ]]
}

@test "Secrets metadata check works with Linux stat and hash helpers" {
    _mock_command stat \
        'for arg in "$@"; do last="$arg"; done' \
        'exec /usr/bin/stat -f "%Lp" "$last"'
    mkdir -p "$HOME/.aws"
    printf '%s\n' '[default]' > "$HOME/.aws/credentials"
    chmod 0644 "$HOME/.aws/credentials"
    # shellcheck source=/dev/null
    source "$OMS_ROOT/lib/checks/security/secrets-exposure.sh"

    run check_secrets_exposure

    [ "$status" -eq 1 ]
    [[ "$output" == *"credential file readable by others"* ]]
    [[ "$output" == *"$HOME/.aws/credentials"* ]]
}
