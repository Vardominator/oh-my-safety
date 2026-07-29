#!/usr/bin/env bats

setup() {
    load test_helper
    _oms_setup
    mkdir -p "$BATS_TEST_TMPDIR/bin"
    export PATH="$BATS_TEST_TMPDIR/bin:$PATH"
    export OMS_NOTIFICATION_ALLOW_HTTP=true
}

@test "external notification channels are globally opt-in" {
    send_notification() { echo "desktop:$1"; }
    export -f send_notification
    config_set notifications.channels.discord.enabled true
    config_set notifications.external.enabled false
    export OMS_DISCORD_WEBHOOK_URL="http://127.0.0.1:1234/hook"

    run dispatch_notification title detail ""
    [ "$status" -eq 0 ]
    [[ "$output" == *"desktop:title"* ]]
    [ ! -f "$BATS_TEST_TMPDIR/curl-called" ]
}

@test "Discord delivery hides details by default and records delivery" {
    cat > "$BATS_TEST_TMPDIR/bin/curl" <<'SH'
#!/bin/bash
[[ "$1" == "-q" && "$2" == "--config" ]] || exit 91
cfg="$3"
body="$(sed -n 's/^data-binary = "@\(.*\)"$/\1/p' "$cfg")"
cp "$body" "$BATS_TEST_TMPDIR/payload"
touch "$BATS_TEST_TMPDIR/curl-called"
printf '204'
SH
    chmod +x "$BATS_TEST_TMPDIR/bin/curl"
    export BATS_TEST_TMPDIR
    export OMS_DISCORD_WEBHOOK_URL="http://127.0.0.1:1234/hook"
    config_set notifications.channels.desktop.enabled false
    config_set notifications.external.enabled true
    config_set notifications.channels.discord.enabled true

    run dispatch_notification "oh-my-safety: routing" "private path /Users/alice/secret" ""
    [ "$status" -eq 0 ]
    grep -q "Open oh-my-safety status locally" "$BATS_TEST_TMPDIR/payload"
    ! grep -q "/Users/alice/secret" "$BATS_TEST_TMPDIR/payload"
    grep -q $'\tnotification.delivered\t.*\tdiscord\t' \
        "$(state_path log/events.tsv)"
}

@test "airgapped profile blocks an enabled external channel" {
    cat > "$BATS_TEST_TMPDIR/bin/curl" <<'SH'
#!/bin/bash
touch "$BATS_TEST_TMPDIR/curl-called"
printf '204'
SH
    chmod +x "$BATS_TEST_TMPDIR/bin/curl"
    export BATS_TEST_TMPDIR
    export OMS_DISCORD_WEBHOOK_URL="http://127.0.0.1:1234/hook"
    config_set notifications.channels.desktop.enabled false
    config_set notifications.external.enabled true
    config_set notifications.channels.discord.enabled true
    config_set profile.connectivity airgapped

    run dispatch_notification title detail ""
    [ "$status" -eq 0 ]
    [ ! -f "$BATS_TEST_TMPDIR/curl-called" ]
}

@test "notification status names env variables but never their values" {
    source "$OMS_ROOT/lib/cmd/notifications.sh"
    export OMS_DISCORD_WEBHOOK_URL="https://discord.invalid/super-secret-token"
    run cmd_notifications show
    [ "$status" -eq 0 ]
    [[ "$output" == *"OMS_DISCORD_WEBHOOK_URL (available)"* ]]
    [[ "$output" != *"super-secret-token"* ]]
}

@test "background services can read a strict credential file without sourcing it" {
    local credentials="$XDG_CONFIG_HOME/oh-my-safety/notifications.env"
    mkdir -p "$(dirname "$credentials")"
    printf '%s\n' \
        '# values are parsed literally' \
        'OMS_DISCORD_WEBHOOK_URL=http://127.0.0.1:1234/hook?token=$not-expanded' \
        > "$credentials"
    chmod 600 "$credentials"
    unset OMS_DISCORD_WEBHOOK_URL

    run _notification_secret OMS_DISCORD_WEBHOOK_URL
    [ "$status" -eq 0 ]
    [ "$output" = 'http://127.0.0.1:1234/hook?token=$not-expanded' ]
}

@test "credential files with unsafe modes or duplicate names fail closed" {
    local credentials="$XDG_CONFIG_HOME/oh-my-safety/notifications.env"
    mkdir -p "$(dirname "$credentials")"
    printf '%s\n' 'OMS_DISCORD_WEBHOOK_URL=https://first.invalid' > "$credentials"
    chmod 644 "$credentials"

    run _notification_secret OMS_DISCORD_WEBHOOK_URL
    [ "$status" -ne 0 ]

    printf '%s\n' \
        'OMS_DISCORD_WEBHOOK_URL=https://first.invalid' \
        'OMS_DISCORD_WEBHOOK_URL=https://second.invalid' \
        > "$credentials"
    chmod 600 "$credentials"
    run _notification_secret OMS_DISCORD_WEBHOOK_URL
    [ "$status" -ne 0 ]
}

@test "credential parser rejects malformed rows and duplicate unused names" {
    local credentials="$XDG_CONFIG_HOME/oh-my-safety/notifications.env"
    mkdir -p "$(dirname "$credentials")"
    printf '%s\n' \
        'OMS_DISCORD_WEBHOOK_URL=https://valid.invalid' \
        'UNUSED_NAME=first' \
        'UNUSED_NAME=second' \
        > "$credentials"
    chmod 600 "$credentials"

    run _notification_secret OMS_DISCORD_WEBHOOK_URL
    [ "$status" -ne 0 ]

    printf '%s\n' \
        'OMS_DISCORD_WEBHOOK_URL=https://valid.invalid' \
        'this is not a KEY=value row' \
        > "$credentials"
    run _notification_secret OMS_DISCORD_WEBHOOK_URL
    [ "$status" -ne 0 ]
}

@test "mode 400 credential file is accepted and symlinks fail closed" {
    local credentials="$XDG_CONFIG_HOME/oh-my-safety/notifications.env"
    local target="$BATS_TEST_TMPDIR/credential-target"
    mkdir -p "$(dirname "$credentials")"
    printf '%s\n' 'OMS_DISCORD_WEBHOOK_URL=https://valid.invalid' > "$credentials"
    chmod 400 "$credentials"

    run _notification_secret OMS_DISCORD_WEBHOOK_URL
    [ "$status" -eq 0 ]
    [ "$output" = "https://valid.invalid" ]

    rm -f "$credentials"
    printf '%s\n' 'OMS_DISCORD_WEBHOOK_URL=https://symlink.invalid' > "$target"
    chmod 600 "$target"
    ln -s "$target" "$credentials"
    run _notification_secret OMS_DISCORD_WEBHOOK_URL
    [ "$status" -ne 0 ]
}

@test "credential status rejects broken symlinks and oversized files" {
    local credentials="$XDG_CONFIG_HOME/oh-my-safety/notifications.env"
    mkdir -p "$(dirname "$credentials")"
    ln -s "$BATS_TEST_TMPDIR/missing-target" "$credentials"
    source "$OMS_ROOT/lib/cmd/notifications.sh"

    run cmd_notifications show
    [ "$status" -eq 0 ]
    [[ "$output" == *"Credential file:"*"rejected"* ]]

    rm -f "$credentials"
    dd if=/dev/zero of="$credentials" bs=65537 count=1 2>/dev/null
    chmod 600 "$credentials"
    run _notification_credentials_secure "$credentials"
    [ "$status" -ne 0 ]
}

@test "macOS credential files with extended ACLs fail closed" {
    [[ "$(uname -s)" == "Darwin" ]] || skip "macOS ACL syntax"
    local credentials="$XDG_CONFIG_HOME/oh-my-safety/notifications.env"
    mkdir -p "$(dirname "$credentials")"
    printf '%s\n' 'OMS_DISCORD_WEBHOOK_URL=https://acl.invalid' > "$credentials"
    chmod 600 "$credentials"
    chmod +a "everyone allow read" "$credentials"

    run _notification_credentials_secure "$credentials"
    [ "$status" -ne 0 ]
}

@test "empty configured path follows XDG_CONFIG_HOME after defaults load" {
    load_config
    run _notification_credentials_path
    [ "$status" -eq 0 ]
    [ "$output" = "$XDG_CONFIG_HOME/oh-my-safety/notifications.env" ]
}

@test "a relative dash credential filename is parsed as a file, not stdin" {
    local previous="$PWD"
    cd "$BATS_TEST_TMPDIR"
    printf '%s\n' 'OMS_DISCORD_WEBHOOK_URL=https://dash.invalid' > ./-
    chmod 600 ./-
    config_set notifications.external.credentials_file -

    run _notification_secret OMS_DISCORD_WEBHOOK_URL
    cd "$previous"
    [ "$status" -eq 0 ]
    [ "$output" = "https://dash.invalid" ]
}

@test "curl config values reject escape injection before transport" {
    cat > "$BATS_TEST_TMPDIR/bin/curl" <<'SH'
#!/bin/bash
touch "$BATS_TEST_TMPDIR/curl-called"
printf '204'
SH
    chmod +x "$BATS_TEST_TMPDIR/bin/curl"
    export BATS_TEST_TMPDIR

    run _notification_http_post webhook \
        'https://alerts.invalid/path\\nheader = "X-Leak: yes"' \
        "" '{}'
    [ "$status" -ne 0 ]
    [ ! -f "$BATS_TEST_TMPDIR/curl-called" ]
}
