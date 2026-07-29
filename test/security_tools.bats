#!/usr/bin/env bats
# Privacy and result-mapping tests for the built-in scanner/exposure wrappers.

setup() {
    load test_helper
    _oms_setup
    # shellcheck source=/dev/null
    source "$OMS_ROOT/lib/runner.sh"
    # shellcheck source=/dev/null
    source "$OMS_ROOT/lib/cmd/organization.sh"
    # shellcheck source=/dev/null
    source "$OMS_ROOT/lib/cmd/security-tools.sh"
    # shellcheck source=/dev/null
    source "$OMS_ROOT/lib/cmd/exposure.sh"
    # shellcheck source=/dev/null
    source "$OMS_ROOT/lib/checks/security/local-secret-scan.sh"
    # shellcheck source=/dev/null
    source "$OMS_ROOT/lib/checks/security/breach-exposure.sh"
    load_config

    OMS_PLATFORM="linux"
    OMS_QUIET=true
    OMS_SCAN_SOURCE="scan"
    OMS_DEEP=true
    export OMS_PLATFORM OMS_QUIET OMS_SCAN_SOURCE OMS_DEEP

    OMS_FAKE_AGENT="$BATS_TEST_TMPDIR/oh-my-safety-agent"
    OMS_FAKE_AGENT_ARGS="$BATS_TEST_TMPDIR/agent-args"
    OMS_FAKE_AGENT_STDIN="$BATS_TEST_TMPDIR/agent-stdin"
    export OMS_FAKE_AGENT_ARGS OMS_FAKE_AGENT_STDIN
    : > "$OMS_FAKE_AGENT_ARGS"
    : > "$OMS_FAKE_AGENT_STDIN"
    cat > "$OMS_FAKE_AGENT" <<'SH'
#!/bin/bash
{
    printf 'call'
    for argument in "$@"; do
        printf '\t<%s>' "$argument"
    done
    printf '\n'
} >> "$OMS_FAKE_AGENT_ARGS"
input="$(cat)"
printf '%s\n' "$input" >> "$OMS_FAKE_AGENT_STDIN"
if [[ -n "${OMS_FAKE_AGENT_FAIL_INPUT:-}" &&
      "$input" == "$OMS_FAKE_AGENT_FAIL_INPUT" ]]; then
    exit 9
fi
printf '%s\n' "${OMS_FAKE_AGENT_RESPONSE:-{}}"
exit "${OMS_FAKE_AGENT_RC:-0}"
SH
    chmod +x "$OMS_FAKE_AGENT"
    OMS_AGENT_CORE_BIN="$OMS_FAKE_AGENT"
    export OMS_AGENT_CORE_BIN
}

@test "password exposure sends the password only on stdin and preserves found exit zero" {
    OMS_TEST_PASSWORD="password-value-that-must-stay-private"
    OMS_FAKE_AGENT_RESPONSE='{"schema":"io.oh-my-safety/pwned-password-check","schema_version":1,"result":{"state":"found","pwned_count":12}}'
    export OMS_TEST_PASSWORD OMS_FAKE_AGENT_RESPONSE
    _exposure_read_secret() {
        printf '%s\n' "$OMS_TEST_PASSWORD"
    }

    run _exposure_password --allow-network

    [ "$status" -eq 0 ]
    [[ "$output" == *'"state":"found"'* ]]
    [[ "$output" != *"$OMS_TEST_PASSWORD"* ]]
    grep -q -- '<--check-pwned-password>' "$OMS_FAKE_AGENT_ARGS"
    grep -q -- '<--allow-network>' "$OMS_FAKE_AGENT_ARGS"
    ! grep -Fq -- "$OMS_TEST_PASSWORD" "$OMS_FAKE_AGENT_ARGS"
    [ "$(cat "$OMS_FAKE_AGENT_STDIN")" = "$OMS_TEST_PASSWORD" ]
}

@test "account exposure accepts lowercase env names without forwarding values in argv" {
    oms_test_email_env="person-private@example.com"
    oms_test_key_env="0123456789abcdef0123456789abcdef"
    OMS_FAKE_AGENT_RESPONSE='{"schema":"io.oh-my-safety/breached-account-check","schema_version":1,"result":{"state":"found","breaches":[{"Name":"Example"}]}}'
    export oms_test_email_env oms_test_key_env OMS_FAKE_AGENT_RESPONSE

    run _exposure_account --allow-network \
        --email-env oms_test_email_env --api-key-env oms_test_key_env

    [ "$status" -eq 0 ]
    [[ "$output" == *'"state":"found"'* ]]
    [[ "$output" != *"$oms_test_email_env"* ]]
    [[ "$output" != *"$oms_test_key_env"* ]]
    grep -q -- '<--hibp-api-key-env>' "$OMS_FAKE_AGENT_ARGS"
    grep -q -- '<oms_test_key_env>' "$OMS_FAKE_AGENT_ARGS"
    ! grep -Fq -- "$oms_test_email_env" "$OMS_FAKE_AGENT_ARGS"
    ! grep -Fq -- "$oms_test_key_env" "$OMS_FAKE_AGENT_ARGS"
    [ "$(cat "$OMS_FAKE_AGENT_STDIN")" = "$oms_test_email_env" ]
}

@test "exposure misuse errors never echo accidental password or email values" {
    password="accidental-private-password"
    email="accidental-private@example.com"

    run _exposure_password "$password"
    [ "$status" -eq 2 ]
    [[ "$output" != *"$password"* ]]

    run _exposure_account --allow-network "$email"
    [ "$status" -eq 2 ]
    [[ "$output" != *"$email"* ]]

    run cmd_exposure "$email"
    [ "$status" -eq 2 ]
    [[ "$output" != *"$email"* ]]

    run cmd_exposure contracts "$password"
    [ "$status" -eq 2 ]
    [[ "$output" != *"$password"* ]]
    [ ! -s "$OMS_FAKE_AGENT_ARGS" ]
}

@test "local secret agent success maps redacted findings into status and history" {
    scan_root="$BATS_TEST_TMPDIR/scan-root"
    mkdir -p "$scan_root"
    raw_secret="raw-secret-value-that-must-never-persist"
    printf 'API_KEY=%s\n' "$raw_secret" > "$scan_root/credentials.env"
    OMS_FAKE_AGENT_RESPONSE='{"schema":"io.oh-my-safety/secret-scan","schema_version":1,"scanner_id":"local-secret-scanner","findings":[{"detector_id":"secret.assignment","path":"redacted-path","line":1,"fingerprint":"hmac-sha256:0123","redacted_excerpt":"api_key = [REDACTED]"}],"coverage":[],"stats":{}}'
    export OMS_FAKE_AGENT_RESPONSE
    OMS_CONFIG_FLAT_OVERRIDE="$(printf '%s\n' \
        'notifications.enabled=false' \
        'journal.enabled=false' \
        'checks.security.local_secret_scan.enabled=true' \
        "checks.security.local_secret_scan.scan_roots=$scan_root")"

    OMS_SCAN_RESULTS=""
    OMS_SCAN_DETAILS=""
    rc=0
    run_one_check security local-secret-scan \
        "$OMS_ROOT/lib/checks/security/local-secret-scan.sh" || rc=$?

    [ "$rc" -eq 1 ]
    [[ "$OMS_SCAN_RESULTS" == *$'result\tsecurity\tlocal-secret-scan\twarn\twarn\tpotential credential material found'* ]]
    [[ "$OMS_SCAN_DETAILS" == *'[id: local-secret-scan:credential]'* ]]
    [[ "$OMS_SCAN_RESULTS$OMS_SCAN_DETAILS" != *"$raw_secret"* ]]
    ! grep -Fq -- "$raw_secret" "$OMS_FAKE_AGENT_ARGS"

    _persist_scan_results 1 false
    _append_scan_log
    ! grep -R -Fq -- "$raw_secret" "$OMS_STATE_DIR"
}

@test "breached-account agent found exit zero becomes a generic check finding" {
    oms_monitored_email="private-account@example.com"
    oms_hibp_key="abcdef0123456789abcdef0123456789"
    OMS_FAKE_AGENT_RESPONSE='{"schema":"io.oh-my-safety/breached-account-check","schema_version":1,"contract":{"id":"hibp-breached-account"},"result":{"state":"found","breaches":[{"Name":"Example"}]}}'
    export oms_monitored_email oms_hibp_key OMS_FAKE_AGENT_RESPONSE
    OMS_CONFIG_FLAT_OVERRIDE="$(printf '%s\n' \
        'notifications.enabled=false' \
        'journal.enabled=false' \
        'checks.security.breach_exposure.enabled=true' \
        'checks.security.breach_exposure.account_envs=oms_monitored_email' \
        'checks.security.breach_exposure.api_key_env=oms_hibp_key')"

    OMS_SCAN_RESULTS=""
    OMS_SCAN_DETAILS=""
    rc=0
    run_one_check security breach-exposure \
        "$OMS_ROOT/lib/checks/security/breach-exposure.sh" || rc=$?

    [ "$rc" -eq 1 ]
    [[ "$OMS_SCAN_RESULTS" == *$'result\tsecurity\tbreach-exposure\twarn\twarn\t1 monitored account(s) have known breach exposure'* ]]
    [[ "$OMS_SCAN_DETAILS" == *'[id: breach-exposure:oms_monitored_email]'* ]]
    [[ "$OMS_SCAN_RESULTS$OMS_SCAN_DETAILS" != *"$oms_monitored_email"* ]]
    [[ "$OMS_SCAN_RESULTS$OMS_SCAN_DETAILS" != *"$oms_hibp_key"* ]]
    ! grep -Fq -- "$oms_monitored_email" "$OMS_FAKE_AGENT_ARGS"
    ! grep -Fq -- "$oms_hibp_key" "$OMS_FAKE_AGENT_ARGS"
    [ "$(cat "$OMS_FAKE_AGENT_STDIN")" = "$oms_monitored_email" ]

    _persist_scan_results 1 false
    _append_scan_log
    ! grep -R -Fq -- "$oms_monitored_email" "$OMS_STATE_DIR"
    ! grep -R -Fq -- "$oms_hibp_key" "$OMS_STATE_DIR"
}

@test "a valid breach finding remains active when another account lookup fails" {
    oms_found_email="found-private@example.com"
    oms_failed_email="failed-private@example.com"
    oms_hibp_key="abcdef0123456789abcdef0123456789"
    OMS_FAKE_AGENT_FAIL_INPUT="$oms_failed_email"
    OMS_FAKE_AGENT_RESPONSE='{"schema":"io.oh-my-safety/breached-account-check","schema_version":1,"result":{"state":"found","breaches":[{"Name":"Example"}]}}'
    export oms_found_email oms_failed_email oms_hibp_key
    export OMS_FAKE_AGENT_FAIL_INPUT OMS_FAKE_AGENT_RESPONSE
    OMS_CONFIG_FLAT_OVERRIDE="$(printf '%s\n' \
        'notifications.enabled=false' \
        'checks.security.breach_exposure.enabled=true' \
        'checks.security.breach_exposure.account_envs=oms_found_email' \
        'checks.security.breach_exposure.account_envs=oms_failed_email' \
        'checks.security.breach_exposure.api_key_env=oms_hibp_key')"

    OMS_SCAN_RESULTS=""
    OMS_SCAN_DETAILS=""
    rc=0
    run_one_check security breach-exposure \
        "$OMS_ROOT/lib/checks/security/breach-exposure.sh" || rc=$?

    [ "$rc" -eq 1 ]
    [[ "$OMS_SCAN_RESULTS" == *'1 monitored account(s) have known breach exposure; 1 lookup(s) incomplete'* ]]
    [[ "$OMS_SCAN_DETAILS" == *'[id: breach-exposure:oms_found_email]'* ]]
    [[ "$OMS_SCAN_DETAILS" == *'[id: breach-exposure:coverage]'* ]]
    [[ "$OMS_SCAN_RESULTS$OMS_SCAN_DETAILS" != *"$oms_found_email"* ]]
    [[ "$OMS_SCAN_RESULTS$OMS_SCAN_DETAILS" != *"$oms_failed_email"* ]]
    [[ "$OMS_SCAN_RESULTS$OMS_SCAN_DETAILS" != *"$oms_hibp_key"* ]]
}

@test "malformed or unsupported agent output is never treated as a clean check" {
    scan_root="$BATS_TEST_TMPDIR/scan-root"
    mkdir -p "$scan_root"
    OMS_CONFIG_FLAT_OVERRIDE="$(printf '%s\n' \
        'checks.security.local_secret_scan.scan_roots='"$scan_root" \
        'checks.security.breach_exposure.account_envs=oms_monitored_email' \
        'checks.security.breach_exposure.api_key_env=oms_hibp_key')"
    oms_monitored_email="private-account@example.com"
    oms_hibp_key="abcdef0123456789abcdef0123456789"
    export oms_monitored_email oms_hibp_key

    OMS_FAKE_AGENT_RESPONSE='{}'
    export OMS_FAKE_AGENT_RESPONSE
    run check_local_secret_scan
    [ "$status" -eq 42 ]
    [[ "$output" != *'No credential material found'* ]]

    run check_breach_exposure
    [ "$status" -eq 42 ]
    [[ "$output" != *'No configured account appeared'* ]]

    OMS_FAKE_AGENT_RESPONSE='{"schema":"io.oh-my-safety/breached-account-check","schema_version":1,"result":{"state":"unsupported","unsupported":{"reason":"offline_mode"}}}'
    export OMS_FAKE_AGENT_RESPONSE
    run check_breach_exposure
    [ "$status" -eq 42 ]
    [[ "$output" != *'No configured account appeared'* ]]
    [[ "$output" != *"$oms_monitored_email"* ]]
    [[ "$output" != *"$oms_hibp_key"* ]]
}
