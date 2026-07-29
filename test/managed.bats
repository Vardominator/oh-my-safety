#!/usr/bin/env bats

setup() {
    load test_helper
    _oms_setup
    source "$OMS_ROOT/lib/runner.sh"
    source "$OMS_ROOT/lib/cmd/profile.sh"
    source "$OMS_ROOT/lib/cmd/organization.sh"
    load_config
}

managed_fixture() {
    cat <<'EOF'
schema	io.oh-my-safety/managed-policy-flat	1
policy_id	engineering
revision	7
profile	managed-workstation
cadence_scan_interval_seconds	120
cadence_jitter_seconds	15
reporting_enabled	true
reporting_sync_interval_seconds	300
remediation	prompt
check	hardening-posture	true
check	wallet-guard	false
EOF
}

@test "verified managed policy maps to a highest-precedence bounded config layer" {
    run _managed_policy_tsv_to_config "$(managed_fixture)"
    [ "$status" -eq 0 ]
    [[ "$output" == *"profile.name=managed-workstation"* ]]
    [[ "$output" == *"organization.policy.revision=7"* ]]
    [[ "$output" == *"managed.check.hardening-posture=true"* ]]
    [[ "$output" == *"remediation.mode=ask"* ]]

    OMS_CONFIG_FLAT_MANAGED="$output"
    OMS_CONFIG_FLAT_OVERRIDE=$'profile.name=personal-balanced'
    [ "$(config_get profile.name)" = "managed-workstation" ]
}

@test "managed policy parser rejects unknown or malformed rows" {
    run _managed_policy_tsv_to_config "$(managed_fixture)
command	rm -rf /"
    [ "$status" -ne 0 ]

    run _managed_policy_tsv_to_config "$(managed_fixture | sed 's/reporting_enabled	true/reporting_enabled	maybe/')"
    [ "$status" -ne 0 ]

    run _managed_policy_tsv_to_config "$(managed_fixture)
check	hardening-posture	false"
    [ "$status" -ne 0 ]

    run _managed_policy_tsv_to_config "$(managed_fixture | sed '/^check	/d')"
    [ "$status" -ne 0 ]

    run _managed_policy_tsv_to_config "$(managed_fixture | sed 's/cadence_scan_interval_seconds	120/cadence_scan_interval_seconds	2678401/')"
    [ "$status" -ne 0 ]
}

@test "load_config activates only a locally enabled verified policy snapshot" {
    state="$(managed_state_path)"
    mkdir -p "$(dirname "$state")"
    printf '{}\n' > "$state"
    chmod 600 "$state"
    fake="$BATS_TEST_TMPDIR/agent"
    cat > "$fake" <<'SH'
#!/bin/bash
cat <<'EOF'
schema	io.oh-my-safety/managed-policy-flat	1
policy_id	engineering
revision	7
profile	managed-workstation
cadence_scan_interval_seconds	120
cadence_jitter_seconds	15
reporting_enabled	true
reporting_sync_interval_seconds	300
remediation	observe
check	hardening-posture	true
EOF
SH
    chmod +x "$fake"
    export OMS_AGENT_CORE_BIN="$fake"

    config_set organization.enabled true
    load_config
    [ "$(config_get organization.policy.id)" = "engineering" ]
    [ "$(config_get profile.management)" = "managed" ]

    config_set organization.enabled false
    load_config
    [ "$(config_get organization.policy.id missing)" = "missing" ]
}

@test "verified policy can require a known locally disabled check" {
    f="$BATS_TEST_TMPDIR/managed-check.sh"
    cat > "$f" <<'CHECK'
CHECK_NAME="managed-check"
CHECK_DESCRIPTION="Managed check"
CHECK_CATEGORY="security"
CHECK_PLATFORMS="all"
CHECK_SEVERITY="warn"
CHECK_CONTRACT="2"
CHECK_REQUIRES_NETWORK="false"
check_managed_check() {
    print_check_result pass "managed policy required this check"
    CHECK_FINDING_SUMMARY="healthy"
    return 0
}
CHECK
    OMS_PLATFORM="linux"
    OMS_QUIET=true
    OMS_CONFIG_FLAT_MANAGED=$'managed.check.managed-check=true'
    OMS_CONFIG_FLAT_OVERRIDE=$'categories.security.enabled=false\nchecks.security.managed_check.enabled=false'
    OMS_SCAN_RESULTS=""
    OMS_SCAN_DETAILS=""

    run_one_check security managed-check "$f"
    [[ "$OMS_SCAN_RESULTS" == *$'result\tsecurity\tmanaged-check\tok'* ]]
}

@test "verified policy can disable a locally enabled check without executing it" {
    f="$BATS_TEST_TMPDIR/managed-disabled-check.sh"
    cat > "$f" <<'CHECK'
CHECK_NAME="managed-disabled-check"
CHECK_DESCRIPTION="Managed disabled check"
CHECK_CATEGORY="security"
CHECK_PLATFORMS="all"
CHECK_SEVERITY="warn"
CHECK_CONTRACT="2"
CHECK_REQUIRES_NETWORK="false"
check_managed_disabled_check() {
    printf 'executed\n' > "$OMS_MANAGED_CALLED"
    print_check_result pass "should not execute"
    return 0
}
CHECK
    export OMS_MANAGED_CALLED="$BATS_TEST_TMPDIR/called"
    OMS_PLATFORM="linux"
    OMS_QUIET=true
    OMS_CONFIG_FLAT_MANAGED=$'managed.check.managed-disabled-check=false'
    OMS_CONFIG_FLAT_OVERRIDE=$'categories.security.enabled=true\nchecks.security.managed_disabled_check.enabled=true'
    OMS_SCAN_RESULTS=""
    OMS_SCAN_DETAILS=""

    run_one_check security managed-disabled-check "$f"
    [[ "$OMS_SCAN_RESULTS" == *$'result\tsecurity\tmanaged-disabled-check\tskip'* ]]
    [ ! -e "$OMS_MANAGED_CALLED" ]
}

@test "signed scan interval is a hard maximum for required checks" {
    slow="$BATS_TEST_TMPDIR/slow-check.sh"
    fast="$BATS_TEST_TMPDIR/fast-check.sh"
    printf 'CHECK_INTERVAL="3600"\n' > "$slow"
    printf 'CHECK_INTERVAL="30"\n' > "$fast"
    OMS_CONFIG_FLAT_MANAGED=$'managed.check.required=true\norganization.policy.scan_interval_seconds=120'

    [ "$(_check_interval_seconds "$slow" required)" -eq 120 ]
    [ "$(_check_interval_seconds "$fast" required)" -eq 30 ]
}

@test "airgapped connectivity prevents an enrolled managed sync" {
    state="$(managed_state_path)"
    mkdir -p "$(dirname "$state")"
    printf '{}\n' > "$state"
    chmod 600 "$state"
    fake="$BATS_TEST_TMPDIR/agent"
    cat > "$fake" <<'SH'
#!/bin/bash
printf 'called\n' > "$OMS_MANAGED_CALLED"
SH
    chmod +x "$fake"
    export OMS_AGENT_CORE_BIN="$fake"
    export OMS_MANAGED_CALLED="$BATS_TEST_TMPDIR/called"
    OMS_CONFIG_FLAT_OVERRIDE=$'organization.enabled=true\nprofile.management=managed\nprofile.connectivity=airgapped'
    OMS_CONFIG_FLAT_MANAGED=$'profile.management=managed\nprofile.connectivity=connected\norganization.policy.reporting_enabled=true\norganization.policy.sync_interval_seconds=60'

    managed_sync_if_due
    [ ! -e "$OMS_MANAGED_CALLED" ]
}

@test "managed sync keeps an in-memory retry gate when schedule state is unwritable" {
    state="$(managed_state_path)"
    mkdir -p "$(dirname "$state")"
    printf '{}\n' > "$state"
    chmod 600 "$state"
    fake="$BATS_TEST_TMPDIR/agent"
    cat > "$fake" <<'SH'
#!/bin/bash
printf 'called\n' >> "$OMS_MANAGED_CALLED"
SH
    chmod +x "$fake"
    export OMS_AGENT_CORE_BIN="$fake"
    export OMS_MANAGED_CALLED="$BATS_TEST_TMPDIR/called"
    OMS_CONFIG_FLAT_OVERRIDE=$'organization.enabled=true\nprofile.management=managed\nprofile.connectivity=connected'
    OMS_CONFIG_FLAT_MANAGED=$'profile.management=managed\nprofile.connectivity=connected\norganization.policy.reporting_enabled=true\norganization.policy.sync_interval_seconds=60'
    _OMS_MANAGED_SYNC_LAST_ATTEMPT=0
    schedule_last_epoch() { printf '0'; }
    schedule_record_epoch() { return 1; }

    managed_sync_if_due
    managed_sync_if_due
    [ "$(wc -l < "$OMS_MANAGED_CALLED" | tr -d ' ')" -eq 1 ]
}

@test "reporting-disabled policy still polls for policy updates at local cadence" {
    state="$(managed_state_path)"
    mkdir -p "$(dirname "$state")"
    printf '{}\n' > "$state"
    chmod 600 "$state"
    fake="$BATS_TEST_TMPDIR/agent"
    cat > "$fake" <<'SH'
#!/bin/bash
printf 'called\n' > "$OMS_MANAGED_CALLED"
SH
    chmod +x "$fake"
    export OMS_AGENT_CORE_BIN="$fake"
    export OMS_MANAGED_CALLED="$BATS_TEST_TMPDIR/called"
    OMS_CONFIG_FLAT_OVERRIDE=$'organization.enabled=true\norganization.sync_interval_seconds=60\nprofile.management=managed\nprofile.connectivity=connected'
    OMS_CONFIG_FLAT_MANAGED=$'profile.management=managed\nprofile.connectivity=connected\norganization.policy.reporting_enabled=false\norganization.policy.sync_interval_seconds=0'
    _OMS_MANAGED_SYNC_LAST_ATTEMPT=0
    schedule_last_epoch() { printf '0'; }

    managed_sync_if_due
    [ -e "$OMS_MANAGED_CALLED" ]
}

@test "config reload retains the last verified managed snapshot on transient failure" {
    state="$(managed_state_path)"
    mkdir -p "$(dirname "$state")"
    printf '{}\n' > "$state"
    chmod 600 "$state"
    fake="$BATS_TEST_TMPDIR/agent"
    cat > "$fake" <<'SH'
#!/bin/bash
[[ ! -e "$OMS_MANAGED_FAIL" ]] || exit 1
cat <<'EOF'
schema	io.oh-my-safety/managed-policy-flat	1
policy_id	retained
revision	1
profile	managed-workstation
cadence_scan_interval_seconds	120
cadence_jitter_seconds	0
reporting_enabled	true
reporting_sync_interval_seconds	300
remediation	observe
check	hardening-posture	true
EOF
SH
    chmod +x "$fake"
    export OMS_AGENT_CORE_BIN="$fake"
    export OMS_MANAGED_FAIL="$BATS_TEST_TMPDIR/fail"

    config_set organization.enabled true
    load_config
    [ "$(config_get organization.policy.id)" = "retained" ]
    touch "$OMS_MANAGED_FAIL"
    load_config
    [ "$(config_get organization.policy.id)" = "retained" ]
}

@test "organization enrollment rejects unsafe token environment names before invoking agent" {
    fake="$BATS_TEST_TMPDIR/agent"
    cat > "$fake" <<'SH'
#!/bin/bash
printf 'called\n' > "$OMS_MANAGED_CALLED"
SH
    chmod +x "$fake"
    export OMS_AGENT_CORE_BIN="$fake"
    export OMS_MANAGED_CALLED="$BATS_TEST_TMPDIR/called"

    run _organization_enroll \
        --url https://controller.example.test \
        --policy-key AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA \
        --token-env $'TOKEN\norganization.enabled=false'
    [ "$status" -eq 2 ]
    [ ! -e "$OMS_MANAGED_CALLED" ]
}

@test "organization enrollment passes only the token environment name and selects a managed profile" {
    fake="$BATS_TEST_TMPDIR/agent"
    cat > "$fake" <<'SH'
#!/bin/bash
printf '%s\n' "$*" > "$OMS_MANAGED_ARGS"
printf '{"enrolled":true}\n'
SH
    chmod +x "$fake"
    export OMS_AGENT_CORE_BIN="$fake"
    export OMS_MANAGED_ARGS="$BATS_TEST_TMPDIR/args"
    export OMS_ENROLLMENT_TOKEN="one-time-secret-that-must-not-be-an-argument"

    _organization_enroll \
        --url https://controller.example.test \
        --policy-key AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >/dev/null
    grep -q -- '--enrollment-token-env OMS_ENROLLMENT_TOKEN' "$OMS_MANAGED_ARGS"
    ! grep -q 'one-time-secret' "$OMS_MANAGED_ARGS"
    [ "$(config_get organization.enabled)" = "true" ]
    [ "$(config_get profile.name)" = "managed-workstation" ]
}
