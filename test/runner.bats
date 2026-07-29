#!/usr/bin/env bats
# Runner, manifest, and helper tests (lib/core.sh, lib/runner.sh)

setup() {
    load test_helper
    _oms_setup
    # shellcheck source=/dev/null
    source "$OMS_ROOT/lib/runner.sh"
}

@test "json_escape escapes quotes and backslashes" {
    run json_escape 'a"b\c'
    [ "$output" = 'a\"b\\c' ]
}

@test "check_meta extracts manifest fields without sourcing" {
    f="$OMS_ROOT/lib/checks/privacy/routing.sh"
    run check_meta "$f" CHECK_NAME;     [ "$output" = "routing" ]
    run check_meta "$f" CHECK_SEVERITY; [ "$output" = "warn" ]
    run check_meta "$f" CHECK_CATEGORY; [ "$output" = "privacy" ]
    run check_meta "$f" CHECK_REMEDIATION
    [[ "$output" == *"reconnect the VPN"* ]]
}

@test "checks_discover finds built-in privacy and security checks" {
    run checks_discover
    [ "$status" -eq 0 ]
    [[ "$output" == *$'privacy\trouting'* ]]
    [[ "$output" == *$'security\tpersistence-scan'* ]]
    [[ "$output" == *$'security\twallet-guard'* ]]
}

@test "checks_discover skips underscore-prefixed template files" {
    [[ "$(checks_discover)" != *"_template"* ]]
}

@test "_order_categories puts privacy before security before custom" {
    input=$'security\ta\tf\nprivacy\tb\tf\ncustom\tc\tf'
    run bash -c "printf '%s\n' \"\$1\" | { $(declare -f _order_categories); _order_categories; }" _ "$input"
    [ "${lines[0]%%$'\t'*}" = "privacy" ]
    [ "${lines[1]%%$'\t'*}" = "security" ]
    [ "${lines[2]%%$'\t'*}" = "custom" ]
}

@test "_sanitize_field collapses tabs and newlines to spaces" {
    run _sanitize_field "$(printf 'a\tb')"
    [ "$output" = "a b" ]
}

@test "run_one_check persists exact details and remediation for a warning" {
    f="$BATS_TEST_TMPDIR/example-warning.sh"
    cat > "$f" <<'CHECK'
CHECK_NAME="example-warning"
CHECK_DESCRIPTION="Example warning"
CHECK_CATEGORY="custom"
CHECK_PLATFORMS="all"
CHECK_SEVERITY="warn"
CHECK_CONTRACT="2"
CHECK_REQUIRES_NETWORK="false"
CHECK_DOC="docs/example.md"
CHECK_REMEDIATION="Generic remediation."
check_example_warning() {
    print_check_result warn "exact unsafe setting"
    echo "  - fix: turn the setting on   [id: example:setting]"
    CHECK_FINDING_SUMMARY="1 unsafe setting"
    CHECK_RESULT_SEVERITY="warn"
    CHECK_REMEDIATION="Fix the exact item, then recheck."
    return 1
}
CHECK
    OMS_SCAN_RESULTS=""
    OMS_SCAN_DETAILS=""
    OMS_PLATFORM="macos"
    OMS_QUIET=true
    OMS_CONFIG_FLAT_OVERRIDE="notifications.enabled=false"

    run_one_check custom example-warning "$f" || true

    [[ "$OMS_SCAN_RESULTS" == *$'result\tcustom\texample-warning\twarn\twarn\t1 unsafe setting\tFix the exact item, then recheck.\tdocs/example.md'* ]]
    [[ "$OMS_SCAN_DETAILS" == *$'detail\tcustom\texample-warning\t⚠️  exact unsafe setting'* ]]
    [[ "$OMS_SCAN_DETAILS" == *"[id: example:setting]"* ]]
}

@test "checks_list --json emits parseable JSON for the catalog" {
    run bash -c "$OMS_ROOT/bin/oh-my-safety checks --json | python3 -m json.tool >/dev/null"
    [ "$status" -eq 0 ]
}

@test "filtered persistence merges matching rows without replacing full posture" {
    set -o pipefail
    OMS_PLATFORM="macos"
    OMS_SCAN_SOURCE="scan"
    OMS_SCAN_RESULTS=$'result\tprivacy\trouting\tok\tinfo\tVPN route\nresult\tsecurity\tprocess-audit\twarn\twarn\told process finding'
    OMS_SCAN_DETAILS=$'detail\tsecurity\tprocess-audit\told detail'
    _persist_scan_results 1 false

    full="$(state_path last-scan.tsv)"
    original_timestamp="$(_scan_meta "$full" timestamp)"

    OMS_SCAN_SOURCE="recheck"
    OMS_SCAN_RESULTS=$'result\tsecurity\tprocess-audit\tok\tinfo\tclean'
    OMS_SCAN_DETAILS=""
    _persist_scan_results 0 true

    run grep -F $'result\tprivacy\trouting\tok\tinfo\tVPN route' "$full"
    [ "$status" -eq 0 ]
    run grep -F $'result\tsecurity\tprocess-audit\tok\tinfo\tclean' "$full"
    [ "$status" -eq 0 ]
    ! grep -q 'old process finding' "$full"
    [ "$(_scan_meta "$full" timestamp)" = "$original_timestamp" ]
    [ "$(_scan_meta "$full" scope)" = "composite" ]
    [ "$(_scan_meta "$full" exit)" = "0" ]

    partial="$(state_path last-partial-scan.tsv)"
    [ "$(_scan_meta "$partial" source)" = "recheck" ]
    [ "$(_scan_meta "$partial" scope)" = "partial" ]
}

@test "per-check schedule honors CHECK_INTERVAL" {
    f="$BATS_TEST_TMPDIR/scheduled.sh"
    cat > "$f" <<'CHECK'
CHECK_INTERVAL="060"
CHECK
    run _check_is_due security scheduled "$f" 1000
    [ "$status" -eq 0 ]
    schedule_record_epoch security scheduled 1000
    run _check_is_due security scheduled "$f" 1059
    [ "$status" -ne 0 ]
    run _check_is_due security scheduled "$f" 1060
    [ "$status" -eq 0 ]
}

@test "scheduled persistence prunes checks removed from discovery" {
    OMS_PLATFORM="macos"
    OMS_SCAN_SOURCE="scan"
    OMS_SCAN_RESULTS=$'result\tprivacy\trouting\tok\tinfo\told route\nresult\tsecurity\tprocess-audit\tok\tinfo\tclean\nresult\tcustom\tremoved-check\twarn\twarn\tobsolete'
    OMS_SCAN_DETAILS=""
    _persist_scan_results 1 false

    OMS_SCAN_SOURCE="agent"
    OMS_SCAN_RESULTS=$'result\tprivacy\trouting\tok\tinfo\tcurrent route'
    OMS_SCAN_DETAILS=""
    _persist_scan_results 0 scheduled

    full="$(state_path last-scan.tsv)"
    grep -q $'result\tsecurity\tprocess-audit\tok' "$full"
    grep -q $'result\tprivacy\trouting\tok\tinfo\tcurrent route' "$full"
    ! grep -q 'removed-check' "$full"
}

@test "global scan lock rejects overlap and can be released" {
    scan_lock_acquire
    run scan_lock_acquire
    [ "$status" -ne 0 ]
    scan_lock_release
    run scan_lock_acquire
    [ "$status" -eq 0 ]
    scan_lock_release
}

@test "contract-v2 item IDs dedupe independently and reopen after resolution" {
    f="$BATS_TEST_TMPDIR/item-warning.sh"
    cat > "$f" <<'CHECK'
CHECK_NAME="item-warning"
CHECK_DESCRIPTION="Item warning"
CHECK_CATEGORY="custom"
CHECK_PLATFORMS="all"
CHECK_SEVERITY="warn"
CHECK_CONTRACT="2"
CHECK_REQUIRES_NETWORK="false"
check_item_warning() {
    echo "first unsafe item [id: item:1]"
    echo "second unsafe item [id: item:2]"
    CHECK_FINDING_SUMMARY="2 unsafe items"
    return 1
}
CHECK
    OMS_PLATFORM="macos"
    OMS_QUIET=true
    OMS_CONFIG_FLAT_OVERRIDE=$'notifications.enabled=true\nnotifications.min_severity=warn'
    OMS_CONFIG_FLAT_DEFAULT=$'notifications.renotify_interval_hours=4'
    SENT=0
    send_notification() { SENT=$(( SENT + 1 )); }

    OMS_SCAN_RESULTS=""; OMS_SCAN_DETAILS=""
    run_one_check custom item-warning "$f" || true
    [ "$SENT" -eq 1 ]
    [ "$(_notify_last_epoch item-warning item:1)" != "" ]
    [ "$(_notify_last_epoch item-warning item:2)" != "" ]

    cat > "$f" <<'CHECK'
CHECK_NAME="item-warning"
CHECK_DESCRIPTION="Item warning"
CHECK_CATEGORY="custom"
CHECK_PLATFORMS="all"
CHECK_SEVERITY="warn"
CHECK_CONTRACT="2"
CHECK_REQUIRES_NETWORK="false"
check_item_warning() {
    CHECK_FINDING_SUMMARY="clean"
    return 0
}
CHECK
    OMS_SCAN_RESULTS=""; OMS_SCAN_DETAILS=""
    run_one_check custom item-warning "$f" || true
    [ "$SENT" -eq 2 ]
    [ ! -f "$(_notified_file item-warning)" ]

    cat > "$f" <<'CHECK'
CHECK_NAME="item-warning"
CHECK_DESCRIPTION="Item warning"
CHECK_CATEGORY="custom"
CHECK_PLATFORMS="all"
CHECK_SEVERITY="warn"
CHECK_CONTRACT="2"
CHECK_REQUIRES_NETWORK="false"
check_item_warning() {
    echo "first unsafe item [id: item:1]"
    CHECK_FINDING_SUMMARY="1 unsafe item"
    return 1
}
CHECK
    OMS_SCAN_RESULTS=""; OMS_SCAN_DETAILS=""
    run_one_check custom item-warning "$f" || true
    [ "$SENT" -eq 3 ]
}

@test "check execution errors create a critical coverage notification" {
    f="$BATS_TEST_TMPDIR/error-check.sh"
    cat > "$f" <<'CHECK'
CHECK_NAME="error-check"
CHECK_DESCRIPTION="Error check"
CHECK_CATEGORY="custom"
CHECK_PLATFORMS="all"
CHECK_SEVERITY="warn"
CHECK_CONTRACT="2"
CHECK_REQUIRES_NETWORK="false"
check_error_check() {
    CHECK_FINDING_SUMMARY="collector unavailable"
    return 42
}
CHECK
    OMS_PLATFORM="macos"
    OMS_QUIET=true
    OMS_CONFIG_FLAT_OVERRIDE=$'notifications.enabled=true\nnotifications.min_severity=warn'
    OMS_CONFIG_FLAT_DEFAULT=$'notifications.renotify_interval_hours=4'
    SENT=0
    send_notification() { SENT=$(( SENT + 1 )); }
    OMS_SCAN_RESULTS=""; OMS_SCAN_DETAILS=""

    run_one_check custom error-check "$f" || true

    [[ "$OMS_SCAN_RESULTS" == *$'result\tcustom\terror-check\terror\tcritical\tcollector unavailable'* ]]
    [ "$SENT" -eq 1 ]
    [ "$(_notify_last_severity error-check coverage:error-check)" = "critical" ]
}

@test "portable journal bridge is optional and receives the structured scan file" {
    load_config
    fake="$BATS_TEST_TMPDIR/oh-my-safety-agent"
    cat > "$fake" <<'SH'
#!/bin/bash
printf '%s\n' "$*" > "$OMS_BRIDGE_ARGS"
printf '{"schema":"io.oh-my-safety/scan-ingest","schema_version":1}\n'
SH
    chmod +x "$fake"
    export OMS_AGENT_CORE_BIN="$fake"
    export OMS_BRIDGE_ARGS="$BATS_TEST_TMPDIR/bridge-args"
    snapshot="$BATS_TEST_TMPDIR/snapshot.tsv"
    printf 'schema\t1\n' > "$snapshot"

    _journal_ingest_scan "$snapshot"
    grep -q -- '--ingest-scan' "$OMS_BRIDGE_ARGS"
    grep -q -- "$snapshot" "$OMS_BRIDGE_ARGS"
    grep -q -- '--profile personal-balanced' "$OMS_BRIDGE_ARGS"
}

@test "portable journal failure does not replace the TSV compatibility path" {
    load_config
    fake="$BATS_TEST_TMPDIR/failing-agent"
    cat > "$fake" <<'SH'
#!/bin/bash
exit 1
SH
    chmod +x "$fake"
    export OMS_AGENT_CORE_BIN="$fake"
    snapshot="$BATS_TEST_TMPDIR/snapshot.tsv"
    printf 'schema\t1\n' > "$snapshot"

    run _journal_ingest_scan "$snapshot"
    [ "$status" -ne 0 ]
    grep -q $'\tjournal.ingest_failed\t' "$(state_path log/events.tsv)"
}
