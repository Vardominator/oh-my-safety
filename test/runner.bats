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
