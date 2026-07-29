#!/usr/bin/env bats

setup() { load test_helper; _oms_setup; }

@test "profile set persists an atomic preset and show reports capabilities" {
    source "$OMS_ROOT/lib/cmd/profile.sh"
    run cmd_profile set airgapped-high-assurance
    [ "$status" -eq 0 ]
    [[ "$output" == *"Connectivity:  airgapped"* ]]
    load_config
    [ "$(config_get profile.name)" = "airgapped-high-assurance" ]
    [ "$(config_get monitoring.interval)" = "60" ]
    [ "$(config_get categories.privacy.enabled)" = "false" ]
    [ "$(config_get notifications.external.enabled)" = "false" ]
}

@test "profile rejects an unknown preset without changing configuration" {
    source "$OMS_ROOT/lib/cmd/profile.sh"
    before="$(config_get profile.name)"
    run cmd_profile set definitely-not-a-profile
    [ "$status" -ne 0 ]
    [ "$(config_get profile.name)" = "$before" ]
}

@test "airgapped connectivity forces one-off scans into offline mode" {
    source "$OMS_ROOT/lib/cmd/scan.sh"
    config_set profile.connectivity airgapped
    load_platform() { :; }
    run_scan() { echo "offline=${OMS_OFFLINE:-false} args=$*"; }
    run cmd_scan --deep
    [ "$status" -eq 0 ]
    [[ "$output" == *"offline=true args=--deep"* ]]
}

@test "event history records safe TSV and emits valid JSON" {
    source "$OMS_ROOT/lib/events.sh"
    source "$OMS_ROOT/lib/cmd/history.sh"
    event_append finding.observed warn scanner routing $'line\twith\nbreak' scan-1
    run cmd_history --json --limit 1
    [ "$status" -eq 0 ]
    printf '%s' "$output" | python3 -m json.tool >/dev/null
    [[ "$output" == *'"type":"finding.observed"'* ]]
    [[ "$output" == *'"summary":"line with break"'* ]]
}

@test "completed scan appends every result and a correlated completion event" {
    source "$OMS_ROOT/lib/runner.sh"
    OMS_SCAN_SOURCE="test"
    OMS_PLATFORM="linux"
    OMS_SCAN_RESULTS=$'result\tsecurity\tone\tok\tinfo\tclean\t\t\nresult\tsecurity\ttwo\twarn\twarn\tchanged\tfix\tguide'
    _append_scan_log
    rows="$(event_read_recent 10)"
    [[ "$rows" == *$'\tcheck.passed\tinfo\ttest\tsecurity/one\tclean\t'* ]]
    [[ "$rows" == *$'\tfinding.observed\twarn\ttest\tsecurity/two\tchanged\t'* ]]
    [[ "$rows" == *$'\tscan.completed\twarn\ttest\tlinux\t1 ok, 1 warn'* ]]
}

@test "history validates format and limit" {
    source "$OMS_ROOT/lib/events.sh"
    source "$OMS_ROOT/lib/cmd/history.sh"
    run cmd_history --limit nope
    [ "$status" -eq 3 ]
    run cmd_history --format xml
    [ "$status" -eq 3 ]
}
