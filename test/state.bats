#!/usr/bin/env bats
# Baseline, allowlist, and notification-dedupe tests (lib/state.sh, lib/allowlist.sh)

setup() { load test_helper; _oms_setup; }

@test "baseline save then load round-trips entries" {
    printf 'a\nb\nc\n' | baseline_save t
    run baseline_load t
    [ "$status" -eq 0 ]
    [[ "$output" == *"a"* && "$output" == *"b"* && "$output" == *"c"* ]]
    [[ "$output" != *"#"* ]]   # header stripped
}

@test "baseline_diff: no drift returns 0 and empty" {
    printf 'a\nb\nc\n' | baseline_save t
    _diff() { printf 'a\nb\nc\n' | baseline_diff t; }
    run _diff
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "baseline_diff: reports additions and removals" {
    printf 'a\nb\nc\n' | baseline_save t
    _diff() { printf 'b\nc\nd\n' | baseline_diff t; }
    run _diff
    [ "$status" -eq 1 ]
    [[ "$output" == *"+d"* ]]
    [[ "$output" == *"-a"* ]]
}

@test "baseline stage_pending then approve promotes it" {
    printf 'a\n' | baseline_save t
    printf 'a\nb\n' | baseline_stage_pending t
    baseline_approve t
    run baseline_load t
    [[ "$output" == *"b"* ]]
}

@test "baseline_exists reflects reality; reset removes it" {
    run baseline_exists t; [ "$status" -ne 0 ]
    printf 'a\n' | baseline_save t
    run baseline_exists t; [ "$status" -eq 0 ]
    baseline_reset t
    run baseline_exists t; [ "$status" -ne 0 ]
}

@test "allowlist_match: exact and glob entries match, others do not" {
    allowlist_add mycheck 'exact:1'
    allowlist_add mycheck 'glob:*'
    run allowlist_match mycheck 'exact:1';      [ "$status" -eq 0 ]
    run allowlist_match mycheck 'glob:anything'; [ "$status" -eq 0 ]
    run allowlist_match mycheck 'nope';          [ "$status" -ne 0 ]
    run allowlist_match other 'exact:1';         [ "$status" -ne 0 ]
}

@test "notification dedupe: record then read back the epoch" {
    _notify_record c1 'id:1' warn 12345
    run _notify_last_epoch c1 'id:1'; [ "$output" = "12345" ]
    run _notify_last_epoch c1 'id:2'; [ -z "$output" ]
    _notify_record c1 'id:1' critical 67890   # refresh, not duplicate
    run _notify_last_epoch c1 'id:1'; [ "$output" = "67890" ]
}

@test "state dir is created mode 700" {
    state_dir >/dev/null
    run stat -f '%Lp' "$OMS_STATE_DIR"
    [ "$output" = "700" ]
}
