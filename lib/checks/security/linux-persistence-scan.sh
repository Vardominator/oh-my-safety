#!/bin/bash
# oh-my-safety - detect Linux persistence drift using a local baseline
CHECK_NAME="linux-persistence-scan"
CHECK_DESCRIPTION="Flags new Linux systemd, cron, autostart, shell-startup, and preload persistence"
CHECK_CATEGORY="security"
CHECK_PLATFORMS="linux"
CHECK_SEVERITY="critical"
CHECK_CONTRACT="2"
CHECK_REQUIRES_NETWORK="false"
CHECK_INTERVAL="600"
CHECK_DOC="docs/checks/security/linux-persistence-scan.md"
CHECK_REMEDIATION="Remove an unexpected startup mechanism. If it is trusted, approve the pending baseline or ignore its stable finding ID."

_lps_hash_file() {
    local path="$1" digest
    [[ -f "$path" ]] || return 0
    digest="$(oms_sha256 "$path" 2>/dev/null)"
    [[ -n "$digest" ]] && printf 'startup-file|%s|%s\n' "$path" "$digest"
}

_lps_collect() {
    local path unit

    for path in \
        "$HOME"/.config/autostart/*.desktop \
        "$HOME"/.config/systemd/user/*.service \
        "$HOME"/.config/systemd/user/*.timer \
        /etc/systemd/system/*.service \
        /etc/systemd/system/*.timer \
        /usr/local/lib/systemd/system/*.service \
        /usr/local/lib/systemd/system/*.timer; do
        [[ -f "$path" ]] || continue
        printf 'unit-file|%s\n' "$path"
    done

    if command -v systemctl >/dev/null 2>&1; then
        systemctl --user list-unit-files --state=enabled --no-legend --no-pager 2>/dev/null |
            awk 'NF {print "user-unit|"$1}'
        systemctl list-unit-files --state=enabled --no-legend --no-pager 2>/dev/null |
            awk 'NF {print "system-unit|"$1}'
    fi

    crontab -l 2>/dev/null |
        grep -vE '^[[:space:]]*(#|$)' |
        while IFS= read -r unit; do
            printf 'user-cron|%s\n' "$unit"
        done

    for path in /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*; do
        [[ -f "$path" ]] || continue
        printf 'system-cron|%s\n' "$path"
    done

    for path in "$HOME/.profile" "$HOME/.bash_profile" "$HOME/.bashrc" "$HOME/.zprofile" "$HOME/.zshrc"; do
        _lps_hash_file "$path"
    done

    [[ -s /etc/ld.so.preload ]] && printf 'dynamic-preload|/etc/ld.so.preload\n'
}

_lps_label() {
    case "$1" in
        unit-file\|*) _LPS_HUMAN="unit file: ${1#unit-file|}"; _LPS_SEV="warn" ;;
        user-unit\|*) _LPS_HUMAN="enabled user unit: ${1#user-unit|}"; _LPS_SEV="warn" ;;
        system-unit\|*) _LPS_HUMAN="enabled system unit: ${1#system-unit|}"; _LPS_SEV="warn" ;;
        user-cron\|*) _LPS_HUMAN="user cron entry: ${1#user-cron|}"; _LPS_SEV="warn" ;;
        system-cron\|*) _LPS_HUMAN="system cron file: ${1#system-cron|}"; _LPS_SEV="warn" ;;
        startup-file\|*)
            _LPS_HUMAN="shell startup file changed: ${1#startup-file|}"
            _LPS_HUMAN="${_LPS_HUMAN%|*}"
            _LPS_SEV="warn"
            ;;
        dynamic-preload\|*)
            _LPS_HUMAN="dynamic linker preload is configured: ${1#dynamic-preload|}"
            _LPS_SEV="critical"
            ;;
        *) _LPS_HUMAN="$1"; _LPS_SEV="warn" ;;
    esac
}

check_linux_persistence_scan() {
    local current drift added removed entry count=0 max_sev="warn"
    current="$(_lps_collect | sort -u)"

    if ! baseline_exists "$CHECK_NAME"; then
        printf '%s\n' "$current" | baseline_save "$CHECK_NAME"
        print_check_result pass "Baseline recorded ($(printf '%s\n' "$current" | grep -c .) persistence item(s)); review it with 'oh-my-safety baseline show $CHECK_NAME'"
        CHECK_FINDING_SUMMARY="baseline created; review recommended"
        return 0
    fi

    drift="$(printf '%s\n' "$current" | baseline_diff "$CHECK_NAME")" || true
    added="$(printf '%s\n' "$drift" | sed -n 's/^+//p')"
    removed="$(printf '%s\n' "$drift" | sed -n 's/^-//p')"

    while IFS= read -r entry; do
        [[ -n "$entry" ]] || continue
        _lps_label "$entry"
        print_check_result info "no longer present: $_LPS_HUMAN"
    done <<EOF
$removed
EOF

    while IFS= read -r entry; do
        [[ -n "$entry" ]] || continue
        allowlist_match "$CHECK_NAME" "$entry" && continue
        _lps_label "$entry"
        print_check_result "$_LPS_SEV" "NEW persistence: $_LPS_HUMAN"
        echo "  - $_LPS_HUMAN   [id: $entry]"
        count=$((count + 1))
        [[ "$_LPS_SEV" == "critical" ]] && max_sev="critical"
    done <<EOF
$added
EOF

    if [[ "$count" -gt 0 ]]; then
        printf '%s\n' "$current" | baseline_stage_pending "$CHECK_NAME"
        CHECK_FINDING_SUMMARY="$count new Linux persistence item(s)"
        CHECK_RESULT_SEVERITY="$max_sev"
        return 1
    fi

    print_check_result pass "No new Linux persistence mechanisms since baseline"
    CHECK_FINDING_SUMMARY="no new persistence"
    return 0
}
