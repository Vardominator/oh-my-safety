#!/bin/bash
# oh-my-safety - Detect NEW persistence mechanisms (launchd, login items, cron, profiles, legacy) via baseline drift.
CHECK_NAME="persistence-scan"
CHECK_DESCRIPTION="Flags newly added persistence mechanisms against a saved baseline"
CHECK_CATEGORY="security"
CHECK_PLATFORMS="macos"
CHECK_SEVERITY="critical"
CHECK_CONTRACT="2"
CHECK_REQUIRES_NETWORK="false"
CHECK_INTERVAL="600"
CHECK_DOC="docs/checks/security/persistence-scan.md"

# Finding-id scheme (stable, path-based; each entry doubles as its own id):
#   launchd|<plist-path>|<program-path>
#   login|<login-item-name>
#   cron|<crontab-line>
#   periodic|<script-path>
#   legacy|<path>
#   profile|<profile-identifier>

# Collect one entry per line to STDOUT ONLY (no other output — it is captured
# into the snapshot). Login items are read from the pre-computed global so we
# never emit the denial notice into the baseline.
_persistence_collect() {
    local f label prog d name line id

    # --- LaunchAgents / LaunchDaemons ---
    for f in "$HOME"/Library/LaunchAgents/*.plist \
             /Library/LaunchAgents/*.plist \
             /Library/LaunchDaemons/*.plist; do
        [ -e "$f" ] || continue
        label="$(plutil -extract Label raw -o - "$f" 2>/dev/null)"
        [ -z "$label" ] && label="$(basename "$f" .plist 2>/dev/null)"
        prog="$(oms_plist_program "$f" 2>/dev/null)"
        printf 'launchd|%s|%s\n' "$f" "$prog"
    done

    # --- Login items (fed in via global; may be disabled) ---
    if [ -n "$_PSCAN_LOGIN_NAMES" ]; then
        printf '%s\n' "$_PSCAN_LOGIN_NAMES" | tr ',' '\n' | while IFS= read -r name; do
            name="$(printf '%s' "$name" | sed 's/^ *//;s/ *$//')"
            [ -z "$name" ] && continue
            printf 'login|%s\n' "$name"
        done
    fi

    # --- cron (per-user; no sudo needed) ---
    crontab -l 2>/dev/null | grep -vE '^[[:space:]]*(#|$)' | while IFS= read -r line; do
        [ -z "$line" ] && continue
        printf 'cron|%s\n' "$line"
    done

    # --- /etc/periodic (may not exist on modern macOS) ---
    if [ -d /etc/periodic ]; then
        for d in daily weekly monthly; do
            for f in /etc/periodic/"$d"/*; do
                [ -e "$f" ] || continue
                printf 'periodic|%s\n' "$f"
            done
        done
    fi

    # --- legacy vectors (presence is itself anomalous) ---
    for f in /Library/StartupItems/* /etc/emond.d/rules/*.plist; do
        [ -e "$f" ] || continue
        printf 'legacy|%s\n' "$f"
    done

    # --- configuration profiles (user scope, best-effort) ---
    profiles list 2>/dev/null | sed -n 's/.*profileIdentifier: *//p' | while IFS= read -r id; do
        id="$(printf '%s' "$id" | sed 's/^ *//;s/ *$//')"
        [ -z "$id" ] && continue
        printf 'profile|%s\n' "$id"
    done
}

# Build a human-readable description + set _PSCAN_SEV for a single entry.
_persistence_classify() {
    local entry="$1"
    local type rest f prog verdict
    _PSCAN_SEV="warn"
    type="${entry%%|*}"
    case "$type" in
        launchd)
            rest="${entry#launchd|}"
            f="${rest%%|*}"
            prog="${rest#*|}"
            _PSCAN_HUMAN="LaunchAgent/Daemon: $f"
            if [ -n "$prog" ] && [ "$prog" != "$f" ]; then
                verdict="$(oms_codesign_verdict "$prog" 2>/dev/null)"
                _PSCAN_HUMAN="$_PSCAN_HUMAN (program: $prog, signing: ${verdict:-unknown})"
                case "$verdict" in
                    unsigned|adhoc)
                        if oms_is_user_writable_path "$prog"; then
                            _PSCAN_SEV="critical"
                        fi
                        ;;
                esac
            fi
            ;;
        login)   _PSCAN_HUMAN="Login item: ${entry#login|}" ;;
        cron)    _PSCAN_HUMAN="cron job: ${entry#cron|}" ;;
        periodic) _PSCAN_HUMAN="periodic script: ${entry#periodic|}" ;;
        legacy)  _PSCAN_HUMAN="legacy persistence (anomalous location): ${entry#legacy|}" ;;
        profile) _PSCAN_HUMAN="Configuration profile: ${entry#profile|}" ;;
        *)       _PSCAN_HUMAN="$entry" ;;
    esac
}

check_persistence_scan() {
    local NAME="$CHECK_NAME"
    local current drift added removed entry
    local actionable="" max_sev="warn" count=0

    # Resolve login items OUTSIDE the snapshot capture so the Automation-denial
    # notice is never folded into the baseline.
    _PSCAN_LOGIN_NAMES=""
    if config_enabled "checks.security.persistence_scan.login_items" "true"; then
        local li_rc
        _PSCAN_LOGIN_NAMES="$(osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null)"
        li_rc=$?
        if [ "$li_rc" -ne 0 ]; then
            _PSCAN_LOGIN_NAMES=""
            print_check_result info "login items skipped: grant Automation > System Events to your terminal, or set checks.security.persistence_scan.login_items false"
        fi
    fi

    current="$(_persistence_collect | sort -u)"

    # First run: record a quiet baseline.
    if ! baseline_exists "$NAME"; then
        printf '%s\n' "$current" | baseline_save "$NAME"
        print_check_result pass "Baseline recorded ($(printf '%s\n' "$current" | grep -c .) persistence item(s)). Future changes will be flagged."
        CHECK_FINDING_SUMMARY="baseline created"
        return 0
    fi

    drift="$(printf '%s\n' "$current" | baseline_diff "$NAME")" || true  # rc1 just means drift exists
    added="$(printf '%s\n' "$drift" | sed -n 's/^+//p')"
    removed="$(printf '%s\n' "$drift" | sed -n 's/^-//p')"

    # Report items that vanished (informational only).
    while IFS= read -r entry; do
        [ -z "$entry" ] && continue
        _persistence_classify "$entry"
        print_check_result info "no longer present: $_PSCAN_HUMAN"
    done <<EOF2
$removed
EOF2

    # Evaluate newly added persistence.
    while IFS= read -r entry; do
        [ -z "$entry" ] && continue
        allowlist_match "$NAME" "$entry" && continue
        _persistence_classify "$entry"
        if [ "$_PSCAN_SEV" = "critical" ]; then
            max_sev="critical"
            print_check_result critical "NEW persistence: $_PSCAN_HUMAN"
        else
            print_check_result warn "NEW persistence: $_PSCAN_HUMAN"
        fi
        echo "  - $_PSCAN_HUMAN   [id: $entry]"
        count=$((count + 1))
        actionable="$actionable$entry
"
    done <<EOF2
$added
EOF2

    if [ -n "$actionable" ]; then
        printf '%s\n' "$current" | baseline_stage_pending "$NAME"
        echo "  Run 'oh-my-safety accept $NAME' to trust these, or allowlist individual [id]s."
        if [ "$max_sev" = "critical" ]; then
            print_check_result critical "$count new persistence item(s) — at least one is unsigned and user-writable"
            CHECK_RESULT_SEVERITY="critical"
        else
            print_check_result warn "$count new persistence item(s) detected"
            CHECK_RESULT_SEVERITY="warn"
        fi
        CHECK_FINDING_SUMMARY="$count new persistence item(s)"
        return 1
    fi

    print_check_result pass "No new persistence mechanisms since baseline"
    CHECK_FINDING_SUMMARY="no new persistence"
    return 0
}
