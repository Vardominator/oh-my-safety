#!/bin/bash
# oh-my-safety - audit sensitive TCC privacy grants (FDA, screen, keylogging, automation) via baseline drift
CHECK_NAME="tcc-audit"
CHECK_DESCRIPTION="Audit which apps hold sensitive privacy grants and flag new ones"
CHECK_CATEGORY="security"
CHECK_PLATFORMS="macos"
CHECK_SEVERITY="warn"
CHECK_CONTRACT="2"
CHECK_REQUIRES_NETWORK="false"
CHECK_INTERVAL="600"
CHECK_DOC="docs/checks/security/tcc-audit.md"

# Map a raw TCC service code to a human-friendly label.
_tcc_friendly() {
    case "$1" in
        kTCCServiceSystemPolicyAllFiles) echo "Full Disk Access" ;;
        kTCCServiceScreenCapture)        echo "Screen Recording" ;;
        kTCCServiceAccessibility)        echo "Accessibility control" ;;
        kTCCServiceListenEvent)          echo "Input Monitoring (keylogging-capable)" ;;
        kTCCServicePostEvent)            echo "Keystroke/mouse injection (PostEvent)" ;;
        kTCCServiceAppleEvents)          echo "Automation (Apple Events)" ;;
        *)                               echo "$1" ;;
    esac
}

# Only these high-value services are tracked; everything else is noise.
_tcc_is_interesting() {
    case "$1" in
        kTCCServiceSystemPolicyAllFiles|kTCCServiceScreenCapture|kTCCServiceAccessibility|kTCCServiceListenEvent|kTCCServicePostEvent|kTCCServiceAppleEvents)
            return 0 ;;
    esac
    return 1
}

# Read granted rows from both the user and system TCC databases.
# immutable=1 avoids lock contention; failures degrade silently.
_tcc_collect() {
    local db
    for db in \
        "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
        "/Library/Application Support/com.apple.TCC/TCC.db"; do
        [ -f "$db" ] || continue
        sqlite3 -separator '|' "file:$db?immutable=1" \
            "SELECT service, client, client_type, auth_value FROM access WHERE auth_value IN (2,3);" 2>/dev/null
    done
}

# Emit one stable, path-based entry per interesting grant: tcc|<service>|<client>
_tcc_snapshot() {
    _tcc_collect | while IFS='|' read -r service client ctype auth; do
        [ -z "$service" ] && continue
        [ -z "$client" ] && continue
        _tcc_is_interesting "$service" || continue
        printf 'tcc|%s|%s\n' "$service" "$client"
    done
}

check_tcc_audit() {
    if ! oms_has_fda; then
        print_check_result skip "reading the TCC database requires Full Disk Access"
        echo "  grant FDA to your terminal for interactive scans, or to /bin/bash for the agent, or set checks.security.tcc_audit.enabled false; see: oh-my-safety doctor"
        CHECK_FINDING_SUMMARY="needs Full Disk Access"
        return 77
    fi

    local NAME="tcc-audit" current
    current="$(_tcc_snapshot | sort -u)"

    if ! baseline_exists "$NAME"; then
        printf '%s\n' "$current" | baseline_save "$NAME"
        local count
        count="$(printf '%s\n' "$current" | grep -c .)"
        print_check_result pass "Baseline recorded ($count sensitive privacy grants). New grants will be flagged."
        CHECK_FINDING_SUMMARY="baseline created"
        return 0
    fi

    local drift added removed
    drift="$(printf '%s\n' "$current" | baseline_diff "$NAME")" || true   # rc1 just means drift exists
    added="$(printf '%s\n' "$drift" | sed -n 's/^+//p')"
    removed="$(printf '%s\n' "$drift" | sed -n 's/^-//p')"

    local actionable="" maxsev="warn" newcount=0

    # New grants: warn by default, escalate to critical for path-clients that
    # resolve to an unsigned/adhoc/missing binary or live in a user-writable path.
    while IFS= read -r entry; do
        [ -z "$entry" ] && continue
        allowlist_match "$NAME" "$entry" && continue

        local service client friendly sev reason
        service="$(printf '%s' "$entry" | cut -d'|' -f2)"
        client="$(printf '%s' "$entry" | cut -d'|' -f3-)"
        friendly="$(_tcc_friendly "$service")"
        sev="warn"
        reason=""

        # An absolute-path client is client_type=1 and can be code-signed verified.
        # A bundle-id client (no leading slash) is client_type=0 -> best-effort warn.
        case "$client" in
            /*)
                local verdict
                verdict="$(oms_codesign_verdict "$client" 2>/dev/null)"
                case "$verdict" in
                    unsigned|adhoc|missing)
                        sev="critical"
                        reason="binary is $verdict"
                        ;;
                esac
                if oms_is_user_writable_path "$client"; then
                    sev="critical"
                    if [ -n "$reason" ]; then
                        reason="$reason; user-writable location"
                    else
                        reason="user-writable location"
                    fi
                fi
                ;;
        esac

        if [ "$sev" = "critical" ]; then
            maxsev="critical"
            echo "  - CRITICAL: $client was granted $friendly ($reason)   [id: $entry]"
        else
            echo "  - $client was granted $friendly   [id: $entry]"
        fi
        actionable="$actionable$entry
"
        newcount=$((newcount + 1))
    done <<EOF2
$added
EOF2

    # Revoked grants are informational, not a failure.
    local removedcount=0
    while IFS= read -r entry; do
        [ -z "$entry" ] && continue
        local service client friendly
        service="$(printf '%s' "$entry" | cut -d'|' -f2)"
        client="$(printf '%s' "$entry" | cut -d'|' -f3-)"
        friendly="$(_tcc_friendly "$service")"
        if [ "$removedcount" = "0" ]; then
            print_check_result info "Some grants were revoked since baseline:"
        fi
        echo "  - $client no longer holds $friendly"
        removedcount=$((removedcount + 1))
    done <<EOF3
$removed
EOF3

    if [ -n "$actionable" ]; then
        printf '%s\n' "$current" | baseline_stage_pending "$NAME"
        if [ "$maxsev" = "critical" ]; then
            print_check_result critical "$newcount new sensitive privacy grant(s); review the flagged apps"
        else
            print_check_result warn "$newcount new sensitive privacy grant(s) since baseline"
        fi
        echo "  Accept expected grants with: oh-my-safety accept $NAME"
        if [ "$newcount" = "1" ]; then
            CHECK_FINDING_SUMMARY="1 new privacy grant"
        else
            CHECK_FINDING_SUMMARY="$newcount new privacy grants"
        fi
        CHECK_RESULT_SEVERITY="$maxsev"
        return 1
    fi

    print_check_result pass "No new sensitive privacy grants since baseline"
    CHECK_FINDING_SUMMARY="no privacy grant changes"
    return 0
}
