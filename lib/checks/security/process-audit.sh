#!/bin/bash
# oh-my-safety - Suspicious running process audit
CHECK_NAME="process-audit"
CHECK_DESCRIPTION="Flag suspicious running processes (unsigned/adhoc/translocated/deleted binaries, osascript phishing)"
CHECK_CATEGORY="security"
CHECK_PLATFORMS="macos"
CHECK_SEVERITY="warn"
CHECK_CONTRACT="2"
CHECK_REQUIRES_NETWORK="false"
CHECK_INTERVAL="60"
CHECK_DOC="docs/checks/security/process-audit.md"

# --- helpers (module-scoped; do not collide with runner globals) ---

# echo the higher of two severities ("" < warn < critical)
_pa_max_sev() {
    if [ "$1" = "critical" ] || [ "$2" = "critical" ]; then
        echo "critical"
    elif [ "$1" = "warn" ] || [ "$2" = "warn" ]; then
        echo "warn"
    else
        echo ""
    fi
}

# rc 0 if path is in a classic malware "drop zone". This is intentionally
# NARROWER than oms_is_user_writable_path ($HOME as a whole): legit dev tools
# live in ~/.pyenv, /opt/homebrew, /Applications and would otherwise all look
# critical. Real stealers run from temp dirs and fresh downloads.
_pa_in_dropzone() {
    case "$1" in
        /tmp/*|/private/tmp/*|/var/tmp/*|/private/var/tmp/*|/private/var/folders/*) return 0 ;;
        "$HOME/Downloads/"*|"$HOME/Library/Caches/"*) return 0 ;;
        *) return 1 ;;
    esac
}

check_process_audit() {
    local NAME="process-audit"
    local findings=0
    local count=0
    local max_sev=""

    # config toggles
    local flag_deleted=0
    if config_enabled "checks.security.process_audit.flag_deleted_binaries" "true"; then
        flag_deleted=1
    fi
    local phish_detect=0
    if config_enabled "checks.security.process_audit.osascript_phishing_detect" "true"; then
        phish_detect=1
    fi

    # Unique set of full executable paths. `comm` is the full exe path on macOS;
    # entries not starting with "/" (kernel threads, unreadable other-user procs)
    # are dropped. Without root we mainly see our own processes' full paths --
    # that is enough to catch user-level malware.
    local unique_paths
    unique_paths="$(ps -axo comm= 2>/dev/null | grep '^/' | sort -u)"
    log_debug "process-audit: $(printf '%s\n' "$unique_paths" | grep -c .) unique exe paths"

    local path verdict sev fid
    while IFS= read -r path; do
        [ -z "$path" ] && continue
        case "$path" in
            /*) ;;
            *) continue ;;
        esac

        # 4) Deleted-while-running: binary vanished from disk while still running.
        if [ ! -e "$path" ]; then
            if [ "$flag_deleted" = "1" ]; then
                fid="proc:deleted:$path"
                allowlist_match "$NAME" "$fid" && continue
                sev="warn"
                if _pa_in_dropzone "$path"; then
                    sev="critical"
                fi
                print_check_result "$sev" "Running process binary no longer exists on disk"
                echo "  - $path (deleted while running -- possible self-cleaning malware)   [id: $fid]"
                max_sev="$(_pa_max_sev "$max_sev" "$sev")"
                findings=1
                count=$((count + 1))
            fi
            continue
        fi

        # 2a) App Translocation: launched straight from a quarantined download.
        case "$path" in
            */AppTranslocation/*)
                fid="proc:translocated:$path"
                if allowlist_match "$NAME" "$fid"; then
                    continue
                fi
                print_check_result warn "Process running from a translocated location"
                echo "  - $path"
                echo "    running from a quarantined/translocated location (app launched straight from a download)   [id: $fid]"
                max_sev="$(_pa_max_sev "$max_sev" "warn")"
                findings=1
                count=$((count + 1))
                continue
                ;;
        esac

        # 2b) Signing verdict. Only flag unsigned/adhoc binaries that are running
        # from a drop zone — that combination is the real red flag. Unsigned dev
        # tools elsewhere (~/.pyenv, /opt/homebrew, /Applications) are normal and
        # would only cause alert fatigue, so they are not reported here.
        if _pa_in_dropzone "$path"; then
            verdict="$(oms_codesign_verdict "$path")"
            if [ "$verdict" = "unsigned" ] || [ "$verdict" = "adhoc" ]; then
                fid="proc:$path"
                allowlist_match "$NAME" "$fid" && continue
                print_check_result critical "Unverified binary running from a drop-zone location"
                echo "  - $path (code signature: $verdict)   [id: $fid]"
                max_sev="$(_pa_max_sev "$max_sev" "critical")"
                findings=1
                count=$((count + 1))
            fi
        fi
    done <<EOF
$unique_paths
EOF

    # 3) osascript password phishing -- the top AMOS/Atomic-Stealer tripwire.
    if [ "$phish_detect" = "1" ]; then
        local osa_lines line phish=0
        osa_lines="$(ps -axo args= 2>/dev/null | grep -i 'osascript')"
        if [ -n "$osa_lines" ]; then
            while IFS= read -r line; do
                [ -z "$line" ] && continue
                if printf '%s' "$line" | grep -qi 'hidden answer'; then
                    phish=1
                elif printf '%s' "$line" | grep -qi 'display dialog' && printf '%s' "$line" | grep -qi 'password'; then
                    phish=1
                fi
            done <<EOF2
$osa_lines
EOF2
        fi
        if [ "$phish" = "1" ]; then
            fid="proc:osascript-phishing"
            if ! allowlist_match "$NAME" "$fid"; then
                print_check_result critical "possible AMOS-style password phishing via osascript"
                echo "  - an osascript process is prompting for a password (classic macOS stealer behavior)   [id: $fid]"
                max_sev="$(_pa_max_sev "$max_sev" "critical")"
                findings=1
                count=$((count + 1))
            fi
        fi
    fi

    if [ "$findings" = "1" ]; then
        [ -z "$max_sev" ] && max_sev="warn"
        CHECK_FINDING_SUMMARY="$count suspicious process finding(s)"
        CHECK_RESULT_SEVERITY="$max_sev"
        return 1
    fi

    print_check_result pass "No suspicious processes detected"
    CHECK_FINDING_SUMMARY="no suspicious processes"
    return 0
}
