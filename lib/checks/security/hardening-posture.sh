#!/bin/bash
# oh-my-safety - audit core macOS security hardening posture (absolute policy, no baseline)
CHECK_NAME="hardening-posture"
CHECK_DESCRIPTION="Audits SIP, Gatekeeper, FileVault, firewall, remote access, auto-updates, and XProtect freshness"
CHECK_CATEGORY="security"
CHECK_PLATFORMS="macos"
CHECK_SEVERITY="warn"
CHECK_CONTRACT="2"
CHECK_REQUIRES_NETWORK="false"
CHECK_INTERVAL="3600"
CHECK_DOC="docs/checks/security/hardening-posture.md"

# --- helper: flag one misconfiguration (honors allowlist, tracks count + max severity) ---
_hardening_flag() {
    local sev="$1" id="$2" msg="$3" fix="$4"
    # Skip anything the user has already accepted.
    allowlist_match "$CHECK_NAME" "$id" && return 0
    print_check_result "$sev" "$msg"
    echo "  - fix: $fix   [id: $id]"
    _HP_FINDINGS=$((_HP_FINDINGS + 1))
    [ "$sev" = "critical" ] && _HP_SEVERITY="critical"
    return 0
}

check_hardening_posture() {
    # Accumulators (globals so the helper can update them across calls this run).
    _HP_FINDINGS=0
    _HP_SEVERITY="warn"

    local now
    now="$(date +%s)"
    # Guard against a broken date(1); without a valid clock XProtect age is meaningless.
    case "$now" in
        ''|*[!0-9]*) now="" ;;
    esac

    # --- System Integrity Protection (critical) ---
    local sip_out
    sip_out="$(csrutil status 2>/dev/null)"
    if [ -n "$sip_out" ]; then
        if ! printf '%s' "$sip_out" | grep -qi 'enabled'; then
            _hardening_flag critical "hard:sip" \
                "System Integrity Protection (SIP) is disabled" \
                "Reboot to Recovery and run: csrutil enable"
        fi
    else
        log_debug "csrutil produced no output; skipping SIP check"
    fi

    # --- Gatekeeper (critical) ---
    local gk_out
    gk_out="$(spctl --status 2>/dev/null)"
    if [ -n "$gk_out" ]; then
        if ! printf '%s' "$gk_out" | grep -qi 'assessments enabled'; then
            _hardening_flag critical "hard:gatekeeper" \
                "Gatekeeper (assessments) is disabled" \
                "System Settings > Privacy & Security > allow App Store & identified developers"
        fi
    else
        log_debug "spctl produced no output; skipping Gatekeeper check"
    fi

    # --- FileVault full-disk encryption (warn) ---
    local fv_out
    fv_out="$(fdesetup status 2>/dev/null)"
    if [ -n "$fv_out" ]; then
        if ! printf '%s' "$fv_out" | grep -qi 'FileVault is On'; then
            _hardening_flag warn "hard:filevault" \
                "FileVault disk encryption is OFF" \
                "System Settings > Privacy & Security > FileVault > Turn On"
        fi
    else
        log_debug "fdesetup produced no output; skipping FileVault check"
    fi

    # --- Application firewall (warn), configurable ---
    if config_enabled "checks.security.hardening_posture.require_firewall" "true"; then
        local fw_bin="/usr/libexec/ApplicationFirewall/socketfilterfw" fw_out
        if [ -x "$fw_bin" ]; then
            fw_out="$("$fw_bin" --getglobalstate 2>/dev/null)"
            if [ -n "$fw_out" ]; then
                # "State = 0" / "disabled" both indicate the firewall is off.
                if printf '%s' "$fw_out" | grep -qiE 'disabled|state = 0'; then
                    _hardening_flag warn "hard:firewall" \
                        "Application Firewall is disabled" \
                        "System Settings > Network > Firewall > On"
                fi
            fi
        fi
    else
        log_debug "require_firewall disabled in config; skipping firewall check"
    fi

    # --- Remote Login / SSH (warn), unless explicitly allowed ---
    if config_enabled "checks.security.hardening_posture.allow_remote_login" "false"; then
        log_debug "remote login allowed in config; skipping SSH check"
    else
        local ssh_out
        ssh_out="$(launchctl print system/com.openssh.sshd 2>&1)"
        # NOTE: systemsetup -getremotelogin lies; presence of the launchd service is the signal.
        if printf '%s' "$ssh_out" | grep -q 'Could not find service'; then
            : # SSH is off
        else
            _hardening_flag warn "hard:remote-login" \
                "Remote Login (SSH) is enabled" \
                "System Settings > General > Sharing > Remote Login > Off"
        fi
    fi

    # --- Screen Sharing (warn), unless explicitly allowed ---
    if config_enabled "checks.security.hardening_posture.allow_screen_sharing" "false"; then
        log_debug "screen sharing allowed in config; skipping check"
    else
        local ss_out; ss_out="$(launchctl print system/com.apple.screensharing 2>&1)"
        case "$ss_out" in *"state = running"*)
            _hardening_flag warn "hard:screen-sharing" \
                "Screen Sharing is running" \
                "System Settings > General > Sharing > Screen Sharing > Off" ;;
        esac
    fi

    # --- File Sharing / SMB (warn) ---
    local smb_out; smb_out="$(launchctl print system/com.apple.smbd 2>&1)"
    case "$smb_out" in *"state = running"*)
        _hardening_flag warn "hard:file-sharing" \
            "File Sharing (SMB) is running" \
            "System Settings > General > Sharing > File Sharing > Off" ;;
    esac

    # --- Automatic security updates (warn) ---
    # 1=on, 0=off, absent (nonzero exit -> empty) = default on (treat as pass).
    local su_pref="/Library/Preferences/com.apple.SoftwareUpdate"
    local cfg_data crit_update
    cfg_data="$(defaults read "$su_pref" ConfigDataInstall 2>/dev/null)"
    crit_update="$(defaults read "$su_pref" CriticalUpdateInstall 2>/dev/null)"
    if [ "$cfg_data" = "0" ] || [ "$crit_update" = "0" ]; then
        _hardening_flag warn "hard:auto-security-updates" \
            "Automatic security/system-data updates are disabled" \
            "System Settings > General > Software Update > enable 'Install Security Responses and system files'"
    fi

    # --- XProtect freshness (warn) + version at info ---
    local xp_plist="/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
    if [ ! -f "$xp_plist" ]; then
        xp_plist="/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
    fi
    if [ -f "$xp_plist" ]; then
        local xp_ver xp_mtime age_days max_age
        xp_ver="$(plutil -extract CFBundleShortVersionString raw "$xp_plist" 2>/dev/null)"
        [ -n "$xp_ver" ] && print_check_result info "XProtect version: $xp_ver"

        xp_mtime="$(oms_file_mtime "$xp_plist")"
        max_age="$(config_get "checks.security.hardening_posture.xprotect_max_age_days" "45")"
        case "$max_age" in
            ''|*[!0-9]*) max_age="45" ;;
        esac
        case "$xp_mtime" in
            ''|*[!0-9]*) xp_mtime="" ;;
        esac
        if [ -n "$now" ] && [ -n "$xp_mtime" ]; then
            age_days=$(( (now - xp_mtime) / 86400 ))
            if [ "$age_days" -gt "$max_age" ]; then
                _hardening_flag warn "hard:xprotect-stale" \
                    "XProtect definitions are stale (${age_days} days old, threshold ${max_age})" \
                    "Run: softwareupdate --background-critical  (or wait for automatic update)"
            fi
        fi
    else
        log_debug "XProtect Info.plist not found; skipping freshness check"
    fi

    # --- Verdict ---
    if [ "$_HP_FINDINGS" -gt 0 ]; then
        CHECK_FINDING_SUMMARY="$_HP_FINDINGS hardening issue(s)"
        CHECK_RESULT_SEVERITY="$_HP_SEVERITY"
        return 1
    fi

    print_check_result pass "System hardening posture looks good"
    CHECK_FINDING_SUMMARY="hardened"
    return 0
}
