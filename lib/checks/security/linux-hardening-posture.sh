#!/bin/bash
# oh-my-safety - audit core Linux security posture without changing the host
CHECK_NAME="linux-hardening-posture"
CHECK_DESCRIPTION="Audits Linux disk encryption, Secure Boot, firewall, MAC, SSH, and automatic security updates"
CHECK_CATEGORY="security"
CHECK_PLATFORMS="linux"
CHECK_SEVERITY="warn"
CHECK_CONTRACT="2"
CHECK_REQUIRES_NETWORK="false"
CHECK_INTERVAL="3600"
CHECK_DOC="docs/checks/security/linux-hardening-posture.md"
CHECK_REMEDIATION="Enable the missing platform protection or explicitly allow the setting, then recheck."

_lh_flag() {
    local sev="$1" id="$2" message="$3" fix="$4"
    allowlist_match "$CHECK_NAME" "$id" && return 0
    print_check_result "$sev" "$message"
    echo "  - fix: $fix   [id: $id]"
    _LH_FINDINGS=$((_LH_FINDINGS + 1))
    [[ "$sev" == "critical" ]] && _LH_SEVERITY="critical"
}

_lh_coverage() {
    print_check_result info "$1"
    _LH_LIMITED=$((_LH_LIMITED + 1))
}

_lh_in_container() {
    [[ -f /.dockerenv ]] && return 0
    command -v systemd-detect-virt >/dev/null 2>&1 &&
        systemd-detect-virt --container --quiet 2>/dev/null
}

_lh_disk_encryption() {
    _lh_in_container && {
        _lh_coverage "Disk-encryption check skipped inside a container"
        return 0
    }
    command -v findmnt >/dev/null 2>&1 || {
        _lh_coverage "Disk-encryption coverage unavailable: findmnt is missing"
        return 0
    }

    local source types
    source="$(findmnt -n -o SOURCE / 2>/dev/null)"
    [[ -n "$source" ]] || {
        _lh_coverage "Disk-encryption coverage unavailable: root device could not be resolved"
        return 0
    }
    case "$source" in
        /dev/mapper/*|/dev/dm-*) return 0 ;;
        overlay|tmpfs|rootfs) _lh_coverage "Disk encryption is owned by the host for this filesystem"; return 0 ;;
    esac

    if command -v lsblk >/dev/null 2>&1; then
        types="$(lsblk -s -n -o TYPE "$source" 2>/dev/null | tr '\n' ' ')"
        case " $types " in *" crypt "*) return 0 ;; esac
    else
        _lh_coverage "Disk-encryption coverage is limited: lsblk is missing"
        return 0
    fi

    _lh_flag warn "linux-hard:disk-encryption" \
        "The root filesystem does not appear to be backed by LUKS/dm-crypt" \
        "Use your distribution's supported full-disk encryption workflow"
}

_lh_secure_boot() {
    if [[ ! -d /sys/firmware/efi ]]; then
        _lh_coverage "Secure Boot is not measurable: the system is not booted through EFI"
        return 0
    fi
    if command -v mokutil >/dev/null 2>&1; then
        local state
        state="$(mokutil --sb-state 2>/dev/null)"
        if printf '%s' "$state" | grep -qi 'enabled'; then
            return 0
        fi
        if [[ -n "$state" ]]; then
            _lh_flag warn "linux-hard:secure-boot" \
                "UEFI Secure Boot is disabled" \
                "Enable Secure Boot in firmware and enroll distribution-supported keys"
            return 0
        fi
    fi
    _lh_coverage "Secure Boot coverage unavailable: install mokutil or expose EFI variables"
}

_lh_firewall() {
    local inspected=0
    if command -v ufw >/dev/null 2>&1; then
        inspected=1
        ufw status 2>/dev/null | grep -qi '^Status: active' && return 0
    fi
    if command -v firewall-cmd >/dev/null 2>&1; then
        inspected=1
        firewall-cmd --state 2>/dev/null | grep -qx 'running' && return 0
    fi
    if command -v nft >/dev/null 2>&1; then
        local rules
        rules="$(nft list ruleset 2>/dev/null)"
        if [[ -n "$rules" ]]; then
            inspected=1
            printf '%s' "$rules" | grep -qE 'hook[[:space:]]+(input|forward)' && return 0
        fi
    fi
    if [[ "$inspected" -eq 0 ]]; then
        _lh_coverage "Firewall coverage unavailable: no readable ufw, firewalld, or nftables policy"
        return 0
    fi
    _lh_flag warn "linux-hard:firewall" \
        "No active host firewall policy was detected" \
        "Enable ufw, firewalld, or an nftables input policy appropriate for this host"
}

_lh_mandatory_access_control() {
    if [[ -r /sys/fs/selinux/enforce ]]; then
        [[ "$(cat /sys/fs/selinux/enforce 2>/dev/null)" == "1" ]] && return 0
        _lh_flag warn "linux-hard:selinux" \
            "SELinux is installed but not enforcing" \
            "Set SELINUX=enforcing using the distribution-supported procedure"
        return 0
    fi
    if command -v aa-status >/dev/null 2>&1; then
        aa-status --enabled >/dev/null 2>&1 && return 0
        _lh_flag warn "linux-hard:apparmor" \
            "AppArmor is installed but disabled" \
            "Enable the AppArmor service and reboot if required"
        return 0
    fi
    _lh_coverage "No active SELinux or AppArmor status interface was found"
}

_lh_ssh() {
    config_enabled "checks.security.linux_hardening_posture.allow_remote_login" "false" && return 0

    local active=1 unit
    if command -v systemctl >/dev/null 2>&1; then
        for unit in sshd.service ssh.service; do
            if systemctl is-active --quiet "$unit" 2>/dev/null; then
                active=0
                break
            fi
        done
    elif pgrep -x sshd >/dev/null 2>&1; then
        active=0
    fi
    [[ "$active" -ne 0 ]] && return 0

    _lh_flag warn "linux-hard:remote-login" \
        "Remote Login (SSH) is active" \
        "Disable SSH if unnecessary, or set checks.security.linux_hardening_posture.allow_remote_login true"

    local root_setting=""
    if command -v sshd >/dev/null 2>&1; then
        root_setting="$(sshd -T 2>/dev/null | awk '$1=="permitrootlogin"{print $2; exit}')"
    fi
    if [[ -z "$root_setting" && -r /etc/ssh/sshd_config ]]; then
        root_setting="$(awk 'tolower($1)=="permitrootlogin"{print tolower($2)}' /etc/ssh/sshd_config | tail -1)"
    fi
    case "$root_setting" in
        yes)
            _lh_flag critical "linux-hard:ssh-root" \
                "SSH permits direct root login" \
                "Set PermitRootLogin no (or prohibit-password where required), validate sshd, and reload it"
            ;;
        "")
            _lh_coverage "SSH root-login policy could not be resolved"
            ;;
    esac
}

_lh_automatic_updates() {
    command -v systemctl >/dev/null 2>&1 || {
        _lh_coverage "Automatic-update coverage unavailable without systemd"
        return 0
    }
    if systemctl is-enabled --quiet apt-daily-upgrade.timer 2>/dev/null ||
       systemctl is-enabled --quiet dnf-automatic-install.timer 2>/dev/null ||
       systemctl is-enabled --quiet dnf-automatic.timer 2>/dev/null; then
        return 0
    fi
    _lh_flag warn "linux-hard:auto-security-updates" \
        "No supported automatic security-update timer is enabled" \
        "Enable unattended-upgrades or dnf-automatic according to distribution policy"
}

check_linux_hardening_posture() {
    _LH_FINDINGS=0
    _LH_LIMITED=0
    _LH_SEVERITY="warn"

    _lh_disk_encryption
    _lh_secure_boot
    _lh_firewall
    _lh_mandatory_access_control
    _lh_ssh
    _lh_automatic_updates

    if [[ "$_LH_FINDINGS" -gt 0 ]]; then
        CHECK_FINDING_SUMMARY="$_LH_FINDINGS Linux hardening issue(s)"
        CHECK_RESULT_SEVERITY="$_LH_SEVERITY"
        return 1
    fi
    if [[ "$_LH_LIMITED" -ge 6 ]]; then
        CHECK_FINDING_SUMMARY="Linux hardening coverage unavailable"
        return 77
    fi

    print_check_result pass "Linux hardening posture passed all available checks"
    CHECK_FINDING_SUMMARY="hardened with $_LH_LIMITED coverage note(s)"
    return 0
}
