#!/bin/bash
# oh-my-safety - composable operating profiles

_profile_names() {
    printf '%s\n' \
        personal-balanced \
        personal-strict \
        developer \
        managed-workstation \
        managed-server \
        airgapped-high-assurance
}

_profile_description() {
    case "$1" in
        personal-balanced) echo "Everyday workstation protection with connected privacy checks." ;;
        personal-strict) echo "Shorter cadence and strict posture for a high-risk personal workstation." ;;
        developer) echo "Workstation protection plus opt-in local repository secret scanners." ;;
        managed-workstation) echo "Strict connected workstation posture prepared for signed organization policy." ;;
        managed-server) echo "Strict server posture; local network privacy checks are disabled." ;;
        airgapped-high-assurance) echo "High-frequency local checks with every outbound adapter disabled." ;;
        *) return 1 ;;
    esac
}

_profile_patch() {
    case "$1" in
        personal-balanced)
            cat <<'EOF'
profile.name=personal-balanced
profile.workload=workstation
profile.protection=balanced
profile.management=standalone
profile.connectivity=connected
monitoring.interval=300
monitoring.fast_interval=15
monitoring.deep=false
notifications.enabled=true
notifications.external.enabled=false
notifications.min_severity=warn
categories.privacy.enabled=true
categories.security.enabled=true
tools.gitleaks.enabled=false
tools.trufflehog.enabled=false
tools.yara.enabled=false
checks.security.local_secret_scan.enabled=false
checks.security.secrets_content.enabled=false
checks.security.yara_scan.enabled=false
remediation.mode=ask
EOF
            ;;
        personal-strict)
            cat <<'EOF'
profile.name=personal-strict
profile.workload=workstation
profile.protection=strict
profile.management=standalone
profile.connectivity=connected
monitoring.interval=120
monitoring.fast_interval=10
monitoring.deep=true
notifications.enabled=true
notifications.external.enabled=false
notifications.min_severity=warn
categories.privacy.enabled=true
categories.security.enabled=true
tools.gitleaks.enabled=false
tools.trufflehog.enabled=false
tools.yara.enabled=false
checks.security.local_secret_scan.enabled=true
checks.security.secrets_content.enabled=false
checks.security.yara_scan.enabled=false
remediation.mode=ask
EOF
            ;;
        developer)
            cat <<'EOF'
profile.name=developer
profile.workload=developer
profile.protection=strict
profile.management=standalone
profile.connectivity=connected
monitoring.interval=180
monitoring.fast_interval=10
monitoring.deep=true
notifications.enabled=true
notifications.external.enabled=false
notifications.min_severity=warn
categories.privacy.enabled=true
categories.security.enabled=true
tools.gitleaks.enabled=true
tools.trufflehog.enabled=true
tools.yara.enabled=false
checks.security.local_secret_scan.enabled=true
checks.security.secrets_content.enabled=true
checks.security.yara_scan.enabled=false
remediation.mode=ask
EOF
            ;;
        managed-workstation)
            cat <<'EOF'
profile.name=managed-workstation
profile.workload=workstation
profile.protection=strict
profile.management=managed
profile.connectivity=connected
monitoring.interval=120
monitoring.fast_interval=10
monitoring.deep=true
notifications.enabled=true
notifications.external.enabled=false
notifications.min_severity=warn
categories.privacy.enabled=true
categories.security.enabled=true
tools.gitleaks.enabled=false
tools.trufflehog.enabled=false
tools.yara.enabled=false
checks.security.local_secret_scan.enabled=true
checks.security.secrets_content.enabled=false
checks.security.yara_scan.enabled=false
remediation.mode=policy
EOF
            ;;
        managed-server)
            cat <<'EOF'
profile.name=managed-server
profile.workload=server
profile.protection=strict
profile.management=managed
profile.connectivity=connected
monitoring.interval=120
monitoring.fast_interval=30
monitoring.deep=true
notifications.enabled=true
notifications.external.enabled=false
notifications.min_severity=warn
categories.privacy.enabled=false
categories.security.enabled=true
tools.gitleaks.enabled=false
tools.trufflehog.enabled=false
tools.yara.enabled=false
checks.security.local_secret_scan.enabled=false
checks.security.secrets_content.enabled=false
checks.security.yara_scan.enabled=false
remediation.mode=policy
EOF
            ;;
        airgapped-high-assurance)
            cat <<'EOF'
profile.name=airgapped-high-assurance
profile.workload=workstation
profile.protection=strict
profile.management=standalone
profile.connectivity=airgapped
monitoring.interval=60
monitoring.fast_interval=15
monitoring.deep=true
notifications.enabled=true
notifications.external.enabled=false
notifications.min_severity=info
categories.privacy.enabled=false
categories.security.enabled=true
tools.gitleaks.enabled=false
tools.trufflehog.enabled=false
tools.yara.enabled=false
checks.security.local_secret_scan.enabled=true
checks.security.secrets_content.enabled=false
checks.security.yara_scan.enabled=false
remediation.mode=ask
EOF
            ;;
        *) return 1 ;;
    esac
}

_profile_list() {
    local name current
    current="$(config_get 'profile.name' 'personal-balanced')"
    printf '%-27s %s\n' "PROFILE" "PURPOSE"
    while IFS= read -r name; do
        if [[ "$name" == "$current" ]]; then
            printf '* %-25s %s\n' "$name" "$(_profile_description "$name")"
        else
            printf '  %-25s %s\n' "$name" "$(_profile_description "$name")"
        fi
    done < <(_profile_names)
}

_profile_show() {
    local name connectivity management
    name="$(config_get 'profile.name' 'personal-balanced')"
    connectivity="$(config_get 'profile.connectivity' 'connected')"
    management="$(config_get 'profile.management' 'standalone')"
    echo "Profile:       $name"
    echo "Workload:      $(config_get 'profile.workload' 'workstation')"
    echo "Protection:    $(config_get 'profile.protection' 'balanced')"
    echo "Management:    $management"
    echo "Connectivity:  $connectivity"
    echo "Full cadence:  $(config_get 'monitoring.interval' '300')s"
    echo "Deep scans:    $(config_get 'monitoring.deep' 'false')"
    if [[ "$connectivity" == "connected" ]]; then
        echo "Internet data: eligible only for explicitly enabled adapters"
    else
        echo "Internet data: blocked by profile"
    fi
    if [[ "$management" == "managed" ]]; then
        if managed_is_enrolled; then
            echo "Controller:    enrolled; signed policy enforced when available"
        else
            echo "Controller:    prepared; no controller enrolled"
        fi
    fi
    echo "Remediation:   $(config_get 'remediation.mode' 'ask')"
}

cmd_profile() {
    local action="${1:-show}" name patch
    case "$action" in
        list) _profile_list ;;
        show) _profile_show ;;
        set)
            name="${2:-}"
            if [[ -z "$name" ]] || ! _profile_patch "$name" >/dev/null; then
                log_error "Unknown profile: ${name:-<missing>}"
                _profile_list
                return 1
            fi
            patch="$(_profile_patch "$name")"
            config_set_many <<EOF || {
$patch
EOF
                log_error "Could not persist profile"
                return 1
            }
            log_info "Profile set to '$name'"
            _profile_show
            ;;
        -h|--help|help)
            echo "usage: oh-my-safety profile [show|list|set NAME]"
            ;;
        *)
            log_error "Unknown profile action: $action"
            echo "usage: oh-my-safety profile [show|list|set NAME]"
            return 1
            ;;
    esac
}
