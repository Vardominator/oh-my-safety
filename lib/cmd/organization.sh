#!/bin/bash
# oh-my-safety - explicit self-hosted organization-controller enrollment/sync.

_organization_agent() {
    local agent
    agent="$(managed_agent_path)"
    [[ -n "$agent" ]] || {
        log_error "The portable agent core is required for this command"
        return 1
    }
    printf '%s' "$agent"
}

_organization_enroll() {
    local url="" key="" token_env device_name="" selected="" agent state db patch
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --url|--policy-key|--token-env|--device-name|--profile)
                [[ $# -ge 2 && -n "$2" ]] || {
                    log_error "$1 requires a value"
                    return 2
                }
                case "$1" in
                    --url) url="$2" ;;
                    --policy-key) key="$2" ;;
                    --token-env) token_env="$2" ;;
                    --device-name) device_name="$2" ;;
                    --profile) selected="$2" ;;
                esac
                shift 2
                ;;
            *)
                # Do not reflect an unexpected positional value: operators
                # sometimes paste a token where an option was expected.
                log_error "Unknown organization enrollment option"
                return 2
                ;;
        esac
    done
    [[ -n "$url" && -n "$key" ]] || {
        log_error "Enrollment requires --url and --policy-key"
        return 2
    }
    token_env="${token_env:-$(config_get 'organization.enrollment_token_env' 'OMS_ENROLLMENT_TOKEN')}"
    case "$token_env" in
        ''|[!A-Z_]*|*[!A-Z0-9_]*)
            log_error "Enrollment token environment variable name is invalid"
            return 2
            ;;
    esac
    [[ "${#token_env}" -le 128 ]] || {
        log_error "Enrollment token environment variable name is invalid"
        return 2
    }
    if [[ -z "$selected" ]]; then
        if [[ "$(config_get 'profile.workload' 'workstation')" == "server" ]]; then
            selected="managed-server"
        else
            selected="managed-workstation"
        fi
    fi
    case "$selected" in managed-workstation|managed-server) ;; *)
        log_error "Organization profile must be managed-workstation or managed-server"
        return 2 ;;
    esac

    agent="$(_organization_agent)" || return 1
    state="$(managed_state_path)"
    db="$(state_path 'journal.db')"
    local -a arguments=(
        --state-db "$db"
        --managed-state "$state"
        --managed-enroll
        --controller-url "$url"
        --controller-policy-key "$key"
        --enrollment-token-env "$token_env"
    )
    [[ -z "$device_name" ]] || arguments+=(--device-name "$device_name")

    "$agent" "${arguments[@]}" || return 1
    patch="$(_profile_patch "$selected")"
    config_set_many <<EOF || {
$patch
organization.enabled=true
organization.enrollment_token_env=$token_env
EOF
        log_error "Enrolled, but could not persist the managed local profile"
        return 1
    }
    log_info "Organization management enabled with profile '$selected'"
}

_organization_status() {
    local state agent db
    state="$(managed_state_path)"
    echo "Enabled:       $(config_get 'organization.enabled' 'false')"
    echo "Enrollment:    $([[ -f "$state" && ! -L "$state" ]] && echo present || echo absent)"
    echo "State:         $state"
    echo "Profile:       $(config_get 'profile.name' 'personal-balanced')"
    echo "Connectivity:  $(config_get 'profile.connectivity' 'connected')"
    echo "Policy ID:     $(config_get 'organization.policy.id' 'none')"
    echo "Revision:      $(config_get 'organization.policy.revision' 'none')"
    echo "Reporting:     $(config_get 'organization.policy.reporting_enabled' 'not synchronized')"
    if [[ -f "$state" && ! -L "$state" ]]; then
        agent="$(managed_agent_path)"
        db="$(state_path 'journal.db')"
        if [[ -n "$agent" ]] && "$agent" --state-db "$db" --managed-state "$state" \
            --managed-policy >/dev/null 2>&1; then
            echo "Policy cache:  verified"
        else
            echo "Policy cache:  unavailable"
        fi
    fi
}

_organization_sync() {
    managed_is_enrolled || {
        log_error "Organization management is disabled or this endpoint is not enrolled"
        return 1
    }
    managed_sync_now
}

_organization_policy() {
    local agent state db
    agent="$(_organization_agent)" || return 1
    state="$(managed_state_path)"
    db="$(state_path 'journal.db')"
    "$agent" --state-db "$db" --managed-state "$state" --managed-policy
}

_organization_rotate() {
    local agent state db
    agent="$(_organization_agent)" || return 1
    state="$(managed_state_path)"
    db="$(state_path 'journal.db')"
    "$agent" --state-db "$db" --managed-state "$state" \
        --managed-rotate-credential
}

cmd_organization() {
    local action="${1:-status}"
    [[ $# -eq 0 ]] || shift
    case "$action" in
        enroll) _organization_enroll "$@" ;;
        status) _organization_status ;;
        sync) _organization_sync ;;
        policy) _organization_policy ;;
        rotate-credential) _organization_rotate ;;
        disable)
            config_set organization.enabled false
            log_info "Organization sync and managed-policy enforcement disabled; enrollment state retained"
            ;;
        help|-h|--help)
            echo "usage: oh-my-safety organization {status|enroll|sync|policy|rotate-credential|disable}"
            echo "       organization enroll --url URL --policy-key BASE64 [--token-env NAME]"
            echo "                           [--device-name NAME] [--profile managed-workstation|managed-server]"
            ;;
        *)
            log_error "Unknown organization action: $action"
            return 2
            ;;
    esac
}
