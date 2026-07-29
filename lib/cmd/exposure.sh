#!/bin/bash
# oh-my-safety - explicit internet-exposure adapter commands.

_exposure_safe_env_name() {
    case "$1" in
        ''|*[!A-Za-z0-9_]*) return 1 ;;
        [0-9]*) return 1 ;;
        *) return 0 ;;
    esac
}

_exposure_read_secret() {
    local label="$1" value
    if [[ -t 0 ]]; then
        printf '%s: ' "$label" >&2
        IFS= read -r -s value
        printf '\n' >&2
        printf '%s\n' "$value"
        value=""
    else
        cat
    fi
}

_exposure_common_flags() {
    local network=false offline=false
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --allow-network) network=true ;;
            --offline) offline=true ;;
            *) return 4 ;;
        esac
        shift
    done
    [[ "$network" == "false" || "$offline" == "false" ]] || return 2
    if [[ "$offline" == "true" ]]; then
        printf '%s\n' "--offline"
    elif [[ "$network" == "true" ]]; then
        printf '%s\n' "--allow-network"
    else
        return 3
    fi
}

_exposure_password() {
    local agent db gate
    gate="$(_exposure_common_flags "$@")"
    case $? in
        2) log_error "Use only one of --allow-network or --offline"; return 2 ;;
        3) log_error "Password exposure checks require explicit --allow-network or --offline"; return 2 ;;
        4) log_error "Unknown password exposure option"; return 2 ;;
    esac
    agent="$(_organization_agent)" || return 1
    db="$(state_path 'journal.db')"
    _exposure_read_secret "Password (input is not stored)" |
        "$agent" --state-db "$db" --check-pwned-password "$gate"
}

_exposure_account() {
    local agent db allow=false offline=false email_env="" key_env input
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --allow-network) allow=true; shift ;;
            --offline) offline=true; shift ;;
            --email-env|--api-key-env)
                [[ $# -ge 2 && -n "$2" ]] || {
                    log_error "$1 requires a value"
                    return 2
                }
                if [[ "$1" == "--email-env" ]]; then email_env="$2"; else key_env="$2"; fi
                shift 2
                ;;
            *) log_error "Unknown exposure account option"; return 2 ;;
        esac
    done
    [[ "$allow" == "false" || "$offline" == "false" ]] || {
        log_error "Use only one of --allow-network or --offline"
        return 2
    }
    [[ "$allow" == "true" || "$offline" == "true" ]] || {
        log_error "Account exposure checks require explicit --allow-network or --offline"
        return 2
    }
    key_env="${key_env:-$(config_get 'checks.security.breach_exposure.api_key_env' 'HIBP_API_KEY')}"
    _exposure_safe_env_name "$key_env" || {
        log_error "Invalid API key environment variable name"
        return 2
    }
    if [[ -n "$email_env" ]]; then
        _exposure_safe_env_name "$email_env" || {
            log_error "Invalid email environment variable name"
            return 2
        }
        input="${!email_env:-}"
        [[ -n "$input" ]] || {
            log_error "The configured email environment variable is empty"
            return 2
        }
    fi
    agent="$(_organization_agent)" || return 1
    db="$(state_path 'journal.db')"
    if [[ -n "$email_env" ]]; then
        if [[ "$offline" == "true" ]]; then
            printf '%s\n' "$input" | "$agent" --state-db "$db" \
                --check-breached-account --offline --hibp-api-key-env "$key_env"
        else
            printf '%s\n' "$input" | "$agent" --state-db "$db" \
                --check-breached-account --allow-network --hibp-api-key-env "$key_env"
        fi
        input=""
    elif [[ "$offline" == "true" ]]; then
        _exposure_read_secret "Email address (sent nowhere in offline mode)" |
            "$agent" --state-db "$db" --check-breached-account \
                --offline --hibp-api-key-env "$key_env"
    else
        _exposure_read_secret "Email address (disclosed to HIBP)" |
            "$agent" --state-db "$db" --check-breached-account \
                --allow-network --hibp-api-key-env "$key_env"
    fi
}

cmd_exposure() {
    local action="${1:-contracts}" agent
    [[ $# -eq 0 ]] || shift
    case "$action" in
        contracts)
            [[ $# -eq 0 ]] || {
                log_error "Exposure contracts accepts no additional arguments"
                return 2
            }
            agent="$(_organization_agent)" || return 1
            "$agent" --exposure-contracts
            ;;
        password) _exposure_password "$@" ;;
        account) _exposure_account "$@" ;;
        help|-h|--help)
            echo "usage: oh-my-safety exposure contracts"
            echo "       oh-my-safety exposure password {--allow-network|--offline}"
            echo "       oh-my-safety exposure account {--allow-network|--offline} [--email-env NAME] [--api-key-env NAME]"
            ;;
        *) log_error "Unknown exposure action"; return 2 ;;
    esac
}
