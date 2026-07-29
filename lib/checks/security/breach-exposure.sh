#!/bin/bash
# oh-my-safety - explicitly enabled HIBP breached-account monitoring.

CHECK_NAME="breach-exposure"
CHECK_DESCRIPTION="Opt-in monitored-account breach exposure"
CHECK_CATEGORY="security"
CHECK_PLATFORMS="all"
CHECK_SEVERITY="warn"
CHECK_CONTRACT="2"
CHECK_REQUIRES_NETWORK="true"
CHECK_INTERVAL="86400"
CHECK_DOC="docs/checks/security/breach-exposure.md"
CHECK_REMEDIATION="Review the breach classes locally, change affected credentials, revoke sessions or tokens, and enable phishing-resistant MFA."

_breach_safe_env_name() {
    case "$1" in
        ''|*[!A-Za-z0-9_]*) return 1 ;;
        [0-9]*) return 1 ;;
        *) return 0 ;;
    esac
}

check_breach_exposure() {
    local agent account_envs account_env email key_env db result findings=0 failures=0
    agent="$(_agent_core_path)"
    if [[ -z "$agent" ]]; then
        print_check_result skip "portable exposure adapter is not installed"
        CHECK_FINDING_SUMMARY="portable exposure adapter unavailable"
        return 77
    fi
    account_envs="$(config_get_list 'checks.security.breach_exposure.account_envs')"
    if [[ -z "$account_envs" ]]; then
        print_check_result skip "no monitored account environment variables configured"
        CHECK_FINDING_SUMMARY="no monitored accounts"
        return 77
    fi
    key_env="$(config_get 'checks.security.breach_exposure.api_key_env' 'HIBP_API_KEY')"
    _breach_safe_env_name "$key_env" || {
        CHECK_FINDING_SUMMARY="invalid HIBP API key environment name"
        return 42
    }
    db="$(state_path 'journal.db')"

    while IFS= read -r account_env; do
        [[ -z "$account_env" ]] && continue
        if ! _breach_safe_env_name "$account_env"; then
            failures=$(( failures + 1 ))
            continue
        fi
        email="${!account_env:-}"
        if [[ -z "$email" ]]; then
            failures=$(( failures + 1 ))
            continue
        fi
        if result="$(printf '%s\n' "$email" |
            "$agent" --state-db "$db" --check-breached-account \
                --allow-network --hibp-api-key-env "$key_env" \
                2>/dev/null)"; then
            if [[ "$result" != *'"schema":"io.oh-my-safety/breached-account-check"'* ||
                  "$result" != *'"schema_version":1'* ]]; then
                failures=$(( failures + 1 ))
            elif [[ "$result" == *'"result":{"state":"found"'* ]]; then
                print_check_result warn "a monitored account appears in one or more known breach records"
                echo "  - inspect privately with: oh-my-safety exposure account --allow-network --email-env $account_env   [id: breach-exposure:$account_env]"
                findings=$(( findings + 1 ))
            elif [[ "$result" != *'"result":{"state":"not_found"'* ]]; then
                # Unsupported or malformed results are coverage failures, never
                # evidence that the monitored account is clear.
                failures=$(( failures + 1 ))
            fi
        else
            failures=$(( failures + 1 ))
        fi
        result=""
        email=""
    done <<EOF
$account_envs
EOF

    if [[ "$findings" -gt 0 ]]; then
        if [[ "$failures" -gt 0 ]]; then
            print_check_result warn "$failures monitored account lookup(s) could not complete"
            echo "  - restore exposure-check coverage and recheck   [id: breach-exposure:coverage]"
            CHECK_FINDING_SUMMARY="$findings monitored account(s) have known breach exposure; $failures lookup(s) incomplete"
        else
            CHECK_FINDING_SUMMARY="$findings monitored account(s) have known breach exposure"
        fi
        CHECK_RESULT_SEVERITY="warn"
        return 1
    fi
    if [[ "$failures" -gt 0 ]]; then
        CHECK_FINDING_SUMMARY="$failures monitored account lookup(s) could not complete"
        return 42
    fi
    print_check_result pass "No configured account appeared in the provider response"
    CHECK_FINDING_SUMMARY="no provider matches"
    return 0
}
