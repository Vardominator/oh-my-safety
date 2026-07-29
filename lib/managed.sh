#!/bin/bash
# oh-my-safety - local adapter for verified organization policy and sync.

[[ -n "${_OMS_MANAGED_LOADED:-}" ]] && return 0
_OMS_MANAGED_LOADED=1

managed_state_path() {
    state_path "managed-enrollment.json"
}

managed_policy_path() {
    state_path "managed-policy.json"
}

managed_agent_path() {
    if [[ -n "${OMS_AGENT_CORE_BIN:-}" && -x "$OMS_AGENT_CORE_BIN" ]]; then
        printf '%s' "$OMS_AGENT_CORE_BIN"
    elif command -v oh-my-safety-agent >/dev/null 2>&1; then
        command -v oh-my-safety-agent
    elif [[ -x "$OMS_ROOT/bin/oh-my-safety-agent" ]]; then
        printf '%s' "$OMS_ROOT/bin/oh-my-safety-agent"
    fi
}

managed_is_enrolled() {
    local state
    state="$(managed_state_path)"
    config_enabled "organization.enabled" "false" &&
        [[ -f "$state" && ! -L "$state" ]]
}

_managed_profile_config() {
    case "$1" in
        personal-balanced)
            printf '%s\n' \
                "profile.name=personal-balanced" \
                "profile.workload=workstation" \
                "profile.protection=balanced" \
                "profile.management=standalone" \
                "profile.connectivity=connected"
            ;;
        personal-strict)
            printf '%s\n' \
                "profile.name=personal-strict" \
                "profile.workload=workstation" \
                "profile.protection=strict" \
                "profile.management=standalone" \
                "profile.connectivity=connected"
            ;;
        developer)
            printf '%s\n' \
                "profile.name=developer" \
                "profile.workload=developer" \
                "profile.protection=strict" \
                "profile.management=standalone" \
                "profile.connectivity=connected"
            ;;
        managed-workstation)
            printf '%s\n' \
                "profile.name=managed-workstation" \
                "profile.workload=workstation" \
                "profile.protection=strict" \
                "profile.management=managed" \
                "profile.connectivity=connected"
            ;;
        managed-server)
            printf '%s\n' \
                "profile.name=managed-server" \
                "profile.workload=server" \
                "profile.protection=strict" \
                "profile.management=managed" \
                "profile.connectivity=connected"
            ;;
        airgapped-high-assurance)
            printf '%s\n' \
                "profile.name=airgapped-high-assurance" \
                "profile.workload=workstation" \
                "profile.protection=strict" \
                "profile.management=standalone" \
                "profile.connectivity=airgapped"
            ;;
        *) return 1 ;;
    esac
}

# Convert the agent's bounded, signed-policy-derived TSV into the ordinary flat
# config layer. Every row is revalidated even though the producer is trusted.
_managed_policy_tsv_to_config() {
    local input="$1" kind first second extra
    local schema=false policy_id="" revision="" profile=""
    local scan_interval="" jitter="" reporting="" sync_interval="" remediation=""
    local checks="" seen_checks="" count=0 check_count=0

    while IFS=$'\t' read -r kind first second extra || [[ -n "$kind" ]]; do
        count=$(( count + 1 ))
        [[ "$count" -le 600 ]] || return 1
        [[ -z "$extra" ]] || return 1
        case "$kind" in
            schema)
                [[ "$schema" == "false" &&
                   "$first" == "io.oh-my-safety/managed-policy-flat" &&
                   "$second" == "1" ]] || return 1
                schema=true
                ;;
            policy_id)
                [[ -z "$policy_id" && -z "$second" ]] || return 1
                case "$first" in ''|*[!A-Za-z0-9._-]*) return 1 ;; esac
                [[ "${#first}" -le 128 ]] || return 1
                policy_id="$first"
                ;;
            revision)
                [[ -z "$revision" && -z "$second" ]] || return 1
                case "$first" in ''|*[!0-9]*|0) return 1 ;; esac
                [[ "${#first}" -le 20 ]] || return 1
                revision="$first"
                ;;
            profile)
                [[ -z "$profile" && -z "$second" ]] || return 1
                _managed_profile_config "$first" >/dev/null || return 1
                profile="$first"
                ;;
            cadence_scan_interval_seconds)
                [[ -z "$scan_interval" && -z "$second" ]] || return 1
                case "$first" in ''|*[!0-9]*|0) return 1 ;; esac
                scan_interval="$first"
                ;;
            cadence_jitter_seconds)
                [[ -z "$jitter" && -z "$second" ]] || return 1
                case "$first" in ''|*[!0-9]*) return 1 ;; esac
                jitter="$first"
                ;;
            reporting_enabled)
                [[ -z "$reporting" && -z "$second" ]] || return 1
                [[ "$first" == "true" || "$first" == "false" ]] || return 1
                reporting="$first"
                ;;
            reporting_sync_interval_seconds)
                [[ -z "$sync_interval" && -z "$second" ]] || return 1
                case "$first" in ''|*[!0-9]*) return 1 ;; esac
                sync_interval="$first"
                ;;
            remediation)
                [[ -z "$remediation" && -z "$second" ]] || return 1
                case "$first" in observe|prompt|safe-automatic) ;; *) return 1 ;; esac
                remediation="$first"
                ;;
            check)
                case "$first" in ''|*[!A-Za-z0-9._-]*) return 1 ;; esac
                [[ "${#first}" -le 128 ]] || return 1
                [[ "$second" == "true" || "$second" == "false" ]] || return 1
                case "$seen_checks" in *"|${first}|"*) return 1 ;; esac
                seen_checks="${seen_checks}|${first}|"
                check_count=$(( check_count + 1 ))
                [[ "$check_count" -le 512 ]] || return 1
                if [[ -z "$checks" ]]; then
                    checks="managed.check.${first}=${second}"
                else
                    checks="$checks
managed.check.${first}=${second}"
                fi
                ;;
            "") ;;
            *) return 1 ;;
        esac
    done <<EOF
$input
EOF

    [[ "$schema" == "true" && -n "$policy_id" && -n "$revision" &&
       -n "$profile" && -n "$scan_interval" && -n "$jitter" &&
       -n "$reporting" && -n "$sync_interval" && -n "$remediation" &&
       "$check_count" -gt 0 ]] || return 1
    [[ "${#scan_interval}" -le 9 && "${#jitter}" -le 9 &&
       "${#sync_interval}" -le 9 ]] || return 1
    scan_interval="$(( 10#$scan_interval ))"
    jitter="$(( 10#$jitter ))"
    sync_interval="$(( 10#$sync_interval ))"
    [[ "$scan_interval" -ge 60 && "$scan_interval" -le 2678400 &&
       "$jitter" -lt "$scan_interval" ]] || return 1
    if [[ "$reporting" == "true" ]]; then
        [[ "$sync_interval" -ge 60 && "$sync_interval" -le 2678400 ]] || return 1
    else
        [[ "$sync_interval" -eq 0 ]] || return 1
    fi

    _managed_profile_config "$profile"
    # Jitter is reserved for a future deterministic early-staggering scheme.
    # It must never add delay beyond the signed hard maximum.
    printf '%s\n' \
        "monitoring.interval=$scan_interval" \
        "organization.policy.id=$policy_id" \
        "organization.policy.revision=$revision" \
        "organization.policy.scan_interval_seconds=$scan_interval" \
        "organization.policy.jitter_seconds=$jitter" \
        "organization.policy.reporting_enabled=$reporting" \
        "organization.policy.sync_interval_seconds=$sync_interval" \
        "organization.policy.remediation=$remediation"
    case "$remediation" in
        observe) printf '%s\n' "remediation.mode=observe" ;;
        prompt) printf '%s\n' "remediation.mode=ask" ;;
        safe-automatic)
            # No automatic remediation engine exists yet. Preserve the signed
            # intent while keeping endpoint behavior non-destructive.
            printf '%s\n' "remediation.mode=policy"
            ;;
    esac
    [[ -n "$checks" ]] && printf '%s\n' "$checks"
}

managed_config_snapshot() {
    local agent state db output
    config_enabled "organization.enabled" "false" || return 0
    agent="$(managed_agent_path)"
    state="$(managed_state_path)"
    db="$(state_path 'journal.db')"
    # Once management is locally enabled, an absent core or unsafe enrollment
    # state is a reload failure. A long-running monitor can then retain its
    # prior verified in-memory policy instead of silently dropping enforcement.
    [[ -n "$agent" && -f "$state" && ! -L "$state" ]] || return 1
    output="$("$agent" --state-db "$db" --managed-state "$state" \
        --managed-policy 2>/dev/null)" || return 1
    _managed_policy_tsv_to_config "$output"
}

_managed_sync_connectivity_allowed() {
    local effective local_setting
    effective="$(config_get 'profile.connectivity' 'connected')"
    # An explicit local offline/air-gapped selection is a safety boundary for
    # outbound traffic even while verified policy remains highest precedence
    # for ordinary configuration lookups.
    local_setting="$(
        OMS_CONFIG_FLAT_MANAGED=""
        config_get 'profile.connectivity' 'connected'
    )"
    [[ "$effective" == "connected" && "$local_setting" == "connected" ]]
}

managed_sync_now() {
    local agent state db
    agent="$(managed_agent_path)"
    state="$(managed_state_path)"
    db="$(state_path 'journal.db')"
    [[ -n "$agent" ]] || {
        log_error "The portable agent core is required for organization sync"
        return 1
    }
    [[ -f "$state" && ! -L "$state" ]] || {
        log_error "This endpoint is not enrolled"
        return 1
    }
    _managed_sync_connectivity_allowed || {
        log_error "Organization sync is blocked by the active local or managed connectivity profile"
        return 1
    }
    "$agent" --state-db "$db" --managed-state "$state" --managed-sync
}

managed_sync_if_due() {
    local now last interval resolved memory_last
    managed_is_enrolled || return 0
    [[ "$(config_get 'profile.management' 'standalone')" == "managed" ]] || return 0
    _managed_sync_connectivity_allowed || return 0

    if config_enabled "organization.policy.reporting_enabled" "true"; then
        interval="$(config_get 'organization.policy.sync_interval_seconds' \
            "$(config_get 'organization.sync_interval_seconds' '300')")"
    else
        # Reporting controls posture upload, not heartbeat/policy retrieval.
        # Continue polling at the local bootstrap cadence so a later signed
        # policy can re-enable reporting without requiring manual intervention.
        interval="$(config_get 'organization.sync_interval_seconds' '300')"
    fi
    case "$interval" in ''|*[!0-9]*|0) interval=300 ;; esac
    [[ "${#interval}" -le 9 ]] || interval=300
    interval="$(( 10#$interval ))"
    [[ "$interval" -ge 60 ]] || interval=300
    now="$(date +%s)"
    last="$(schedule_last_epoch organization managed-sync)"
    case "$last" in ''|*[!0-9]*) last=0 ;; esac
    [[ "${#last}" -le 18 ]] || last=0
    memory_last="${_OMS_MANAGED_SYNC_LAST_ATTEMPT:-0}"
    case "$memory_last" in ''|*[!0-9]*) memory_last=0 ;; esac
    [[ "${#memory_last}" -le 18 ]] || memory_last=0
    [[ "$memory_last" -le "$last" ]] || last="$memory_last"
    [[ "$now" -ge "$last" && $(( now - last )) -ge "$interval" ]] || return 0

    # Advance the retry clock even on failure so an unavailable controller
    # cannot create a tight network/notification loop. The in-memory clock is
    # also authoritative for this process if durable schedule state is
    # temporarily unwritable.
    _OMS_MANAGED_SYNC_LAST_ATTEMPT="$now"
    schedule_record_epoch organization managed-sync "$now" ||
        log_warn "Could not persist organization sync schedule state"
    if managed_sync_now >/dev/null 2>&1; then
        event_append "organization.sync_succeeded" "info" "organization" \
            "controller" "redacted posture synchronized" || true
        resolved="$(_notify_resolve_missing managed-sync </dev/null)"
        [[ -z "$resolved" ]] || notify "oh-my-safety: resolved" \
            "Organization synchronization recovered" ""
        return 0
    fi
    event_append "organization.sync_failed" "warn" "organization" \
        "controller" "controller synchronization failed" || true
    notify_finding managed-sync warn coverage:managed-sync \
        "oh-my-safety: organization sync failed" \
        "The controller could not be reached or its signed policy was rejected"
    return 1
}
