#!/bin/bash
# oh-my-safety - bounded, built-in local secret content scanner.

CHECK_NAME="local-secret-scan"
CHECK_DESCRIPTION="Bounded built-in credential content scan"
CHECK_CATEGORY="security"
CHECK_PLATFORMS="macos linux"
CHECK_SEVERITY="warn"
CHECK_CONTRACT="2"
CHECK_REQUIRES_NETWORK="false"
CHECK_INTERVAL="86400"
CHECK_DOC="docs/checks/security/local-secret-scan.md"
CHECK_REMEDIATION="Inspect the redacted local result, rotate any exposed credential, remove it from files and history, then recheck."

check_local_secret_scan() {
    local agent roots root db result findings=false coverage=false
    local -a arguments=()
    agent="$(_agent_core_path)"
    if [[ -z "$agent" ]]; then
        print_check_result skip "portable local scanner is not installed"
        CHECK_FINDING_SUMMARY="portable scanner unavailable"
        CHECK_REMEDIATION="Install the v0.3.0 portable agent core, then recheck."
        return 77
    fi
    if [[ "${OMS_SCAN_SOURCE:-scan}" == "agent" &&
          "${OMS_DEEP:-false}" != "true" ]]; then
        print_check_result skip "scheduled deep scanning is disabled"
        CHECK_FINDING_SUMMARY="scheduled deep scanning disabled"
        return 77
    fi

    roots="$(config_get_list 'checks.security.local_secret_scan.scan_roots')"
    [[ -n "$roots" ]] ||
        roots="$(printf '%s\n' "$HOME/Projects" "$HOME/Developer" "$HOME/code" "$HOME/src")"
    while IFS= read -r root; do
        [[ -z "$root" ]] && continue
        root="$(config_expand_path "$root")"
        [[ -d "$root" || -f "$root" ]] || continue
        arguments+=(--scan-secrets "$root")
    done <<EOF
$roots
EOF
    if [[ "${#arguments[@]}" -eq 0 ]]; then
        print_check_result skip "no configured local secret scan roots exist"
        CHECK_FINDING_SUMMARY="no local scan roots"
        return 77
    fi

    db="$(state_path 'journal.db')"
    if ! result="$("$agent" --state-db "$db" "${arguments[@]}" 2>/dev/null)"; then
        CHECK_FINDING_SUMMARY="built-in credential scanner failed"
        return 42
    fi
    if [[ "$result" != *'"schema":"io.oh-my-safety/secret-scan"'* ||
          "$result" != *'"schema_version":1'* ||
          "$result" != *'"findings":['* ||
          "$result" != *'"coverage":['* ]]; then
        result=""
        CHECK_FINDING_SUMMARY="built-in credential scanner returned an invalid result"
        return 42
    fi
    [[ "$result" == *'"findings":[]'* ]] || findings=true
    [[ "$result" == *'"coverage":[]'* ]] || coverage=true
    result=""

    if [[ "$findings" == "true" ]]; then
        print_check_result warn "potential credential material found by the redacted local scanner"
        echo "  - inspect locally with: oh-my-safety secret-scan   [id: local-secret-scan:credential]"
    fi
    if [[ "$coverage" == "true" ]]; then
        print_check_result warn "local scanner reached a configured safety bound"
        echo "  - narrow scan roots or review scanner limits   [id: local-secret-scan:coverage]"
    fi
    if [[ "$findings" == "true" || "$coverage" == "true" ]]; then
        if [[ "$findings" == "true" ]]; then
            CHECK_FINDING_SUMMARY="potential credential material found"
        else
            CHECK_FINDING_SUMMARY="credential scan coverage was incomplete"
        fi
        CHECK_RESULT_SEVERITY="warn"
        return 1
    fi
    print_check_result pass "No credential material found within bounded local scan scope"
    CHECK_FINDING_SUMMARY="clean"
    return 0
}
