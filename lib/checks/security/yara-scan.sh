#!/bin/bash
# oh-my-safety - YARA scan (opt-in)
# Off by default. Runs ONLY when tools.yara is enabled, yara is installed, and
# the user has pointed rules_dir at a LOCAL rules directory. oh-my-safety never
# downloads YARA rules (that would break the no-network guarantee); clone a
# rules repo yourself and point rules_dir at it.

CHECK_NAME="yara-scan"
CHECK_DESCRIPTION="YARA malware-rule scan of download/temp dirs"
CHECK_CATEGORY="security"
CHECK_PLATFORMS="macos"
CHECK_SEVERITY="critical"
CHECK_CONTRACT="2"
CHECK_REQUIRES_NETWORK="false"
CHECK_INTERVAL="86400"
CHECK_DOC="docs/checks/security/yara-scan.md"

check_yara_scan() {
    if ! optional_tool yara; then
        print_check_result skip "YARA scan off — enable tools.yara and install yara"
        CHECK_FINDING_SUMMARY="disabled"
        return 77
    fi

    local rules
    rules="$(config_expand_path "$(config_get 'checks.security.yara_scan.rules_dir' '')")"
    if [[ -z "$rules" || ! -d "$rules" ]]; then
        print_check_result skip "no YARA rules_dir configured — set checks.security.yara_scan.rules_dir to a local rules directory"
        CHECK_FINDING_SUMMARY="no rules dir"
        return 77
    fi

    local paths hits=0 rulefile target match
    paths="$(config_get_list 'checks.security.yara_scan.scan_paths')"
    [[ -z "$paths" ]] && paths="$(printf '%s\n' "$HOME/Downloads" "/tmp")"

    for rulefile in "$rules"/*.yar "$rules"/*.yara; do
        [[ -f "$rulefile" ]] || continue
        while IFS= read -r target; do
            [[ -z "$target" ]] && continue
            target="$(config_expand_path "$target")"
            [[ -e "$target" ]] || continue
            match="$(yara -r -w "$rulefile" "$target" 2>/dev/null)" || true
            if [[ -n "$match" ]]; then
                allowlist_match yara-scan "yara:$(basename "$rulefile")" && continue
                print_check_result critical "YARA match ($(basename "$rulefile")) in $target"
                printf '%s\n' "$match" | sed 's/^/    /'
                echo "  [id: yara:$(basename "$rulefile")]"
                hits=$((hits + 1))
            fi
        done <<EOF
$paths
EOF
    done

    if [[ $hits -gt 0 ]]; then
        CHECK_FINDING_SUMMARY="$hits YARA match(es)"
        CHECK_RESULT_SEVERITY="critical"
        return 1
    fi
    print_check_result pass "No YARA matches"
    CHECK_FINDING_SUMMARY="clean"
    return 0
}
