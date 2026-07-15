#!/bin/bash
# oh-my-safety - Deep secret content scan (opt-in gitleaks/trufflehog)
# Off by default. Runs ONLY when the tool is enabled under `tools:` in config
# AND installed. oh-my-safety never installs or auto-updates these tools.

CHECK_NAME="secrets-content"
CHECK_DESCRIPTION="Deep secret scan (gitleaks/trufflehog)"
CHECK_CATEGORY="security"
CHECK_PLATFORMS="macos"
CHECK_SEVERITY="warn"
CHECK_CONTRACT="2"
CHECK_REQUIRES_NETWORK="false"
CHECK_INTERVAL="86400"
CHECK_DOC="docs/checks/security/secrets-content.md"

check_secrets_content() {
    if ! optional_tool gitleaks && ! optional_tool trufflehog; then
        print_check_result skip "content scan off — enable tools.gitleaks or tools.trufflehog and install the tool"
        CHECK_FINDING_SUMMARY="disabled"
        return 77
    fi

    local roots findings=0 root
    roots="$(config_get_list 'checks.security.secrets_content.scan_roots')"
    [[ -z "$roots" ]] && roots="$(printf '%s\n' "$HOME/Projects" "$HOME/Developer" "$HOME/code" "$HOME/src")"

    while IFS= read -r root; do
        [[ -z "$root" ]] && continue
        root="$(config_expand_path "$root")"
        [[ -d "$root" ]] || continue

        if optional_tool gitleaks; then
            # --redact is mandatory: never surface secret values.
            if ! gitleaks dir "$root" --redact --no-banner >/dev/null 2>&1; then
                allowlist_match secrets-content "sec-content:gitleaks:$root" || {
                    print_check_result warn "gitleaks flagged potential secrets under $root"
                    echo "  - inspect: gitleaks dir '$root' --redact   [id: sec-content:gitleaks:$root]"
                    findings=$((findings + 1))
                }
            fi
        fi

        if optional_tool trufflehog; then
            # --no-verification is NON-NEGOTIABLE: trufflehog's default behavior
            # sends discovered candidate credentials to their issuing services to
            # verify them — a phone-home that violates our no-network guarantee.
            local th_out; th_out="$(trufflehog filesystem "$root" --no-verification --no-update --json 2>/dev/null)"
            if [[ -n "$th_out" ]]; then
                allowlist_match secrets-content "sec-content:trufflehog:$root" || {
                    print_check_result warn "trufflehog flagged potential secrets under $root"
                    echo "  - inspect: trufflehog filesystem '$root' --no-verification   [id: sec-content:trufflehog:$root]"
                    findings=$((findings + 1))
                }
            fi
        fi
    done <<EOF
$roots
EOF

    if [[ $findings -gt 0 ]]; then
        CHECK_FINDING_SUMMARY="$findings location(s) with potential secrets"
        CHECK_RESULT_SEVERITY="warn"
        return 1
    fi
    print_check_result pass "No secrets found by content scan"
    CHECK_FINDING_SUMMARY="clean"
    return 0
}
