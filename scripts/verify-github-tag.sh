#!/bin/bash
# Require an annotated tag whose signature GitHub has cryptographically verified.

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: verify-github-tag.sh TAG [OWNER/REPOSITORY] [EXPECTED_COMMIT]

GH_TOKEN must authorize read access to the repository. EXPECTED_COMMIT, when
provided, must be the full commit SHA referenced by the signed annotated tag.
EOF
}

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 2
}

TAG="${1:-}"
REPOSITORY="${2:-${GITHUB_REPOSITORY:-}}"
EXPECTED_COMMIT="${3:-}"

[[ -n "$TAG" && -n "$REPOSITORY" ]] || {
    usage >&2
    exit 2
}
[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] ||
    die "invalid release tag: $TAG"
[[ "$REPOSITORY" =~ ^[0-9A-Za-z_.-]+/[0-9A-Za-z_.-]+$ ]] ||
    die "invalid GitHub repository: $REPOSITORY"
if [[ -n "$EXPECTED_COMMIT" ]]; then
    [[ "$EXPECTED_COMMIT" =~ ^[0-9a-fA-F]{40}$ ]] ||
        die "EXPECTED_COMMIT must be a full commit SHA"
    EXPECTED_COMMIT="$(printf '%s' "$EXPECTED_COMMIT" | tr '[:upper:]' '[:lower:]')"
fi

command -v gh >/dev/null 2>&1 || die "GitHub CLI is required"
[[ -n "${GH_TOKEN:-}" ]] || die "GH_TOKEN is required"

ref_record="$(
    gh api "repos/$REPOSITORY/git/ref/tags/$TAG" \
        --jq '[.object.type, .object.sha] | @tsv'
)" || die "unable to resolve tag $TAG"
IFS=$'\t' read -r ref_type tag_object_sha <<<"$ref_record"
[[ "$ref_type" = tag ]] ||
    die "$TAG must be an annotated tag; lightweight tags are not accepted"
[[ "$tag_object_sha" =~ ^[0-9a-f]{40}$ ]] ||
    die "GitHub returned an invalid tag-object SHA"

tag_record="$(
    gh api "repos/$REPOSITORY/git/tags/$tag_object_sha" \
        --jq '[.verification.verified, .verification.reason, .object.type, .object.sha] | @tsv'
)" || die "unable to inspect annotated tag $TAG"
IFS=$'\t' read -r verified verification_reason target_type target_sha <<<"$tag_record"

[[ "$verified" = true ]] ||
    die "GitHub did not verify the tag signature (reason: ${verification_reason:-unknown})"
[[ "$target_type" = commit ]] ||
    die "signed tag must point directly to a commit, not $target_type"
[[ "$target_sha" =~ ^[0-9a-f]{40}$ ]] ||
    die "GitHub returned an invalid target commit SHA"
if [[ -n "$EXPECTED_COMMIT" && "$target_sha" != "$EXPECTED_COMMIT" ]]; then
    die "signed tag targets $target_sha, expected $EXPECTED_COMMIT"
fi

printf 'Verified signed tag %s at commit %s\n' "$TAG" "$target_sha"
