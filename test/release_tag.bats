#!/usr/bin/env bats

setup() {
    OMS_ROOT="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
    MOCK_BIN="$BATS_TEST_TMPDIR/bin"
    mkdir -p "$MOCK_BIN"
    export PATH="$MOCK_BIN:$PATH"
    export GH_TOKEN="test-token"
    TAG_OBJECT_SHA="1111111111111111111111111111111111111111"
    COMMIT_SHA="2222222222222222222222222222222222222222"
    export TAG_OBJECT_SHA COMMIT_SHA
}

write_mock_gh() {
    ref_type="$1"
    verified="$2"
    reason="$3"
    cat >"$MOCK_BIN/gh" <<'EOF'
#!/bin/bash
case "$*" in
    *"/git/ref/tags/"*)
        printf '%s\t%s\n' "${MOCK_REF_TYPE}" "$TAG_OBJECT_SHA"
        ;;
    *"/git/tags/"*)
        printf '%s\t%s\tcommit\t%s\n' \
            "${MOCK_VERIFIED}" "${MOCK_REASON}" "$COMMIT_SHA"
        ;;
    *)
        exit 2
        ;;
esac
EOF
    chmod 0755 "$MOCK_BIN/gh"
    export MOCK_REF_TYPE="$ref_type"
    export MOCK_VERIFIED="$verified"
    export MOCK_REASON="$reason"
}

@test "release tag verification accepts a verified annotated tag at the expected commit" {
    write_mock_gh tag true valid

    run "$OMS_ROOT/scripts/verify-github-tag.sh" \
        v1.2.3 owner/repository "$COMMIT_SHA"

    [ "$status" -eq 0 ]
    [[ "$output" == *"Verified signed tag v1.2.3"* ]]
}

@test "release tag verification rejects lightweight tags" {
    write_mock_gh commit true valid

    run "$OMS_ROOT/scripts/verify-github-tag.sh" \
        v1.2.3 owner/repository "$COMMIT_SHA"

    [ "$status" -eq 2 ]
    [[ "$output" == *"lightweight tags are not accepted"* ]]
}

@test "release tag verification rejects signatures GitHub did not verify" {
    write_mock_gh tag false unknown_key

    run "$OMS_ROOT/scripts/verify-github-tag.sh" \
        v1.2.3 owner/repository "$COMMIT_SHA"

    [ "$status" -eq 2 ]
    [[ "$output" == *"reason: unknown_key"* ]]
}
