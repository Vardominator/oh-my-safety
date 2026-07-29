#!/usr/bin/env bats
# SwiftBar wrapper resolution is deterministic across parallel installations.

setup() {
    PLUGIN_DIR="$BATS_TEST_TMPDIR/plugins"
    PINNED_DIR="$BATS_TEST_TMPDIR/pinned"
    FALLBACK_DIR="$BATS_TEST_TMPDIR/fallback"
    mkdir -p "$PLUGIN_DIR" "$PINNED_DIR" "$FALLBACK_DIR"
    cp "$BATS_TEST_DIRNAME/../plugins/swiftbar/oh-my-safety.30s.sh" \
        "$PLUGIN_DIR/oh-my-safety.30s.sh"
    chmod +x "$PLUGIN_DIR/oh-my-safety.30s.sh"

    cat > "$PINNED_DIR/oh-my-safety" <<'EOF'
#!/bin/sh
printf 'pinned:%s\n' "$*"
EOF
    cat > "$FALLBACK_DIR/oh-my-safety" <<'EOF'
#!/bin/sh
printf 'fallback:%s\n' "$*"
EOF
    chmod +x "$PINNED_DIR/oh-my-safety" "$FALLBACK_DIR/oh-my-safety"
}

@test "SwiftBar uses the binary selected by menubar install" {
    printf '%s\n' "$PINNED_DIR/oh-my-safety" > "$PLUGIN_DIR/.oh-my-safety-bin"

    run env PATH="$FALLBACK_DIR:$PATH" "$PLUGIN_DIR/oh-my-safety.30s.sh"

    [ "$status" -eq 0 ]
    [ "$output" = "pinned:status --format swiftbar" ]
}

@test "SwiftBar ignores a symlinked pin and falls back safely" {
    ln -s "$PINNED_DIR/oh-my-safety" "$PLUGIN_DIR/.oh-my-safety-bin"

    run env PATH="$FALLBACK_DIR:$PATH" "$PLUGIN_DIR/oh-my-safety.30s.sh"

    [ "$status" -eq 0 ]
    [ "$output" = "fallback:status --format swiftbar" ]
}
