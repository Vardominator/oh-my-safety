# Shared bats setup for oh-my-safety unit tests.
# Sources the framework with an isolated state/config dir per test.

_oms_setup() {
    OMS_ROOT="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
    export OMS_ROOT
    export OMS_STATE_DIR="$BATS_TEST_TMPDIR/state"
    export XDG_CONFIG_HOME="$BATS_TEST_TMPDIR/config"
    export OMS_VERBOSE=false
    # core.sh sources detect.sh, yaml.sh, state.sh, allowlist.sh
    # shellcheck source=/dev/null
    source "$OMS_ROOT/lib/core.sh"
}

# Return only the portable octal permission bits for a test path. GNU stat's
# -f option describes the filesystem and can still exit successfully, so
# probing BSD syntax before GNU syntax is not a reliable portability check.
_oms_test_file_mode() {
    case "$(uname -s)" in
        Darwin) stat -f '%Lp' "$1" ;;
        *) stat -c '%a' "$1" ;;
    esac
}
