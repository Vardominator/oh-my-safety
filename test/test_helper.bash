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
