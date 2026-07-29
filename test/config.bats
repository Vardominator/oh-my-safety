#!/usr/bin/env bats
# Config parser + layering tests (lib/yaml.sh)

setup() { load test_helper; _oms_setup; }

@test "yaml_flatten handles nesting, lists, inline comments and quotes" {
    cat > "$BATS_TEST_TMPDIR/f.yaml" <<'YAML'
a:
  b: 1        # inline comment stripped
  c: "quoted value"
  list:
    - x
    - y
YAML
    run yaml_flatten "$BATS_TEST_TMPDIR/f.yaml"
    [ "$status" -eq 0 ]
    [[ "$output" == *"a.b=1"* ]]
    [[ "$output" != *"inline comment"* ]]
    [[ "$output" == *"a.c=quoted value"* ]]
    [[ "$output" == *"a.list=x"* ]]
    [[ "$output" == *"a.list=y"* ]]
}

@test "config_get precedence: managed > override > user > default > fallback" {
    OMS_CONFIG_FLAT_MANAGED=$'x.y=managed'
    OMS_CONFIG_FLAT_OVERRIDE=$'x.y=override'
    OMS_CONFIG_FLAT_USER=$'x.y=user'
    OMS_CONFIG_FLAT_DEFAULT=$'x.y=default'
    run config_get x.y;   [ "$output" = "managed" ]

    OMS_CONFIG_FLAT_MANAGED=""
    run config_get x.y;   [ "$output" = "override" ]

    OMS_CONFIG_FLAT_OVERRIDE=""
    run config_get x.y;   [ "$output" = "user" ]

    OMS_CONFIG_FLAT_USER=""
    run config_get x.y;   [ "$output" = "default" ]

    OMS_CONFIG_FLAT_DEFAULT=""
    run config_get x.y fallback; [ "$output" = "fallback" ]
}

@test "config_get escapes dots (no accidental regex match)" {
    OMS_CONFIG_FLAT_DEFAULT=$'axb=nope\na.b=yes'
    run config_get a.b; [ "$output" = "yes" ]
}

@test "config_get_list returns each list item; user replaces default" {
    OMS_CONFIG_FLAT_DEFAULT=$'s.items=d1\ns.items=d2'
    OMS_CONFIG_FLAT_USER=$'s.items=u1'
    run config_get_list s.items
    [ "${lines[0]}" = "u1" ]
    [ "${#lines[@]}" -eq 1 ]
}

@test "config_enabled true/false/default" {
    OMS_CONFIG_FLAT_OVERRIDE=$'k.enabled=false'
    run config_enabled k.enabled; [ "$status" -ne 0 ]
    OMS_CONFIG_FLAT_OVERRIDE=$'k.enabled=yes'
    run config_enabled k.enabled; [ "$status" -eq 0 ]
    OMS_CONFIG_FLAT_OVERRIDE=""
    run config_enabled missing.key; [ "$status" -eq 0 ]  # defaults true
}

@test "config_set persists an override and config_get reads it back" {
    load_config
    config_set foo.bar baz
    run config_get foo.bar; [ "$output" = "baz" ]
    run grep -q '^foo.bar=baz' "$OMS_OVERRIDES_FILE"; [ "$status" -eq 0 ]
}

@test "config_set_many atomically replaces selected keys and preserves others" {
    load_config
    config_set keep.this yes
    config_set replace.this old
    config_set_many <<'EOF'
replace.this=new
add.this=value
EOF
    [ "$(config_get keep.this)" = "yes" ]
    [ "$(config_get replace.this)" = "new" ]
    [ "$(config_get add.this)" = "value" ]
    [ "$(grep -c '^replace.this=' "$OMS_OVERRIDES_FILE")" -eq 1 ]
}

@test "config setters reject unsafe paths and multiline values" {
    load_config
    run config_set 'bad[path]' value
    [ "$status" -ne 0 ]
    run config_set good.path $'line1\nline2'
    [ "$status" -ne 0 ]
}

@test "config_expand_path expands a leading tilde" {
    run config_expand_path '~/x'; [ "$output" = "$HOME/x" ]
    run config_expand_path '/abs'; [ "$output" = "/abs" ]
}

@test "monitor config reload applies a valid snapshot and rejects invalid cadence" {
    source "$OMS_ROOT/lib/cmd/monitor.sh"
    cfg="$BATS_TEST_TMPDIR/monitor.yaml"
    cat > "$cfg" <<'YAML'
monitoring:
  interval: 120
  fast_interval: 5
YAML
    OMS_CONFIG_FILE_ARG="$cfg"
    load_config "$cfg"
    _monitor_reload_config
    [ "$OMS_MONITOR_INTERVAL" = "120" ]
    [ "$OMS_MONITOR_FAST_INTERVAL" = "5" ]

    cat > "$cfg" <<'YAML'
monitoring:
  interval: never
  fast_interval: 1
YAML
    run _monitor_reload_config
    [ "$status" -ne 0 ]
    [ "$(config_get monitoring.interval)" = "120" ]
    [ "$(config_get monitoring.fast_interval)" = "5" ]
}
