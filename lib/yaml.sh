#!/bin/bash
# oh-my-safety - Configuration (path-aware YAML subset parser)
#
# Pure-bash, bash 3.2 compatible. Parses a deliberately small, documented
# subset of YAML once into flat "dotted.path=value" lines, then answers
# lookups against that in-memory flattened form.
#
# Supported subset:
#   - 2-space indentation only
#   - key: scalar
#   - block lists of scalars ("- item") indented 2 spaces deeper than their key
#   - full-line "#" comments and blank lines
#   - single/double quotes around scalars are stripped
# NOT supported: inline {}/[] flow collections, multi-line strings, anchors,
#   nested maps inside list items, inline "# comments" after a value, tabs.

# Guard against double-sourcing
[[ -n "${_OMS_YAML_LOADED:-}" ]] && return 0
_OMS_YAML_LOADED=1

# Flatten a YAML file to "path=value" lines on stdout.
# List items become repeated "path=value" lines (one per item).
yaml_flatten() {
    local file="$1"
    [[ -f "$file" ]] || return 0

    local -a stack=()
    local stack_len=0
    local line stripped indent level key rest value parent i

    while IFS= read -r line || [[ -n "$line" ]]; do
        # Strip trailing CR (files edited on Windows)
        line="${line%$'\r'}"
        # Skip blank lines and full-line comments
        [[ -z "${line//[[:space:]]/}" ]] && continue
        [[ "$line" =~ ^[[:space:]]*# ]] && continue

        # Compute indentation (spaces only; tabs are unsupported and will misparse)
        stripped="${line#"${line%%[![:space:]]*}"}"
        indent=$(( ${#line} - ${#stripped} ))
        level=$(( indent / 2 ))

        if [[ "$stripped" =~ ^-[[:space:]]+(.*)$ ]]; then
            # List item: parent is the key stack up to (level-1)
            value="${BASH_REMATCH[1]}"
            value="$(_yaml_clean_value "$value")"
            parent=""
            i=0
            while [[ $i -lt $level && $i -lt $stack_len ]]; do
                if [[ -z "$parent" ]]; then
                    parent="${stack[$i]}"
                else
                    parent="${parent}.${stack[$i]}"
                fi
                i=$(( i + 1 ))
            done
            [[ -n "$parent" ]] && printf '%s=%s\n' "$parent" "$value"
            continue
        fi

        if [[ "$stripped" =~ ^([A-Za-z0-9_.-]+):[[:space:]]*(.*)$ ]]; then
            key="${BASH_REMATCH[1]}"
            rest="${BASH_REMATCH[2]}"

            # Record key at this level, truncating anything deeper
            stack[$level]="$key"
            stack_len=$(( level + 1 ))

            if [[ -n "${rest//[[:space:]]/}" ]]; then
                value="$(_yaml_clean_value "$rest")"
                # Build full dotted path
                local path=""
                i=0
                while [[ $i -lt $stack_len ]]; do
                    if [[ -z "$path" ]]; then
                        path="${stack[$i]}"
                    else
                        path="${path}.${stack[$i]}"
                    fi
                    i=$(( i + 1 ))
                done
                printf '%s=%s\n' "$path" "$value"
            fi
        fi
    done < "$file"
}

# Clean a scalar value: strip a whitespace-preceded inline "# comment" (unless
# the value is quoted), trailing whitespace, then surrounding quotes.
_yaml_clean_value() {
    local v="$1"
    case "$v" in
        \"*|\'*) : ;;                      # quoted value: leave any '#' intact
        *) v="${v%%[[:space:]]#*}" ;;      # drop inline comment
    esac
    # Trim trailing whitespace
    v="${v%"${v##*[![:space:]]}"}"
    # Strip matching surrounding quotes
    v="${v#\"}"; v="${v%\"}"
    v="${v#\'}"; v="${v%\'}"
    printf '%s' "$v"
}

# Resolve which config file to use, migrating the legacy oh-my-privacy config
# once if present, and load user + default layers into memory.
# Sets: OMS_CONFIG_FILE, OMS_CONFIG_FLAT_USER, OMS_CONFIG_FLAT_DEFAULT
load_config() {
    local explicit="${1:-}"
    local user_cfg=""
    local default_cfg="$OMS_ROOT/config/default.yaml"

    local cfg_dir="${XDG_CONFIG_HOME:-$HOME/.config}/oh-my-safety"
    local legacy_dir="$HOME/.config/oh-my-privacy"

    if [[ -n "$explicit" ]]; then
        if [[ ! -f "$explicit" ]]; then
            log_error "Config file not found: $explicit"
            return 1
        fi
        user_cfg="$explicit"
    elif [[ -f "$cfg_dir/config.yaml" ]]; then
        user_cfg="$cfg_dir/config.yaml"
    elif [[ -f "$legacy_dir/config.yaml" ]]; then
        # One-time migration: copy (never move) the legacy config forward
        if mkdir -p "$cfg_dir" 2>/dev/null && cp "$legacy_dir/config.yaml" "$cfg_dir/config.yaml" 2>/dev/null; then
            log_info "Migrated config from ~/.config/oh-my-privacy to ~/.config/oh-my-safety"
            user_cfg="$cfg_dir/config.yaml"
        else
            user_cfg="$legacy_dir/config.yaml"
        fi
    fi

    OMS_CONFIG_FILE="${user_cfg:-$default_cfg}"
    export OMS_CONFIG_FILE

    if [[ -n "$user_cfg" && "$user_cfg" != "$default_cfg" ]]; then
        OMS_CONFIG_FLAT_USER="$(yaml_flatten "$user_cfg")"
    else
        OMS_CONFIG_FLAT_USER=""
    fi
    OMS_CONFIG_FLAT_DEFAULT="$(yaml_flatten "$default_cfg")"

    # Highest-precedence override layer, managed by enable/disable/set. Stored
    # as flat "path=value" lines (no YAML parsing needed).
    OMS_OVERRIDES_FILE="$cfg_dir/overrides.conf"
    export OMS_OVERRIDES_FILE
    if [[ -f "$OMS_OVERRIDES_FILE" ]]; then
        OMS_CONFIG_FLAT_OVERRIDE="$(grep -vE '^[[:space:]]*(#|$)' "$OMS_OVERRIDES_FILE" || true)"
    else
        OMS_CONFIG_FLAT_OVERRIDE=""
    fi

    log_debug "Config: user=${user_cfg:-none} default=$default_cfg overrides=$OMS_OVERRIDES_FILE"
}

# Get a scalar config value by dotted path. Precedence: override layer, then
# user layer, then default layer, then the provided fallback.
config_get() {
    local path="$1"
    local default="${2:-}"
    local esc="${path//./\\.}"
    local v=""

    if [[ -n "${OMS_CONFIG_FLAT_OVERRIDE:-}" ]]; then
        v="$(printf '%s\n' "$OMS_CONFIG_FLAT_OVERRIDE" | grep -m1 "^${esc}=" || true)"
    fi
    if [[ -z "$v" && -n "${OMS_CONFIG_FLAT_USER:-}" ]]; then
        v="$(printf '%s\n' "$OMS_CONFIG_FLAT_USER" | grep -m1 "^${esc}=" || true)"
    fi
    if [[ -z "$v" && -n "${OMS_CONFIG_FLAT_DEFAULT:-}" ]]; then
        v="$(printf '%s\n' "$OMS_CONFIG_FLAT_DEFAULT" | grep -m1 "^${esc}=" || true)"
    fi

    if [[ -z "$v" ]]; then
        printf '%s\n' "$default"
    else
        printf '%s\n' "${v#*=}"
    fi
}

# Get a list config value by dotted path (one item per line). The first layer
# (override, then user, then default) that defines the path fully supplies it.
config_get_list() {
    local path="$1"
    local esc="${path//./\\.}"
    local out=""

    if [[ -n "${OMS_CONFIG_FLAT_OVERRIDE:-}" ]]; then
        out="$(printf '%s\n' "$OMS_CONFIG_FLAT_OVERRIDE" | grep "^${esc}=" || true)"
    fi
    if [[ -z "$out" && -n "${OMS_CONFIG_FLAT_USER:-}" ]]; then
        out="$(printf '%s\n' "$OMS_CONFIG_FLAT_USER" | grep "^${esc}=" || true)"
    fi
    if [[ -z "$out" && -n "${OMS_CONFIG_FLAT_DEFAULT:-}" ]]; then
        out="$(printf '%s\n' "$OMS_CONFIG_FLAT_DEFAULT" | grep "^${esc}=" || true)"
    fi

    [[ -z "$out" ]] && return 0
    printf '%s\n' "$out" | sed 's/^[^=]*=//'
}

# Persist a scalar override (highest precedence) and refresh it in memory.
# This is how `enable`/`disable`/`set` mutate configuration without editing
# the user's nested YAML by hand.
config_set() {
    local path="$1" value="$2"
    local ov="${OMS_OVERRIDES_FILE:-${XDG_CONFIG_HOME:-$HOME/.config}/oh-my-safety/overrides.conf}"
    local esc="${path//./\\.}" tmp
    mkdir -p "$(dirname "$ov")" 2>/dev/null || true
    tmp="${ov}.tmp.$$"
    if [[ -f "$ov" ]]; then
        grep -v "^${esc}=" "$ov" > "$tmp" 2>/dev/null || true
    else
        printf '# oh-my-safety config overrides (managed by enable/disable/set)\n' > "$tmp"
    fi
    printf '%s=%s\n' "$path" "$value" >> "$tmp"
    mv -f "$tmp" "$ov"
    OMS_OVERRIDES_FILE="$ov"
    OMS_CONFIG_FLAT_OVERRIDE="$(grep -vE '^[[:space:]]*(#|$)' "$ov" || true)"
}

# True if a config path is enabled (true/yes/1/on). Defaults to true when unset.
config_enabled() {
    local path="$1"
    local default="${2:-true}"
    local v
    v="$(config_get "$path" "$default")"
    [[ "$v" == "true" || "$v" == "yes" || "$v" == "1" || "$v" == "on" ]]
}

# True if an optional external tool is BOTH enabled in config AND installed.
# Never auto-installs; this is the single gate for opt-in integrations.
optional_tool() {
    local name="$1"
    config_enabled "tools.${name}.enabled" "false" && command_exists "$name"
}

# Expand a leading ~ in a config path value to $HOME.
config_expand_path() {
    local p="$1"
    case "$p" in
        "~") printf '%s' "$HOME" ;;
        "~/"*) printf '%s' "$HOME/${p#\~/}" ;;
        *) printf '%s' "$p" ;;
    esac
}
