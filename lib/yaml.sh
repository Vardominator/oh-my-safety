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
# Sets: OMS_CONFIG_FILE, OMS_CONFIG_FLAT_USER, OMS_CONFIG_FLAT_DEFAULT,
# OMS_CONFIG_FLAT_OVERRIDE, and the optional verified managed-policy layer.
load_config() {
    local explicit="${1:-}"
    local user_cfg=""
    local default_cfg="$OMS_ROOT/config/default.yaml"
    local previous_managed="${OMS_CONFIG_FLAT_MANAGED:-}"

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

    OMS_CONFIG_FLAT_MANAGED=""
    if type managed_config_snapshot >/dev/null 2>&1; then
        if ! OMS_CONFIG_FLAT_MANAGED="$(managed_config_snapshot)"; then
            OMS_CONFIG_FLAT_MANAGED="$previous_managed"
            if [[ -n "$previous_managed" ]]; then
                log_warn "Verified organization policy could not be reloaded; retaining the last verified snapshot"
            else
                log_warn "Verified organization policy could not be loaded; retaining local protection"
            fi
        fi
    fi

    log_debug "Config: user=${user_cfg:-none} default=$default_cfg overrides=$OMS_OVERRIDES_FILE managed=$([[ -n "$OMS_CONFIG_FLAT_MANAGED" ]] && echo active || echo none)"
}

# Get a scalar config value by dotted path. A verified organization policy has
# precedence for the fields it explicitly controls, followed by local
# override, user, default, and fallback layers.
config_get() {
    local path="$1"
    local default="${2:-}"
    local esc="${path//./\\.}"
    local v=""

    if [[ -n "${OMS_CONFIG_FLAT_MANAGED:-}" ]]; then
        v="$(printf '%s\n' "$OMS_CONFIG_FLAT_MANAGED" | grep -m1 "^${esc}=" || true)"
    fi
    if [[ -z "$v" && -n "${OMS_CONFIG_FLAT_OVERRIDE:-}" ]]; then
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

    if [[ -n "${OMS_CONFIG_FLAT_MANAGED:-}" ]]; then
        out="$(printf '%s\n' "$OMS_CONFIG_FLAT_MANAGED" | grep "^${esc}=" || true)"
    fi
    if [[ -z "$out" && -n "${OMS_CONFIG_FLAT_OVERRIDE:-}" ]]; then
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
    local esc tmp
    case "$path" in ''|*[!A-Za-z0-9_.-]*)
        log_error "Invalid configuration path: $path"
        return 1 ;;
    esac
    case "$value" in *$'\n'*|*$'\r'*)
        log_error "Configuration values must fit on one line"
        return 1 ;;
    esac
    esc="${path//./\\.}"
    mkdir -p "$(dirname "$ov")" 2>/dev/null || true
    tmp="${ov}.tmp.$$"
    if [[ -f "$ov" ]]; then
        grep -v "^${esc}=" "$ov" > "$tmp" 2>/dev/null || true
    else
        printf '# oh-my-safety config overrides (managed by enable/disable/set)\n' > "$tmp"
    fi
    printf '%s=%s\n' "$path" "$value" >> "$tmp"
    chmod 600 "$tmp" 2>/dev/null || true
    mv -f "$tmp" "$ov" || { rm -f "$tmp"; return 1; }
    OMS_OVERRIDES_FILE="$ov"
    OMS_CONFIG_FLAT_OVERRIDE="$(grep -vE '^[[:space:]]*(#|$)' "$ov" || true)"
}

# Persist multiple path=value records from stdin as one atomic override update.
# Later records win. This is used for profile changes so a crash cannot leave a
# half-applied security posture.
config_set_many() {
    local ov="${OMS_OVERRIDES_FILE:-${XDG_CONFIG_HOME:-$HOME/.config}/oh-my-safety/overrides.conf}"
    local incoming="${ov}.incoming.$$" merged="${ov}.tmp.$$"
    local line path value esc
    mkdir -p "$(dirname "$ov")" 2>/dev/null || return 1
    : > "$incoming" || return 1
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" ]] && continue
        case "$line" in *=*) : ;; *) rm -f "$incoming"; return 1 ;; esac
        path="${line%%=*}"
        value="${line#*=}"
        case "$path" in ''|*[!A-Za-z0-9_.-]*) rm -f "$incoming"; return 1 ;; esac
        case "$value" in *$'\r'*|*$'\n'*) rm -f "$incoming"; return 1 ;; esac
        esc="${path//./\\.}"
        grep -v "^${esc}=" "$incoming" > "${incoming}.next" 2>/dev/null || true
        printf '%s=%s\n' "$path" "$value" >> "${incoming}.next"
        mv -f "${incoming}.next" "$incoming" || { rm -f "$incoming"; return 1; }
    done

    printf '# oh-my-safety config overrides (managed by enable/disable/set/profile)\n' > "$merged"
    if [[ -f "$ov" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ -z "$line" || "$line" == \#* ]] && continue
            path="${line%%=*}"
            esc="${path//./\\.}"
            if ! grep -q "^${esc}=" "$incoming" 2>/dev/null; then
                printf '%s\n' "$line" >> "$merged"
            fi
        done < "$ov"
    fi
    cat "$incoming" >> "$merged"
    chmod 600 "$merged" 2>/dev/null || true
    mv -f "$merged" "$ov" || {
        rm -f "$incoming" "$merged"
        return 1
    }
    rm -f "$incoming"
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
