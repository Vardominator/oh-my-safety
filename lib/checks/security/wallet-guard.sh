#!/bin/bash
# oh-my-safety - inventory crypto wallets (desktop + browser) and flag exposure
CHECK_NAME="wallet-guard"
CHECK_DESCRIPTION="Inventory crypto wallets and flag insecure permissions or cloud-synced seed data"
CHECK_CATEGORY="security"
CHECK_PLATFORMS="macos"
CHECK_SEVERITY="critical"
CHECK_CONTRACT="2"
CHECK_REQUIRES_NETWORK="false"
CHECK_INTERVAL="600"
CHECK_DOC="docs/checks/security/wallet-guard.md"

# Finding-id scheme (stable, path/id based - no pids):
#   wallet:<id>          inventory of a present desktop wallet (info)
#   wallet:<id>:perms    insecure group/other permissions on wallet data (critical)
#   wallet:<id>:cloud    wallet data lives in a cloud-synced folder (warn)
#   walletext:<extid>    inventory of an installed browser wallet extension (info)

check_wallet_guard() {
    local NAME="wallet-guard"
    local TAB
    TAB="$(printf '\t')"

    local walletfile="$OMS_ROOT/lib/data/wallets.tsv"
    local extfile="$OMS_ROOT/lib/data/wallet-extensions.tsv"

    local wallet_count=0
    local perms_count=0
    local cloud_count=0

    # ---- Desktop wallets --------------------------------------------------
    if [ -f "$walletfile" ]; then
        local id path_glob hint path mode group_d other_d fixcmd
        while IFS="$TAB" read -r id path_glob hint; do
            case "$id" in
                ''|\#*) continue ;;
            esac
            [ -z "$path_glob" ] && continue

            # Expand a leading ~/ to $HOME (literal expansion; no glob expansion
            # so paths containing spaces stay intact).
            case "$path_glob" in
                "~/"*) path="$HOME/${path_glob#~/}" ;;
                "~")   path="$HOME" ;;
                *)     path="$path_glob" ;;
            esac

            [ -e "$path" ] || continue
            wallet_count=$((wallet_count + 1))

            print_check_result info "wallet present: $id ($path)  [id: wallet:$id]"

            # -- permissions: any group/other bit set is an exposure ---------
            mode="$(oms_file_mode "$path" 2>/dev/null)"
            if [ -n "$mode" ]; then
                group_d="${mode: -2:1}"
                other_d="${mode: -1}"
                if [ "$group_d" != "0" ] || [ "$other_d" != "0" ]; then
                    if ! allowlist_match "$NAME" "wallet:$id:perms"; then
                        if [ -f "$path" ]; then
                            fixcmd="chmod 600 '$path'"
                        else
                            fixcmd="chmod 700 '$path'"
                        fi
                        print_check_result critical "wallet '$id' is group/other-accessible (mode $mode)"
                        echo "  - a local attacker or another user can read your wallet/seed data"
                        echo "  - fix: $fixcmd   [id: wallet:$id:perms]"
                        perms_count=$((perms_count + 1))
                    fi
                fi
            fi

            # -- cloud sync: seed material in a synced folder ----------------
            if oms_in_cloud_path "$path"; then
                if ! allowlist_match "$NAME" "wallet:$id:cloud"; then
                    print_check_result warn "wallet '$id' data is in a cloud-synced folder"
                    echo "  - $path"
                    echo "  - a compromised cloud account could exfiltrate your seed   [id: wallet:$id:cloud]"
                    cloud_count=$((cloud_count + 1))
                fi
            fi
        done < "$walletfile"
    else
        log_debug "wallet-guard: wallets.tsv not found at $walletfile"
    fi

    # ---- Browser wallet extensions (inventory only) -----------------------
    # Load the extension id/name table into parallel indexed arrays.
    local ext_ids ext_names
    ext_ids=()
    ext_names=()
    if [ -f "$extfile" ]; then
        local extid extname
        while IFS="$TAB" read -r extid extname; do
            case "$extid" in
                ''|\#*) continue ;;
            esac
            [ -z "$extid" ] && continue
            [ -z "$extname" ] && extname="$extid"
            ext_ids[${#ext_ids[@]}]="$extid"
            ext_names[${#ext_names[@]}]="$extname"
        done < "$extfile"
    else
        log_debug "wallet-guard: wallet-extensions.tsv not found at $extfile"
    fi

    if [ "${#ext_ids[@]}" -gt 0 ]; then
        local base browser profile prof_name les i eid enm
        for base in \
            "$HOME/Library/Application Support/Google/Chrome" \
            "$HOME/Library/Application Support/BraveSoftware/Brave-Browser" \
            "$HOME/Library/Application Support/Microsoft Edge" \
            "$HOME/Library/Application Support/Arc/User Data" ; do

            [ -d "$base" ] || continue

            case "$base" in
                *"/Google/Chrome")                 browser="Google Chrome" ;;
                *"/BraveSoftware/Brave-Browser")   browser="Brave" ;;
                *"/Microsoft Edge")                browser="Microsoft Edge" ;;
                *"/Arc/User Data")                 browser="Arc" ;;
                *)                                 browser="$(basename "$base")" ;;
            esac

            for profile in "$base"/*/ ; do
                [ -d "$profile" ] || continue
                les="${profile}Local Extension Settings"
                [ -d "$les" ] || continue
                prof_name="$(basename "$profile")"

                i=0
                while [ "$i" -lt "${#ext_ids[@]}" ]; do
                    eid="${ext_ids[$i]}"
                    enm="${ext_names[$i]}"
                    if [ -e "$les/$eid" ]; then
                        print_check_result info "wallet extension: $enm in $browser ($prof_name)  [id: walletext:$eid]"
                    fi
                    i=$((i + 1))
                done
            done
        done
    fi

    # ---- Verdict ----------------------------------------------------------
    if [ "$perms_count" -gt 0 ] || [ "$cloud_count" -gt 0 ]; then
        local summary=""
        if [ "$perms_count" -gt 0 ]; then
            summary="$perms_count wallet(s) with insecure permissions"
        fi
        if [ "$cloud_count" -gt 0 ]; then
            [ -n "$summary" ] && summary="$summary; "
            summary="${summary}$cloud_count wallet(s) in cloud-synced folder(s)"
        fi
        CHECK_FINDING_SUMMARY="$summary"
        if [ "$perms_count" -gt 0 ]; then
            CHECK_RESULT_SEVERITY="critical"
        else
            CHECK_RESULT_SEVERITY="warn"
        fi
        return 1
    fi

    print_check_result pass "$wallet_count wallet(s) monitored, no exposure"
    CHECK_FINDING_SUMMARY="$wallet_count wallet(s) monitored, no exposure"
    return 0
}
