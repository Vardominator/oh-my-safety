#!/bin/bash
# oh-my-safety - `scan` subcommand: run all (or filtered) checks once.

cmd_scan() {
    load_platform
    case "$(config_get 'profile.connectivity' 'connected')" in
        offline|airgapped)
            OMS_OFFLINE=true
            export OMS_OFFLINE
            ;;
    esac
    run_scan "$@"
}
