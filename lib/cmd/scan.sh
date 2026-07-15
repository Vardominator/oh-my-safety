#!/bin/bash
# oh-my-safety - `scan` subcommand: run all (or filtered) checks once.

cmd_scan() {
    load_platform
    run_scan "$@"
}
