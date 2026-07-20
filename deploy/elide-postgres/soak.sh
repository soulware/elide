#!/usr/bin/env bash
# Drive pgsoak cycles from the workstation, rotating crash modes:
#
#   pg    kill -9 postgres (device healthy; postgres WAL recovery baseline)
#   vol   kill -9 the elide volume server mid-IO (elide crash recovery:
#         supervisor respawn, elide WAL replay, fsck, remount)
#   host  fly machine stop --signal KILL mid-run, then start (whole-VM crash:
#         acked fsyncs must survive through elide's local WAL on the Fly
#         volume; this is the closest Fly gets to pulling the power)
#
#   ./soak.sh [cycles]     default 6 (two of each mode)
#
# Runs from this directory (fly.toml names the app). The pg and vol modes are
# one ssh round-trip each (`pgsoak cycle` crashes and verifies on-machine);
# host mode starts a detached pgbench, kills the machine from here at a random
# point mid-run, restarts it, and verifies with `pgsoak check`.
#
# Env overrides:
#   MODES       modes to rotate (default "pg vol host")
#   RUN_SECS    pgbench duration per cycle, passed through to pgsoak (default 120)
#   MACHINE     Fly machine id (default: the app's first machine)
set -euo pipefail
cd "$(dirname "$0")"

cycles="${1:-6}"
read -ra modes <<<"${MODES:-pg vol host}"
RUN_SECS="${RUN_SECS:-120}"

run() { echo "+ $*" >&2; "$@"; }
ssh_cmd() { run fly ssh console -C "env RUN_SECS=$RUN_SECS $1"; }

machine_id() {
    if [ -n "${MACHINE:-}" ]; then echo "$MACHINE"; return; fi
    fly machine list --json | grep -o '"id": *"[0-9a-f]*"' \
        | head -n 1 | sed 's/.*"\([0-9a-f]*\)"$/\1/'
}

wait_ssh() {
    local deadline=$((SECONDS + 300))
    until fly ssh console -C "true" >/dev/null 2>&1; do
        ((SECONDS < deadline)) || { echo "machine did not come back within 300s" >&2; exit 1; }
        sleep 5
    done
}

host_cycle() {
    local machine point
    machine="$(machine_id)"
    [ -n "$machine" ] || { echo "could not resolve the machine id; set MACHINE" >&2; exit 1; }
    ssh_cmd "pgsoak check"
    ssh_cmd "pgsoak bench-bg $RUN_SECS"
    point=$((10 + RANDOM % (RUN_SECS - 20)))
    echo "host cycle: crashing machine $machine in ${point}s" >&2
    sleep "$point"
    run fly machine stop --signal KILL "$machine" || true
    run fly machine start "$machine"
    wait_ssh
    ssh_cmd "pgsoak check"
}

for ((i = 1; i <= cycles; i++)); do
    mode="${modes[(i - 1) % ${#modes[@]}]}"
    echo "=== cycle $i/$cycles: mode $mode ===" >&2
    case "$mode" in
        pg | vol) ssh_cmd "pgsoak cycle $mode" ;;
        host)     host_cycle ;;
        *)        echo "unknown mode '$mode'" >&2; exit 1 ;;
    esac
done
echo "=== soak complete: $cycles cycles PASS ===" >&2
