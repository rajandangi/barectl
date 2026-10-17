#!/bin/sh
# docs/agents/orchestration.md#long-running-commands
#
# Usage: quiet-run.sh start LOG -- COMMAND...   run COMMAND detached, all output to LOG
#        quiet-run.sh wait LOG [SECONDS]        block until it exits (default 540), then summarize
#        quiet-run.sh run LOG -- COMMAND...     start, then wait
# wait exits with COMMAND's status, or 124 while it is still running.
set -eu

usage() {
    sed -n '4,7p' "$0" >&2
    exit 2
}

start() {
    log=$1
    shift
    [ "${1-}" = -- ] || usage
    shift
    [ $# -gt 0 ] || usage
    mkdir -p "$(dirname "$log")"
    rm -f "$log.status"
    # shellcheck disable=SC2016 # expanded by the inner shell
    nohup sh -c 'log=$1; shift; status=0; "$@" >"$log" 2>&1 || status=$?; echo "$status" >"$log.status"' \
        sh "$log" "$@" </dev/null >/dev/null 2>&1 &
}

summarize() {
    grep -n -E 'FAIL|ERROR|Error:|Traceback|refused|limit|passed in|failed' "$1" | tail -n 20 || true
    echo "--- last lines of $1"
    tail -n 15 "$1"
}

wait_for() {
    log=$1
    deadline=$(($(date +%s) + ${2:-540}))
    while [ ! -f "$log.status" ]; do
        if [ "$(date +%s)" -ge "$deadline" ]; then
            echo "still running; last line of $log:"
            tail -n 1 "$log" 2>/dev/null || true
            exit 124
        fi
        sleep 5
    done
    summarize "$log"
    status=$(cat "$log.status")
    echo "exit status $status"
    exit "$status"
}

[ $# -ge 2 ] || usage
mode=$1
shift
case $mode in
start) start "$@" ;;
wait) wait_for "$@" ;;
run)
    start "$@"
    wait_for "$1"
    ;;
*) usage ;;
esac
