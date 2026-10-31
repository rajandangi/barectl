#!/bin/sh
# docs/agents/orchestration.md#long-running-commands
#
# Wait for a pull request's required checks without flooding the agent's context.
#
# Usage: watch-checks.sh PR [LOG]
#        (default log: ~/.cache/barectl/pr-<PR>-checks.log)
set -eu
[ $# -ge 1 ] || {
    echo "usage: $0 PR [LOG]" >&2
    exit 2
}
pr=$1
log=${2:-"$HOME/.cache/barectl/pr-$pr-checks.log"}
mkdir -p "$(dirname "$log")"
status=0
gh pr checks "$pr" --watch --interval 20 >"$log" 2>&1 || status=$?
tail -n 30 "$log"
exit "$status"
