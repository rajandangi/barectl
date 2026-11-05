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
if [ "$status" -eq 0 ]; then
    printf 'All checks passed for PR #%s.\n' "$pr"
    exit 0
fi
failures=$(awk -F '\t' 'NF >= 4 && $2 != "pass" {print}' "$log")
if [ -n "$failures" ]; then
    printf '%s\n' "$failures" | tail -n 40
else
    tail -n 20 "$log"
fi
printf 'Full checks log: %s\n' "$log"
exit "$status"
