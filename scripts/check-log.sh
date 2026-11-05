#!/bin/sh
# docs/agents/orchestration.md#long-running-commands
#
# Print the failing jobs of a run, or one job, without the full log.
#
# Usage: check-log.sh <run-id|job-id>
set -eu
[ $# -eq 1 ] || {
    echo "usage: $0 <run-id|job-id>" >&2
    exit 2
}
target=$1
pattern='FAIL:|ERROR:|AssertionError|Traceback|##\[error\]|Ran [0-9]+ tests|FAILED|Killed|timed out|OperationalError|NameError|Permission denied'
if gh run view "$target" --json jobs >/dev/null 2>&1; then
    jobs=$(gh run view "$target" --json jobs \
        --jq '.jobs[] | select(.conclusion == "failure") | "\(.databaseId)\t\(.name)"')
    if [ -z "$jobs" ]; then
        printf 'No failed jobs in run %s.\n' "$target"
        exit 0
    fi
    printf '%s\n' "$jobs" | while IFS="$(printf '\t')" read -r job name; do
        printf '== %s ==\n' "$name"
        gh run view --job "$job" --log 2>/dev/null | grep -E "$pattern" | tail -n 80 || true
    done
else
    gh run view --job "$target" --log 2>/dev/null | grep -E "$pattern" | tail -n 120 || true
fi
