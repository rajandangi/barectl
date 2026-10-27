#!/bin/sh
# docs/quality.md#recorded-transcripts
#
# Record every transcript state a scenario declares, on one integration tree. Run this after
# a change to a shared native read source lands on the integration branch, not on a ticket
# branch that will merge other read changes later.
#
# Usage: record-all-transcripts.sh [--env-file FILE]   (default .env)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
cd "$here/.."

env_file=.env
if [ "${1:-}" = --env-file ]; then
    env_file=$2
fi

states=$(uv run --env-file "$env_file" python -m disposable.scenarios --list-records)
for state in $states; do
    printf '\n== recording %s\n' "$state"
    "$here/../docker/disposable-server/run-scenarios.sh" \
        --env-file "$env_file" -- --record "$state"
done
