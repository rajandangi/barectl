#!/bin/sh
# docs/quality.md#native-layer
#
# One full local build. The fast gate, the browser tests and the native scenarios run
# concurrently; each is timed and the wall time is reported against the 10-minute target
# and the 15-minute limit (docs/adr/0033-prove-real-behavior-in-two-test-layers.md).
#
# Usage: build.sh [--env-file FILE]   (default .env)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
cd "$here/../.."

env_file=.env
if [ "${1:-}" = --env-file ]; then
    env_file=$2
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
started=$(date +%s)

run() {
    name=$1
    shift
    (
        job_started=$(date +%s)
        set +e
        "$@" >"$work/$name.log" 2>&1
        echo $? >"$work/$name.code"
        echo $(( $(date +%s) - job_started )) >"$work/$name.secs"
    ) &
}

run controller-fast uv run --env-file "$env_file" python manage.py test \
    --exclude-tag browser --exclude-tag scenario --parallel
run fast-validators env BARECTL_DISPOSABLE_LOGS="$work/validator-logs" \
    "$here/run-scenarios.sh" --env-file "$env_file" -- --validators
run browser uv run --env-file "$env_file" python manage.py test --tag browser
run native "$here/run-scenarios.sh" --env-file "$env_file"

status=0
# Each job is a subshell that records its own exit code, so this wait always succeeds.
wait

for name in controller-fast fast-validators browser native; do
    code=$(cat "$work/$name.code" 2>/dev/null || echo 1)
    secs=$(cat "$work/$name.secs" 2>/dev/null || echo 0)
    printf '%-8s %4ss  %s\n' "$name" "$secs" "$( [ "$code" = 0 ] && echo ok || echo FAIL )"
    if [ "$code" != 0 ]; then
        status=1
        printf '%s\n' "---- $name ----"
        tail -n 60 "$work/$name.log"
    fi
done

controller_fast=$(cat "$work/controller-fast.secs")
validator_fast=$(cat "$work/fast-validators.secs")
fast_wall=$controller_fast
if [ "$validator_fast" -gt "$fast_wall" ]; then
    fast_wall=$validator_fast
fi
printf 'joint fast stage: %ss against the 60s target\n' "$fast_wall"

wall=$(( $(date +%s) - started ))
printf 'full build: %ss against the 300s target and 900s limit\n' "$wall"
if [ "$status" != 0 ]; then
    echo "full build: FAILED" >&2
fi
exit "$status"
