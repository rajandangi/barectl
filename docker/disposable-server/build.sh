#!/bin/sh
# docs/quality.md#native-layer
#
# One full local build. The fast gate, the fast validators, the browser tests and the native
# scenarios run concurrently; each is timed and the wall time is reported against the
# 5-minute target and the 15-minute limit
# (docs/adr/0033-prove-real-behavior-in-two-test-layers.md).
#
# The wall is the native stage, the longest one. Running the browser stage first and starting
# the native stage when it ends was measured at Phase D and made the build slower: browser
# 79 s plus native 335 s, 414 s against 365 s for the concurrent build, because the native
# stage takes almost the same time alone as it does beside the browser stage. The stage times
# are recorded in docs/phase-d-qualification.md#build-budget.
#
# Usage: build.sh [--env-file FILE]   (default .env)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
cd "$here/../.."

# The validator and native stages run side by side by design, so this process holds the
# host-wide native lock for the whole build and the stages below pass --no-lock
# (disposable/locking.py, docs/quality.md#limits).
if [ "${BARECTL_NATIVE_LOCKED:-0}" = 0 ]; then
    BARECTL_NATIVE_LOCKED=1
    export BARECTL_NATIVE_LOCKED
    exec uv run python -m disposable.lock -- sh "$here/build.sh" "$@"
fi

env_file=.env
if [ "${1:-}" = --env-file ]; then
    env_file=$2
fi
strict=${BARECTL_BUDGET_STRICT:-0}

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
    "$here/run-scenarios.sh" --env-file "$env_file" -- --validators --no-lock
run browser uv run --env-file "$env_file" python manage.py test --tag browser
run native "$here/run-scenarios.sh" --env-file "$env_file" -- --no-lock

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
if [ "$fast_wall" -gt 60 ]; then
    printf 'joint fast stage: %ss against the 60s target (missed)\n' "$fast_wall"
    if [ "$strict" = 1 ]; then
        status=1
    fi
else
    printf 'joint fast stage: %ss against the 60s target\n' "$fast_wall"
fi

wall=$(( $(date +%s) - started ))
if [ "$wall" -gt 300 ]; then
    printf 'full build: %ss against the 300s target and 900s limit (target missed)\n' "$wall"
    if [ "$strict" = 1 ]; then
        status=1
    fi
else
    printf 'full build: %ss against the 300s target and 900s limit\n' "$wall"
fi
if [ "$status" != 0 ]; then
    echo "full build: FAILED" >&2
fi
exit "$status"
