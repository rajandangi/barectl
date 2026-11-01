#!/bin/sh
# docs/quality.md#native-layer
#
# One full local build. The fast gate, the fast validators, the browser tests and the native
# scenarios are timed and the wall time is reported against the
# 5-minute target and the 15-minute limit
# (docs/adr/0033-prove-real-behavior-in-two-test-layers.md).
#
# Controller tests and validators run first, alongside the browser stage. Native lifecycle
# work starts when both fast gates finish, avoiding contention during the joint fast stage.
# The full-build clock includes this wait; browser work remains concurrent with native work.
#
# Usage: build.sh [--env-file FILE]   (default .env)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
cd "$here/../.."

# This process holds the host-wide native lock across validator and lifecycle stages,
# and the stages below pass --no-lock
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

logs=${BARECTL_BUILD_LOGS:-"${XDG_CACHE_HOME:-$HOME/.cache}/barectl/builds"}
mkdir -p "$logs"
work=$(mktemp -d "$logs/run-XXXXXXXX")
printf 'Full build logs: %s\n' "$work"
started=$(date +%s)
BARECTL_BUILD_DEADLINE=$(( started + 900 ))
export BARECTL_BUILD_DEADLINE

run() {
    name=$1
    (
        job_started=$(date +%s)
        set +e
        "$here/quiet-run.sh" build "$work/$name.log" "$env_file" >"$work/$name.summary" 2>&1
        echo $? >"$work/$name.code"
        echo $(( $(date +%s) - job_started )) >"$work/$name.secs"
    ) &
    run_pid=$!
}

run controller-fast
controller_pid=$run_pid
run fast-validators
validators_pid=$run_pid
run browser
wait "$controller_pid" "$validators_pid"
run native

status=0
# Each job is a subshell that records its own exit code, so this wait always succeeds.
wait
uv run python -m disposable.verification ledger "$work"

for name in controller-fast fast-validators browser native; do
    code=$(cat "$work/$name.code" 2>/dev/null || echo 1)
    secs=$(cat "$work/$name.secs" 2>/dev/null || echo 0)
    printf '%-8s %4ss  %s\n' "$name" "$secs" "$( [ "$code" = 0 ] && echo ok || echo FAIL )"
    if [ "$code" != 0 ]; then
        status=1
        printf '%s\n' "---- $name ----"
        printf 'Full failure log: %s\n' "$work/$name.log"
        grep -E '^(FAIL:|ERROR:|AssertionError)' "$work/$name.log" || true
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
