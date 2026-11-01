#!/bin/sh
# docs/quality.md#recorded-transcripts
#
# Record every transcript state a scenario declares, on one integration tree. Run this after
# a change to a shared native read source lands on the integration branch, not on a ticket
# branch that will merge other read changes later.
#
# Usage: record-all-transcripts.sh [--env-file FILE] [--from STATE] [--only STATE] [--affected] [--check]
#        (default env file .env)
#
# --check reports whether the committed source manifest still matches the tree and records
# nothing. Freeze command-affecting edits before the final full pass; run --check first and
# after the pass.
#
# One failed state does not stop the pass: the script records the rest, then exits 1 naming
# every failure and the state that resumes it. --from STATE requires matching frozen inputs and intact completed-state
# receipts from the earlier pass; --only STATE records one state and never
# writes the source manifest. A pass without --only writes the manifest when no state failed.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
cd "$here/.."

usage() {
    echo "usage: $0 [--env-file FILE] [--from STATE] [--only STATE] [--affected] [--check]" >&2
    exit 2
}

env_file=.env
from=
only=
affected=
check=
while [ $# -gt 0 ]; do
    case "$1" in
        --affected)
            affected=1
            shift
            ;;
        --check)
            check=1
            shift
            ;;
        --env-file)
            [ $# -ge 2 ] || usage
            env_file=$2
            shift 2
            ;;
        --from)
            [ $# -ge 2 ] || usage
            from=$2
            shift 2
            ;;
        --only)
            [ $# -ge 2 ] || usage
            only=$2
            shift 2
            ;;
        *)
            usage
            ;;
    esac
done
if [ -n "$affected" ] && { [ -n "$from" ] || [ -n "$only" ] || [ -n "$check" ]; }; then
    echo "--affected selects its own pass" >&2
    exit 2
fi
if [ -n "$from" ] && [ -n "$only" ]; then
    echo "--from and --only select different passes; use one." >&2
    exit 2
fi
if [ -n "$check" ]; then
    if [ -n "$from" ] || [ -n "$only" ]; then
        echo "--check records nothing; do not combine it with --from or --only." >&2
        exit 2
    fi
    uv run --env-file "$env_file" python -m discovery.source_manifest
    exit $?
fi

states=$(uv run --env-file "$env_file" python -m disposable.scenarios --list-records)
# shellcheck disable=SC2086 # --list-records prints whitespace-free state names
set -- $states
for selector in "$from" "$only"; do
    [ -n "$selector" ] || continue
    found=
    for state in "$@"; do
        if [ "$state" = "$selector" ]; then
            found=1
        fi
    done
    if [ -z "$found" ]; then
        echo "unknown state: $selector" >&2
        printf 'declared states:\n%s\n' "$states" >&2
        exit 2
    fi
done

if [ -z "$only" ]; then
    mode=begin
    [ -z "$from" ] || mode=resume
    [ -z "$affected" ] || mode=incremental
    pending=$(uv run --env-file "$env_file" python -m discovery.transcript_provenance "$mode" "$@")
    if [ -n "$from" ]; then
        for state in "$@"; do
            [ "$state" != "$from" ] || break
            if printf '%s\n' "$pending" | grep -Fxq "$state"; then
                echo "Cannot resume after an unrecorded state: $state" >&2
                exit 1
            fi
        done
    fi
fi
total=$#
index=0
skipping=$from
failed=
first_failed=
selected=0
for state in "$@"; do
    index=$((index + 1))
    if [ -n "$only" ] && [ "$state" != "$only" ]; then
        continue
    fi
    if [ -n "$skipping" ]; then
        if [ "$state" = "$skipping" ]; then
            skipping=
        else
            continue
        fi
    fi
    if [ -z "$only" ]; then
        printf '%s\n' "$pending" | grep -Fxq "$state" || continue
        uv run --env-file "$env_file" python -m discovery.transcript_provenance start "$state"
    fi
    selected=$((selected + 1))
    printf '\n== recording %s (%s/%s)\n' "$state" "$index" "$total"
    if ! "$here/../docker/disposable-server/run-scenarios.sh" \
        --env-file "$env_file" -- --record "$state"; then
        failed="$failed $state"
        if [ -z "$first_failed" ]; then
            first_failed=$state
        fi
    else
        if [ -z "$only" ]; then
            uv run --env-file "$env_file" python -m discovery.transcript_provenance complete "$state"
        fi
    fi
done

if [ "$selected" -eq 0 ]; then
    if [ -n "$affected" ]; then
        uv run --env-file "$env_file" python -m discovery.transcript_provenance finish
        exit 0
    fi
    echo "no state selected; nothing was recorded." >&2
    exit 2
fi
if [ -n "$failed" ]; then
    printf '\nFailed states:%s\n' "$failed" >&2
    printf 'Resume with: %s --env-file %s --from %s\n' "$0" "$env_file" "$first_failed" >&2
    exit 1
fi
if [ -n "$only" ]; then
    echo "Recorded $only; a full pass writes the source manifest."
    exit 0
fi
uv run --env-file "$env_file" python -m discovery.transcript_provenance finish
