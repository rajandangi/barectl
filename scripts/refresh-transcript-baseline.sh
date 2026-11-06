#!/bin/sh
# docs/quality.md#recorded-transcripts
#
# Refresh the transcript manifest for a new harness-only source that no recorded command
# embeds, or for a shared-source edit that cannot change a command. The default form
# refuses a changed or removed shared source, changed pins or changed transcript bytes;
# those still need scripts/record-all-transcripts.sh. --command-neutral replays every
# recorded transcript first and rewrites the manifest only when the replay still matches.
set -eu
cd "$(dirname "$0")/.."

case "${1:-}" in
    "")
        exec uv run python -m discovery.source_manifest refresh-baseline
        ;;
    --command-neutral)
        [ $# -eq 1 ] || {
            echo "usage: $0 [--command-neutral]" >&2
            exit 2
        }
        ;;
    *)
        echo "usage: $0 [--command-neutral]" >&2
        exit 2
        ;;
esac

if [ ! -f .env ]; then
    echo "refresh-transcript-baseline: .env is missing. Configure it as the README describes." >&2
    exit 1
fi

# A changed source may only be absorbed when the stored commands still replay exactly.
modules=$(git ls-files '*recorded*.py' |
    grep -v '^discovery/test_recorded.py$' |
    sed 's#/#.#g; s#\.py$##')
# shellcheck disable=SC2086 # module names are whitespace-free
uv run --env-file .env python manage.py test \
    discovery.test_recorded.ReplayTests \
    discovery.test_recorded.TranscriptSearchTests \
    $modules
exec uv run python -m discovery.source_manifest refresh-baseline --command-neutral
