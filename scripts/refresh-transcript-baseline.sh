#!/bin/sh
# docs/quality.md#recorded-transcripts
#
# Refresh the transcript manifest for a new harness-only source that no recorded command
# embeds. It refuses a changed or removed shared source, changed pins or changed transcript
# bytes; those still need scripts/record-all-transcripts.sh.
set -eu
cd "$(dirname "$0")/.."
exec uv run python -m discovery.source_manifest refresh-baseline
