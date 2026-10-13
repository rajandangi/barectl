#!/bin/sh
# docs/quality.md#native-layer
#
# Usage: run-scenarios.sh [uv run options] [-- scenario options and labels]
# For example: run-scenarios.sh --env-file .env -- --list
# Run `run-scenarios.sh --env-file .env -- --help` for the runner's options.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
cd "$here/../.."
uv_options=""
while [ $# -gt 0 ]; do
    if [ "$1" = -- ]; then
        shift
        break
    fi
    uv_options="$uv_options $(printf '%s' "$1" | sed "s/'/'\\\\''/g; s/^/'/; s/\$/'/")"
    shift
done
eval "exec uv run $uv_options python -m disposable.scenarios \"\$@\""
