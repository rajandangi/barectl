#!/bin/sh
# Fetch and check the local byte-exact mirror (docs/quality.md#native-layer).
#
# Usage: mirror.sh [uv run options] [-- mirror command and options]
# For example: mirror.sh --env-file .env -- fetch
# Run `mirror.sh --env-file .env -- --help` for the commands.
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
eval "exec uv run $uv_options python -m disposable.mirror \"\$@\""
