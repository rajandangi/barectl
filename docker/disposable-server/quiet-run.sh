#!/bin/sh
# docs/agents/orchestration.md#long-running-commands
# Usage: quiet-run.sh run LOG -- COMMAND... (persistent foreground, no wait deadline)
#        quiet-run.sh build LOG ENV_FILE (fixed repository gate, full safe argv)
#        quiet-run.sh start LOG -- COMMAND... (detached, runtime support required)
#        quiet-run.sh follow LOG (no wait deadline)
#        quiet-run.sh wait LOG [SECONDS] (observational timeout, default 540)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
cd "$here/../.."
exec uv run python -m disposable.verification "$@"
