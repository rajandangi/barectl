#!/usr/bin/env python3
"""Run one native suite per host, serialized with a portable file lock.

docs/agents/orchestration.md#long-running-commands. Concurrent native suites share Docker
lanes and a package manager, producing contended timings and false failures. `build.sh` keeps
its validator and native stages concurrent by design; parallel implementers use this wrapper.

Usage:
    uv run python scripts/native-run.py --env-file .env -- --validators
    uv run python scripts/native-run.py --env-file .env
"""

import fcntl
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parent.parent
RUNNER = REPOSITORY / "docker" / "disposable-server" / "run-scenarios.sh"
LOCK = Path(
    os.environ.get("BARECTL_NATIVE_LOCK", str(Path(tempfile.gettempdir()) / "barectl-native.lock"))
)


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    LOCK.parent.mkdir(parents=True, exist_ok=True)
    with LOCK.open("w", encoding="utf-8") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print(f"waiting for the native lock at {LOCK}", flush=True)  # noqa: T201
            fcntl.flock(lock, fcntl.LOCK_EX)
        completed = subprocess.run(  # noqa: S603 - this repository's own runner
            [str(RUNNER), *arguments], cwd=REPOSITORY, check=False
        )
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
