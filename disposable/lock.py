"""Run one command under the host-wide native lock.

`docker/disposable-server/build.sh` runs its validator and native stages side by side by
design, so it takes the lock once here and passes `--no-lock` to both stages
(docs/quality.md#limits).

    uv run python -m disposable.lock -- COMMAND [ARG...]
"""

import subprocess
import sys
from collections.abc import Sequence

from . import locking


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments[:1] == ["--"]:
        arguments = arguments[1:]
    if not arguments:
        print("usage: python -m disposable.lock -- COMMAND [ARG...]", file=sys.stderr)  # noqa: T201
        return 2

    def announce(message: str) -> None:
        print(message, flush=True)  # noqa: T201

    with locking.host_lock(announce):
        return subprocess.run(arguments, check=False).returncode  # noqa: S603


if __name__ == "__main__":
    raise SystemExit(main())
