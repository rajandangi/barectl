"""One native suite per host, enforced for every entry path.

docs/quality.md#limits: concurrent suites share Docker lanes and a package manager, which
produces contended timings and false failures. The lock lives here rather than in a wrapper
script so that every caller — the runner, the full build, an implementer's one-item run —
takes it. ``BARECTL_NATIVE_LOCK`` moves the lock file; ``build.sh`` holds it for both of its
stages and passes ``--no-lock`` to them.
"""

import fcntl
import os
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

LOCK_ENV = "BARECTL_NATIVE_LOCK"
LOCK_NAME = "barectl-native.lock"
WAITING = "waiting for the native lock at "


def lock_path() -> Path:
    return Path(os.environ.get(LOCK_ENV, str(Path(tempfile.gettempdir()) / LOCK_NAME)))


@contextmanager
def host_lock(announce: Callable[[str], None]) -> Iterator[None]:
    """Hold the host-wide native lock, announcing once when another run owns it."""
    with file_lock(lock_path(), announce):
        yield


@contextmanager
def file_lock(path: Path, announce: Callable[[str], None] | None = None) -> Iterator[None]:
    """Serialize shared harness cache creation with the same kernel lock as native runs."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            if announce is not None:
                announce(f"{WAITING}{path}")
            fcntl.flock(handle, fcntl.LOCK_EX)
        yield
