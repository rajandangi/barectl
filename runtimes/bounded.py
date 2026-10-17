"""One bounded native probe, shared by the runtime and site read bodies.

docs/ssh-connections.md#bounds-and-read-only-commands
"""

import os
import signal
import subprocess
from contextlib import suppress

PROBE_SECONDS = 8
TIMED_OUT = 124
OVER_LIMIT = 125


def bounded(
    command: str, seconds: float = PROBE_SECONDS, *, limit: int | None = None
) -> tuple[int, bytes]:
    """Run ``command`` with ``bash -o pipefail`` in its own process group.

    At the bound the group gets SIGTERM, then SIGKILL once the shell has exited or one second
    has passed, and the status is ``TIMED_OUT``. Output longer than ``limit`` bytes ends the
    producer and the status is ``OVER_LIMIT``.
    """
    if limit is not None:
        command = f"{command} | /usr/bin/head -c {limit + 1}"
    process = subprocess.Popen(  # noqa: S603 - fixed shell; callers pass fixed native argv
        ["/bin/bash", "-o", "pipefail", "-c", command],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        output, _ = process.communicate(timeout=seconds)
    except subprocess.TimeoutExpired:
        _stop(process)
        return TIMED_OUT, b""
    if limit is not None and len(output) > limit:
        return OVER_LIMIT, b""
    return process.returncode, output


def _stop(process: subprocess.Popen[bytes]) -> None:
    _signal_group(process.pid, signal.SIGTERM)
    with suppress(subprocess.TimeoutExpired):
        process.wait(timeout=1)
    _signal_group(process.pid, signal.SIGKILL)
    process.wait()
    if process.stdout is not None:
        process.stdout.close()


def _signal_group(group: int, sig: signal.Signals) -> None:
    with suppress(ProcessLookupError):
        os.killpg(group, sig)
