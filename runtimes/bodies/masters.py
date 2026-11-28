"""Restart the running runtime PHP masters once after a body reloads systemd (#580, #586).

docs/runtimes.md#restarting-the-runtime-masters-after-a-systemd-reload. Assembled as source
text into every Python body that reloads systemd; it imports only the standard library.
"""

import atexit
import contextlib
import os
import re
import signal
import subprocess
import sys
from types import FrameType

RUNTIME_MASTER = re.compile(r"php-fpm@php[0-9]{2}\.service")


def note_reload() -> None:
    """Restart the runtime masters when this body ends, once however often it reloaded.

    A restart per reload step can exceed the masters' start limit across a few quick
    changes. The exit path covers a result, a refusal and an exception after the reload; a
    stop's SIGTERM restarts them first and then ends the body by that signal as before. The
    controller reads a run only once its unit has ended. A body with its own SIGTERM
    handler keeps it.
    """
    atexit.unregister(_restart_at_exit)
    atexit.register(_restart_at_exit)
    if signal.getsignal(signal.SIGTERM) is signal.SIG_DFL:
        signal.signal(signal.SIGTERM, _restart_then_terminate)


def _restart_at_exit() -> None:
    if signal.getsignal(signal.SIGTERM) is _restart_then_terminate:
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
    restart_runtime_masters()


def _restart_then_terminate(_signum: int, _frame: FrameType | None) -> None:
    atexit.unregister(_restart_at_exit)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    restart_runtime_masters()
    os.kill(os.getpid(), signal.SIGTERM)


def restart_runtime_masters() -> None:
    """Restart each running ``php-fpm@<entry>`` master, never a site's own master or proxy.

    A failed restart leaves the master as systemd reports it, and discovery reads that.
    """
    listed = subprocess.run(
        [
            "/usr/bin/systemctl",
            "list-units",
            "--type=service",
            "--state=running",
            "--no-legend",
            "--plain",
            "php-fpm@*.service",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    for line in listed.stdout.splitlines():
        unit = line.split(maxsplit=1)[0] if line.strip() else ""
        if not RUNTIME_MASTER.fullmatch(unit):
            continue
        restarted = subprocess.run(  # noqa: S603 - a checked runtime master name
            ["/usr/bin/systemctl", "restart", unit],
            capture_output=True,
            timeout=120,
            check=False,
        )
        # A stop ends the journal pipe with the body, so the line may have nowhere to go.
        if restarted.returncode == 0:
            with contextlib.suppress(OSError):
                sys.stdout.write("barectl-restarted " + unit + "\n")
                sys.stdout.flush()
