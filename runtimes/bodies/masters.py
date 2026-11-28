"""Restart the running runtime PHP masters once after a body reloads systemd (#580, #586).

docs/runtimes.md#restarting-the-runtime-masters-after-a-systemd-reload. Assembled as source
text into every Python body that reloads systemd; it imports only the standard library.
"""

import atexit
import re
import subprocess
import sys

RUNTIME_MASTER = re.compile(r"php-fpm@php[0-9]{2}\.service")


def note_reload() -> None:
    """Restart the runtime masters when this body exits, once however often it reloaded.

    A restart per reload step can exceed the masters' start limit across a few quick
    changes. The exit path covers every outcome, including a refusal or an exception after
    the reload; the controller reads a run only once its unit has ended.
    """
    atexit.unregister(restart_runtime_masters)
    atexit.register(restart_runtime_masters)


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
        if restarted.returncode == 0:
            sys.stdout.write("barectl-restarted " + unit + "\n")
            sys.stdout.flush()
