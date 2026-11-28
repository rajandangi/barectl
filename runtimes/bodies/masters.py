"""Restart the running runtime PHP masters after a body reloads systemd (#580).

docs/runtimes.md#restarting-the-runtime-masters-after-a-systemd-reload. Assembled as source
text into every Python body that reloads systemd; it imports only the standard library.
"""

import re
import subprocess
import sys

RUNTIME_MASTER = re.compile(r"php-fpm@php[0-9]{2}\.service")


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
