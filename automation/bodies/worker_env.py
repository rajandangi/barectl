"""Gracefully restart a Laravel site's enabled queue workers after a `.env` change.

Phase C #393 needs this before #266's worker change kind lands: an Edit settings body (or the
object cache change) must make running workers load the new configuration. Only an enabled
worker is restarted, so a deliberate Stop survives an unrelated environment change.
``systemctl restart`` sends SIGTERM, so each process finishes its current job within its own
stop budget (docs/automation.md#queue-workers).

This helper is the one #266 installs as well; when that branch merges, keep its definition
and delete this note rather than forking a second restart path.
"""

import subprocess
from typing import Final

from automation.convention import service_name

WORKER_ROLES: Final = ("queue1", "queue2", "queue3", "queue4")
ENABLED_STATES: Final = frozenset({"enabled", "enabled-runtime", "static", "indirect"})
RESTART_TIMEOUT: Final = 180
SHOW_TIMEOUT: Final = 20


def _unit_file_state(name: str) -> str:
    try:
        completed = subprocess.run(  # noqa: S603 - fixed native argv
            ["/usr/bin/systemctl", "show", "--value", "-p", "UnitFileState", name],
            capture_output=True,
            text=True,
            timeout=SHOW_TIMEOUT,
            check=False,
        )
    except OSError, subprocess.TimeoutExpired:
        return ""
    return completed.stdout.strip() if completed.returncode == 0 else ""


def restart_workers(identifier: str) -> tuple[bool, bool]:
    """``(any restarted, all restarts succeeded)`` for the site's enabled workers."""
    restarted = False
    for role in WORKER_ROLES:
        name = service_name(identifier, role)
        if _unit_file_state(name) not in ENABLED_STATES:
            continue
        restarted = True
        try:
            completed = subprocess.run(  # noqa: S603 - fixed native argv
                ["/usr/bin/systemctl", "restart", name],
                capture_output=True,
                text=True,
                timeout=RESTART_TIMEOUT,
                check=False,
            )
        except OSError, subprocess.TimeoutExpired:
            return True, False
        if completed.returncode:
            return True, False
    return restarted, True


__all__ = ["ENABLED_STATES", "WORKER_ROLES", "restart_workers"]
