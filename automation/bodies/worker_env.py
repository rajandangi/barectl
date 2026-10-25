"""Gracefully restart a Laravel site's enabled queue workers after an environment change.

Called from the Edit-settings body between its configuration rebuild and its verify stage.
Only an enabled worker is restarted: a deliberate Stop must survive an unrelated
environment change. ``systemctl restart`` sends SIGTERM, so each process finishes its
current job within its own stop budget.
"""

import subprocess
from typing import Final

from automation.convention import service_name
from automation.workers import WORKER_ROLES

ENABLED_STATES: Final = frozenset({"enabled", "enabled-runtime", "static", "indirect"})
RESTART_TIMEOUT: Final = 180


def _unit_file_state(name: str) -> str:
    try:
        completed = subprocess.run(  # noqa: S603 - fixed native argv
            ["/usr/bin/systemctl", "show", "--value", "-p", "UnitFileState", name],
            capture_output=True,
            text=True,
            timeout=20,
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


__all__ = ["ENABLED_STATES", "restart_workers"]
