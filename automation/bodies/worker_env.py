"""Gracefully restart a Laravel site's enabled queue workers after an environment change.

Called from the bodies that edit a Laravel environment, between the configuration rebuild
and the verify stage. Only an enabled worker is restarted: a deliberate Stop must survive an
unrelated environment change. ``systemctl restart`` sends SIGTERM, so each process finishes
its current job within its own stop budget. A worker the change's fence stopped is left to
``restore``, which unmasks it and starts it on the new environment (docs/automation.md).
"""

import subprocess
from typing import Final

from automation.convention import ENABLED_STATES, service_name
from automation.workers import WORKER_ROLES

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


def fenced_workers(document: object, identifier: str) -> bool:
    """Whether the change's reviewed fence plan stops one of this site's worker services."""
    plan = document.get("automation_fence") if isinstance(document, dict) else None
    sites = plan.get("sites") if isinstance(plan, dict) else None
    if not isinstance(sites, list):
        return False
    workers = {service_name(identifier, role) for role in WORKER_ROLES}
    for entry in sites:
        if isinstance(entry, dict) and entry.get("identifier") == identifier:
            services = entry.get("services")
            return isinstance(services, list) and bool(workers.intersection(services))
    return False


def restart_unfenced_workers(document: object, identifier: str) -> tuple[bool, bool]:
    """:func:`restart_workers`, or nothing when the fence stopped them for ``restore``."""
    if fenced_workers(document, identifier):
        return False, True
    return restart_workers(identifier)


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


__all__ = ["ENABLED_STATES", "fenced_workers", "restart_unfenced_workers", "restart_workers"]
