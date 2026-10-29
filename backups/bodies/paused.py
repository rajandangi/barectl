"""Pause and reopen a site for a reviewed capture or restore (#399, #400).

The full capture and the database restore share one pause path: publish the reviewed
maintenance gate, drain private HAProxy admission, prove every FPM worker Idle, and later
publish the reviewed open file. Assembled bodies receive these helpers as source text
(automation/bodies/source.py), so this module imports only the names its neighbours supply.
"""

import pathlib
import time
from types import SimpleNamespace

from sites.bodies.admission import hap_api, haproxy_state
from sites.bodies.common import (
    caddy_file,
    current_bytes,
    laravel_caddy_file,
    maintenance_file,
    publish_caddy,
    setting,
    site_fpm_read,
    wordpress_caddy_file,
)
from sites.bodies.site_fpm import site_fpm_idle

APPLICATIONS = ("plain", "wordpress", "laravel")
SHARED = {
    "laravel": ("private/laravel.env", "private/storage", "private/cache"),
    "wordpress": ("private/wp-config.php",),
    "plain": (),
}
DRAIN_SECONDS = 10


def site_settings(document: dict[str, object]) -> SimpleNamespace:
    names = document.get("names")
    if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
        raise ValueError("The change has no site names.")
    return setting(
        str(document.get("identifier", "")),
        names,
        str(document.get("runtime", "")),
        https=document.get("https", True) is not False,
        readiness=str(document.get("readiness", "/")),
    )


def open_file(settings: SimpleNamespace, application: str) -> str:
    if application == "wordpress":
        return wordpress_caddy_file(settings)
    if application == "laravel":
        return laravel_caddy_file(settings)
    return caddy_file(settings)


def publish_gate(settings: SimpleNamespace, document: dict[str, object]) -> bool:
    path = pathlib.Path(f"/etc/caddy/sites/{settings.identifier}.caddy")
    preimage = current_bytes(path)
    if preimage != document.get("caddy"):
        return False
    candidate = maintenance_file(settings)
    if candidate != document.get("gate"):
        return False
    return publish_caddy(settings.identifier, candidate, preimage)


def open_site(settings: SimpleNamespace, document: dict[str, object]) -> bool:
    path = pathlib.Path(f"/etc/caddy/sites/{settings.identifier}.caddy")
    preimage = current_bytes(path)
    if preimage != document.get("gate"):
        return False
    return publish_caddy(settings.identifier, str(document.get("caddy", "")), preimage)


def drain(settings: SimpleNamespace) -> bool:
    """Stop new admission, prove no connection remains, then prove the workers idle."""
    before = haproxy_state(settings)
    selection = before["selection"]
    if not selection:
        return False
    identifier = settings.identifier
    changed = False
    failed = False
    try:
        if hap_api(identifier, f"set server php/{selection} state maint"):
            return False
        changed = True
        answer = hap_api(
            identifier,
            f"wait {DRAIN_SECONDS}s srv-removable php/{selection}",
            seconds=11,
        )
        failed = answer != "Done."
    finally:
        if changed and hap_api(identifier, f"set server php/{selection} state ready"):
            failed = True
    if failed:
        return False
    evidence = site_fpm_read(settings)
    if evidence is None:
        return False
    deadline = time.monotonic() + DRAIN_SECONDS
    while not site_fpm_idle(identifier, selection, evidence):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)
        evidence = site_fpm_read(settings)
        if evidence is None:
            return False
    return True
