"""Open a site whose full backup stopped after publishing the maintenance gate (#399).

It publishes the reviewed open Caddy file with the same validation and reload as every site
change. It does not restart the site's background work: Scheduled tasks and Queue workers
ask the operator what should be on (docs/adr/0036).
"""

import base64
import gzip
import json
import os
import sys
from types import SimpleNamespace

from sites.bodies.common import (
    caddy_file,
    current_bytes,
    laravel_caddy_file,
    maintenance_file,
    open_site_lock,
    publish_caddy,
    result,
    setting,
    stage,
    wordpress_caddy_file,
)

APPLICATIONS = ("plain", "wordpress", "laravel")


def open_file(settings: SimpleNamespace, application: str) -> str:
    if application == "wordpress":
        return wordpress_caddy_file(settings)
    if application == "laravel":
        return laravel_caddy_file(settings)
    return caddy_file(settings)


def main() -> None:  # noqa: C901 - one reviewed reopen
    document = json.loads(gzip.decompress(base64.b64decode(sys.argv[1])))
    identifier = str(document.get("identifier", ""))
    application = str(document.get("application", ""))
    names = document.get("names")
    if (
        not identifier
        or application not in APPLICATIONS
        or not isinstance(names, list)
        or not all(isinstance(name, str) for name in names)
    ):
        result("refused", "evidence")
        return
    try:
        settings = setting(
            identifier,
            names,
            str(document.get("runtime", "")),
            https=document.get("https", True) is not False,
            readiness=str(document.get("readiness", "/")),
        )
    except ValueError:
        result("refused", "evidence")
        return
    if open_file(settings, application) != document.get("caddy"):
        result("refused", "evidence")
        return
    if maintenance_file(settings) != document.get("gate"):
        result("refused", "evidence")
        return
    try:
        lock = open_site_lock(identifier)
    except BlockingIOError:
        result("lock_busy")
        return
    except OSError, ValueError:
        result("refused", "unsafe_lock")
        return
    try:
        stage("preflight")
        path = f"/etc/caddy/sites/{identifier}.caddy"
        from pathlib import Path

        if current_bytes(Path(path)) != document.get("gate"):
            result("refused", "evidence")
            return
        stage("publish")
        opened = publish_caddy(
            identifier,
            str(document.get("caddy", "")),
            str(document.get("gate", "")),
        )
        if not opened:
            result("partial", "site_reopen")
            return
        stage("verify")
        if current_bytes(Path(path)) != document.get("caddy"):
            result("partial", "site_reopen")
            return
        result("succeeded")
    except OSError, ValueError:
        result("partial", "site_reopen")
    finally:
        os.close(lock)


if __name__ == "__main__":
    main()
