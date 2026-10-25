"""Turn a Laravel site's scheduler on or off, or run one tick now (Phase C #357, #265).

On publishes the slice, service and timer and starts the timer. Off stops and disables the
timer before it removes the units. Run now starts the installed oneshot service and waits for
its result, changing no unit and no schedule. The body re-validates the reviewed document and
every unit preimage before it changes anything. Ticks take no Barectl lock.
"""

import base64
import gzip
import json
import pathlib
import re
import sys
from types import SimpleNamespace

from automation.bodies.units import (
    daemon_reload,
    disable_and_stop,
    enable_timer,
    load_state,
    publish_units,
    remove_units,
    start_and_wait,
    timer_ready,
    unit_digests,
)
from automation.convention import ROLE_SCHEDULE, service_name, timer_name
from sites.bodies.common import result, site_account, stage

IDENTIFIER = re.compile(r"[a-z][a-z0-9]{2,23}")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
KINDS = ("slice", "service", "timer")
SUCCESS = "success"


def _reviewed(document: dict[str, object]) -> SimpleNamespace:
    identifier = str(document.get("identifier", ""))
    state = document.get("state")
    digests = document.get("units")
    wait = document.get("run_wait_seconds")
    if (
        document.get("version") != 1
        or IDENTIFIER.fullmatch(identifier) is None
        or state not in ("on", "off", "run")
        or type(document.get("uid")) is not int
        or type(document.get("gid")) is not int
        or not isinstance(digests, dict)
        or set(digests) != set(KINDS)
        or not all(
            digests.get(kind) == "absent" or DIGEST.fullmatch(str(digests.get(kind))) is not None
            for kind in KINDS
        )
        or type(wait) is not int
        or not 1 <= wait <= 1800
    ):
        raise ValueError("The scheduler review is not a valid immutable selection.")
    return SimpleNamespace(
        identifier=identifier,
        state=state,
        uid=document["uid"],
        gid=document["gid"],
        units={kind: str(digests[kind]) for kind in KINDS},
        run_wait_seconds=document["run_wait_seconds"],
    )


def _preflight(value: SimpleNamespace) -> bool:
    account = site_account(value.identifier)
    if account is None or account[0] != value.uid or account[1] != value.gid:
        return False
    if value.state == "off":
        return True
    directory = pathlib.Path("/var/www") / value.identifier
    return bool(
        (directory / "current").is_dir()
        and (directory / "bin" / "php").is_file()
        and (directory / "current" / "artisan").is_file()
    )


def _turn_on(value: SimpleNamespace) -> None:
    stage("install")
    publish_units(value.identifier, ROLE_SCHEDULE, value.units)
    daemon_reload()
    enable_timer(timer_name(value.identifier, ROLE_SCHEDULE))
    if not timer_ready(value.identifier, ROLE_SCHEDULE):
        result("partial", "automation_start")
        return
    stage("verify")
    if load_state(service_name(value.identifier, ROLE_SCHEDULE)) == "not-found":
        result("partial", "automation_units")
        return
    result("succeeded")


def _turn_off(value: SimpleNamespace) -> None:
    stage("install")
    disable_and_stop(value.identifier, ROLE_SCHEDULE)
    remove_units(value.identifier, ROLE_SCHEDULE, value.units)
    stage("verify")
    if unit_digests(value.identifier, ROLE_SCHEDULE) != dict.fromkeys(KINDS, "absent"):
        result("partial", "automation_units")
        return
    if load_state(timer_name(value.identifier, ROLE_SCHEDULE)) != "not-found":
        result("partial", "automation_units")
        return
    result("succeeded")


def _run_now(value: SimpleNamespace) -> None:
    service = service_name(value.identifier, ROLE_SCHEDULE)
    if load_state(service) == "not-found":
        result("refused", "automation_scheduler")
        return
    stage("run")
    outcome = start_and_wait(value.identifier, ROLE_SCHEDULE, value.run_wait_seconds)
    if outcome == "running":
        result("partial", "automation_running")
        return
    if outcome != SUCCESS:
        result("partial", "automation_run")
        return
    stage("verify")
    if load_state(service) == "not-found":
        result("partial", "automation_units")
        return
    result("succeeded")


def main(document: dict[str, object]) -> None:
    identifier = str(document.get("identifier", ""))
    try:
        value = _reviewed(document)
        identifier = value.identifier
        stage("preflight")
        if not _preflight(value):
            result("refused", "automation_scheduler")
            return
        if unit_digests(identifier, ROLE_SCHEDULE) != value.units:
            result("refused", "evidence")
            return
        if value.state == "on":
            _turn_on(value)
        elif value.state == "off":
            _turn_off(value)
        else:
            _run_now(value)
    except (ValueError, OSError) as error:
        sys.stderr.write(f"barectl-problem {type(error).__name__}: {error}\n")
        sys.stderr.flush()
        result("refused", "automation")
    except Exception:
        sys.stderr.write("barectl-problem The site's scheduler could not be changed.\n")
        sys.stderr.flush()
        result("failed", "automation")


if __name__ == "__main__":
    main(json.loads(gzip.decompress(base64.b64decode(sys.argv[1]))))
