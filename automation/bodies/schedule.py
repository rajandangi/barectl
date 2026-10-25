"""Turn a WordPress site's server cron on or off, in the reviewed order (Phase C #357).

On: publish the slice, service and timer, start the timer, wait for one successful run,
then hand page-load cron over by setting ``DISABLE_WP_CRON``. Off: clear the constant first,
then stop and remove the timer. The body re-validates the reviewed document and every
preimage under the site lock before it changes anything.
"""

import base64
import gzip
import hashlib
import json
import pathlib
import pwd
import re
import subprocess
import sys
from types import SimpleNamespace

from automation.bodies.units import (
    daemon_reload,
    disable_and_stop,
    enable_timer,
    properties,
    publish_units,
    remove_units,
    timer_ready,
    unit_digests,
    wait_for_tick,
)
from automation.convention import ROLE_WPCRON, service_name, timer_name
from sites.bodies.common import open_site_lock, result, site_account, stage
from wordpress.convention import (
    apply_owned_constant,
    cron_disabled,
    private_configuration_path,
    private_configuration_problem,
)

IDENTIFIER = re.compile(r"[a-z][a-z0-9]{2,23}")
WRITE_SCRIPT = (
    "import json,os,sys,tempfile\n"
    "payload=json.load(sys.stdin)\n"
    "path=payload['path']\n"
    "text=payload['text']\n"
    "directory=os.path.dirname(path)\n"
    "fd,temp=tempfile.mkstemp(prefix='.barectl-',suffix='.tmp',dir=directory)\n"
    "try:\n"
    "    os.fchmod(fd,0o600)\n"
    "    with os.fdopen(fd,'w',encoding='utf-8') as output:\n"
    "        output.write(text)\n"
    "        output.flush()\n"
    "        os.fsync(output.fileno())\n"
    "    os.replace(temp,path)\n"
    "except BaseException:\n"
    "    try: os.unlink(temp)\n"
    "    except OSError: pass\n"
    "    raise\n"
)
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
KINDS = ("slice", "service", "timer")
SUCCESS_RESULTS = frozenset({"success"})


def _private(path: pathlib.Path, account: str) -> bool:
    try:
        info = path.lstat()
        owner = pwd.getpwnam(account)
    except OSError, KeyError:
        return False
    return (
        info.st_uid == owner.pw_uid
        and info.st_mode & 0o077 == 0
        and info.st_mode & 0o170000 == 0o100000
    )


def _reviewed(document: dict[str, object]) -> SimpleNamespace:
    identifier = str(document.get("identifier", ""))
    state = document.get("state")
    digests = document.get("units")
    if (
        document.get("version") != 1
        or IDENTIFIER.fullmatch(identifier) is None
        or state not in ("on", "off")
        or type(document.get("uid")) is not int
        or type(document.get("gid")) is not int
        or not isinstance(document.get("configuration_digest"), str)
        or DIGEST.fullmatch(str(document["configuration_digest"])) is None
        or not isinstance(digests, dict)
        or set(digests) != set(KINDS)
        or not all(
            digests.get(kind) == "absent" or DIGEST.fullmatch(str(digests.get(kind))) is not None
            for kind in KINDS
        )
        or type(document.get("tick_budget_seconds")) is not int
    ):
        raise ValueError("The scheduled-tasks review is not a valid immutable selection.")
    return SimpleNamespace(
        identifier=identifier,
        state=state,
        uid=document["uid"],
        gid=document["gid"],
        configuration_digest=document["configuration_digest"],
        units={kind: str(digests[kind]) for kind in KINDS},
        tick_budget_seconds=document["tick_budget_seconds"],
    )


def _read_configuration(identifier: str) -> str:
    path = pathlib.Path(private_configuration_path(identifier))
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError, ValueError:
        return ""
    return text if len(text.encode("utf-8", "replace")) <= 65536 else ""


def _write_as_site(identifier: str, path: pathlib.Path, text: str) -> None:
    payload = json.dumps({"path": str(path), "text": text}).encode()
    completed = subprocess.run(  # noqa: S603 - fixed argv as the site user
        [
            "/usr/sbin/runuser",
            "-u",
            "s" + identifier,
            "--",
            "/usr/bin/python3",
            "-c",
            WRITE_SCRIPT,
        ],
        input=payload,
        capture_output=True,
        timeout=120,
        check=False,
    )
    if completed.returncode:
        raise ValueError("The private WordPress configuration could not be written.")


def _configuration(identifier: str, path: pathlib.Path, before: str, value: str) -> None:
    """Write the reviewed constant value (empty removes it)."""
    text = apply_owned_constant(before, "DISABLE_WP_CRON", value, identifier)
    if private_configuration_problem(text, identifier):
        raise ValueError("The new configuration is outside the supported grammar.")
    _write_as_site(identifier, path, text)


def _verify_configuration(identifier: str, path: pathlib.Path, value: str) -> bool:
    text = _read_configuration(identifier)
    return (
        bool(text)
        and not private_configuration_problem(text, identifier)
        and cron_disabled(text, identifier) == value
        and path.exists()
    )


def _preflight(value: SimpleNamespace, path: pathlib.Path) -> bool:
    account = site_account(value.identifier)
    directory = pathlib.Path("/var/www") / value.identifier
    return (
        account is not None
        and account[0] == value.uid
        and account[1] == value.gid
        and (directory / "current").is_dir()
        and (directory / "bin" / "wp").is_file()
        and _private(path, "s" + value.identifier)
    )


def _turn_on(value: SimpleNamespace, path: pathlib.Path, before: str) -> None:
    stage("install")
    publish_units(value.identifier, ROLE_WPCRON, value.units)
    daemon_reload()
    enable_timer(timer_name(value.identifier, ROLE_WPCRON))
    if not timer_ready(value.identifier, ROLE_WPCRON):
        result("partial", "automation_start")
        return
    stage("tick")
    if not wait_for_tick(value.identifier, ROLE_WPCRON, value.tick_budget_seconds):
        result("partial", "automation_tick")
        return
    stage("configuration")
    _configuration(value.identifier, path, before, "true")
    if not _verify_configuration(value.identifier, path, "true"):
        result("partial", "automation_configuration")
        return
    stage("verify")
    if not timer_ready(value.identifier, ROLE_WPCRON):
        result("partial", "automation_start")
        return
    if properties(service_name(value.identifier, ROLE_WPCRON)).get("Result") not in SUCCESS_RESULTS:
        result("partial", "automation_tick")
        return
    result("succeeded")


def _turn_off(value: SimpleNamespace, path: pathlib.Path, before: str) -> None:
    stage("configuration")
    _configuration(value.identifier, path, before, "")
    if not _verify_configuration(value.identifier, path, ""):
        result("partial", "automation_configuration")
        return
    stage("install")
    disable_and_stop(value.identifier, ROLE_WPCRON)
    remove_units(value.identifier, ROLE_WPCRON, value.units)
    stage("verify")
    if unit_digests(value.identifier, ROLE_WPCRON) != dict.fromkeys(KINDS, "absent"):
        result("partial", "automation_units")
        return
    if not _verify_configuration(value.identifier, path, ""):
        result("partial", "automation_configuration")
        return
    result("succeeded")


def main(document: dict[str, object]) -> None:
    identifier = str(document.get("identifier", ""))
    lock: int | None = None
    try:
        value = _reviewed(document)
        identifier = value.identifier
        path = pathlib.Path(private_configuration_path(identifier))
        try:
            lock = open_site_lock(identifier)
        except BlockingIOError:
            result("lock_busy")
            return
        except OSError, ValueError:
            result("refused", "unsafe_lock")
            return
        stage("preflight")
        before = _read_configuration(identifier)
        if not _preflight(value, path) or not before:
            result("refused", "automation_site")
            return
        if (
            hashlib.sha256(before.encode("utf-8")).hexdigest() != value.configuration_digest
            or private_configuration_problem(before, identifier)
            or unit_digests(identifier, ROLE_WPCRON) != value.units
        ):
            result("refused", "evidence")
            return
        if value.state == "on":
            _turn_on(value, path, before)
        else:
            _turn_off(value, path, before)
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        sys.stderr.write(f"barectl-problem {type(error).__name__}: {error}\n")
        sys.stderr.flush()
        result("refused", "automation")
    except Exception:
        sys.stderr.write("barectl-problem The scheduled tasks could not be changed.\n")
        sys.stderr.flush()
        result("failed", "automation")
    finally:
        if lock is not None:
            import os

            os.close(lock)


if __name__ == "__main__":
    main(json.loads(gzip.decompress(base64.b64decode(sys.argv[1]))))
