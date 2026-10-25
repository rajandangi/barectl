"""Apply reviewed catalog builds without refused requests (Phase B #386).

Appended to the site PHP program's source, so the request-preserving switch primitives,
site locks and readiness checks are the same code a site PHP change uses. PHP entries move
each affected site to the other installed runtime through ADR 0038's admission and drain,
switch the profile, restart its diagnostic master, then move the site back. Caddy and
HAProxy profiles restart the stack's own services. The previous generation stays; only
after every reviewed postcondition holds are older generations collected.
"""

import os
import pathlib
import subprocess
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # Assembled into this body by automation/bodies/source.py (Phase C #395).
    from automation.bodies.units import fence, restore

# COMPOSED-SITE-PROGRAM: these names are defined by the site PHP program this source is
# appended to; the composer removes this block before staging.
from sites.bodies.common import (
    open_site_lock,
    result,
    same_site_lock,
    stage,
    verify_readiness,
    wrapper,
)
from sites.bodies.php_runtime import (
    finish_source_php,
    missing_php_modules,
    php_settings,
    php_state,
    replace_php_wrapper,
    select_target_php,
    start_target_php,
)

# END-COMPOSED-SITE-PROGRAM


class FenceStopped(Exception):
    """A moved site's background work could not be paused or started again (#395)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


PROFILE_ROOT = "/nix/var/nix/profiles/barectl"
NIX_BIN = "/nix/var/nix/profiles/default/bin"
NIX_ENV = {"HOME": "/root", "USER": "root"}


def native(argv: list[str], *, timeout: int = 600) -> str:
    environment = {**os.environ, **NIX_ENV}
    process = subprocess.run(  # noqa: S603 - fixed native argv from the reviewed catalog
        argv,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env=environment,
    )
    if process.returncode:
        raise ValueError("A native catalog command failed.")
    return process.stdout


def profile_path(entry: str) -> str:
    return os.path.realpath(f"{PROFILE_ROOT}/{entry}")


def other_php(entry: str) -> str:
    return "php85" if entry == "php84" else "php84"


def realise(paths: list[str]) -> None:
    """Realise the reviewed builds; nothing is built locally and nothing else is used.

    A path this server already holds is returned as it is. A missing closure comes from the
    configured signed substituter, cache.nixos.org, or realisation refuses.
    """
    native(
        [
            NIX_BIN + "/nix-store",
            "--realise",
            *paths,
            "--option",
            "max-jobs",
            "0",
            "--option",
            "fallback",
            "false",
        ]
    )


def check_php_build(path: str, entry: str) -> None:
    """Refuse a reviewed build that cannot run before any profile or site changes."""
    for name in ("php", "php-fpm", ".php-fpm-wrapped"):
        if not os.path.lexists(f"{path}/bin/{name}"):
            raise ValueError("A reviewed PHP build is missing a required executable.")
    executable = os.path.realpath(f"{path}/bin/.php-fpm-wrapped")
    if not executable.startswith("/nix/store/") or not executable.endswith("/bin/php-fpm"):
        raise ValueError("A reviewed PHP build has no supported wrapped executable.")
    native(
        [
            f"{path}/bin/php-fpm",
            "-t",
            "-y",
            f"/etc/php-fpm/{entry}/php-fpm.conf",
            "-c",
            f"/etc/php-fpm/{entry}/php.ini",
        ],
        timeout=60,
    )


def set_profile(entry: str, path: str) -> None:
    native(
        [NIX_BIN + "/nix-env", "--profile", f"{PROFILE_ROOT}/{entry}", "--set", path],
        timeout=120,
    )


def restart(unit: str) -> None:
    native(["systemctl", "restart", unit], timeout=340)


def service_properties(unit: str, *properties: str) -> dict[str, str]:
    report = native(["systemctl", "show", unit, *(f"-p{name}" for name in properties)])
    return dict(line.split("=", 1) for line in report.splitlines() if "=" in line)


def running_executable(unit: str, expected: str) -> None:
    values = service_properties(unit, "ActiveState", "MainPID")
    pid = values.get("MainPID", "0")
    if values.get("ActiveState") != "active" or not pid.isdecimal() or int(pid) <= 0:
        raise ValueError("A restarted native service is not active.")
    if os.path.realpath(f"/proc/{pid}/exe") != os.path.realpath(expected):
        raise ValueError("A restarted native service runs another executable.")


def active_site_units(entry: str) -> list[str]:
    output = native(
        [
            "systemctl",
            "list-units",
            "--type=service",
            "--state=active",
            "--no-legend",
            "--plain",
            f"php-fpm-site-{entry}@*.service",
        ]
    )
    return [line.split()[0] for line in output.splitlines() if line.split()]


def haproxy_units() -> list[str]:
    output = native(
        [
            "systemctl",
            "list-units",
            "--type=service",
            "--state=active",
            "--no-legend",
            "--plain",
            "haproxy-site@*.service",
        ]
    )
    return [line.split()[0] for line in output.splitlines() if line.split()]


def move_site(identifier: str, target: str, document: dict[str, object]) -> None:
    descriptor = open_site_lock(identifier)
    try:
        state = php_state(identifier)
        if state["profiles"].get(target) != profile_path(target):
            raise ValueError("A site's target runtime profile changed during the update.")
        if missing_php_modules(state, target):
            raise ValueError("A site's target runtime would lose a loaded optional module.")
        if not fence(document, identifier):
            raise FenceStopped("automation_fence")
        source = other_php(target)
        settings = php_settings(identifier, state, target)
        source_evidence = start_target_php(settings, state, source)
        select_target_php(settings, state, source)
        finish_source_php(settings, state, source, source_evidence, descriptor)
        for name in ("php", "composer", "wp"):
            replace_php_wrapper(
                pathlib.Path(settings.directory) / "bin" / name,
                wrapper(settings, name, getattr(settings, "client", "")),
            )
        final = php_state(identifier)
        if (
            not final["complete"]
            or final["proxy"]["selection"] != target
            or not same_site_lock(descriptor, identifier)
        ):
            raise ValueError("A site's PHP runtime did not verify after the update.")
        verify_readiness(php_settings(identifier, final, target))
        if not restore(document, identifier):
            raise FenceStopped("automation_restore")
    finally:
        os.close(descriptor)


def update_php(item: dict[str, object], document: dict[str, object]) -> None:
    entry = str(item["entry"])
    sites = item["sites"]
    if not isinstance(sites, list):
        raise ValueError("A reviewed PHP update lost its sites.")
    identifiers = [site for site in sites if isinstance(site, str)]
    if len(identifiers) != len(sites):
        raise ValueError("A reviewed PHP update names an invalid site.")
    for identifier in identifiers:
        move_site(identifier, other_php(entry), document)
    if active_site_units(entry):
        raise ValueError("A site's PHP service still serves from the updated runtime.")
    set_profile(entry, str(item["to"]))
    restart(f"php-fpm@{entry}.service")
    running_executable(f"php-fpm@{entry}.service", f"{item['to']!s}/bin/.php-fpm-wrapped")
    for identifier in identifiers:
        move_site(identifier, entry, document)


def update_service(item: dict[str, object]) -> None:
    entry = str(item["entry"])
    set_profile(entry, str(item["to"]))
    path = str(item["to"])
    if entry == "caddy":
        restart("caddy.service")
        running_executable("caddy.service", path + "/bin/caddy")
    elif entry == "haproxy":
        for unit in haproxy_units():
            restart(unit)
            running_executable(unit, path + "/bin/haproxy")


def verify_entry(item: dict[str, object]) -> None:
    if profile_path(str(item["entry"])) != str(item["to"]):
        raise ValueError("A profile did not move to the updated catalog build.")


def verify_php_site(identifier: str, entry: str, path: str) -> None:
    final = php_state(identifier)
    if (
        not final["complete"]
        or final["proxy"]["selection"] != entry
        or final["profiles"].get(entry) != path
    ):
        raise ValueError("A site did not return to its updated runtime.")


def delete_generations(entry: str) -> None:
    native(
        [
            NIX_BIN + "/nix-env",
            "--profile",
            f"{PROFILE_ROOT}/{entry}",
            "--delete-generations",
            "+2",
        ],
        timeout=120,
    )


def collect_store() -> None:
    subprocess.run(  # noqa: S603 - the fixed Nix garbage collector
        [NIX_BIN + "/nix-store", "--gc"],
        stdin=subprocess.DEVNULL,
        env={**os.environ, **NIX_ENV},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=900,
        check=True,
    )


def update_catalog(document: dict[str, object]) -> None:  # noqa: C901 - one reviewed run
    entries = document.get("entries")
    if not isinstance(entries, list) or not entries:
        result("refused", "evidence")
        return
    stage("preflight")
    changed = False
    try:
        for item in entries:
            if not isinstance(item, dict):
                raise ValueError("The reviewed catalog update is malformed.")
            if profile_path(str(item["entry"])) != str(item["from"]):
                result("refused", "evidence")
                return
        states = document.get("states")
        if not isinstance(states, dict):
            raise ValueError("The reviewed catalog update has no site state.")
        for item in entries:
            if not isinstance(item, dict) or item.get("kind") != "php":
                continue
            sites = item.get("sites")
            if not isinstance(sites, list):
                continue
            for identifier in sites:
                if not isinstance(identifier, str):
                    raise ValueError("A reviewed PHP update names an invalid site.")
                state = php_state(identifier)
                if state["digest"] != states.get(identifier):
                    result("refused", "evidence")
                    return
        stage("realise")
        realise([str(item["to"]) for item in entries if isinstance(item, dict)])
        for item in entries:
            if isinstance(item, dict) and item.get("kind") == "php":
                check_php_build(str(item["to"]), str(item["entry"]))
        changed = True
        stage("sites")
        for item in entries:
            if isinstance(item, dict) and item.get("kind") == "php":
                update_php(item, document)
        stage("profiles")
        for item in entries:
            if isinstance(item, dict) and item.get("kind") != "php":
                update_service(item)
        stage("verify")
        for item in entries:
            if not isinstance(item, dict):
                raise ValueError("The reviewed catalog update is malformed.")
            verify_entry(item)
            if item.get("kind") == "php":
                sites = item.get("sites")
                if isinstance(sites, list):
                    for identifier in sites:
                        if isinstance(identifier, str):
                            verify_php_site(identifier, str(item["entry"]), str(item["to"]))
        stage("collect")
        for item in entries:
            if isinstance(item, dict):
                delete_generations(str(item["entry"]))
        try:
            collect_store()
        except OSError, subprocess.SubprocessError:
            sys.stderr.write("Garbage collection did not finish; older builds stay in the store.\n")
        result("succeeded")
    except FenceStopped as error:
        result("partial" if changed else "refused", error.reason)
    except BlockingIOError:
        result("lock_busy")
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        sys.stderr.write(
            "Catalog update stopped (" + type(error).__name__ + "): " + str(error)[:500] + "\n"
        )
        result("partial" if changed else "refused", "runtime_config" if changed else "evidence")
