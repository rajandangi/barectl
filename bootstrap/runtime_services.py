"""Fresh native PHP selections and the runtime request boundary."""

import hashlib
import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from discovery.ssh import RemoteShell

if TYPE_CHECKING:
    from django.contrib.auth.models import AbstractBaseUser

    from servers.models import Server

    from .models import PlanPreparation

from . import inspection, php_source, php_trust, releases, runtime_native


@dataclass(frozen=True)
class PhpDefault:
    branch: str
    path: str
    mode: str
    package: str
    version: str
    architecture: str


@dataclass(frozen=True)
class PhpRuntimeObservation:
    default: PhpDefault | None = None
    installed: tuple[str, ...] = ()
    supply: str | None = None
    failure: str = ""
    fingerprint: str = ""
    fresh: bool = False


def _package(value: object, *, default: bool = False) -> PhpDefault:
    keys = {"branch", "path", "package", "version", "architecture"}
    if default:
        keys.add("mode")
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError("The native PHP evidence has an unknown shape.")
    strings: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not isinstance(item, str):
            raise ValueError("The native PHP evidence has unknown fields.")
        strings[key] = item
    branch = strings["branch"]
    if (
        branch not in ("8.3", "8.4", "8.5")
        or strings["path"] != f"/usr/bin/php{branch}"
        or strings["package"] != f"php{branch}-cli"
        or strings["architecture"] not in ("arm64", "amd64")
        or not re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,100}", strings["version"])
        or (default and strings["mode"] not in ("auto", "manual"))
    ):
        raise ValueError("The selected PHP CLI is unsupported.")
    return PhpDefault(
        branch,
        strings["path"],
        strings.get("mode", ""),
        strings["package"],
        strings["version"],
        strings["architecture"],
    )


def observe_php_runtime(shell: RemoteShell) -> PhpRuntimeObservation:
    """Read native alternatives and authenticated installed supply; never use a cache."""
    result = shell.run(runtime_native.READ)
    if result.exit_status or result.truncated or len(result.stdout) > 32768:
        return PhpRuntimeObservation(failure="The native PHP alternatives could not be read.")
    try:
        selected, packages = _decode(result.stdout)
    except ValueError, TypeError:
        return PhpRuntimeObservation(
            failure="The native PHP alternatives are incomplete or unsupported."
        )
    reader = inspection.Reader(shell)
    platform = inspection.read_platform(reader)
    release = releases.of(platform.os) if platform is not None else None
    if reader.gaps or platform is None or release is None:
        return PhpRuntimeObservation(failure="The PHP server platform could not be established.")
    if packages:
        supply = php_trust.observed_supply(shell, release, platform.architecture)
    else:
        state = shell.run(php_source.STATE)
        if state.exit_status or state.truncated:
            supply = None
        elif all(path + "|absent" in state.stdout.splitlines() for path in php_source.FILES):
            supply = "sury"
        else:
            supply = (
                "sury"
                if php_trust.collect(
                    shell, release, platform.architecture, platform.privilege
                ).admitted
                else None
            )
    if supply is None or any(row.architecture != platform.architecture for row in packages):
        return PhpRuntimeObservation(
            failure="The installed PHP supply is mixed, customized or not currently admitted."
        )
    after = shell.run(runtime_native.READ)
    if after.exit_status or after.truncated or after.stdout != result.stdout:
        return PhpRuntimeObservation(failure="The native PHP selection changed while it was read.")
    return PhpRuntimeObservation(
        selected,
        tuple(row.branch for row in packages),
        supply,
        fingerprint=hashlib.sha256(result.stdout.encode()).hexdigest(),
        fresh=not packages,
    )


def _decode(text: str) -> tuple[PhpDefault | None, tuple[PhpDefault, ...]]:
    value: object = json.loads(text)
    if not isinstance(value, dict) or set(value) != {"default", "packages"}:
        raise ValueError("The native PHP alternatives have an unknown shape.")
    rows = value["packages"]
    if not isinstance(rows, list) or len(rows) > 3:
        raise ValueError("The installed PHP CLI list exceeds its bound.")
    packages = tuple(_package(row) for row in rows)
    selected = _package(value["default"], default=True) if value["default"] is not None else None
    if len({row.branch for row in packages}) != len(packages) or bool(packages) != bool(selected):
        raise ValueError("The native PHP default and installed CLI branches disagree.")
    if selected is not None and not any(
        (row.branch, row.path, row.package, row.version, row.architecture)
        == (
            selected.branch,
            selected.path,
            selected.package,
            selected.version,
            selected.architecture,
        )
        for row in packages
    ):
        raise ValueError("The native PHP default has no matching installed package.")
    return selected, packages


def request_runtime_preparation(
    server: Server, user: AbstractBaseUser, branch: str, *, identifier: str = ""
) -> PlanPreparation | None:
    from django.db import transaction

    from operations import lifecycle
    from operations.lifecycle import OperationBusy

    from .models import Action, PlanPreparation
    from .runtime_models import RuntimeRequest

    if branch not in ("8.3", "8.4", "8.5") or (
        identifier and not re.fullmatch(r"[a-z][a-z0-9]{2,23}", identifier)
    ):
        raise ValueError("The PHP branch or site identifier is unsupported.")
    with transaction.atomic():
        try:
            preparation = lifecycle.queue(
                PlanPreparation,
                server,
                action=Action.SITE_PHP_SWITCH if identifier else Action.PHP_DEFAULT,
                requested_by=user,
            )
        except OperationBusy:
            return None
        RuntimeRequest.objects.create(preparation=preparation, branch=branch, identifier=identifier)
    return preparation


def request_php_installation(
    server: Server, user: AbstractBaseUser, branch: str, supply: str
) -> PlanPreparation | None:
    from django.db import transaction

    from .models import Action
    from .runtime_models import PackagePhpDefaultRequest
    from .services import request_preparation

    with transaction.atomic():
        preparation = request_preparation(
            server, user, Action.PHP, php_version=branch, php_supply=supply
        )
        if preparation is not None:
            PackagePhpDefaultRequest.objects.create(preparation=preparation)
    return preparation
