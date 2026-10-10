"""Native Node reconstruction (docs/node-runtimes-native-design.md)."""

from dataclasses import dataclass

from bootstrap import native as bootstrap_native
from discovery.ssh import RemoteShell
from sites.names import valid_identifier

from . import catalog, native


class Unreadable(Exception):
    pass


@dataclass(frozen=True)
class Inventory:
    default: str
    installed: tuple[str, ...]
    sites: dict[str, str]


def inspect(shell: RemoteShell, *, root: bool = True) -> Inventory:
    result = shell.run(bootstrap_native.privileged(native.inventory(), root=root))
    if result.exit_status or result.truncated:
        raise Unreadable("Native Node configuration is unavailable or unsafe.")
    default = ""
    installed: list[str] = []
    sites: dict[str, str] = {}
    for line in result.stdout.splitlines():
        parts = line.split()
        if (
            len(parts) == 2
            and parts[0] in {"default", "installed"}
            and parts[1] in catalog.VERSIONS
        ):
            if parts[0] == "default" and not default:
                default = parts[1]
            elif parts[0] == "installed" and parts[1] not in installed:
                installed.append(parts[1])
            else:
                raise Unreadable("Duplicate Node evidence.")
        elif (
            len(parts) == 3
            and parts[0] == "site"
            and valid_identifier(parts[1])
            and parts[2] in catalog.VERSIONS
            and parts[1] not in sites
        ):
            sites[parts[1]] = parts[2]
        else:
            raise Unreadable("Unrecognized native Node configuration.")
    return Inventory(default, tuple(installed), sites)


@dataclass(frozen=True)
class Observation:
    inventory: Inventory | None = None
    failure: str = ""


def observe_runtime(shell: RemoteShell) -> Observation:
    root = bootstrap_native.is_root(shell)
    if root is None:
        return Observation(failure="Native Node privilege is unavailable.")
    if not root and shell.run(bootstrap_native.authorization(native.inventory())).exit_status:
        return Observation(failure="Native Node inventory requires read privilege.")
    try:
        return Observation(inspect(shell, root=root))
    except Unreadable as error:
        return Observation(failure=str(error))


def save_snapshot_runtime(snapshot_id: int, observed: Observation) -> None:
    from .models import NodeRuntimeSnapshot

    found = observed.inventory
    NodeRuntimeSnapshot.objects.create(
        snapshot_id=snapshot_id,
        default="" if found is None else found.default,
        installed="" if found is None else "\n".join(found.installed),
        site_pins=""
        if found is None
        else "\n".join(f"{i} {v}" for i, v in sorted(found.sites.items())),
        failure=observed.failure,
    )
