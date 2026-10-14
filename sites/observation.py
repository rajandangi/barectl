"""Read target sites through native configuration and the upstream Caddy adapter."""

import importlib.resources
import json
import shlex
from typing import Final

from discovery.root_read import run_root
from discovery.ssh import RemoteShell
from operations import native

from .configuration import CADDY_TEMPLATE, POOL_TEMPLATE

COMMON_SOURCE: Final = (
    importlib.resources.files("sites.bodies")
    .joinpath("common.py")
    .read_text()
    .replace('CADDY_TEMPLATE = ""', "CADDY_TEMPLATE = " + repr(CADDY_TEMPLATE))
    .replace('POOL_TEMPLATE = ""', "POOL_TEMPLATE = " + repr(POOL_TEMPLATE))
)
READ_SOURCE: Final = (
    COMMON_SOURCE + "\nimport sys\nprint(canonical(native_state(sys.argv[1], sys.argv[2])))\n"
)


def read_command(identifier: str, runtime: str) -> str:
    from .configuration import SiteSettings

    SiteSettings(identifier, ("example.com",), runtime)
    command = shlex.join(["python3", "-c", READ_SOURCE, identifier, runtime])
    return "sh -c " + shlex.quote(
        "; ".join([*native.lock_steps("exit 11", "exit 10"), "exec " + command])
    )


def read(shell: RemoteShell, identifier: str, runtime: str) -> dict[str, object] | None:
    result = run_root(shell, read_command(identifier, runtime))
    if result.exit_status or result.truncated:
        return None
    try:
        value: object = json.loads(result.stdout)
    except ValueError:
        return None
    if not isinstance(value, dict) or value.get("version") != 1:
        return None
    return value
