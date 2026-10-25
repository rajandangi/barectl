"""The per-site Valkey convention the object-cache changes share.

docs/adr/0030-give-each-site-its-own-valkey-instance.md and the target architecture's
Valkey section. Installing the server-wide package is issue #391; this module is the
extension point #392 and #393 use for a site's own instance: the packaged unit template,
the root-owned configuration, and a private Unix socket in a runtime directory owned by
the site user. Nothing here is applied by #391.
"""

import re
from dataclasses import dataclass
from typing import Final

# https://manpages.ubuntu.com/manpages/resolute/man5/valkey.conf.5.html
PACKAGE: Final = "valkey-server"
UNIT: Final = "valkey-server.service"
INSTANCE_TEMPLATE: Final = "valkey-server@.service"
CONFIG_ROOT: Final = "/etc/valkey"
DATA_ROOT: Final = "/var/lib/valkey"
RUNTIME_ROOT: Final = "/run/valkey"
SOCKET_NAME: Final = "valkey.sock"
# The reviewed sizes, in MiB. A site picks one; the default keeps a small site cheap.
MAXMEMORY_MIB: Final = (32, 64, 128, 256)
DEFAULT_MAXMEMORY_MIB: Final = 64
# The site identifier grammar (sites/names.py).
_IDENTIFIER = re.compile(r"[a-z][a-z0-9]{2,23}")


@dataclass(frozen=True)
class InstancePaths:
    """One site's instance paths, all derived from its identifier."""

    unit: str
    config: str
    run_directory: str
    socket: str
    data_directory: str


def instance_paths(identifier: str) -> InstancePaths:
    """The reviewed paths for one site's instance, or ``ValueError`` for another name."""
    if _IDENTIFIER.fullmatch(identifier) is None:
        raise ValueError("Not a valid site identifier.")
    run_directory = f"{RUNTIME_ROOT}/{identifier}"
    return InstancePaths(
        unit=f"{PACKAGE}@{identifier}.service",
        config=f"{CONFIG_ROOT}/{identifier}.conf",
        run_directory=run_directory,
        socket=f"{run_directory}/{SOCKET_NAME}",
        data_directory=f"{DATA_ROOT}/{identifier}",
    )


def render_config(identifier: str, maxmemory_mib: int = DEFAULT_MAXMEMORY_MIB) -> str:
    """The instance configuration: socket only, no persistence, bounded and evicting.

    The default ACL user keeps ordinary data commands, including the flushes the
    applications themselves run, and loses the administration commands one site must not
    use against the server (docs/adr/0030-give-each-site-its-own-valkey-instance.md).
    """
    if maxmemory_mib not in MAXMEMORY_MIB:
        raise ValueError("Not a reviewed cache memory size.")
    paths = instance_paths(identifier)
    return "\n".join(
        (
            "port 0",
            "bind 127.0.0.1",
            "protected-mode yes",
            "daemonize no",
            "supervised no",
            f"dir {paths.data_directory}",
            f"unixsocket {paths.socket}",
            "unixsocketperm 600",
            'save ""',
            "appendonly no",
            f"maxmemory {maxmemory_mib * 1024**2}",
            "maxmemory-policy allkeys-lru",
            "user default on nopass ~* &* +@all -@admin -debug -module",
        )
    )
