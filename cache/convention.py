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
    drop_in_directory: str
    drop_in: str


def instance_paths(identifier: str) -> InstancePaths:
    """The reviewed paths for one site's instance, or ``ValueError`` for another name."""
    if _IDENTIFIER.fullmatch(identifier) is None:
        raise ValueError("Not a valid site identifier.")
    run_directory = f"{RUNTIME_ROOT}/{identifier}"
    drop_in_directory = f"/etc/systemd/system/{PACKAGE}@{identifier}.service.d"
    return InstancePaths(
        unit=f"{PACKAGE}@{identifier}.service",
        config=f"{CONFIG_ROOT}/{identifier}.conf",
        run_directory=run_directory,
        socket=f"{run_directory}/{SOCKET_NAME}",
        data_directory=f"{DATA_ROOT}/{identifier}",
        drop_in_directory=drop_in_directory,
        drop_in=f"{drop_in_directory}/barectl.conf",
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
            'logfile ""',
            f"pidfile {paths.run_directory}/valkey-server.pid",
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


def render_drop_in(identifier: str) -> str:
    """The root-owned drop-in that makes the packaged template run the site's own instance.

    Ubuntu's ``valkey-server@.service`` reads ``/etc/valkey/valkey-%i.conf`` and runs as
    the ``valkey`` user with a shared runtime directory. The drop-in names this site's
    configuration and account, and gives the process only its own runtime and data
    directories. ``ExecStart`` must be reset before it changes.
    """
    paths = instance_paths(identifier)
    return "\n".join(
        (
            "[Service]",
            f"User=s{identifier}",
            f"Group=s{identifier}",
            "ExecStart=",
            (
                f"ExecStart=/usr/bin/valkey-server {paths.config} "
                "--supervised systemd --daemonize no"
            ),
            f"PIDFile={paths.run_directory}/valkey-server.pid",
            f"RuntimeDirectory=valkey/{identifier}",
            "RuntimeDirectoryMode=0700",
            f"ReadWritePaths={paths.run_directory} {paths.data_directory}",
        )
    )


@dataclass(frozen=True)
class ConfigShape:
    """One observed configuration: the reviewed limit, or why it is outside."""

    memory_mib: int | None
    # Empty when the file is exactly a reviewed configuration.
    problem: str
    # Why the limit itself is outside the reviewed sizes; empty when it is not.
    outside: str


def config_shape(identifier: str, text: str) -> ConfigShape:
    """Recognize a hand-edited instance configuration.

    A reviewed configuration with any of the reviewed memory limits is supported, so an
    operator who resizes a cache inside the bounds keeps a recognized instance. Any other
    change is reported once as outside supported settings.
    """
    for size in MAXMEMORY_MIB:
        if text == render_config(identifier, size):
            return ConfigShape(size, "", "")
    limit: int | None = None
    for line in text.splitlines():
        if line.startswith("maxmemory "):
            raw = line.removeprefix("maxmemory ").strip()
            if raw.isdigit():
                value = int(raw)
                if value % 1024**2 == 0:
                    limit = value // 1024**2
    if limit is not None and limit not in MAXMEMORY_MIB:
        return ConfigShape(
            limit,
            "The cache's memory limit is outside the reviewed sizes.",
            "The cache's memory limit is outside the reviewed sizes.",
        )
    return ConfigShape(
        limit,
        "The cache configuration is outside the supported settings.",
        "",
    )
