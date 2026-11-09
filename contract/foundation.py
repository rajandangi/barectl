"""The server-foundation section of the native contract (docs/bootstrap.md, docs/runtimes.md).

The Nix profile layout, catalog lock, Caddy and journald configuration and runtime
templates are read from ``bootstrap/foundation.py``, ``runtimes/catalog.py``,
``runtimes/configuration.py`` and ``sites/serving.py``. The native execution shape is read
from ``operations/native.py``, which owns the transient unit and the mutation lock.
"""

from pathlib import Path
from typing import Final

from bootstrap import foundation
from operations import native
from runtimes import catalog, configuration
from runtimes.bodies import defaults
from sites import serving
from sites.bodies import common

REPOSITORY: Final = Path(__file__).resolve().parents[1]

# The lock directory and file modes are the native adapter's admission rules; the file is
# an empty, root-owned regular file with one link and carries no version or inventory.
LOCK_DIRECTORY_MODE: Final = "0700"
CADDY_MAIN_FILE: Final = "/etc/caddy/Caddyfile"
CADDY_SITES_DIRECTORY: Final = "/etc/caddy/sites"
CADDY_UNIT_FILE: Final = "/etc/systemd/system/caddy.service"
JOURNAL_DROP_IN: Final = "/etc/systemd/journald.conf.d/50-barectl.conf"
NIX_CONFIG: Final = "/etc/nix/nix.conf"
RUNTIME_UNIT_FILE: Final = "/etc/systemd/system/php-fpm@.service"


def _caddy_admin_socket() -> str:
    return common.ADMIN.removeprefix("unix/")


def _nix() -> dict[str, object]:
    return {
        "profile_root": defaults.PROFILES,
        "profile_pattern": defaults.PROFILES + "/<entry>",
        "profiles": list(foundation.PROFILES),
        "catalog_entries": list(configuration.ENTRIES),
        "config": {"path": NIX_CONFIG, "mode": "0644"},
    }


def _catalog_lock() -> dict[str, object]:
    return {
        "path": str(catalog.LOCK_PATH.resolve().relative_to(REPOSITORY)),
        "format": catalog.FORMAT,
        "architectures": [str(architecture) for architecture in catalog.Architecture],
        "kinds": [str(kind) for kind in catalog.Kind],
        "entry_pattern": catalog.ENTRY_NAME.pattern,
    }


def _caddy() -> dict[str, object]:
    return {
        "main_file": CADDY_MAIN_FILE,
        "main_file_owner": "root",
        "main_file_group": "root",
        "main_file_mode": "0644",
        "main_configuration": foundation.CADDY_CONFIG,
        "sites_directory": CADDY_SITES_DIRECTORY,
        "sites_directory_owner": "root",
        "sites_directory_group": "root",
        "sites_directory_mode": "0755",
        "unit_file": CADDY_UNIT_FILE,
        "unit_file_mode": "0644",
        "unit": foundation.CADDY_UNIT,
        "user": "caddy",
        "group": "caddy",
        "admin_socket": _caddy_admin_socket(),
        "state_directory": "/var/lib/caddy",
        "state_directory_mode": "0700",
    }


def _runtime_templates() -> dict[str, object]:
    site_units = {
        path: value for path, value in serving.service_units().items() if "php-fpm-site-" in path
    }
    return {
        "master_unit": {"path": RUNTIME_UNIT_FILE, "mode": "0644", "template": configuration.UNIT},
        "site_php_units": {
            path: {"mode": "0644", "template": value} for path, value in site_units.items()
        },
    }


def _native_execution() -> dict[str, object]:
    from operations import engine

    return {
        "systemd_run": native.SYSTEMD_RUN,
        "lock": {
            "directory": native.LOCK_DIRECTORY,
            "directory_mode": LOCK_DIRECTORY_MODE,
            "file": native.LOCK_FILE,
            "file_shape": "root-owned regular empty file with one link",
        },
        "unit": {
            "prefix": native.UNIT_PREFIX,
            # ``_UNIT`` is the adapter's own name check; reusing its pattern keeps the
            # promised name shape beside the code that creates and inspects it.
            "pattern": native._UNIT.pattern,
        },
        "limits": {
            "max_payload_bytes": native.MAX_PAYLOAD,
            "max_staged_body_bytes": native.MAX_BODY,
            "runtime_max": native.RUNTIME_MAX,
            "timeout_stop_seconds": int(native.TIMEOUT_STOP),
        },
        "stages": list(foundation.STAGES),
        "stage_line_prefix": engine.STAGE_PREFIX,
        "exit": {
            "probe": {member.name: int(member) for member in native.Exit},
            "engine": {member.name: int(member) for member in native.Code},
        },
    }


def build() -> dict[str, object]:
    """The server foundation as one JSON-serializable mapping."""
    return {
        "nix": _nix(),
        "catalog_lock": _catalog_lock(),
        "caddy": _caddy(),
        "journald": {
            "path": JOURNAL_DROP_IN,
            "mode": "0644",
            "contents": foundation.JOURNAL_CONFIG,
        },
        "runtime_templates": _runtime_templates(),
        "native_execution": _native_execution(),
    }
