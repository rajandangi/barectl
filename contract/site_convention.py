"""The site convention section of the native contract (docs/site-conventions.md).

Every path, account, unit and template below is read from the module that owns it.
``sites/configuration.py`` owns the selection and its Caddy and pool templates,
``sites/serving.py`` owns the per-site HAProxy and PHP-FPM serving configuration,
``sites/names.py`` owns the identifier grammar, and ``sites/bodies/common.py`` owns the
shared layout and deploy-lock constants.
"""

from typing import Final

from sites import configuration, names, serving
from sites.bodies.common import DEPLOY_LOCK, SITE_LAYOUT

IDENTIFIER_PLACEHOLDER: Final = "zzzsite"
NAME_PLACEHOLDER: Final = "site.test"


def _templated(value: str) -> str:
    """``value`` with the publisher's placeholders, so the manifest names the shape."""
    return value.replace(IDENTIFIER_PLACEHOLDER, "<identifier>").replace(NAME_PLACEHOLDER, "<name>")


def _settings(runtime: str) -> configuration.SiteSettings:
    return configuration.SiteSettings(
        identifier=IDENTIFIER_PLACEHOLDER,
        names=(NAME_PLACEHOLDER,),
        runtime=runtime,
    )


def _layout(settings: configuration.SiteSettings) -> list[dict[str, str]]:
    values = {"directory": settings.directory, "account": settings.account}
    return [
        {
            "path": _templated(path.format(**values)),
            "owner": _templated(owner.format(**values)),
            "group": _templated(group.format(**values)),
            "mode": mode,
        }
        for path, owner, group, mode in (*SITE_LAYOUT, DEPLOY_LOCK)
    ]


def _haproxy(settings: configuration.SiteSettings) -> dict[str, object]:
    units = serving.service_units()
    unit_file = next(path for path in units if path.endswith("haproxy-site@.service"))
    return {
        "service": "haproxy-site@<identifier>.service",
        "unit_file": unit_file,
        "unit_mode": "0644",
        "unit": units[unit_file],
        "config": "/etc/haproxy/sites/<identifier>.cfg",
        "config_mode": "0600",
        "config_template": _templated(serving.haproxy_config(settings)),
        "state": "/var/lib/haproxy/sites/<identifier>.state",
        "state_mode": "0600",
        "http_socket": _templated(settings.proxy_socket),
        "http_socket_owner": "caddy",
        "http_socket_group": "caddy",
        "http_socket_mode": "0600",
        "admin_socket": "/run/haproxy/<identifier>/admin.sock",
        "admin_socket_owner": "root",
        "admin_socket_group": "root",
        "admin_socket_mode": "0600",
    }


def _php_runtime(runtime: str) -> dict[str, object]:
    settings = _settings(runtime)
    units = serving.service_units()
    unit_prefix = f"php-fpm-site-{runtime}@"
    unit_file = next(path for path in units if unit_prefix in path)
    socket_root = f"/run/php-fpm/sites/{IDENTIFIER_PLACEHOLDER}/{runtime}"
    return {
        "service": f"php-fpm-site-{runtime}@<identifier>.service",
        "unit_file": unit_file,
        "unit_mode": "0644",
        "unit": units[unit_file],
        "config_directory": _templated(serving.php_directory(IDENTIFIER_PLACEHOLDER, runtime)),
        "app_socket": _templated(settings.socket),
        "app_socket_mode": "0660",
        "status_socket": _templated(socket_root + "/status/listen.sock"),
        "status_socket_mode": "0600",
        "diagnostic_socket": _templated(socket_root + "/diagnostic/listen.sock"),
        "diagnostic_socket_mode": "0600",
        "master_config": _templated(serving.master_config(settings)),
        "diagnostic_pool": _templated(serving.diagnostic_pool(settings)),
    }


def _php_fpm() -> dict[str, object]:
    return {
        "runtimes": list(configuration.PHP_RUNTIMES),
        "config_files": [
            "php.ini",
            "php-fpm.conf",
            "pools/<identifier>.conf",
            "pools/diagnostic.conf",
        ],
        "service": "php-fpm-site-<runtime>@<identifier>.service",
        "per_runtime": {runtime: _php_runtime(runtime) for runtime in configuration.PHP_RUNTIMES},
    }


def build() -> dict[str, object]:
    """The site convention as one JSON-serializable mapping."""
    settings = _settings(configuration.PHP_RUNTIMES[0])
    site = _templated(settings.directory)
    return {
        "identifier": {
            "pattern": names.IDENTIFIER.pattern,
            "reserved": sorted(names.RESERVED_IDENTIFIERS),
            "system_accounts": sorted(names.SYSTEM_ACCOUNTS),
            "max_names": names.MAX_NAMES,
            "max_name_octets": names.MAX_NAME_OCTETS,
            "label_pattern": names.LABEL.pattern,
            "reserved_names": sorted(names.RESERVED_NAMES),
            "readiness_pattern": names.READINESS_PATH.pattern,
            "readiness_max_chars": names.MAX_READINESS_PATH,
        },
        "accounts": {
            "site": {
                "name": _templated(settings.account),
                "home": site,
                "shell": "/usr/sbin/nologin",
                "supplementary_groups": [],
            },
            "proxy": {
                "name": _templated(settings.proxy),
                "home": "/nonexistent",
                "shell": "/usr/sbin/nologin",
            },
            "web": {"name": "caddy"},
        },
        "layout": _layout(settings),
        "release": {
            "directory": site + "/releases",
            "initial": "releases/initial",
            "current": site + "/current",
            "current_owner": "root",
            "target_pattern": "releases/[A-Za-z0-9][A-Za-z0-9._-]{0,63}",
            "public": site + "/releases/<release>/public",
        },
        "caddy": {
            "site_file": "/etc/caddy/sites/<identifier>.caddy",
            "site_file_owner": "root",
            "site_file_group": "root",
            "site_file_mode": "0644",
            "route": _templated(configuration.render_caddy(settings)),
        },
        "haproxy": _haproxy(settings),
        "php_fpm": _php_fpm(),
    }
