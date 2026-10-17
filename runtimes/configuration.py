"""Native FPM master convention, based on the pinned NixOS module and ADR 0029."""

import importlib.resources
from dataclasses import dataclass

ENTRIES = ("php84", "php85", "nodejs_22", "nodejs_24")
PROBE_DIRECTORY = "/etc/php-fpm/diagnostics/"
DIAGNOSTIC_USER = "php-probe"
MANDATORY = {
    "opcache.enable": "1",
    "opcache.validate_permission": "1",
    "opcache.validate_root": "1",
    "opcache.restrict_api": PROBE_DIRECTORY,
    "opcache.file_cache": "",
    "opcache.preload": "",
    "expose_php": "0",
}
UNIT = importlib.resources.files("runtimes.bodies").joinpath("php-fpm@.service").read_text()
PROBE = importlib.resources.files("runtimes.bodies").joinpath("probe.php").read_text()


@dataclass(frozen=True)
class MasterFiles:
    ini: str
    master: str
    pool: str
    unit: str = UNIT
    probe: str = PROBE


def validate(ini: str) -> None:
    values: dict[str, str] = {}
    for line in ini.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in values:
            raise ValueError(
                "The master configuration must contain every mandatory protection once."
            )
        values[key] = value
    if any(values.get(key) != value for key, value in MANDATORY.items()):
        raise ValueError("The master configuration is missing a mandatory protection.")


def render(entry: str) -> MasterFiles:
    if entry not in ("php84", "php85"):
        raise ValueError("This catalog entry is not a PHP runtime.")
    ini = "".join(f"{key}={value}\n" for key, value in MANDATORY.items())
    validate(ini)
    return MasterFiles(
        ini,
        (
            "[global]\ndaemonize = no\nerror_log = syslog\n"
            f"include = /etc/php-fpm/{entry}/pools/*.conf\n"
        ),
        f"""[diagnostic]
user = {DIAGNOSTIC_USER}
group = {DIAGNOSTIC_USER}
listen = /run/php-fpm/{entry}/diagnostic.sock
listen.owner = root
listen.group = root
listen.mode = 0600
pm = static
pm.max_children = 1
clear_env = yes
security.limit_extensions = .php
php_admin_value[session.save_path] = /var/lib/php-fpm/{entry}/diagnostic/session
php_admin_value[upload_tmp_dir] = /var/lib/php-fpm/{entry}/diagnostic/upload
php_admin_value[sys_temp_dir] = /var/lib/php-fpm/{entry}/diagnostic/tmp
""",
    )
