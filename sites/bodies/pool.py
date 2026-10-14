import re
from types import SimpleNamespace

from sites.bodies.pool_boundary import ini_pool

SITE_POOL_TEMPLATE = ""


def pool_settings(identifier: str, runtime: str) -> SimpleNamespace:
    return SimpleNamespace(
        identifier=identifier,
        account="s" + identifier,
        directory="/var/www/" + identifier,
        socket=f"/run/php-fpm/{runtime}/{identifier}.sock",
    )


def bounded_integer(value: str, minimum: int, maximum: int) -> bool:
    return value.isdecimal() and minimum <= int(value) <= maximum


def supported_pool(identifier: str, runtime: str, text: str) -> bool:
    if re.fullmatch(r"[a-z][a-z0-9]{2,23}", identifier) is None or runtime not in (
        "php84",
        "php85",
    ):
        return False
    actual = ini_pool(text, identifier)
    expected = ini_pool(
        SITE_POOL_TEMPLATE.format(settings=pool_settings(identifier, runtime)), identifier
    )
    if actual is None or expected is None:
        return False
    mutable = {
        "pm",
        "pm.max_children",
        "pm.process_idle_timeout",
        "request_slowlog_timeout",
        "pm.start_servers",
        "pm.min_spare_servers",
        "pm.max_spare_servers",
        "request_terminate_timeout",
        "php_admin_value[memory_limit]",
        "php_admin_value[upload_max_filesize]",
        "php_admin_value[post_max_size]",
    }
    if any(key not in expected and key not in mutable for key in actual):
        return False
    if any(actual.get(key) != value for key, value in expected.items() if key not in mutable):
        return False
    if actual.get("pm") not in ("ondemand", "static", "dynamic") or not bounded_integer(
        actual.get("pm.max_children", ""), 1, 64
    ):
        return False
    return bounded_pool_settings(actual)


def bounded_pool_settings(actual: dict[str, str]) -> bool:
    children = int(actual["pm.max_children"])
    if actual["pm"] == "dynamic":
        if not all(
            bounded_integer(actual.get(key, ""), 1, children)
            for key in ("pm.start_servers", "pm.min_spare_servers", "pm.max_spare_servers")
        ):
            return False
        if (
            not int(actual["pm.min_spare_servers"])
            <= int(actual["pm.start_servers"])
            <= int(actual["pm.max_spare_servers"])
        ):
            return False
    for key in ("pm.process_idle_timeout", "request_slowlog_timeout", "request_terminate_timeout"):
        value = actual.get(key)
        if value is not None and (
            not value.endswith("s") or not bounded_integer(value[:-1], 1, 300)
        ):
            return False
    for key, minimum, maximum in (
        ("php_admin_value[memory_limit]", 16, 1024),
        ("php_admin_value[upload_max_filesize]", 1, 256),
        ("php_admin_value[post_max_size]", 1, 256),
    ):
        value = actual.get(key)
        if value is not None and (
            not value.endswith("M") or not bounded_integer(value[:-1], minimum, maximum)
        ):
            return False
    return True
