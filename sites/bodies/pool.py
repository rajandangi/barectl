import contextlib
import importlib.resources
import re
from dataclasses import dataclass
from types import SimpleNamespace

from sites.bodies.pool_boundary import ini_pool

SITE_POOL_TEMPLATE = ""
with contextlib.suppress(ImportError, OSError):
    SITE_POOL_TEMPLATE = importlib.resources.files("sites.bodies").joinpath("pool.conf").read_text()
PROCESS_MANAGERS = ("ondemand", "static", "dynamic")


def pool_settings(identifier: str, runtime: str) -> SimpleNamespace:
    return SimpleNamespace(
        identifier=identifier,
        account="s" + identifier,
        directory="/var/www/" + identifier,
        socket=f"/run/php-fpm/sites/{identifier}/{runtime}/app.sock",
        proxy="p" + identifier,
        runtime=runtime,
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


@dataclass(frozen=True)
class SitePool:
    """A site pool's supported operator-tunable settings (docs/site-conventions.md)."""

    process_manager: str = "static"
    max_children: int = 2
    start_servers: int | None = None
    min_spare_servers: int | None = None
    max_spare_servers: int | None = None
    process_idle_timeout: int | None = None
    slowlog_timeout: int | None = 5
    terminate_timeout: int | None = 300
    memory_limit: int | None = None
    upload_max_filesize: int | None = None
    post_max_size: int | None = None

    @classmethod
    def from_document(cls, value: object) -> SitePool | None:
        if not isinstance(value, dict) or set(value) != {
            "process_manager",
            "max_children",
            "start_servers",
            "min_spare_servers",
            "max_spare_servers",
            "process_idle_timeout",
            "slowlog_timeout",
            "terminate_timeout",
            "memory_limit",
            "upload_max_filesize",
            "post_max_size",
        }:
            return None
        process_manager = value["process_manager"]
        numbers = {
            key: value[key]
            for key in (
                "start_servers",
                "min_spare_servers",
                "max_spare_servers",
                "process_idle_timeout",
                "slowlog_timeout",
                "terminate_timeout",
                "memory_limit",
                "upload_max_filesize",
                "post_max_size",
            )
        }
        if (
            not isinstance(process_manager, str)
            or type(value["max_children"]) is not int
            or any(item is not None and type(item) is not int for item in numbers.values())
        ):
            return None
        pool = cls(process_manager=process_manager, max_children=value["max_children"], **numbers)
        return pool if pool.valid() else None

    def document(self) -> dict[str, object]:
        return {
            "process_manager": self.process_manager,
            "max_children": self.max_children,
            "start_servers": self.start_servers,
            "min_spare_servers": self.min_spare_servers,
            "max_spare_servers": self.max_spare_servers,
            "process_idle_timeout": self.process_idle_timeout,
            "slowlog_timeout": self.slowlog_timeout,
            "terminate_timeout": self.terminate_timeout,
            "memory_limit": self.memory_limit,
            "upload_max_filesize": self.upload_max_filesize,
            "post_max_size": self.post_max_size,
        }

    def valid(self) -> bool:
        if self.process_manager not in PROCESS_MANAGERS or not 1 <= self.max_children <= 64:
            return False
        if self.process_manager == "dynamic":
            start, minimum, maximum = (
                self.start_servers,
                self.min_spare_servers,
                self.max_spare_servers,
            )
            if start is None or minimum is None or maximum is None:
                return False
            if not all(1 <= item <= self.max_children for item in (start, minimum, maximum)):
                return False
            if not minimum <= start <= maximum:
                return False
        for seconds in (
            self.process_idle_timeout,
            self.slowlog_timeout,
            self.terminate_timeout,
        ):
            if seconds is not None and not 1 <= seconds <= 300:
                return False
        for megabytes, minimum, maximum in (
            (self.memory_limit, 16, 1024),
            (self.upload_max_filesize, 1, 256),
            (self.post_max_size, 1, 256),
        ):
            if megabytes is not None and not minimum <= megabytes <= maximum:
                return False
        return True

    def valid_change(self) -> bool:
        """Whether a reviewed selection only sets keys its process manager uses."""
        if not self.valid():
            return False
        if self.process_manager != "dynamic" and any(
            value is not None
            for value in (self.start_servers, self.min_spare_servers, self.max_spare_servers)
        ):
            return False
        return not (self.process_manager != "ondemand" and self.process_idle_timeout is not None)

    def rendered(self) -> dict[str, str | None]:
        """The pool keys this selection writes, with ``None`` for a removed setting."""
        values: dict[str, str | None] = {
            "pm": self.process_manager,
            "pm.max_children": str(self.max_children),
            "pm.start_servers": _shown(self.start_servers),
            "pm.min_spare_servers": _shown(self.min_spare_servers),
            "pm.max_spare_servers": _shown(self.max_spare_servers),
            "pm.process_idle_timeout": _seconds(self.process_idle_timeout),
            "request_slowlog_timeout": _seconds(self.slowlog_timeout),
            "request_terminate_timeout": _seconds(self.terminate_timeout),
            "php_admin_value[memory_limit]": _megabytes(self.memory_limit),
            "php_admin_value[upload_max_filesize]": _megabytes(self.upload_max_filesize),
            "php_admin_value[post_max_size]": _megabytes(self.post_max_size),
        }
        if self.process_manager != "dynamic":
            for key in ("pm.start_servers", "pm.min_spare_servers", "pm.max_spare_servers"):
                values[key] = None
        if self.process_manager != "ondemand":
            values["pm.process_idle_timeout"] = None
        return values


def _shown(value: int | None) -> str | None:
    return None if value is None else str(value)


def valid_pool_document(value: object) -> bool:
    return SitePool.from_document(value) is not None


def _seconds(value: int | None) -> str | None:
    return None if value is None else f"{value}s"


def _megabytes(value: int | None) -> str | None:
    return None if value is None else f"{value}M"


def _unshown(value: str | None, minimum: int, maximum: int) -> int | None:
    if value is None or not value.isdecimal() or not minimum <= int(value) <= maximum:
        return None
    return int(value)


def _unit_value(value: str | None, suffix: str, minimum: int, maximum: int) -> int | None:
    if value is None or not value.endswith(suffix):
        return None
    return _unshown(value[: -len(suffix)], minimum, maximum)


def parse_pool(identifier: str, runtime: str, text: str) -> SitePool | None:
    """The supported pool values of one site's own configuration, or ``None``."""
    if not supported_pool(identifier, runtime, text):
        return None
    actual = ini_pool(text, identifier)
    if actual is None:
        return None
    seconds = {
        key: _unit_value(actual.get(key), "s", 1, 300)
        for key in (
            "pm.process_idle_timeout",
            "request_slowlog_timeout",
            "request_terminate_timeout",
        )
    }
    megabytes = {
        key: _unit_value(
            actual.get(key),
            "M",
            minimum,
            1024 if key.endswith("[memory_limit]") else 256,
        )
        for key, minimum in (
            ("php_admin_value[memory_limit]", 16),
            ("php_admin_value[upload_max_filesize]", 1),
            ("php_admin_value[post_max_size]", 1),
        )
    }
    pool = SitePool(
        process_manager=str(actual["pm"]),
        max_children=int(actual["pm.max_children"]),
        start_servers=_unshown(actual.get("pm.start_servers"), 1, 64),
        min_spare_servers=_unshown(actual.get("pm.min_spare_servers"), 1, 64),
        max_spare_servers=_unshown(actual.get("pm.max_spare_servers"), 1, 64),
        process_idle_timeout=seconds["pm.process_idle_timeout"],
        slowlog_timeout=seconds["request_slowlog_timeout"],
        terminate_timeout=seconds["request_terminate_timeout"],
        memory_limit=megabytes["php_admin_value[memory_limit]"],
        upload_max_filesize=megabytes["php_admin_value[upload_max_filesize]"],
        post_max_size=megabytes["php_admin_value[post_max_size]"],
    )
    return pool if pool.valid() else None


def render_pool_settings(text: str, pool: SitePool) -> str:
    """Rewrite only the mutable pool keys of an accepted pool file."""
    values = pool.rendered()
    mutable = set(values)
    output: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        key = stripped.split("=", 1)[0].strip() if "=" in stripped else ""
        if key in mutable:
            seen.add(key)
            if values[key] is not None:
                output.append(f"{key} = {values[key]}\n")
            continue
        output.append(line)
    if output and not output[-1].endswith("\n"):
        output[-1] += "\n"
    output.extend(
        f"{key} = {value}\n"
        for key, value in values.items()
        if key not in seen and value is not None
    )
    return "".join(output)
