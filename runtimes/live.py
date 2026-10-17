"""Pure validation of a native diagnostic response and its master identity."""

import json
import re

from .configuration import MANDATORY


def _text(row: dict[str, object], key: str) -> str:
    value = row.get(key)
    return value if isinstance(value, str) and len(value) <= 32768 else ""


def live_values(
    row: dict[str, object], version: str
) -> tuple[dict[str, object], dict[str, object], list[str]] | None:
    response = _text(row, "response")
    header, separator, body = response.replace("\r\n", "\n").partition("\n\n")
    if not separator or any(
        line.lower().startswith("status:") and line.strip() != "Status: 200 OK"
        for line in header.splitlines()
    ):
        return None
    try:
        data: object = json.loads(body)
    except ValueError:
        return None
    if (
        not isinstance(data, dict)
        or set(data) != {"version", "sapi", "php", "parent", "uid", "extensions", "ini", "opcache"}
        or type(data["version"]) is not int
        or data["version"] != 1
        or type(data["parent"]) is not int
        or data["parent"] != row.get("master_pid")
        or data["sapi"] != "fpm-fcgi"
        or data["php"] != version
    ):
        return None
    identity = row.get("identity")
    if (
        not isinstance(identity, list)
        or len(identity) != 5
        or type(identity[0]) is not int
        or identity[0] <= 0
        or type(data.get("uid")) is not int
        or data["uid"] != identity[0]
    ):
        return None
    ini, opcache, raw_extensions = data["ini"], data["opcache"], data["extensions"]
    if (
        not isinstance(ini, dict)
        or not isinstance(opcache, dict)
        or not isinstance(raw_extensions, list)
        or len(raw_extensions) > 128
        or not all(
            isinstance(e, str) and re.fullmatch(r"[A-Za-z0-9_ -]{1,64}", e) for e in raw_extensions
        )
    ):
        return None
    return ini, opcache, raw_extensions


def protected(
    ini: dict[str, object], opcache: dict[str, object], extensions: tuple[str, ...]
) -> bool:
    if "Zend OPcache" not in extensions:
        return False
    for key, expected_value in MANDATORY.items():
        actual = ini.get(key)
        if key == "expose_php":
            if actual not in ("", "0"):
                return False
        elif actual != expected_value:
            return False
        if key != "expose_php":
            expected: object = True if expected_value == "1" else expected_value
            if opcache.get(key) != expected:
                return False
    return True


def master_identity(row: dict[str, object]) -> bool:
    expected = _text(row, "expected_executable")
    return (
        expected.startswith("/nix/store/")
        and expected.endswith("/bin/php-fpm")
        and _text(row, "master_executable") == expected
        and row.get("socket_owned") is True
        and row.get("load_safe") is True
        and row.get("same_invocation") is True
    )
