"""The WordPress application convention (docs/wordpress.md, ADR 0017 and ADR 0018).

The pinned core archive, its private configuration and the fixed public loader are one
definition shared by the controller's review and the native body that installs the site.
Nothing here runs PHP or reads a secret from the controller.
"""

import re
import secrets
from typing import Final

CORE_VERSION: Final = "7.1.3"
CORE_ARCHIVE_URL: Final = (
    "https://downloads.wordpress.org/release/wordpress-" + CORE_VERSION + ".zip"
)
# The mirrored upstream archive's exact size and SHA-256 (docs/quality.md#native-layer).
CORE_ARCHIVE_SIZE: Final = 37226383
CORE_ARCHIVE_SHA256: Final = "eb58a90ed55147f90f7bd55d0d3334960a69b7e8a4cc142c8ddfea8965218227"
CORE_MARKERS: Final = (
    "index.php",
    "wp-load.php",
    "wp-settings.php",
    "wp-admin",
    "wp-includes",
    "wp-includes/version.php",
    "wp-content",
)
TABLE_PREFIX: Final = "wp_"
SALTS: Final = (
    "AUTH_KEY",
    "SECURE_AUTH_KEY",
    "LOGGED_IN_KEY",
    "NONCE_KEY",
    "AUTH_SALT",
    "SECURE_AUTH_SALT",
    "LOGGED_IN_SALT",
    "NONCE_SALT",
)
# The constants Barectl owns in the private configuration. An operator's extra constants
# use the same grammar but never these names: the salts and database settings are written
# by Barectl, ``DISABLE_WP_CRON`` and every ``WP_REDIS_*`` name belong to Phase C (#357).
RESERVED_CONSTANTS: Final = frozenset(
    {
        "ABSPATH",
        "DB_NAME",
        "DB_USER",
        "DB_PASSWORD",
        "DB_HOST",
        "DB_CHARSET",
        "DB_COLLATE",
        "DISABLE_WP_CRON",
        *SALTS,
    }
)
# Phase C (#357) owns these names in the same private file. Their values follow a fixed
# grammar so recovery reads them without interpreting arbitrary PHP: WordPress cron hands
# over to the server, and the object cache names #392 writes point at one private socket.
OWNED_CONSTANTS: Final = frozenset(
    {"DISABLE_WP_CRON", "WP_REDIS_PATH", "WP_REDIS_PREFIX", "WP_REDIS_SCHEME"}
)
OWNED_VALUE: Final[dict[str, re.Pattern[str]]] = {
    "DISABLE_WP_CRON": re.compile(r"(?:true|false)\Z"),
    "WP_REDIS_SCHEME": re.compile(r"unix\Z"),
    "WP_REDIS_PATH": re.compile(r"/run/[A-Za-z0-9_./-]{1,180}\Z"),
    "WP_REDIS_PREFIX": re.compile(r"[A-Za-z0-9_:-]{1,64}\Z"),
}
CONSTANT_KEY: Final = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
CONSTANT_LINE: Final = re.compile(r"define\( '([A-Z][A-Z0-9_]{0,63})', '(.*)' \);\Z")
MAX_CONSTANT_VALUE: Final = 2048
SALT_VALUE: Final = re.compile(r"[\x21-\x26\x28-\x5b\x5d-\x7e]{32,128}\Z")
VERSION: Final = re.compile(r"^\$wp_version = '([0-9A-Za-z.-]{1,40})';$", re.MULTILINE)
IDENTIFIER: Final = re.compile(r"[a-z][a-z0-9]{2,23}\Z")
# A WordPress user login, as the create form, the reset input and the native body accept it.
ADMIN_USERNAME: Final = re.compile(r"[A-Za-z0-9_.@-]{1,60}")
# The site's public tree after the pinned archive is installed: the archive's own
# ``wordpress/`` root is removed, so these paths are relative to ``current/public``.
PUBLIC_ROOT: Final = "/var/www/{identifier}/current/public"
PRIVATE_CONFIGURATION: Final = "/var/www/{identifier}/private/wp-config.php"
ARCHIVE_NAME: Final = "wordpress-{version}.zip"


def public_root(identifier: str) -> str:
    _checked(identifier)
    return PUBLIC_ROOT.format(identifier=identifier)


def private_configuration_path(identifier: str) -> str:
    _checked(identifier)
    return PRIVATE_CONFIGURATION.format(identifier=identifier)


def render_loader(identifier: str) -> str:
    """The fixed public ``wp-config.php``; the private configuration stays outside public."""
    return (
        "<?php\n"
        f"require '{private_configuration_path(identifier)}';\n"
        "require_once ABSPATH . 'wp-settings.php';\n"
    )


def loader_problem(text: str, identifier: str) -> str:
    if text == render_loader(identifier):
        return ""
    return "The WordPress loader is not the supported one."


def new_salts() -> tuple[str, ...]:
    """Eight independent salts generated on the managed server, never in the controller."""
    return tuple(secrets.token_urlsafe(48) for _ in SALTS)


def reserved_constant(key: str) -> bool:
    return key in RESERVED_CONSTANTS or key.startswith("WP_REDIS_")


def owned_constant(key: str) -> bool:
    """A name Phase C writes itself, and the operator's settings never edit."""
    return key in OWNED_CONSTANTS


def owned_value_problem(key: str, value: str) -> str:
    rule = OWNED_VALUE.get(key)
    if rule is None:
        return f"{key} is not a name Barectl writes."
    if rule.fullmatch(value) is None:
        return f"{key} has a value Barectl does not write."
    return ""


def valid_constant_key(key: str) -> bool:
    return CONSTANT_KEY.fullmatch(key) is not None and not reserved_constant(key)


def render_owned_constant(key: str, value: str) -> str:
    if not owned_constant(key) or owned_value_problem(key, value):
        raise ValueError("A Barectl-owned WordPress constant is not supported.")
    return f"define( '{key}', '{value}' );"


def cron_disabled(text: str, identifier: str) -> str:
    """The DISABLE_WP_CRON value in a supported private configuration, or empty."""
    if private_configuration_problem(text, identifier):
        return ""
    for line in text.splitlines():
        parsed = parse_constant(line)
        if parsed is not None and parsed[0] == "DISABLE_WP_CRON":
            return parsed[1]
    return ""


def apply_owned_constant(text: str, key: str, value: str, identifier: str) -> str:
    """Set ``key`` to ``value``, or remove it when ``value`` is empty, touching no other line."""
    if not owned_constant(key) or (value and owned_value_problem(key, value)):
        raise ValueError("A Barectl-owned WordPress constant is not supported.")
    lines = text.splitlines(keepends=True)
    fixed = _fixed_configuration_lines(identifier)
    if len(lines) < len(fixed) or _fixed_problem(lines, fixed):
        raise ValueError("The private WordPress configuration is outside the supported grammar.")
    output: list[str] = list(lines[: len(fixed)])
    written = False
    for line in lines[len(fixed) :]:
        parsed = parse_constant(line.rstrip("\r\n"))
        if parsed is not None and parsed[0] == key:
            if written:
                raise ValueError(
                    "The private WordPress configuration is outside the supported grammar."
                )
            written = True
            if not value:
                continue
            ending = line[len(line.rstrip("\r\n")) :] or "\n"
            output.append(render_owned_constant(key, value) + ending)
            continue
        if (
            parsed is not None
            and owned_constant(parsed[0])
            and (owned_value_problem(parsed[0], parsed[1]))
        ):
            raise ValueError(
                "The private WordPress configuration is outside the supported grammar."
            )
        output.append(line)
    if value and not written:
        if output and not output[-1].endswith(("\n", "\r")):
            output[-1] += "\n"
        output.append(render_owned_constant(key, value) + "\n")
    return "".join(output)


def constant_value(value: str) -> str:
    """One constant as a PHP single-quoted literal (only ``\\`` and ``'`` need escaping)."""
    if len(value) > MAX_CONSTANT_VALUE or any(character in "\x00\r\n" for character in value):
        raise ValueError("A WordPress constant is too long or contains a line break.")
    if not all(character.isprintable() or character == "\t" for character in value):
        raise ValueError("A WordPress constant contains an unsupported character.")
    return value.replace("\\", "\\\\").replace("'", "\\'")


def render_constant(key: str, value: str) -> str:
    if not valid_constant_key(key):
        raise ValueError("A WordPress constant is not supported.")
    return f"define( '{key}', '{constant_value(value)}' );"


def parse_constant(line: str) -> tuple[str, str] | None:
    match = CONSTANT_LINE.fullmatch(line)
    if match is None:
        return None
    escaped, value, index = match.group(2), [], 0
    while index < len(escaped):
        character = escaped[index]
        if character == "\\" and index + 1 < len(escaped):
            following = escaped[index + 1]
            value.append(following if following in ("\\", "'") else "\\" + following)
            index += 2
            continue
        value.append(character)
        index += 1
    return match.group(1), "".join(value)


def extra_constants(text: str, identifier: str) -> list[tuple[str, str]]:
    """The operator's constants after the fixed Barectl block, in file order."""
    lines = text.splitlines()
    fixed = _fixed_configuration_lines(identifier)
    if len(lines) < len(fixed) or _fixed_problem(lines, fixed):
        return []
    constants: list[tuple[str, str]] = []
    for line in lines[len(fixed) :]:
        parsed = parse_constant(line)
        if parsed is None:
            return []
        if owned_constant(parsed[0]):
            if owned_value_problem(parsed[0], parsed[1]):
                return []
            continue
        if not valid_constant_key(parsed[0]):
            return []
        constants.append(parsed)
    return constants


def constant_details(text: str, identifier: str) -> list[dict[str, str]]:
    """Each extra constant's key and server-computed value digest; never the value."""
    import hashlib

    keys: set[str] = set()
    rows: list[dict[str, str]] = []
    for key, value in extra_constants(text, identifier):
        if key in keys:
            return []
        keys.add(key)
        rows.append({"key": key, "digest": hashlib.sha256(value.encode("utf-8")).hexdigest()})
    return rows


def _constant_edits(changes: list[dict[str, object]]) -> dict[str, tuple[str, str]]:
    edits: dict[str, tuple[str, str]] = {}
    for change in changes:
        key = str(change.get("key", ""))
        action = str(change.get("action", ""))
        if not valid_constant_key(key) or action not in ("set", "remove"):
            raise ValueError("A WordPress constant change is not supported.")
        edits[key] = (action, str(change.get("value", "")))
    return edits


def apply_constants(  # noqa: C901 - one pass over every line
    text: str, changes: list[dict[str, object]], identifier: str
) -> str:
    """Apply extra-constant edits, leaving every untouched line byte-identical."""
    edits = _constant_edits(changes)
    lines = text.splitlines(keepends=True)
    fixed = _fixed_configuration_lines(identifier)
    if len(lines) < len(fixed) or _fixed_problem(lines, fixed):
        raise ValueError("The private WordPress configuration is outside the supported grammar.")
    head, tail = lines[: len(fixed)], lines[len(fixed) :]
    written: set[str] = set()
    output: list[str] = list(head)
    for line in tail:
        parsed = parse_constant(line.rstrip("\r\n"))
        if parsed is not None and parsed[0] in edits:
            action, value = edits[parsed[0]]
            written.add(parsed[0])
            if action == "remove":
                continue
            ending = line[len(line.rstrip("\r\n")) :] or "\n"
            output.append(render_constant(parsed[0], value) + ending)
            continue
        if parsed is None:
            raise ValueError(
                "The private WordPress configuration is outside the supported grammar."
            )
        if owned_constant(parsed[0]):
            if owned_value_problem(parsed[0], parsed[1]):
                raise ValueError(
                    "The private WordPress configuration is outside the supported grammar."
                )
            output.append(line)
            continue
        if not valid_constant_key(parsed[0]):
            raise ValueError(
                "The private WordPress configuration is outside the supported grammar."
            )
        output.append(line)
    for key, (action, value) in edits.items():
        if action != "set" or key in written:
            continue
        if output and not output[-1].endswith(("\n", "\r")):
            output[-1] += "\n"
        output.append(render_constant(key, value) + "\n")
    return "".join(output)


def render_private_configuration(
    identifier: str, salts: tuple[str, ...], constants: tuple[tuple[str, str], ...] = ()
) -> str:
    _checked(identifier)
    if len(salts) != len(SALTS) or not all(SALT_VALUE.fullmatch(salt) for salt in salts):
        raise ValueError("Not eight valid WordPress salts.")
    name = f"s{identifier}"
    lines = [
        "<?php",
        "if ( isset( $_SERVER['HTTP_X_FORWARDED_URI'] ) ) {",
        "\t$_SERVER['REQUEST_URI'] = $_SERVER['HTTP_X_FORWARDED_URI'];",
        "}",
        "if ( ! defined( 'ABSPATH' ) ) {",
        f"\tdefine( 'ABSPATH', '{public_root(identifier)}/' );",
        "}",
        f"define( 'DB_NAME', '{name}' );",
        f"define( 'DB_USER', '{name}' );",
        "define( 'DB_PASSWORD', '' );",
        f"define( 'DB_HOST', 'localhost:{MARIADB_SOCKET}' );",
        "define( 'DB_CHARSET', 'utf8mb4' );",
        "define( 'DB_COLLATE', '' );",
        *(f"define( '{key}', '{salt}' );" for key, salt in zip(SALTS, salts, strict=True)),
        f"$table_prefix = '{TABLE_PREFIX}';",
        *(render_constant(key, value) for key, value in constants),
    ]
    return "\n".join(lines) + "\n"


MARIADB_SOCKET: Final = "/run/mysqld/mysqld.sock"


def _fixed_configuration_lines(identifier: str) -> list[str]:
    return render_private_configuration(identifier, ("x" * 64,) * len(SALTS)).splitlines()


def _fixed_problem(lines: list[str], expected: list[str]) -> str:
    salt_start = expected.index(f"define( '{SALTS[0]}', '{'x' * 64}' );")
    salt_end = salt_start + len(SALTS)
    for number, (raw_line, pattern) in enumerate(zip(lines, expected, strict=False), 1):
        line = raw_line.rstrip("\r\n")
        if salt_start <= number - 1 < salt_end:
            key = SALTS[number - 1 - salt_start]
            prefix = f"define( '{key}', '"
            if not (line.startswith(prefix) and line.endswith("' );")):
                return f"The private WordPress configuration line {number} is not supported."
            if not SALT_VALUE.fullmatch(line[len(prefix) : -len("' );")]):
                return f"The private WordPress configuration line {number} is not supported."
            continue
        if line != pattern:
            return f"The private WordPress configuration line {number} is not supported."
    return ""


def private_configuration_problem(text: str, identifier: str) -> str:
    """Whether the private configuration follows the supported grammar, or why not."""
    expected = _fixed_configuration_lines(identifier)
    lines = text.splitlines()
    if len(lines) < len(expected):
        return "The private WordPress configuration has an unsupported shape."
    if problem := _fixed_problem(lines, expected):
        return problem
    seen: set[str] = set()
    for number, line in enumerate(lines[len(expected) :], len(expected) + 1):
        parsed = parse_constant(line)
        if parsed is None:
            return f"The private WordPress configuration line {number} is not supported."
        if owned_constant(parsed[0]):
            if owned_value_problem(parsed[0], parsed[1]):
                return f"The private WordPress configuration line {number} is not supported."
        elif not valid_constant_key(parsed[0]):
            return f"The private WordPress configuration line {number} is not supported."
        if parsed[0] in seen:
            return f"The private WordPress configuration line {number} is not supported."
        seen.add(parsed[0])
    return ""


def version_of(text: str) -> str:
    """The core version from ``wp-includes/version.php``, without executing PHP."""
    found = VERSION.findall(text)
    return found[0] if len(found) == 1 else ""


def _checked(identifier: str) -> str:
    if IDENTIFIER.fullmatch(identifier) is None:
        raise ValueError("Not a valid site identifier.")
    return identifier
