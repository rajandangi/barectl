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


def render_private_configuration(identifier: str, salts: tuple[str, ...]) -> str:
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
    ]
    return "\n".join(lines) + "\n"


MARIADB_SOCKET: Final = "/run/mysqld/mysqld.sock"


def private_configuration_problem(text: str, identifier: str) -> str:
    """Whether the private configuration follows the supported grammar, or why not."""
    expected = render_private_configuration(identifier, ("x" * 64,) * len(SALTS))
    expected_lines = expected.splitlines()
    lines = text.splitlines()
    if len(lines) != len(expected_lines):
        return "The private WordPress configuration has an unsupported shape."
    salt_start = expected_lines.index(f"define( '{SALTS[0]}', '{'x' * 64}' );")
    salt_end = salt_start + len(SALTS)
    for number, (line, pattern) in enumerate(zip(lines, expected_lines, strict=True), 1):
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


def version_of(text: str) -> str:
    """The core version from ``wp-includes/version.php``, without executing PHP."""
    found = VERSION.findall(text)
    return found[0] if len(found) == 1 else ""


def _checked(identifier: str) -> str:
    if IDENTIFIER.fullmatch(identifier) is None:
        raise ValueError("Not a valid site identifier.")
    return identifier
