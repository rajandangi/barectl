"""The WordPress application convention.

docs/wordpress-native-design.md#native-wordpress-convention owns the contract.

Pure grammar and fixed reads, with no Django dependency, so passive discovery and the
workflows that publish the same files share one definition. Private configuration is only
ever parsed as data, on the managed server.
"""

import re
import shlex
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from discovery.models import CoreQualification

# docs/wordpress-native-design.md#compatibility-and-supply: the qualified core release.
CORE_VERSION: Final = "7.1.3"
IDENTIFIER: Final = re.compile(r"[a-z][a-z0-9]{2,23}")
WEB_ROOT: Final = "/var/www"
MARIADB_SOCKET: Final = "/run/mysqld/mysqld.sock"
DB_HOST: Final = f"localhost:{MARIADB_SOCKET}"
TABLE_PREFIX: Final = "wp_"
# Release files whose presence marks a WordPress tree; presence alone is a candidate.
MARKERS: Final = (
    "index.php",
    "wp-load.php",
    "wp-settings.php",
    "wp-admin",
    "wp-includes",
    "wp-includes/version.php",
    "wp-content",
)
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
# Visible ASCII but the quote and the backslash, which a single-quoted PHP literal reads
# differently.
SALT_VALUE: Final = r"[\x21-\x26\x28-\x5b\x5d-\x7e]{32,128}"


def _checked(identifier: str) -> str:
    if not IDENTIFIER.fullmatch(identifier):
        raise ValueError("Not a valid site identifier.")
    return identifier


def public_root(identifier: str) -> str:
    return f"{WEB_ROOT}/{_checked(identifier)}/public"


def private_configuration_path(identifier: str) -> str:
    return f"{WEB_ROOT}/{_checked(identifier)}/private/wp-config.php"


def render_loader(identifier: str) -> str:
    """The fixed public ``wp-config.php``, byte for byte."""
    return (
        "<?php\n"
        f"require '{private_configuration_path(identifier)}';\n"
        "require_once ABSPATH . 'wp-settings.php';\n"
    )


def render_private_configuration(identifier: str, salts: Sequence[str]) -> str:
    """The private configuration's supported grammar; the values are the convention's
    except the eight ``salts``, which are generated on the managed server."""
    if len(salts) != len(SALTS) or not all(re.fullmatch(SALT_VALUE, salt) for salt in salts):
        raise ValueError("Not eight valid salts.")
    name = f"s{_checked(identifier)}"
    return (
        "<?php\n"
        "if ( ! defined( 'ABSPATH' ) ) {\n"
        f"\tdefine( 'ABSPATH', '{public_root(identifier)}/' );\n"
        "}\n"
        f"define( 'DB_NAME', '{name}' );\n"
        f"define( 'DB_USER', '{name}' );\n"
        "define( 'DB_PASSWORD', '' );\n"
        f"define( 'DB_HOST', '{DB_HOST}' );\n"
        "define( 'DB_CHARSET', 'utf8mb4' );\n"
        "define( 'DB_COLLATE', '' );\n"
        + "".join(f"define( '{key}', '{salt}' );\n" for key, salt in zip(SALTS, salts, strict=True))
        + f"$table_prefix = '{TABLE_PREFIX}';\n"
    )


# The script runs on the managed server as the SSH user: it reads three files as data and
# prints only fixed tokens, the release's version literal and the configuration's digest.
# It never parses PHP, includes a file or starts another program.
_SCRIPT = r"""
import hashlib, os, re, stat, sys
ident = sys.argv[1]
if not re.fullmatch(r"[a-z][a-z0-9]{2,23}", ident):
    sys.exit(2)
base = "@BASE@/" + ident
limit = 8192
def read(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return "absent", b""
    except PermissionError:
        return "denied", b""
    except OSError:
        return "other", b""
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            return "other", b""
        return "read", os.read(fd, limit + 1)
    except OSError:
        return "denied", b""
    finally:
        os.close(fd)
loader = "require '" + base + "/private/wp-config.php';"
want = ("<?php", loader, "require_once ABSPATH . 'wp-settings.php';")
state, data = read(base + "/public/wp-config.php")
if state == "read":
    state = "exact" if data == ("\n".join(want) + "\n").encode() else "other"
print("loader", state)
q = re.escape
salt = r"[\x21-\x26\x28-\x5b\x5d-\x7e]{32,128}"
name = "s" + ident
grammar = [
    r"<\?php",
    r"if \( ! defined\( 'ABSPATH' \) \) \{",
    "\t" + q("define( 'ABSPATH', '" + base + "/public/' );"),
    r"\}",
    q("define( 'DB_NAME', '" + name + "' );"),
    q("define( 'DB_USER', '" + name + "' );"),
    q("define( 'DB_PASSWORD', '' );"),
    q("define( 'DB_HOST', 'localhost:@SOCKET@' );"),
    q("define( 'DB_CHARSET', 'utf8mb4' );"),
    q("define( 'DB_COLLATE', '' );"),
]
for key in "@SALTS@".split():
    grammar.append(q("define( '" + key + "', '") + salt + q("' );"))
grammar.append(q("$table_prefix = '@PREFIX@';"))
state, data = read(base + "/private/wp-config.php")
if state == "read":
    try:
        lines = data.decode("ascii").split("\n")
    except UnicodeDecodeError:
        lines = []
    if lines and lines[-1] == "":
        lines.pop()
    else:
        lines = []
    bad = 0
    if len(lines) != len(grammar):
        bad = min(len(lines), len(grammar)) + 1
    else:
        for number, (line, pattern) in enumerate(zip(lines, grammar), 1):
            if not re.fullmatch(pattern, line):
                bad = number
                break
    if bad:
        state = "unsupported"
        print("configuration", state, "line", bad)
    else:
        state = "supported"
        print("configuration", state)
        print("digest", hashlib.sha256(data).hexdigest())
else:
    print("configuration", state)
state, data = read(base + "/public/wp-includes/version.php")
version = "none"
if state == "read":
    found = re.findall(rb"^\$wp_version = '([0-9A-Za-z.-]{1,40})';$", data, re.M)
    version = found[0].decode() if len(found) == 1 else "unparseable"
elif state != "absent":
    version = state
print("version", version)
"""


def inspection_command(identifier: str, *, base: str = WEB_ROOT) -> str:
    """The one fixed read of a site's loader, private configuration and version literal."""
    script = (
        _SCRIPT.replace("@BASE@", base)
        .replace("@SOCKET@", MARIADB_SOCKET)
        .replace("@SALTS@", " ".join(SALTS))
        .replace("@PREFIX@", TABLE_PREFIX)
    )
    return f"python3 -I -c {shlex.quote(script)} {shlex.quote(_checked(identifier))}"


@dataclass(frozen=True)
class FileInspection:
    # absent, denied, other, exact, supported or unsupported, as the script reports.
    loader: str
    configuration: str
    configuration_digest: str
    # A release version, none (no file), unparseable, denied or other.
    version: str
    # The first line the configuration's grammar refused; 0 when none.
    line: int = 0


_VERSION = re.compile(r"[0-9A-Za-z.-]{1,40}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_LOADER_STATES = frozenset({"absent", "denied", "other", "exact"})
_CONFIGURATION_STATES = frozenset({"absent", "denied", "other", "supported", "unsupported"})


def parse_inspection(output: str) -> FileInspection | None:
    """The script's tokens, or ``None`` for any other output."""
    loader = configuration = digest = version = ""
    line = 0
    seen: list[str] = []
    for text in output.splitlines():
        words = text.split(" ")
        seen.append(words[0])
        match words:
            case ["loader", state] if state in _LOADER_STATES:
                loader = state
            case ["configuration", state] if state in _CONFIGURATION_STATES:
                configuration = state
            case ["configuration", "unsupported", "line", number] if number.isdigit():
                configuration, line = "unsupported", int(number)
            case ["digest", value] if _DIGEST.fullmatch(value):
                digest = value
            case ["version", value] if _VERSION.fullmatch(value):
                version = value
            case _:
                return None
    if (
        not (loader and configuration and version)
        or (configuration == "supported") != bool(digest)
        or len(seen) != len(set(seen))
    ):
        return None
    return FileInspection(loader, configuration, digest, version, line)


# Version comparison -----------------------------------------------------------------------

_RELEASE = re.compile(r"[0-9]+(?:\.[0-9]+){1,2}")


def qualification(version: str) -> CoreQualification:
    """Where an observed core version stands against the qualified release."""
    if not _RELEASE.fullmatch(version):
        return CoreQualification.UNRECOGNIZED
    observed = _numbers(version)
    qualified = _numbers(CORE_VERSION)
    if observed == qualified:
        return CoreQualification.QUALIFIED
    return CoreQualification.NEWER if observed > qualified else CoreQualification.OLDER


def _numbers(version: str) -> tuple[int, int, int]:
    parts = [int(part) for part in version.split(".")]
    return (parts[0], parts[1], parts[2] if len(parts) > 2 else 0)


# Catalog ---------------------------------------------------------------------------------

# The required core tables and, for each, the columns it must have. Extra columns and
# tables belong to plugins and are never read.
CORE_TABLES: Final[dict[str, tuple[str, ...]]] = {
    "commentmeta": ("meta_id", "comment_id", "meta_key", "meta_value"),
    "comments": (
        "comment_ID",
        "comment_post_ID",
        "comment_author",
        "comment_author_email",
        "comment_author_url",
        "comment_author_IP",
        "comment_date",
        "comment_date_gmt",
        "comment_content",
        "comment_karma",
        "comment_approved",
        "comment_agent",
        "comment_type",
        "comment_parent",
        "user_id",
    ),
    "links": (
        "link_id",
        "link_url",
        "link_name",
        "link_image",
        "link_target",
        "link_description",
        "link_visible",
        "link_owner",
        "link_rating",
        "link_updated",
        "link_rel",
        "link_notes",
        "link_rss",
    ),
    "options": ("option_id", "option_name", "option_value", "autoload"),
    "postmeta": ("meta_id", "post_id", "meta_key", "meta_value"),
    "posts": (
        "ID",
        "post_author",
        "post_date",
        "post_date_gmt",
        "post_content",
        "post_title",
        "post_excerpt",
        "post_status",
        "comment_status",
        "ping_status",
        "post_password",
        "post_name",
        "to_ping",
        "pinged",
        "post_modified",
        "post_modified_gmt",
        "post_content_filtered",
        "post_parent",
        "guid",
        "menu_order",
        "post_type",
        "post_mime_type",
        "comment_count",
    ),
    "term_relationships": ("object_id", "term_taxonomy_id", "term_order"),
    "term_taxonomy": ("term_taxonomy_id", "term_id", "taxonomy", "description", "parent", "count"),
    "termmeta": ("meta_id", "term_id", "meta_key", "meta_value"),
    "terms": ("term_id", "name", "slug", "term_group"),
    "usermeta": ("umeta_id", "user_id", "meta_key", "meta_value"),
    "users": (
        "ID",
        "user_login",
        "user_pass",
        "user_nicename",
        "user_email",
        "user_url",
        "user_registered",
        "user_activation_key",
        "user_status",
        "display_name",
    ),
}
MARIADB_CLIENT: Final = (
    f"mariadb --no-defaults --protocol=socket --socket={MARIADB_SOCKET} --user=root -N -B "
    "--init-command='SET SESSION TRANSACTION READ ONLY' -e"
)
SITE_OPTIONS: Final = ("siteurl", "home")
_DATABASE = re.compile(r"s[a-z][a-z0-9]{2,23}")


def _check_databases(databases: Sequence[str]) -> str:
    if not databases or not all(_DATABASE.fullmatch(name) for name in databases):
        raise ValueError("Not site database names.")
    return ",".join(f"'{name}'" for name in databases)


def schema_sql(databases: Sequence[str]) -> str:
    """Per site database: how many of each core table's required columns exist, how many
    core tables exist, and how many other table prefixes hold their own users and options
    tables. Table and column names only; no row of any table is read."""
    listed = _check_databases(databases)
    tables = ",".join(f"'{TABLE_PREFIX}{table}'" for table in CORE_TABLES)
    columns = " OR ".join(
        f"(TABLE_NAME='{TABLE_PREFIX}{table}' AND COLUMN_NAME IN "
        f"({','.join(repr(column) for column in names)}))"
        for table, names in CORE_TABLES.items()
    )
    return (
        "SELECT 'C',TABLE_SCHEMA,TABLE_NAME,COUNT(*) FROM information_schema.COLUMNS "  # noqa: S608 - fixed names, checked databases
        f"WHERE TABLE_SCHEMA IN ({listed}) AND ({columns}) GROUP BY 2,3 ORDER BY 2,3;"
        "SELECT 'W',TABLE_SCHEMA,COUNT(*) FROM information_schema.TABLES "
        f"WHERE TABLE_SCHEMA IN ({listed}) AND TABLE_NAME IN ({tables}) GROUP BY 2 ORDER BY 2;"
        "SELECT 'X',u.TABLE_SCHEMA,COUNT(*) FROM information_schema.TABLES u "
        "JOIN information_schema.TABLES o ON o.TABLE_SCHEMA=u.TABLE_SCHEMA AND "
        "o.TABLE_NAME=CONCAT(LEFT(u.TABLE_NAME,CHAR_LENGTH(u.TABLE_NAME)-5),'options') "
        f"WHERE u.TABLE_SCHEMA IN ({listed}) AND u.TABLE_NAME LIKE '%users' "
        f"AND u.TABLE_NAME<>'{TABLE_PREFIX}users' GROUP BY 2 ORDER BY 2"
    )


def schema_command(databases: Sequence[str]) -> str:
    return f"{MARIADB_CLIENT} {shlex.quote(schema_sql(databases))}"


def options_sql(database: str) -> str:
    """The two canonical options, bounded; no other option is read."""
    _check_databases([database])
    listed = ",".join(f"'{name}'" for name in SITE_OPTIONS)
    return (
        "SELECT option_name,LEFT(option_value,201) "  # noqa: S608 - fixed names, checked database
        f"FROM `{database}`.`{TABLE_PREFIX}options` WHERE option_name IN ({listed}) ORDER BY 1"
    )


def options_command(database: str) -> str:
    return f"{MARIADB_CLIENT} {shlex.quote(options_sql(database))}"


@dataclass(frozen=True)
class Schema:
    # Core tables present, and whether each has every required column.
    tables: int
    complete: bool
    # Whether another prefix holds its own users and options tables.
    ambiguous: bool


class CatalogFormatError(ValueError):
    pass


def parse_schema(output: str, databases: Sequence[str]) -> dict[str, Schema]:
    columns: dict[str, dict[str, int]] = {name: {} for name in databases}
    tables = dict.fromkeys(databases, 0)
    others = dict.fromkeys(databases, 0)
    for line in output.splitlines():
        match line.split("\t"):
            case ["C", database, table, count] if (
                database in columns
                and table.startswith(TABLE_PREFIX)
                and table[len(TABLE_PREFIX) :] in CORE_TABLES
                and count.isdigit()
            ):
                columns[database][table[len(TABLE_PREFIX) :]] = int(count)
            case ["W", database, count] if database in tables and count.isdigit():
                tables[database] = int(count)
            case ["X", database, count] if database in others and count.isdigit():
                others[database] = int(count)
            case _:
                raise CatalogFormatError
    return {
        name: Schema(
            tables[name],
            tables[name] == len(CORE_TABLES)
            and all(columns[name].get(table) == len(names) for table, names in CORE_TABLES.items()),
            others[name] > 0,
        )
        for name in databases
    }


_URL = re.compile(r"https?://[A-Za-z0-9.-]{1,100}(?::[0-9]{1,5})?(?:/[A-Za-z0-9._~%/-]{0,60})?")


def parse_options(output: str) -> dict[str, str]:
    """``siteurl`` and ``home`` as stored; a value that is not a plain URL, or any other
    option, is a format error."""
    values: dict[str, str] = {}
    for line in output.splitlines():
        match line.split("\t"):
            case [name, value] if name in SITE_OPTIONS and name not in values:
                if not _URL.fullmatch(value):
                    value = ""
                values[name] = value
            case _:
                raise CatalogFormatError
    return values
