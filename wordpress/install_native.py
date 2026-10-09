"""The WordPress installation's native body, its fixed read and the unit's limits.

docs/wordpress.md#applying-an-installation describes the run; docs/wordpress-native-design.md
owns the pins and rules, and docs/adr/0006-use-native-bootstrap-execution.md#staged-bodies
the way the body reaches the server. Everything here is fixed shell text with validated
parameters. The body is a pure function of the reviewed rows and evidence, so its SHA-256
is part of the review; only the unit's suffix, set before it runs, differs between runs.

Root performs the trusted native steps: the gate, publication, the private configuration,
the ready routing and every probe. WP-CLI, the archive's admission and its extraction and
the application run only as the site user through ``runuser -u`` with a controlled
environment. No password or salt appears in a command line, an environment or the journal:
WP-CLI's own output is discarded.
"""

import hashlib
import re
import shlex
from dataclasses import dataclass
from typing import Final

from bootstrap import native as bootstrap_native
from bootstrap import profiles
from bootstrap.models import Action
from bootstrap.releases import RELEASES
from databases import binding
from discovery.models import DatabaseEngine
from sites import native as site_native
from sites.convention import BACKUP_DIRECTORY, SITES_AVAILABLE, SITES_ENABLED, SitePaths
from tls import issuance_native

from . import convention, core_native, runtime, setup_native
from .models import InstallationReview

_DIGEST = re.compile(r"[0-9a-f]{64}")
SUFFIX: Final = re.compile(r"[0-9a-f]{32}")
_ENV = "export LC_ALL=C PATH=/usr/sbin:/usr/bin"


class Exit:
    """docs/wordpress.md#recovering-a-partial-installation: the payload's own boundaries.

    Statuses 31 to 37 stop before the routing or any application file changed; 38 and 40
    restore the site file; 39, 52 and every status from 42 on leave a changed server.
    """

    DRIFT = bootstrap_native.Exit.DRIFT
    TOOLS = 31
    STAGING = 32
    DOWNLOAD = 33
    ARCHIVE = 34
    ENTRIES = 35
    EXTRACT = 36
    CHECKSUMS = 37
    GATE = 38
    GATE_NOT_RESTORED = 39
    GATE_NOT_SERVING = 40
    PUBLISH = 42
    PLACEHOLDER = 43
    LOADER = 44
    CONFIGURATION = 45
    INSTALL = 46
    SCHEMA = 47
    INTEGRITY = 48
    ACCESS = 49
    READY = 50
    NOT_SERVING = 51
    EXPOSED = 52


ARTIFACT_REFUSALS: Final = frozenset(
    {
        Exit.TOOLS,
        Exit.STAGING,
        Exit.DOWNLOAD,
        Exit.ARCHIVE,
        Exit.ENTRIES,
        Exit.EXTRACT,
        Exit.CHECKSUMS,
    }
)
PARTIAL: Final = frozenset(
    {
        Exit.GATE_NOT_RESTORED,
        Exit.PUBLISH,
        Exit.PLACEHOLDER,
        Exit.LOADER,
        Exit.CONFIGURATION,
        Exit.INSTALL,
        Exit.SCHEMA,
        Exit.INTEGRITY,
        Exit.ACCESS,
        Exit.READY,
    }
)

# The characters an archive member's name may use; anything else refuses the archive.
NAME_CHARACTERS: Final = r"[A-Za-z0-9._@,+~-]"
# The archive's admission, run as the site user with the standard library: every member is a
# plain file or directory under the sole wordpress/ prefix with a safe name and no special
# mode bits, within the reviewed entry, size and per-file limits. It extracts nothing.
ADMISSION: Final = (
    "import re, sys, tarfile\n"
    "path, entries_max, tree_max, file_max = sys.argv[1], *map(int, sys.argv[2:5])\n"
    f'name_ok = re.compile(r"wordpress(/{NAME_CHARACTERS}{{1,200}}){{0,30}}/?")\n'
    "entries = total = 0\n"
    'with tarfile.open(path, "r:gz") as archive:\n'
    "    for member in archive:\n"
    "        entries += 1\n"
    '        parts = member.name.rstrip("/").split("/")\n'
    "        if (\n"
    "            entries > entries_max\n"
    "            or not name_ok.fullmatch(member.name)\n"
    '            or any(part in ("", ".", "..") for part in parts)\n'
    "            or member.mode & 0o7000\n"
    "        ):\n"
    "            sys.exit(3)\n"
    "        if member.isreg():\n"
    "            if member.issparse() or member.size > file_max:\n"
    "                sys.exit(4)\n"
    "            total += member.size\n"
    "        elif not member.isdir():\n"
    "            sys.exit(5)\n"
    "        if total > tree_max:\n"
    "            sys.exit(6)\n"
    'print("entries", entries, "bytes", total)'
)

# One site-user process generates the first-login password, feeds it to WP-CLI's documented
# prompt and discards it. WP-CLI echoes the command it assembled, so its output is discarded.
INSTALL_SCRIPT: Final = (
    "umask 022; p=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 32); "
    '[ "${#p}" -eq 32 ] || exit 1; '
    'printf "%s\\n" "$p" | "$@" >/dev/null 2>&1; r=$?; unset p; exit "$r"'
)


@dataclass(frozen=True)
class Evidence:
    """The digests the plan recorded and the run rechecks under the mutation lock."""

    site: str
    lineage: str
    package: str
    driver: str
    catalog: str
    wpcli: str
    files: str
    database: str

    def checked(self) -> None:
        for value in (
            self.site,
            self.lineage,
            self.package,
            self.driver,
            self.catalog,
            self.wpcli,
            self.files,
            self.database,
        ):
            if not _DIGEST.fullmatch(value):
                raise ValueError("Not a valid digest.")


def digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def limits() -> bootstrap_native.Limits:
    """The native limits the unit runs under: the archive is the largest file it writes."""
    return bootstrap_native.Limits(core_native.MAX_FILE_BYTES, core_native.MEMORY_MAX_BYTES)


def probe_path(identifier: str, token: str) -> str:
    if not runtime.TOKEN.fullmatch(token) or not convention.IDENTIFIER.fullmatch(identifier):
        raise ValueError("Not a probe token or site identifier.")
    return f"{convention.WEB_ROOT}/{identifier}/wpinstall-{token}.php"


def render_probe(identifier: str) -> str:
    """What the site's own pool prints after loading WordPress: the run's token, which its
    file name carries, the effective user, whether WordPress finds its tables and the stored
    site address."""
    return (
        "<?php\n"
        "define('WP_USE_THEMES',false);\n"
        f"require '{convention.public_root(identifier)}/wp-load.php';\n"
        'echo "barectl-wordpress-install ",substr(basename(__FILE__,".php"),10)," ",'
        'posix_geteuid()," ",is_blog_installed()?1:0," ",get_option("siteurl"),"\\n";\n'
    )


def expected_probe(token: str, uid: int, url: str) -> str:
    return f"barectl-wordpress-install {token} {uid} 1 {url}"


# The database facts the run and its verification expect ----------------------------------


def expected_schema_digest(database: str) -> str:
    """The SHA-256 of the fixed schema read's sorted lines for a complete core schema: every
    core table with its required column count, and the count of the core tables."""
    lines = [
        f"C\t{database}\t{convention.TABLE_PREFIX}{table}\t{len(columns)}\n"
        for table, columns in convention.CORE_TABLES.items()
    ]
    lines.append(f"W\t{database}\t{len(convention.CORE_TABLES)}\n")
    return digest("".join(sorted(lines)))


def expected_options(url: str) -> str:
    return "".join(f"{name}\t{url}\n" for name in sorted(convention.SITE_OPTIONS))


def table_count_command(database: str) -> str:
    if not re.fullmatch(r"s[a-z][a-z0-9]{2,23}", database):
        raise ValueError("Not a site database name.")
    sql = (
        "SELECT COUNT(*) FROM information_schema.TABLES "  # noqa: S608 - fixed, checked name
        f"WHERE TABLE_SCHEMA='{database}'"
    )
    return f"{convention.MARIADB_CLIENT} {shlex.quote(sql)}"


def split_configuration(identifier: str) -> tuple[str, str]:
    """The private configuration's text before its salts and after them."""
    text = convention.render_private_configuration(identifier, ["x" * 64] * len(convention.SALTS))
    first = text.index(f"define( '{convention.SALTS[0]}'")
    last = text.index("$table_prefix")
    head, tail = text[:first], text[last:]
    middle = "".join(f"define( '{key}', '{'x' * 64}' );\n" for key in convention.SALTS)
    if head + middle + tail != text:
        raise ValueError("The private configuration is not the convention's.")
    return head, tail


# The body --------------------------------------------------------------------------------


@dataclass(frozen=True)
class Step:
    name: str
    text: str


def _verified(row: InstallationReview, evidence: Evidence) -> SitePaths:
    """Every value the body interpolates is the reviewed convention's, or it is refused."""
    evidence.checked()
    identifier = row.identifier
    paths = SitePaths(identifier, row.php_version, revision=row.site_revision)
    names = tuple(row.names.split(" "))
    if (
        row.canonical_name not in names
        or row.url != f"https://{row.canonical_name}"
        or row.database_name != f"s{identifier}"
        or row.site_user != f"s{identifier}"
        or row.public_root != convention.public_root(identifier)
        or row.private_configuration != convention.private_configuration_path(identifier)
        or row.socket != paths.socket
        or not 0 < row.uid < 2**31
        or not 0 < row.gid < 2**31
        or digest(row.gate_content) != row.gate_sha256
        or digest(row.ready_content) != row.ready_sha256
    ):
        raise ValueError("The review is not the convention's.")
    for value in (
        row.preimage_sha256,
        row.gate_sha256,
        row.ready_sha256,
        row.placeholder_sha256,
        row.loader_sha256,
        row.certificate_sha256,
        row.archive_sha256,
        row.tool_sha256,
    ):
        if not _DIGEST.fullmatch(value):
            raise ValueError("Not a valid digest.")
    return paths


def _bindings(row: InstallationReview, paths: SitePaths) -> str:
    identifier = row.identifier
    base = f"{convention.WEB_ROOT}/{identifier}"
    return "; ".join(
        (
            f"site={shlex.quote(identifier)}",
            f"u={shlex.quote(row.site_user)}",
            f"php={shlex.quote(row.php_version)}",
            f"nm={shlex.quote(row.canonical_name)}",
            f"url={shlex.quote(row.url)}",
            f"base={shlex.quote(base)}",
            f"pub={shlex.quote(row.public_root)}",
            f"prv={shlex.quote(base + '/private')}",
            'stg="$base/.wp-$q"',
            f"src={shlex.quote(paths.source)}",
            f"avl={shlex.quote(SITES_AVAILABLE)}",
            f"bkd={shlex.quote(BACKUP_DIRECTORY)}",
            f'bak="$bkd/{identifier}.conf.$q"',
            f'phb="$bkd/{identifier}.index.html.$q"',
            f'sn="$avl/.{identifier}.conf.$q"',
            'pr="$base/wpinstall-$q.php"',
            f"phar={shlex.quote(row.tool_path)}",
            f"sock={shlex.quote(row.socket)}",
            'ar="$stg/dl/wordpress.tar.gz"',
        )
    )


_CLEANUP = (
    'k(){ cd /; rm -f -- "$pr" "$sn" "$base/.wp-config.php.$q" "$base/.wp-private.$q"; '
    'if [ -d "$stg" ] && [ ! -L "$stg" ] && [ "$(stat -c %U -- "$stg")" = "$u" ]; then '
    's /usr/bin/rm -rf -- "$stg/dl" "$stg/tmp" "$stg/home" "$stg/tree"; '
    'rmdir -- "$stg"; fi; }'
)
# The site user's controlled environment: a private home and temporary directory, an empty
# configuration file, cache and package directory, and no inherited variable.
_AS_SITE_USER = (
    's(){ runuser -u "$u" -- /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C HOME="$stg/home" '
    'TMPDIR="$stg/tmp" WP_CLI_CACHE_DIR="$stg/home/cache" '
    'WP_CLI_PACKAGES_DIR="$stg/home/packages" WP_CLI_CONFIG_PATH="$stg/home/config.yml" '
    'WP_CLI_DISABLE_AUTO_CHECK_UPDATE=1 "$@"; }'
)
_WPCLI = (
    'W(){ wpath=$1; shift; s "/usr/bin/php$php" "$phar" --no-color --skip-packages '
    '"--path=$wpath" "$@"; }'
)
# ``hq HOST PATH`` prints the status and the Location of one HTTPS request through the
# loopback; ``hs PATH`` only the status for the canonical name; ``hb`` the body's start;
# ``hp HOST PATH`` the same as ``hq`` over HTTP.
_HTTP = (
    (
        'hq(){ curl --silent --insecure --max-time 10 --resolve "$1:443:127.0.0.1" '
        "--output /dev/null --write-out '%{http_code} %{redirect_url}' "
        '"https://$1$2" 2>/dev/null; }'
    ),
    'hs(){ set -- $(hq "$nm" "$1"); printf %s "$1"; }',
    (
        'hb(){ curl --silent --insecure --max-time 10 --resolve "$nm:443:127.0.0.1" '
        '"https://$nm$1" 2>/dev/null | head -c 65536; }'
    ),
    (
        'hp(){ curl --silent --max-time 10 --header "Host: $1" --output /dev/null '
        "--write-out '%{http_code} %{redirect_url}' \"http://127.0.0.1$2\" 2>/dev/null; }"
    ),
)
# Withdraw a routing form just applied: while the current bytes are exactly this run's
# candidate, replace them with the bytes on standard input, validate and reload.
_PUT = (
    'put(){ rm -f -- "$sn"; [ "$(z "$src")" = "$1" ] && '
    "n \"$src\" 'regular file root root 644' && "
    'cat >"$sn" && chmod 0644 -- "$sn" && sync -- "$sn" && [ "$(z "$sn")" = "$2" ] && '
    'a "$avl" && mv -T -- "$sn" "$src" && sync -- "$avl" && nginx -t -q && '
    "systemctl reload nginx.service; }"
)


def _helpers(row: InstallationReview, paths: SitePaths) -> str:
    aliases = [name for name in row.names.split(" ") if name != row.canonical_name]
    aliased = "".join(f'[ "$(hq {shlex.quote(alias)} /)" = "301 $url/" ] && ' for alias in aliases)
    certificate = (
        'ct(){ [ "$(timeout 5 openssl s_client -connect 127.0.0.1:443 -servername "$nm" '
        "</dev/null 2>/dev/null | openssl x509 -outform DER 2>/dev/null | sha256sum "
        f"| cut -d' ' -f1)\" = {row.certificate_sha256} ]; }}"
    )
    gated = (
        'gv(){ [ "$(hs /)" = 503 ] && [ "$(hs /index.php)" = 503 ] && '
        '[ "$(hs /wp-login.php)" = 503 ] && [ "$(hs /wp-admin/install.php)" = 503 ] && '
        '[ "$(hp "$nm" /.well-known/acme-challenge/barectl-$q)" = \'404 \' ] && ct; }'
    )
    served = (
        'sv(){ [ "$(hs /)" = 200 ] && [ "$(hs /wp-login.php)" = 200 ] && '
        'hb /wp-login.php | grep -q loginform && [ "$(hs /wp-config.php)" = 403 ] && '
        '[ "$(hs /wp-content/uploads/barectl-$q.php)" = 403 ] && '
        '[ "$(hs /.barectl-$q)" = 403 ] && [ "$(hp "$nm" /)" = "301 $url/" ] && '
        '[ "$(hp "$nm" /.well-known/acme-challenge/barectl-$q)" = \'404 \' ] && '
        f"{aliased}ct; }}"
    )
    return "; ".join(
        (
            _ENV,
            "umask 077",
            "set -C",
            _bindings(row, paths),
            site_native.ANCESTORS,
            'm(){ [ "$(stat -c \'%F %U %G %a\' -- "$1")" = "$2" ]; }',
            'n(){ [ ! -L "$1" ] && m "$1" "$2" && [ "$(stat -c %h -- "$1")" = 1 ]; }',
            "z(){ sha256sum <\"$1\" | cut -d' ' -f1; }",
            _AS_SITE_USER,
            _WPCLI,
            *_HTTP,
            certificate,
            gated,
            served,
            _PUT,
            binding.fastcgi_client(row.php_version),
            _CLEANUP,
        )
    )


def _revalidation(
    row: InstallationReview, evidence: Evidence, paths: SitePaths, release: str
) -> str:
    """Everything the review recorded, recomputed as root under the lock before any change."""
    reviewed = RELEASES[release]
    drift = f"exit {Exit.DRIFT}"
    roots = profiles.php_driver(
        reviewed, Action.PHP_MYSQL, version=row.php_version, supply=row.php_supply
    ).roots
    listed = "; ".join(
        f"echo \"{root} $(dpkg-query -W -f='${{Version}}' {root} 2>/dev/null)\"" for root in roots
    )
    catalog = binding.catalog_function(row.database_name, DatabaseEngine.MARIADB, row.engine_other)
    files = core_native.files_argv(row.identifier)[2]
    database = core_native.database_argv(row.identifier)[2]
    cut = '| cut -d" " -f1)"'
    return "; ".join(
        (
            f'case "$q" in *[!0-9a-f]*|"") {drift};; esac',
            f'[ "${{#q}}" -eq 32 ] || {drift}',
            f'[ "$({site_native.site_digest(paths)} {cut} = {evidence.site} ] || {drift}',
            (
                f'[ "$({issuance_native.lineage_digest(row.identifier)} {cut} = '
                f"{evidence.lineage} ] || {drift}"
            ),
            (
                f'[ "$({profiles.profile(reviewed, Action.MARIADB).revalidation} {cut} = '
                f"{evidence.package} ] || {drift}"
            ),
            (
                f'[ "$(printf %s "$({{ {listed}; }})" | sha256sum {cut} = '
                f"{evidence.driver} ] || {drift}"
            ),
            catalog,
            f'[ "$(c | sha256sum {cut} = {evidence.catalog} ] || {drift}',
            f'[ "$({setup_native.wpcli_digest()} {cut} = {evidence.wpcli} ] || {drift}',
            f'[ "$({{ {files}; }} | sha256sum {cut} = {evidence.files} ] || {drift}',
            f'[ "$({{ {database}; }} | sha256sum {cut} = {evidence.database} ] || {drift}',
            (
                "n \"$src\" 'regular file root root 644' && "
                f'[ "$(z "$src")" = {row.preimage_sha256} ] || {drift}'
            ),
            (
                'for p in "$stg" "$bak" "$phb" "$sn" "$pr" "$pub/wp-config.php" '
                '"$prv/wp-config.php" "$base/.wp-config.php.$q" "$base/.wp-private.$q"; do '
                f'[ ! -e "$p" ] && [ ! -L "$p" ] || {drift}; done'
            ),
            f'a "$base" {SITES_AVAILABLE} {SITES_ENABLED} /var/backups || {drift}',
            (
                "m \"$base\" 'directory root root 755' && "
                'm "$pub" "directory $u www-data 750" && '
                f'm "$prv" "directory $u $u 700" || {drift}'
            ),
            (
                'for d in "$base" /var/www /var /; do [ ! -e "$d/wp-cli.yml" ] && '
                f'[ ! -e "$d/wp-cli.local.yml" ] || exit {Exit.STAGING}; done'
            ),
            (
                f"[ \"$(df -P -B1 {convention.WEB_ROOT} | awk 'NR==2{{print $4}}')\" -ge "
                f"{core_native.REQUIRED_FREE_BYTES} ] || exit {Exit.STAGING}"
            ),
        )
    )


def _tools(row: InstallationReview) -> str:
    required = (
        "/usr/bin/curl /usr/bin/tar /usr/bin/sha256sum /usr/bin/python3 /usr/bin/gzip "
        "/usr/bin/openssl /usr/bin/mariadb /usr/sbin/runuser /usr/sbin/nginx "
        f"/usr/bin/php{row.php_version}"
    )
    return f'for b in {required}; do [ -x "$b" ] || exit {Exit.TOOLS}; done'


def _stage() -> str:
    """Cleanup is armed only now, when the staging path was proven absent, so it can never
    remove anything this run did not create."""
    return "; ".join(
        (
            "trap k EXIT",
            "trap 'exit 129' HUP",
            "trap 'exit 130' INT",
            "trap 'exit 143' TERM",
            f'mkdir -m 0700 -- "$stg" && chown "$u:$u" -- "$stg" || exit {Exit.STAGING}',
            (
                's /usr/bin/mkdir -m 0700 -- "$stg/dl" "$stg/tmp" "$stg/home" "$stg/tree" && '
                's /usr/bin/mkdir -m 0700 -- "$stg/home/cache" "$stg/home/packages" && '
                f's /usr/bin/touch -- "$stg/home/config.yml" || exit {Exit.STAGING}'
            ),
            f'cd "$stg/home" || exit {Exit.STAGING}',
        )
    )


def _download(row: InstallationReview) -> str:
    return "; ".join(
        (
            (
                f'W "$stg/dl" core download --no-extract {shlex.quote(row.archive_url)} '
                f">/dev/null 2>&1 || exit {Exit.DOWNLOAD}"
            ),
            (
                'set -- "$stg"/dl/*; [ "$#" -eq 1 ] && [ -f "$1" ] && [ ! -L "$1" ] '
                f"|| exit {Exit.ARCHIVE}"
            ),
            f'case "$1" in "$stg"/dl/wp_*.tar.gz) ;; *) exit {Exit.ARCHIVE};; esac',
            f's /usr/bin/mv -T -- "$1" "$ar" || exit {Exit.ARCHIVE}',
        )
    )


def _archive(row: InstallationReview) -> str:
    limits_text = f"{row.max_entries} {row.max_tree_bytes} {row.max_file_bytes}"
    return "; ".join(
        (
            (
                f'[ "$(s /usr/bin/stat -c %s -- "$ar")" = {row.archive_bytes} ] '
                f"|| exit {Exit.ARCHIVE}"
            ),
            (
                '[ "$(s /usr/bin/sha256sum -- "$ar" | cut -d\' \' -f1)" = '
                f"{row.archive_sha256} ] || exit {Exit.ARCHIVE}"
            ),
            (
                f'o=$(s /usr/bin/python3 -I -c {shlex.quote(ADMISSION)} "$ar" {limits_text} '
                f"2>/dev/null) || exit {Exit.ENTRIES}"
            ),
            f'case "$o" in "entries "[0-9]*" bytes "[0-9]*) ;; *) exit {Exit.ENTRIES};; esac',
        )
    )


def _extract(row: InstallationReview) -> str:
    extraction = (
        'umask 022; exec /usr/bin/tar --extract --gzip --file="$1" --directory="$2" '
        "--strip-components=1 --no-same-owner --no-same-permissions --no-overwrite-dir"
    )
    refuse = f"exit {Exit.EXTRACT}"
    return "; ".join(
        (
            (
                f's /usr/bin/sh -c {shlex.quote(extraction)} sh "$ar" "$stg/tree" '
                f">/dev/null 2>&1 || {refuse}"
            ),
            (
                's /usr/bin/find "$stg/tree" -mindepth 1 -type d '
                f"-exec /usr/bin/chmod 0755 -- {{}} + || {refuse}"
            ),
            (
                's /usr/bin/find "$stg/tree" -mindepth 1 -type f '
                f"-exec /usr/bin/chmod 0644 -- {{}} + || {refuse}"
            ),
            f'[ -z "$(find "$stg/tree" ! -type f ! -type d -print -quit)" ] || {refuse}',
            (f'[ -z "$(find "$stg/tree" -mindepth 1 ! -user "$u" -print -quit)" ] || {refuse}'),
            f'[ -z "$(find "$stg/tree" -type f -links +1 -print -quit)" ] || {refuse}',
            (f'[ "$(find "$stg/tree" -mindepth 1 | wc -l)" -le {row.max_entries} ] || {refuse}'),
            (
                f'[ "$(grep -cxF "\\$wp_version = \'{row.core_version}\';" '
                f'"$stg/tree/wp-includes/version.php")" = 1 ] || {refuse}'
            ),
        )
    )


def _checksums(row: InstallationReview) -> str:
    return (
        f'W "$stg/tree" core verify-checksums --version={row.core_version} '
        f"--locale={row.core_locale} >/dev/null 2>&1 || exit {Exit.CHECKSUMS}"
    )


def _gate(row: InstallationReview) -> str:
    gate, preimage = row.gate_sha256, row.preimage_sha256
    restored = f"{{ g && exit {Exit.GATE}; exit {Exit.GATE_NOT_RESTORED}; }}"
    return "; ".join(
        (
            f'[ -d "$bkd" ] || mkdir -m 0700 -- "$bkd" || exit {Exit.GATE}',
            f'a "$avl" "$bkd" || exit {Exit.GATE}',
            (
                "n \"$src\" 'regular file root root 644' && "
                f'[ "$(z "$src")" = {preimage} ] || exit {Exit.DRIFT}'
            ),
            (
                'cat -- "$src" >"$bak" && n "$bak" \'regular file root root 600\' && '
                f'[ "$(z "$bak")" = {preimage} ] && sync -- "$bak" "$bkd" || exit {Exit.GATE}'
            ),
            f'g(){{ cat -- "$bak" | put {gate} {preimage}; }}',
            (
                f'printf %s {shlex.quote(row.gate_content)} >"$sn" && chmod 0644 -- "$sn" && '
                f'sync -- "$sn" && [ "$(z "$sn")" = {gate} ] && a "$avl" && '
                "n \"$src\" 'regular file root root 644' && "
                f'[ "$(z "$src")" = {preimage} ] || {{ rm -f -- "$sn"; exit {Exit.GATE}; }}'
            ),
            f'mv -T -- "$sn" "$src" || {{ rm -f -- "$sn"; exit {Exit.GATE}; }}',
            'sync -- "$avl"',
            f"nginx -t -q || {restored}",
            f"systemctl reload nginx.service || {restored}",
            (
                'i=0; until gv; do i=$((i + 1)); [ "$i" -lt 50 ] || { '
                f"g && exit {Exit.GATE_NOT_SERVING}; exit {Exit.GATE_NOT_RESTORED}; }}; "
                "sleep 0.2; done"
            ),
            "echo 'barectl-wordpress: gate verified'",
        )
    )


def _publish() -> str:
    refuse = f"exit {Exit.PUBLISH}"
    return "; ".join(
        (
            f'a "$base" && m "$pub" "directory $u www-data 750" || {refuse}',
            (
                'for t in $(ls -A -- "$stg/tree"); do d="$pub/$t"; '
                f'[ ! -e "$d" ] && [ ! -L "$d" ] || {refuse}; '
                '/usr/bin/mv --no-copy --no-clobber -T -- "$stg/tree/$t" "$d" '
                f'|| {refuse}; [ -e "$d" ] && [ ! -e "$stg/tree/$t" ] || {refuse}; done'
            ),
        )
    )


def _placeholder(row: InstallationReview) -> tuple[str, ...]:
    refuse = f"exit {Exit.PLACEHOLDER}"
    if not row.placeholder_present:
        return (f'[ ! -e "$pub/index.html" ] && [ ! -L "$pub/index.html" ] || {refuse}',)
    sha = row.placeholder_sha256
    return (
        'd="$pub/index.html"',
        f'n "$d" "regular file $u www-data 640" && [ "$(z "$d")" = {sha} ] || {refuse}',
        (
            'cat -- "$d" >"$phb" && n "$phb" \'regular file root root 600\' && '
            f'[ "$(z "$phb")" = {sha} ] && sync -- "$phb" "$bkd" && rm -f -- "$d" && '
            f'[ ! -e "$d" ] || {refuse}'
        ),
    )


def _loader(row: InstallationReview) -> str:
    sha = row.loader_sha256
    loader = convention.render_loader(row.identifier)
    return "; ".join(
        (
            't="$base/.wp-config.php.$q"',
            (
                f'printf %s {shlex.quote(loader)} >"$t" && '
                'chown "$u:www-data" -- "$t" && chmod 0640 -- "$t" && sync -- "$t" && '
                f'[ "$(z "$t")" = {sha} ] && a "$base" && '
                'm "$pub" "directory $u www-data 750" && '
                '[ ! -e "$pub/wp-config.php" ] && [ ! -L "$pub/wp-config.php" ] && '
                'ln -T -- "$t" "$pub/wp-config.php" || '
                f'{{ rm -f -- "$t"; exit {Exit.LOADER}; }}'
            ),
            'rm -f -- "$t"',
            (
                'n "$pub/wp-config.php" "regular file $u www-data 640" && '
                f'[ "$(z "$pub/wp-config.php")" = {sha} ] || exit {Exit.LOADER}'
            ),
        )
    )


def _configuration(row: InstallationReview) -> str:
    head, tail = split_configuration(row.identifier)
    keys = " ".join(convention.SALTS)
    refuse = f"exit {Exit.CONFIGURATION}"
    return "; ".join(
        (
            't="$base/.wp-private.$q"',
            (
                f"{{ printf %s {shlex.quote(head)}; for k in {keys}; do "
                "v=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 64); "
                f'[ "${{#v}}" -eq 64 ] || {refuse}; '
                'printf "define( \'%s\', \'%s\' );\\n" "$k" "$v"; done; unset v; '
                f'printf %s {shlex.quote(tail)}; }} >"$t" || {refuse}'
            ),
            (
                'chown "$u:$u" -- "$t" && chmod 0600 -- "$t" && sync -- "$t" && a "$base" && '
                'm "$prv" "directory $u $u 700" && '
                '[ ! -e "$prv/wp-config.php" ] && [ ! -L "$prv/wp-config.php" ] && '
                f'ln -T -- "$t" "$prv/wp-config.php" || {{ rm -f -- "$t"; {refuse}; }}'
            ),
            'rm -f -- "$t"',
            (
                f"o=$({convention.inspection_command(row.identifier)}) || {refuse}; "
                "for l in 'loader exact' 'configuration supported' "
                f"'version {row.core_version}'; do "
                f'printf "%s\\n" "$o" | grep -qxF "$l" || {refuse}; done'
            ),
        )
    )


def _install(row: InstallationReview) -> str:
    arguments = (
        '"/usr/bin/php$php" "$phar" --no-color --skip-packages "--path=$pub" core install '
        f'"--url=$url" {shlex.quote("--title=" + row.title)} '
        f"{shlex.quote('--admin_user=' + row.admin_login)} "
        f"{shlex.quote('--admin_email=' + row.admin_email)} "
        "--prompt=admin_password --skip-email"
    )
    return f"s /usr/bin/sh -c {shlex.quote(INSTALL_SCRIPT)} sh {arguments} || exit {Exit.INSTALL}"


def _schema(row: InstallationReview) -> str:
    database = row.database_name
    cut = '| cut -d" " -f1)"'
    return "; ".join(
        (
            (
                f'[ "$({convention.schema_command([database])} | LC_ALL=C sort | sha256sum {cut} = '
                f"{expected_schema_digest(database)} ] || exit {Exit.SCHEMA}"
            ),
            (
                f'[ "$({table_count_command(database)})" = {len(convention.CORE_TABLES)} ] '
                f"|| exit {Exit.SCHEMA}"
            ),
            (
                f'[ "$({convention.options_command(database)} | sha256sum {cut} = '
                f"{digest(expected_options(row.url))} ] || exit {Exit.SCHEMA}"
            ),
        )
    )


def _integrity(row: InstallationReview) -> str:
    return (
        f'W "$pub" core verify-checksums --version={row.core_version} '
        f"--locale={row.core_locale} >/dev/null 2>&1 || exit {Exit.INTEGRITY}"
    )


def _access(row: InstallationReview) -> str:
    content = render_probe(row.identifier)
    refuse = f"exit {Exit.ACCESS}"
    return "; ".join(
        (
            f'W "$pub" core is-installed >/dev/null 2>&1 || {refuse}',
            f'[ "$(W "$pub" option get siteurl 2>/dev/null)" = "$url" ] || {refuse}',
            (
                f'[ "$(W "$pub" user get {shlex.quote(row.admin_login)} --field=user_email '
                f'2>/dev/null)" = {shlex.quote(row.admin_email)} ] || {refuse}'
            ),
            f'[ "$(W "$pub" user list --format=count 2>/dev/null)" = 1 ] || {refuse}',
            (
                f'printf %s {shlex.quote(content)} >"$pr" && chown "root:$u" -- "$pr" && '
                f'chmod 0640 -- "$pr" && [ "$(z "$pr")" = {digest(content)} ] || '
                f'{{ rm -f -- "$pr"; {refuse}; }}'
            ),
            (
                'o=$(f "$sock" "$pr"); rm -f -- "$pr"; '
                '[ "$o" = "barectl-wordpress-install $q $(id -u "$u") 1 $url" ] || '
                f"{refuse}"
            ),
            "echo 'barectl-wordpress: schema, integrity and access verified while gated'",
        )
    )


def _ready(row: InstallationReview) -> str:
    gate, ready = row.gate_sha256, row.ready_sha256
    restored = f"{{ r && exit {Exit.READY}; exit {Exit.EXPOSED}; }}"
    return "; ".join(
        (
            (
                f"r(){{ printf %s {shlex.quote(row.gate_content)} | put {ready} {gate} && i=0 && "
                'until gv; do i=$((i + 1)); [ "$i" -lt 50 ] || return 1; sleep 0.2; done; }'
            ),
            (
                f'printf %s {shlex.quote(row.ready_content)} >"$sn" && chmod 0644 -- "$sn" && '
                f'sync -- "$sn" && [ "$(z "$sn")" = {ready} ] && a "$avl" && '
                "n \"$src\" 'regular file root root 644' && "
                f'[ "$(z "$src")" = {gate} ] || {{ rm -f -- "$sn"; exit {Exit.READY}; }}'
            ),
            f'mv -T -- "$sn" "$src" || {{ rm -f -- "$sn"; exit {Exit.READY}; }}',
            'sync -- "$avl"',
            f"nginx -t -q || {restored}",
            f"systemctl reload nginx.service || {restored}",
        )
    )


def _serving() -> str:
    return "; ".join(
        (
            (
                'i=0; until sv; do i=$((i + 1)); [ "$i" -lt 100 ] || { '
                f"r && exit {Exit.NOT_SERVING}; exit {Exit.EXPOSED}; }}; sleep 0.2; done"
            ),
            "echo 'barectl-wordpress: HTTPS verified'",
        )
    )


def body_steps(row: InstallationReview, evidence: Evidence, release: str) -> list[Step]:
    """The named fragments of the run's native body, in order."""
    paths = _verified(row, evidence)
    if release not in RELEASES:
        raise ValueError("Not a reviewed release.")
    return [
        Step("helpers", _helpers(row, paths)),
        Step("tools", _tools(row)),
        Step("revalidation", _revalidation(row, evidence, paths, release)),
        Step("stage", _stage()),
        Step("download", _download(row)),
        Step("archive", _archive(row)),
        Step("extract", _extract(row)),
        Step("checksums", _checksums(row)),
        Step("gate", _gate(row)),
        Step("publish", _publish()),
        Step("placeholder", "; ".join(_placeholder(row))),
        Step("loader", _loader(row)),
        Step("configuration", _configuration(row)),
        Step("install", _install(row)),
        Step("schema", _schema(row)),
        Step("integrity", _integrity(row)),
        Step("access", _access(row)),
        Step("ready", _ready(row)),
        Step("serving", _serving()),
        Step("finish", "exit 0"),
    ]


def body(row: InstallationReview, evidence: Evidence, release: str) -> str:
    return "; ".join(step.text for step in body_steps(row, evidence, release))


def payload(
    unit: str,
    boot_id: str,
    deadline: int,
    row: InstallationReview,
    evidence: Evidence,
    release: str,
) -> str:
    """The submitted script: the shared admission under the mutation lock, then the reviewed
    body, compressed and bound to its digest."""
    return staged_payload(unit, boot_id, deadline, row, evidence, release)[0]


def staged_payload(
    unit: str,
    boot_id: str,
    deadline: int,
    row: InstallationReview,
    evidence: Evidence,
    release: str,
) -> tuple[str, str]:
    """The submitted script and the body it carries."""
    suffix = unit.removeprefix(bootstrap_native.UNIT_PREFIX).removesuffix(".service")
    if not SUFFIX.fullmatch(suffix):
        raise ValueError("Not a valid unit suffix.")
    text = body(row, evidence, release)
    steps = [
        *bootstrap_native.admission(unit, boot_id, deadline),
        f"q={suffix}",
        *bootstrap_native.staged(text),
    ]
    return "; ".join(steps), text


# The verification read ---------------------------------------------------------------------


def state(row: InstallationReview, suffix: str) -> list[str]:
    """What an installation leaves, read as root after a run: the routing, its recovery
    preimages, the public and private configuration, the site directory's entries, the
    database's schema and options and whether Nginx accepts its configuration."""
    if not SUFFIX.fullmatch(suffix):
        raise ValueError("Not a valid unit suffix.")
    identifier = row.identifier
    paths = SitePaths(identifier, row.php_version, revision=row.site_revision)
    base = f"{convention.WEB_ROOT}/{identifier}"
    database = row.database_name
    watched = [
        paths.source,
        f"{BACKUP_DIRECTORY}/{identifier}.conf.{suffix}",
        f"{BACKUP_DIRECTORY}/{identifier}.index.html.{suffix}",
        f"{row.public_root}/wp-config.php",
        row.private_configuration,
        f"{row.public_root}/index.html",
        f"{row.public_root}/wp-includes/version.php",
    ]
    cut = "| cut -d' ' -f1"
    return site_native.script(
        "; ".join(
            (
                _ENV,
                (
                    f"for p in {' '.join(shlex.quote(path) for path in watched)}; do "
                    'if [ -e "$p" ] || [ -L "$p" ]; then '
                    "stat -c 'path %F|%U|%G|%a|%h|%n' -- \"$p\"; "
                    '[ -f "$p" ] && [ ! -L "$p" ] && '
                    f'echo "sha $(sha256sum <"$p" {cut}) $p"; '
                    'else echo "absent $p"; fi; done'
                ),
                (
                    f"find {shlex.quote(base)} -mindepth 1 -maxdepth 1 "
                    "-printf 'entry %y %u %g %m %f\\n' | sort"
                ),
                f"{convention.inspection_command(identifier)} | sed 's/^/inspect /'",
                (
                    f'echo "schema $({convention.schema_command([database])} '
                    f'| LC_ALL=C sort | sha256sum {cut})"'
                ),
                f'echo "tables $({table_count_command(database)})"',
                f'echo "options $({convention.options_command(database)} | sha256sum {cut})"',
                "nginx -t -q 2>/dev/null && echo 'nginx valid' || echo 'nginx invalid'",
            )
        )
    )


@dataclass(frozen=True)
class State:
    paths: dict[str, tuple[str, str, str, str, str]]
    sha: dict[str, str]
    entries: tuple[tuple[str, str, str, str, str], ...]
    inspect: dict[str, str]
    schema: str
    tables: str
    options: str
    nginx: str


class Unreadable(Exception):
    pass


def parse_state(text: str) -> State:
    paths: dict[str, tuple[str, str, str, str, str]] = {}
    sha: dict[str, str] = {}
    entries: list[tuple[str, str, str, str, str]] = []
    inspect: dict[str, str] = {}
    single: dict[str, str] = {}
    for line in text.splitlines():
        kind, _, rest = line.partition(" ")
        if kind == "path":
            fields = rest.split("|", 5)
            if len(fields) != 6:
                raise Unreadable("The installation read is not in its expected form.")
            paths[fields[5]] = (fields[0], fields[1], fields[2], fields[3], fields[4])
        elif kind == "absent":
            continue
        elif kind == "sha":
            value, _, path = rest.partition(" ")
            if not _DIGEST.fullmatch(value) or not path:
                raise Unreadable("The installation read is not in its expected form.")
            sha[path] = value
        elif kind == "entry":
            fields = rest.split(" ", 4)
            if len(fields) != 5:
                raise Unreadable("The installation read is not in its expected form.")
            entries.append((fields[0], fields[1], fields[2], fields[3], fields[4]))
        elif kind == "inspect":
            key, _, value = rest.partition(" ")
            inspect[key] = value
        elif kind in {"schema", "tables", "options", "nginx"} and kind not in single:
            single[kind] = rest
        else:
            raise Unreadable("The installation read is not in its expected form.")
    if set(single) != {"schema", "tables", "options", "nginx"}:
        raise Unreadable("The installation read is not in its expected form.")
    return State(
        paths,
        sha,
        tuple(sorted(entries)),
        inspect,
        single["schema"],
        single["tables"],
        single["options"],
        single["nginx"],
    )


def problems(row: InstallationReview, suffix: str, found: State) -> list[str]:
    """Each difference between the server and the reviewed, installed application."""
    identifier = row.identifier
    paths = SitePaths(identifier, row.php_version, revision=row.site_revision)
    user = row.site_user
    wrong: list[str] = []
    ready = found.paths.get(paths.source)
    if ready != ("regular file", "root", "root", "644", "1") or (
        found.sha.get(paths.source) != row.ready_sha256
    ):
        wrong.append(f"The site file {paths.source} is not the reviewed ready form.")
    backup = f"{BACKUP_DIRECTORY}/{identifier}.conf.{suffix}"
    if found.sha.get(backup) != row.preimage_sha256:
        wrong.append(f"The recovery preimage {backup} is not the reviewed site file.")
    placeholder = f"{BACKUP_DIRECTORY}/{identifier}.index.html.{suffix}"
    if row.placeholder_present and found.sha.get(placeholder) != row.placeholder_sha256:
        wrong.append(f"The placeholder's preimage {placeholder} is not kept.")
    loader = f"{row.public_root}/wp-config.php"
    if found.paths.get(loader) != ("regular file", user, "www-data", "640", "1"):
        wrong.append(f"{loader} is not the fixed loader with its reviewed owner and mode.")
    private = row.private_configuration
    if found.paths.get(private) != ("regular file", user, user, "600", "1"):
        wrong.append(f"{private} does not have its reviewed owner and mode.")
    if found.inspect.get("loader") != "exact" or found.inspect.get("configuration") != "supported":
        wrong.append("The WordPress loader or private configuration is not in its supported form.")
    if found.inspect.get("version") != row.core_version:
        wrong.append(f"The installed core release is not {row.core_version}.")
    if f"{row.public_root}/index.html" in found.paths:
        wrong.append("The placeholder is still in the public root.")
    names = sorted(entry[4] for entry in found.entries)
    if names != ["private", "public"]:
        wrong.append(f"/var/www/{identifier} holds more than public and private: {names}.")
    if found.schema != expected_schema_digest(row.database_name):
        wrong.append("The database does not hold exactly the complete WordPress core schema.")
    if found.tables != str(len(convention.CORE_TABLES)):
        wrong.append(f"The database does not hold exactly {len(convention.CORE_TABLES)} tables.")
    if found.options != digest(expected_options(row.url)):
        wrong.append(f"The siteurl and home options are not {row.url}.")
    if found.nginx != "valid":
        wrong.append("Nginx does not accept its configuration.")
    return wrong
