"""The native boundary of WordPress actions that run application code.

docs/wordpress-native-design.md#named-wp-cli-operations owns the contract: root revalidates
and stages, the site user runs WP-CLI through the fixed fragments here, and the unit publishes
one validated result line that the controller retrieves from the journal. ADR 0006 owns the
staged body and ADR 0018 the rule that no secret reaches the journal. An action builds its
reviewed body from these fragments and adds its own projection, ``payload`` and ``retrieve``.
"""

import json
import re
import shlex
from dataclasses import dataclass
from typing import Final

from bootstrap import native as bootstrap_native
from sites import native as site_native
from sites.convention import SITES_AVAILABLE, SITES_ENABLED, SitePaths

from . import convention, setup_native

RECORD_MARKER: Final = "barectl-wordpress-result"
# docs/wordpress-native-design.md#named-wp-cli-operations: one sanitized record per action,
# of at most 16 KiB, and at most 128 inventory items.
MAX_RECORD: Final = 16 * 1024
MAX_ITEMS: Final = 128
# The journal read is bounded above one record (JSON escaping grows a line) and below the SSH
# shell's output cap, so a read is never truncated.
MAX_JOURNAL_READ: Final = 60 * 1024
SUFFIX: Final = re.compile(r"[0-9a-f]{32}")
INVOCATION: Final = re.compile(r"[0-9a-f]{32}")
_DIGEST: Final = re.compile(r"[0-9a-f]{64}")
_ENV: Final = "export LC_ALL=C PATH=/usr/sbin:/usr/bin"


class Exit:
    """Statuses every application-executing body shares; an action adds its own."""

    DRIFT = bootstrap_native.Exit.DRIFT
    TOOLS = 61
    STAGING = 62
    PROJECTION = 63


@dataclass(frozen=True)
class Step:
    name: str
    text: str


@dataclass(frozen=True)
class Target:
    """The reviewed application a body runs against, checked against the convention."""

    identifier: str
    php_version: str
    site_revision: int
    site_user: str
    canonical_name: str
    url: str
    tool_path: str

    def verified(self) -> SitePaths:
        if (
            not convention.IDENTIFIER.fullmatch(self.identifier)
            or self.site_user != f"s{self.identifier}"
            or self.url != f"https://{self.canonical_name}"
            or not re.fullmatch(r"[a-z0-9.-]{1,46}", self.canonical_name)
            or not re.fullmatch(r"8\.[0-9]", self.php_version)
            or not self.tool_path.startswith("/usr/local/lib/wp-cli/")
        ):
            raise ValueError("The review is not the convention's.")
        return SitePaths(self.identifier, self.php_version, revision=self.site_revision)

    @property
    def base(self) -> str:
        return f"{convention.WEB_ROOT}/{self.identifier}"

    @property
    def public(self) -> str:
        return convention.public_root(self.identifier)


def digest_ok(value: str) -> str:
    if not _DIGEST.fullmatch(value):
        raise ValueError("Not a valid digest.")
    return value


def staging_path(identifier: str, suffix: str) -> str:
    if not SUFFIX.fullmatch(suffix) or not convention.IDENTIFIER.fullmatch(identifier):
        raise ValueError("Not a valid unit suffix or site identifier.")
    return f"{convention.WEB_ROOT}/{identifier}/.wp-{suffix}"


# The site user's controlled environment: a private home and temporary directory, an empty
# configuration file, cache and package directory, and no inherited variable. ``x NAME
# SECONDS COMMAND...`` runs a command as that user under a time limit and a file-size limit,
# leaving only its standard output, standard error and status in files of the private
# ``out`` directory; nothing it prints reaches the journal.
_FUNCTIONS = (
    (
        's(){ runuser -u "$u" -- /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C HOME="$stg/home" '
        'TMPDIR="$stg/tmp" WP_CLI_CACHE_DIR="$stg/home/cache" '
        'WP_CLI_PACKAGES_DIR="$stg/home/packages" WP_CLI_CONFIG_PATH="$stg/home/config.yml" '
        'WP_CLI_DISABLE_AUTO_CHECK_UPDATE=1 "$@"; }'
    ),
    (
        "x(){ n=$1; t=$2; shift 2; "
        "s /usr/bin/sh -c 'ulimit -f 1024; o=$1; t=$2; shift 2; "
        '/usr/bin/timeout --kill-after=5 "$t" "$@" >"$o.out" 2>"$o.err" </dev/null; '
        'echo $? >"$o.rc"\' sh "$stg/out/$n" "$t" "$@" >/dev/null 2>&1; }'
    ),
    (
        'k(){ cd /; if [ -d "$stg" ] && [ ! -L "$stg" ] && [ "$(stat -c %U -- "$stg")" = "$u" ]; '
        'then s /usr/bin/rm -rf -- "$stg/out" "$stg/tmp" "$stg/home"; rmdir -- "$stg"; fi; }'
    ),
)


# ``W NAME COMMAND...`` is ``x`` with the selected PHP, the pinned tool and the fixed targets.
# Diagnostics skip ordinary plugins and themes; an action that needs their registered hooks (a
# rewrite flush) loads them, because the skip flags would drop their routes.
_SKIP = "--skip-plugins --skip-themes "
_RUNNER = (
    'W(){{ n=$1; shift; x "$n" "$cs" "/usr/bin/php$php" "$phar" --no-color --skip-packages '
    '{skip}"--path=$pub" "--url=$url" "$@"; }}'
)


_MODE = 'm(){ [ "$(stat -c \'%F %U %G %a\' -- "$1")" = "$2" ]; }'


def helpers(target: Target, *, command_seconds: int, load_extensions: bool = False) -> str:
    """The body's first fragment: the environment, the reviewed bindings and the functions.
    ``load_extensions`` leaves ordinary plugins and themes loaded for the action's commands."""
    paths = target.verified()
    if not 0 < command_seconds <= 600:
        raise ValueError("Not a valid command time limit.")
    bindings = "; ".join(
        (
            f"site={shlex.quote(target.identifier)}",
            f"u={shlex.quote(target.site_user)}",
            f"php={shlex.quote(target.php_version)}",
            f"nm={shlex.quote(target.canonical_name)}",
            f"url={shlex.quote(target.url)}",
            f"base={shlex.quote(target.base)}",
            f"pub={shlex.quote(target.public)}",
            f"prv={shlex.quote(target.base + '/private')}",
            'stg="$base/.wp-$q"',
            f"src={shlex.quote(paths.source)}",
            f"phar={shlex.quote(target.tool_path)}",
            f"cs={command_seconds}",
        )
    )
    runner = _RUNNER.format(skip="" if load_extensions else _SKIP)
    shell_functions, cleanup = _FUNCTIONS[:2], _FUNCTIONS[2]
    return "; ".join(
        (
            _ENV,
            "umask 077",
            "set -C",
            bindings,
            site_native.ANCESTORS,
            _MODE,
            *shell_functions,
            runner,
            cleanup,
        )
    )


def tools(target: Target) -> str:
    required = (
        "/usr/bin/python3 /usr/bin/sha256sum /usr/bin/timeout /usr/bin/mariadb "
        f"/usr/sbin/runuser /usr/bin/php{target.php_version}"
    )
    return (
        f'for b in {required}; do [ -x "$b" ] || exit {Exit.TOOLS}; done; '
        f'[ -f "$phar" ] && [ ! -L "$phar" ] || exit {Exit.TOOLS}'
    )


def revalidation(*, site: str, wpcli: str, state_script: str, state: str, target: Target) -> str:
    """Everything the review recorded, recomputed as root under the lock before the
    application runs. ``state_script`` prints the action's own passive state."""
    paths = target.verified()
    drift = f"exit {Exit.DRIFT}"
    cut = '| cut -d" " -f1)"'
    return "; ".join(
        (
            f'case "$q" in *[!0-9a-f]*|"") {drift};; esac',
            f'[ "${{#q}}" -eq 32 ] || {drift}',
            f'[ "$({site_native.site_digest(paths)} {cut} = {digest_ok(site)} ] || {drift}',
            f'[ "$({setup_native.wpcli_digest()} {cut} = {digest_ok(wpcli)} ] || {drift}',
            (
                f'[ "$({{ {state_script}; }} 2>/dev/null | sha256sum {cut} = {digest_ok(state)} ] '
                f"|| {drift}"
            ),
            f'[ ! -e "$stg" ] && [ ! -L "$stg" ] || {drift}',
            f'a "$base" {SITES_AVAILABLE} {SITES_ENABLED} /var/backups || {drift}',
            (
                "m \"$base\" 'directory root root 755' && "
                'm "$pub" "directory $u www-data 750" && '
                f'm "$prv" "directory $u $u 700" || {drift}'
            ),
            # docs/wordpress-native-design.md#upstream-reuse-assessment: project and global
            # configuration files above the working directory or in the application refuse.
            (
                'for d in "$pub" "$base" /var/www /var /; do [ ! -e "$d/wp-cli.yml" ] && '
                f'[ ! -e "$d/wp-cli.local.yml" ] || exit {Exit.STAGING}; done'
            ),
        )
    )


def stage() -> str:
    """Cleanup is armed only after the staging path was proven absent, so it can never remove
    anything this run did not create."""
    return "; ".join(
        (
            "trap k EXIT",
            "trap 'exit 129' HUP",
            "trap 'exit 130' INT",
            "trap 'exit 143' TERM",
            f'mkdir -m 0700 -- "$stg" && chown "$u:$u" -- "$stg" || exit {Exit.STAGING}',
            (
                's /usr/bin/mkdir -m 0700 -- "$stg/out" "$stg/tmp" "$stg/home" && '
                's /usr/bin/mkdir -m 0700 -- "$stg/home/cache" "$stg/home/packages" && '
                f's /usr/bin/touch -- "$stg/home/config.yml" || exit {Exit.STAGING}'
            ),
            f'cd "$stg/home" || exit {Exit.STAGING}',
        )
    )


# Run as the site user over the files the commands left. The shared start of every projection:
# the fixed argument order, the bounded reads and the command-status classification.
PROJECTION_PRELUDE: Final = r"""
import json, re, sys, time
MARKER = "barectl-wordpress-result"
LIMIT = 16384
READ = 262144
directory, operation = sys.argv[1], sys.argv[2]
arguments = sys.argv[3:]


class Unavailable(Exception):
    pass


def read(path):
    with open(path, "rb") as handle:
        data = handle.read(READ + 1)
    if len(data) > READ:
        raise Unavailable("overflow")
    return data


def run(name):
    try:
        status = int(read(directory + "/" + name + ".rc").decode("ascii").strip())
    except FileNotFoundError:
        raise Unavailable("skipped")
    except (OSError, ValueError):
        raise Unavailable("failed")
    try:
        out, err = read(directory + "/" + name + ".out"), read(directory + "/" + name + ".err")
        text = out.decode("ascii"), err.decode("ascii")
    except UnicodeDecodeError:
        raise Unavailable("output")
    except OSError:
        raise Unavailable("failed")
    if status in (124, 137):
        raise Unavailable("timeout")
    if status == 153:
        raise Unavailable("overflow")
    return status, text[0], text[1]
"""


def emit(projection: str, *arguments: str) -> str:
    """Run the trusted ``projection`` (Python, standard library) as the site user over the
    captured files and publish its one validated line; anything else refuses."""
    quoted = " ".join(shlex.quote(argument) for argument in arguments)
    refuse = f"exit {Exit.PROJECTION}"
    return "; ".join(
        (
            (
                f'r=$(s /usr/bin/python3 -I -c {shlex.quote(projection)} "$stg/out" {quoted} '
                f"2>/dev/null | head -c {MAX_RECORD + 1}) || {refuse}"
            ),
            f'[ "${{#r}}" -le {MAX_RECORD} ] && [ "${{#r}}" -gt 0 ] || {refuse}',
            f'case "$r" in "{RECORD_MARKER} {{"*"}}") ;; *) {refuse};; esac',
            f"printf %s \"$r\" | grep -q '[^ -~]' && {refuse}",
            'printf "%s\\n" "$r"',
        )
    )


def payload(unit: str, boot_id: str, deadline: int, body: str) -> str:
    """The submitted script: the shared admission under the mutation lock, then the reviewed
    body, compressed and bound to its digest."""
    suffix = unit.removeprefix(bootstrap_native.UNIT_PREFIX).removesuffix(".service")
    if not SUFFIX.fullmatch(suffix):
        raise ValueError("Not a valid unit suffix.")
    steps = [
        *bootstrap_native.admission(unit, boot_id, deadline),
        f"q={suffix}",
        *bootstrap_native.staged(body),
    ]
    return "; ".join(steps)


def retrieval_argv(unit: str, identifier: str) -> list[str]:
    """The one fixed read of a finished run, as root: whether its staging directory is gone and
    the journal entries of exactly this unit's recorded invocation (on standard input), as
    JSON. The invocation is data, not part of the command line, so sudo authorizes the same
    command before and after the run is known."""
    suffix = unit.removeprefix(bootstrap_native.UNIT_PREFIX).removesuffix(".service")
    stg = shlex.quote(staging_path(identifier, suffix))
    name = shlex.quote(f"{bootstrap_native.UNIT_PREFIX}{suffix}.service")
    fields = "MESSAGE,_SYSTEMD_UNIT,_SYSTEMD_INVOCATION_ID,_TRANSPORT,_UID"
    return site_native.script(
        "; ".join(
            (
                _ENV,
                (
                    f'if [ -e {stg} ] || [ -L {stg} ]; then echo "residue present"; '
                    'else echo "residue absent"; fi'
                ),
                "read -r i || exit 2",
                'case "$i" in *[!0-9a-f]*|"") exit 2;; esac',
                '[ "${#i}" -eq 32 ] || exit 2',
                (
                    f"if o=$(journalctl -q --no-pager -o json --all --output-fields={fields} "
                    f'-n 8 _SYSTEMD_UNIT={name} _SYSTEMD_INVOCATION_ID="$i" _TRANSPORT=stdout '
                    '_UID=0 2>/dev/null); then echo "journal ok"; '
                    f'printf "%s\\n" "$o" | head -c {MAX_JOURNAL_READ}; '
                    'else echo "journal error"; fi'
                ),
                "true",
            )
        )
    )


def retrieval_command(argv: list[str], invocation: str, *, root: bool) -> str:
    """``argv`` with the recorded invocation piped to it."""
    if not INVOCATION.fullmatch(invocation):
        raise ValueError("Not an invocation ID.")
    return f"printf '%s\\n' {invocation} | {bootstrap_native.privileged(argv, root=root)}"


@dataclass(frozen=True)
class Retrieved:
    """What the retrieval read established, and the one record line when it exists."""

    residue: bool
    # ``None`` when the journal could not supply the record; then ``why`` says why.
    record: str | None
    why: str = ""


class Unreadable(Exception):
    pass


def _record_of(line: str, *, unit: str, invocation: str) -> str | None:
    """The record a journal entry carries, when it is this unit's and invocation's stdout line
    with the result marker that root wrote. docs/wordpress-native-design.md: the site user's
    processes share the unit's cgroup and can open the journal's stdout socket, but journald
    stamps their entries with their own ``_UID``."""
    try:
        entry = json.loads(line)
    except ValueError:
        return None
    if not isinstance(entry, dict):
        return None
    message = entry.get("MESSAGE")
    if (
        entry.get("_SYSTEMD_UNIT") == unit
        and entry.get("_SYSTEMD_INVOCATION_ID") == invocation
        and entry.get("_TRANSPORT") == "stdout"
        and entry.get("_UID") == "0"
        and isinstance(message, str)
        and message.startswith(f"{RECORD_MARKER} ")
    ):
        return message.removeprefix(f"{RECORD_MARKER} ")
    return None


def parse_retrieval(text: str, *, unit: str, invocation: str) -> Retrieved:
    """Accept only exactly one stdout entry of this unit and invocation that carries the
    result marker; absence, rotation and surplus records are unavailable evidence, and a read
    that is not in its form is unreadable."""
    lines = text.splitlines()
    if len(lines) < 2 or lines[0] not in {"residue present", "residue absent"}:
        raise Unreadable("The retrieval is not in its expected form.")
    residue = lines[0] == "residue present"
    if lines[1] == "journal error":
        return Retrieved(residue, None, "journal_unreadable")
    if lines[1] != "journal ok":
        raise Unreadable("The retrieval is not in its expected form.")
    found = [
        record
        for line in lines[2:]
        if (record := _record_of(line, unit=unit, invocation=invocation)) is not None
    ]
    if not found:
        return Retrieved(residue, None, "journal_missing")
    if len(found) > 1:
        return Retrieved(residue, None, "extra")
    return Retrieved(residue, found[0])


COMMON_REFUSALS: Final = {
    "lock_conflict": (
        "Another change held Barectl's mutation lock on the server, so the run stopped before "
        "running any application code. Prepare a new review after that change finishes."
    ),
    "unsafe_lock": (
        "The lock directory /run/lock/barectl or its lock file is not a root-owned private "
        "directory with an empty lock file, so the run stopped before running any application "
        "code. Remove it through ordinary administration, then prepare again."
    ),
    "boot_changed": (
        "The server restarted after the review, so the run stopped before running any "
        "application code. Prepare a new review."
    ),
    "expired": (
        "The review's admission deadline had passed on the server's clock when the run "
        "started, so it stopped before running any application code. Prepare a new review."
    ),
    "other_run_active": (
        "Another Barectl run still had processes on the server, so this run stopped before "
        "running any application code. Prepare a new review after it finishes."
    ),
    "renewal_active": (
        "Scheduled certificate renewal still had processes on the server, so the run stopped "
        "before running any application code. Prepare a new review after it finishes."
    ),
    "capacity": (
        "The server kept too many finished runs when this run held the lock, so it stopped "
        "before running any application code. Clear finished runs with a reviewed cleanup, "
        "then prepare again."
    ),
}
