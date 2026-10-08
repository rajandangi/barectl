"""docs/adr/0006-use-native-bootstrap-execution.md"""

import re
import shlex
import uuid
from dataclasses import dataclass
from enum import IntEnum
from typing import Final

from discovery.ssh import RemoteShell

from .models import Execution

UNIT_PREFIX: Final = "barectl-apply-"
_UNIT = re.compile(r"barectl-apply-[0-9a-f]{32}\.service")
_BOOT = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_INVOCATION = re.compile(r"[0-9a-f]{32}")
LOCK_DIRECTORY: Final = "/run/lock/barectl"
LOCK_FILE: Final = f"{LOCK_DIRECTORY}/mutation.lock"
SYSTEMD_RUN: Final = "/usr/bin/systemd-run"
RUNTIME_MAX: Final = "30min"
TIMEOUT_STOP: Final = "60"
MAX_PAYLOAD: Final = 16 * 1024
MAX_JOURNAL_OUTPUT: Final = 16 * 1024
RETAINED_LIMIT: Final = 100
# docs/ssh-connections.md#clearing-finished-bootstrap-runs
CLEANUP_CEILING: Final = RETAINED_LIMIT + 10
CLEANUP_BATCH: Final = CLEANUP_CEILING + 10


class Exit(IntEnum):
    """docs/adr/0006-use-native-bootstrap-execution.md#payload"""

    SUCCESS = 0
    LOCK_CONFLICT = 10
    UNSAFE_LOCK = 11
    BOOT_CHANGED = 12
    EXPIRED = 13
    OTHER_RUN_ACTIVE = 14
    DRIFT = 15
    PACKAGE_MANAGER_BUSY = 16
    UPDATE_FAILED = 17
    CAPACITY = 18
    CLEANUP_FAILED = 19
    INSTALL_FAILED = 20
    TRANSACTION_REFUSED = 21
    SERVICE_FAILED = 22
    INSTALL_NOT_STARTED = 23
    VALIDATION_FAILED = 24
    RENEWAL_ACTIVE = 25
    RELOAD_FAILED = 26


_EXECUTIONS = {
    Exit.SUCCESS: Execution.SUCCEEDED,
    Exit.LOCK_CONFLICT: Execution.LOCK_CONFLICT,
    Exit.UNSAFE_LOCK: Execution.UNSAFE_LOCK,
    Exit.BOOT_CHANGED: Execution.BOOT_CHANGED,
    Exit.EXPIRED: Execution.EXPIRED,
    Exit.OTHER_RUN_ACTIVE: Execution.OTHER_RUN_ACTIVE,
    Exit.DRIFT: Execution.DRIFT,
    Exit.PACKAGE_MANAGER_BUSY: Execution.PACKAGE_MANAGER_BUSY,
    Exit.UPDATE_FAILED: Execution.FAILED,
    Exit.CAPACITY: Execution.CAPACITY,
    Exit.CLEANUP_FAILED: Execution.FAILED,
    Exit.INSTALL_FAILED: Execution.INSTALL_FAILED,
    Exit.TRANSACTION_REFUSED: Execution.TRANSACTION_REFUSED,
    Exit.SERVICE_FAILED: Execution.SERVICE_FAILED,
    Exit.INSTALL_NOT_STARTED: Execution.INSTALL_NOT_STARTED,
    Exit.VALIDATION_FAILED: Execution.VALIDATION_FAILED,
    Exit.RENEWAL_ACTIVE: Execution.RENEWAL_ACTIVE,
    Exit.RELOAD_FAILED: Execution.RELOAD_FAILED,
}

# docs/adr/0006-use-native-bootstrap-execution.md#payload
APT_DIGEST: Final = (
    "{ LC_ALL=C apt-config dump; "
    "find /etc/apt -xdev -type f ! -path '/etc/apt/auth.conf*' -exec sha256sum -- {} + "
    "| LC_ALL=C sort; "
    "LC_ALL=C apt-get indextargets --no-release-info --format "
    "'$(SITE)|$(RELEASE)|$(COMPONENT)' 'Created-By: Packages' | LC_ALL=C sort; "
    "} 2>/dev/null | sha256sum"
)
DPKG_STATUS_DIGEST: Final = "sha256sum /var/lib/dpkg/status"
USER_ID: Final = "id -u"
RETAINED_UNITS: Final = (
    f"systemctl list-units --all --plain --no-legend --type=service '{UNIT_PREFIX}*'"
)
_PROPERTIES = (
    "Id",
    "LoadState",
    "ActiveState",
    "SubState",
    "Result",
    "ExecMainCode",
    "ExecMainStatus",
    "InvocationID",
)
# waitid(2) codes that systemd reports as ExecMainCode.
CLD_EXITED = 1
_CLD_SIGNALLED = frozenset({2, 3})


class PayloadTooLarge(Exception):
    pass


class Unreadable(Exception):
    """Native evidence that is not in the form systemd and the kernel report."""


def new_unit_name() -> str:
    return f"{UNIT_PREFIX}{uuid.uuid4().hex}.service"


def parse_digest(text: str) -> str:
    digest = text.split(" ", 1)[0].strip()
    if not _DIGEST.fullmatch(digest):
        raise Unreadable("sha256sum did not report a digest.")
    return digest


def _check(pattern: re.Pattern[str], value: str, what: str) -> str:
    if not pattern.fullmatch(value):
        raise ValueError(f"Not a valid {what}.")
    return value


def lock_steps(unsafe: str, conflict: str) -> list[str]:
    """docs/adr/0006-use-native-bootstrap-execution.md#payload: take the mutation lock on
    descriptor 9 without waiting, running ``unsafe`` or ``conflict`` when it cannot.

    Certbot's guarded renewal takes the lock with these same steps (docs/tls.md).
    """
    return [
        "export LC_ALL=C",
        f"d={LOCK_DIRECTORY}",
        f"f={LOCK_FILE}",
        'mkdir -m 0700 "$d" 2>/dev/null',
        f"[ \"$(stat -c '%F %u %a' \"$d\")\" = 'directory 0 700' ] || {unsafe}",
        f'[ ! -L "$f" ] || {unsafe}',
        f'exec 9>>"$f" || {unsafe}',
        f"[ \"$(stat -c '%F %u %h' \"$f\")\" = 'regular empty file 0 1' ] || {unsafe}",
        f"flock -n 9 || {conflict}",
    ]


def _lock() -> list[str]:
    return lock_steps(f"exit {Exit.UNSAFE_LOCK}", f"exit {Exit.LOCK_CONFLICT}")


# Every bootstrap unit's control-group events file; a unit's is present while it runs.
_UNIT_EVENTS = f"/sys/fs/cgroup/system.slice/{UNIT_PREFIX}*.service/cgroup.events"
# docs/adr/0006-use-native-bootstrap-execution.md#payload: Certbot's packaged renewal
# service, at its fixed path and wherever systemd reports its control group.
_RENEWAL = (
    "r=0; c=$(systemctl show -p ControlGroup --value certbot.service 2>/dev/null); "
    "for e in /sys/fs/cgroup/system.slice/certbot.service/cgroup.events "
    '${c:+"/sys/fs/cgroup$c/cgroup.events"}; do '
    "grep -qx 'populated 1' \"$e\" 2>/dev/null && r=1; done"
)


def renewal_check() -> list[str]:
    """Exit RENEWAL_ACTIVE while Certbot's renewal service has processes."""
    return [_RENEWAL, f'[ "$r" = 0 ] || exit {Exit.RENEWAL_ACTIVE}']


_RETAINED_COUNT = (
    f"systemctl list-units --all --plain --no-legend --type=service '{UNIT_PREFIX}*' | grep -c ."
)


def admission(
    unit: str, boot_id: str, deadline_centiseconds: int, *, capacity: int = RETAINED_LIMIT
) -> list[str]:
    unit = _check(_UNIT, unit, "unit name")
    boot_id = _check(_BOOT, boot_id, "boot ID")
    deadline = int(deadline_centiseconds)
    limit = int(capacity)
    own = f"/sys/fs/cgroup/system.slice/{unit}/cgroup.events"
    return [
        *_lock(),
        f'[ "$(cat /proc/sys/kernel/random/boot_id)" = {boot_id} ] || exit {Exit.BOOT_CHANGED}',
        f"[ \"$(cut -d' ' -f1 /proc/uptime | tr -d .)\" -lt {deadline} ] || exit {Exit.EXPIRED}",
        (
            f"for e in {_UNIT_EVENTS}; do "
            f'[ "$e" = {own} ] && continue; [ -e "$e" ] || continue; '
            f"grep -qx 'populated 1' \"$e\" && exit {Exit.OTHER_RUN_ACTIVE}; done"
        ),
        *renewal_check(),
        # The run's own unit is listed too.
        f"n=$({_RETAINED_COUNT})",
        f'[ "$((n - 1))" -lt {limit} ] || exit {Exit.CAPACITY}',
    ]


def metadata_refresh(
    unit: str,
    boot_id: str,
    deadline_centiseconds: int,
    apt: str,
    *,
    preconditions: tuple[tuple[str, str], ...] = (),
) -> str:
    apt = _check(_DIGEST, apt, "digest")
    steps = [
        *admission(unit, boot_id, deadline_centiseconds),
        f'[ "$({APT_DIGEST} | cut -d" " -f1)" = {apt} ] || exit {Exit.DRIFT}',
        *digest_preconditions(preconditions),
        "o=$(apt-get -q --error-on=any update 2>&1); s=$?",
        f"printf '%s\\n' \"$o\" | tail -c {MAX_JOURNAL_OUTPUT}",
        f"case \"$o\" in *'Could not get lock'*) exit {Exit.PACKAGE_MANAGER_BUSY};; esac",
        f'[ "$s" -eq 0 ] || exit {Exit.UPDATE_FAILED}',
        f"printf '%s\\n' \"$o\" | grep -Eq '^(W:|E:|Err:)' && exit {Exit.UPDATE_FAILED}",
        f"exit {Exit.SUCCESS}",
    ]
    return "; ".join(steps)


# Package changes ------------------------------------------------------------------------

_PACKAGE = re.compile(r"[a-z0-9][a-z0-9+.-]{0,99}")
_VERSION = re.compile(r"[A-Za-z0-9.+~:-]{1,100}")
_ARCHITECTURE = re.compile(r"[a-z0-9-]{1,20}")
_SERVICE = re.compile(r"[a-z0-9][a-z0-9.@-]{0,90}\.(service|timer)")
_TREE = re.compile(r"/etc(/[a-z0-9][a-z0-9._-]{0,50}){1,4}")
# A Unix socket under /run, such as /run/mysqld/mysqld.sock or PostgreSQL's
# /var/run/postgresql/.s.PGSQL.5432.
_SOCKET = re.compile(r"(/var)?/run(/(?!\.\.)[a-zA-Z0-9._-]{1,50}){1,3}")
# A path under /etc, /var/lib or /var/log, such as /var/lib/postgresql/16/main.
_PATH = re.compile(r"/(etc|var/lib|var/log)(/[a-zA-Z0-9_][a-zA-Z0-9._-]{0,50}){1,5}")
_EXECUTABLE = re.compile(r"/usr/s?bin/[a-z0-9][a-z0-9._-]{0,50}")
# One printable ASCII argument without sudoers wildcards; the payload quotes it.
_ARGUMENT = re.compile(r"[ -)+->@-Z\\^-~]+")
_SUDOERS_SPECIAL = frozenset("\\,:=")
_OUTPUT = re.compile(r"[ -~\n]{1,1000}")


@dataclass(frozen=True)
class Check:
    """A fixed command a profile runs as root at the end of every run, and optionally the
    exact output it must print (without trailing newlines)."""

    argv: tuple[str, ...]
    expected: str | None = None
    # The longest argument, such as a query, the check may pass.
    limit: int = 300

    @property
    def command(self) -> str:
        executable, *arguments = self.argv
        _check(_EXECUTABLE, executable, "check command")
        for argument in arguments:
            if len(argument) > self.limit:
                raise ValueError("Not a valid check argument.")
            _check(_ARGUMENT, argument, "check argument")
        if self.expected is not None:
            _check(_OUTPUT, self.expected, "expected check output")
        return shlex.join(self.argv)

    @property
    def sudoers(self) -> str:
        """docs/bootstrap.md#authorizing-readiness-checks: the command as a sudoers rule
        matches it, with sudoers' special characters escaped."""
        self.command  # noqa: B018 - validates the arguments, which have no wildcards
        return " ".join(
            "".join(f"\\{c}" if c in _SUDOERS_SPECIAL else c for c in argument)
            for argument in self.argv
        )

    def step(self) -> str:
        """The payload's final step, which exits VALIDATION_FAILED unless the check holds."""
        failed = f"exit {Exit.VALIDATION_FAILED}"
        if self.expected is None:
            return f"{self.command} || {failed}"
        return (
            f"c=$({self.command}) || {failed}; printf '%s\\n' \"$c\"; "
            f'[ "$c" = {shlex.quote(self.expected)} ] || {failed}'
        )


DPKG_STATUS: Final = "/var/lib/dpkg/status"
ARCHIVES: Final = "/var/cache/apt/archives/"
# docs/adr/0007-admit-exact-package-transactions-with-an-inline-apt-guard.md#the-guard
GUARD_NAME: Final = "barectl_package_guard"
GUARD_ADMITTED: Final = "barectl-guard: admitted"
GUARD_REFUSED: Final = "barectl-guard: refused"
STATUS_VARIABLE: Final = "BARECTL_DPKG_STATUS"
# docs/adr/0007-admit-exact-package-transactions-with-an-inline-apt-guard.md#installation
INSTALL_OPTIONS: Final = (
    "-q",
    "-y",
    "--no-remove",
    "-o",
    "APT::Install-Recommends=0",
    "-o",
    "APT::Install-Suggests=0",
    "-o",
    "APT::Get::Fix-Missing=0",
    "-o",
    "DPkg::Lock::Timeout=0",
)


@dataclass(frozen=True)
class PackageAction:
    """One dpkg action a reviewed package transaction approves: unpacking a new package's
    version, or configuring it."""

    unpack: bool
    package: str
    version: str
    architecture: str

    def normalized(self) -> str:
        """docs/adr/0007-admit-exact-package-transactions-with-an-inline-apt-guard.md#the-guard"""
        package = _check(_PACKAGE, self.package, "package name")
        version = _check(_VERSION, self.version, "version")
        architecture = _check(_ARCHITECTURE, self.architecture, "architecture")
        if not self.unpack:
            return f"C {package} {version} {architecture}"
        archive = f"{package}_{version.replace(':', '%3a')}_{architecture}.deb"
        return f"U {package} {version} {architecture} {archive}"


def package_digest(
    units: tuple[str, ...],
    trees: tuple[str, ...],
    port: int | None,
    *,
    ucf: bool,
    listings: tuple[str, ...] = (),
    data_listings: tuple[str, ...] = (),
    socket: str | None = None,
    paths: tuple[str, ...] = (),
    private: tuple[str, ...] = (),
    hashed: tuple[str, ...] = (),
    resolved: tuple[str, ...] = (),
) -> str:
    """docs/adr/0007-admit-exact-package-transactions-with-an-inline-apt-guard.md#revalidation-under-the-mutation-lock"""
    services = " ".join(_check(_SERVICE, unit, "unit name") for unit in units)
    roots_text = " ".join(_check(_TREE, tree, "configuration directory") for tree in trees)
    hidden = [_check(_PATH, path, "configuration file") for path in private]
    skipped = "".join(f" ! -path {path}" for path in hidden)
    listed = " ".join(_check(_PATH, tree, "listed directory") for tree in listings)
    lists = "find /var/lib/apt/lists -maxdepth 1 -type f"
    parts = [
        f"sha256sum {DPKG_STATUS} /var/lib/apt/extended_states",
        f"{lists} -name '*_InRelease' -exec sha256sum -- {{}} + | LC_ALL=C sort",
        f"{lists} ! -name lock -printf '%f %s %T@\\n' | LC_ALL=C sort",
        (
            "systemctl show -p Id -p LoadState -p ActiveState -p UnitFileState "
            f"-p FragmentPath -p DropInPaths {services}"
        ),
        f"find {roots_text} -xdev -printf '%y %p %l\\n' | LC_ALL=C sort",
        f"find {roots_text} -xdev -type f{skipped} -exec sha256sum -- {{}} + | LC_ALL=C sort",
    ]
    if listed:
        parts.append(f"find {listed} -mindepth 1 -maxdepth 1 -printf '%p\\n' | LC_ALL=C sort")
    if data_listings:
        # docs/bootstrap.md#postgresql: a data root's dot files, such as psql's history, are
        # the administrator's, not data.
        named = " ".join(_check(_PATH, tree, "listed directory") for tree in data_listings)
        parts.append(
            f"find {named} -mindepth 1 -maxdepth 1 ! -name '.*' -printf '%p\\n' | LC_ALL=C sort"
        )
    if ucf:
        parts.append("sha256sum /var/lib/ucf/hashfile")
    if port is not None:
        parts.append(f"ss -Hltn sport = :{int(port)} | awk '{{print $4}}' | LC_ALL=C sort")
    if socket is not None:
        path = _check(_SOCKET, socket, "socket path")
        parts.append(f"ss -Hlx src {path} | awk '{{print $5}}' | LC_ALL=C sort")
    if hidden:
        parts.append(f"stat -c '%s %Y %n' -- {' '.join(hidden)}")
    if paths:
        named = " ".join(_check(_PATH, path, "path") for path in paths)
        parts.append(f"stat -c '%F %U %n' -- {named}")
    if hashed:
        named = " ".join(_check(_PATH, path, "file") for path in hashed)
        parts.append(f"sha256sum -- {named}")
    if resolved:
        named = " ".join(_check(_PATH, path, "link") for path in resolved)
        parts.append(f"readlink -f -- {named}")
    return "{ " + "; ".join(parts) + "; } 2>/dev/null | sha256sum"


def guard(actions: list[PackageAction], *, archives: str = ARCHIVES) -> str:
    """docs/adr/0007-admit-exact-package-transactions-with-an-inline-apt-guard.md#the-guard"""
    if archives != ARCHIVES and not re.fullmatch(
        r"/run/barectl-apt-[0-9a-f]{32}/archives/", archives
    ):
        raise ValueError("Not an admitted archive cache path.")
    approved = sorted(action.normalized() for action in actions)
    if not approved or len(set(approved)) != len(approved):
        raise ValueError("Not a valid package transaction.")
    expected = " ".join(f"'{line}'" for line in approved)
    refuse = "barectl_refuse"
    body = [
        "set -f",
        f'{refuse}() {{ echo "{GUARD_REFUSED} $1"; exit 1; }}',
        f'[ "${{DPKG_FRONTEND_LOCKED:-}}" = true ] || {refuse} frontend-lock',
        f'[ "${{APT_HOOK_INFO_FD:-}}" = 0 ] || {refuse} descriptor',
        (
            f'[ "$(sha256sum {DPKG_STATUS} | cut -d\' \' -f1)" = "${{{STATUS_VARIABLE}:-}}" ] '
            f"|| {refuse} dpkg-status"
        ),
        f"IFS= read -r l || {refuse} truncated",
        f'[ "$l" = "VERSION 3" ] || {refuse} version',
        f'while :; do IFS= read -r l || {refuse} truncated; [ -n "$l" ] || break; done',
        "a=",
        (
            "while IFS= read -r l; do IFS=' '; set -- $l; IFS=; "
            f"[ $# -eq 9 ] || {refuse} form; "
            f'[ "$l" = "$1 $2 $3 $4 $5 $6 $7 $8 $9" ] || {refuse} form; '
            f"case \"$2 $3 $4 $5\" in '- - none <'|'- - no <') ;; *) {refuse} transition;; esac; "
            f'case "$8" in none|no|same|foreign|allowed) ;; *) {refuse} form;; esac; '
            'case "$9" in '
            "'**CONFIGURE**') a=\"$a|C $1 $6 $7\";; "
            f'{archives}*.deb) a="$a|U $1 $6 $7 ${{9#{archives}}}";; '
            f"*) {refuse} action;; esac; done"
        ),
        f'[ -z "$l" ] || {refuse} truncated',
        (
            "[ \"$(printf '%s\\n' \"${a#|}\" | tr '|' '\\n' | LC_ALL=C sort)\" = "
            f"\"$(printf '%s\\n' {expected})\" ] || {refuse} transaction"
        ),
        f'echo "{GUARD_ADMITTED}"',
    ]
    return f"{GUARD_NAME}() {{ {'; '.join(body)}; }}; {GUARD_NAME}"


def package_change(
    unit: str,
    boot_id: str,
    deadline_centiseconds: int,
    *,
    apt: str,
    packages: str,
    scope: str,
    roots: list[tuple[str, str]],
    actions: list[PackageAction],
    services: tuple[str, ...],
    enable: bool,
    start: bool,
    check: Check,
    reload: str = "",
    sockets: tuple[str, ...] = (),
    isolated_archives: bool = False,
    preconditions: tuple[tuple[str, str], ...] = (),
    after: tuple[str, ...] = (),
) -> str:
    """docs/adr/0007-admit-exact-package-transactions-with-an-inline-apt-guard.md#installation

    ``scope`` is the ``package_digest`` text whose digest the plan recorded as ``packages``.
    After a passing check, ``reload`` is reloaded and each of ``sockets`` must listen again;
    ``after`` are the caller's own steps once they do, each of which exits on failure.
    """
    for service in services:
        _check(_SERVICE, service, "unit name")
    steps = [
        *admission(unit, boot_id, deadline_centiseconds),
        *digest_preconditions(preconditions),
        *package_revalidation(apt, packages, scope),
    ]
    if actions:
        archives = archive_cache(unit) if isolated_archives else ARCHIVES
        if isolated_archives:
            steps += archive_cache_steps(unit)
        steps += install_steps(roots, actions, archives=archives)
    elif not (enable or start):
        raise ValueError("A package plan without changes is not applied.")
    for service in services:
        if enable:
            steps.append(f"systemctl enable {service} || exit {Exit.SERVICE_FAILED}")
        if start:
            steps.append(f"systemctl start {service} || exit {Exit.SERVICE_FAILED}")
    steps.append(check.step())
    if reload:
        steps += reload_steps(reload, sockets)
    steps += after
    steps.append(f"exit {Exit.SUCCESS}")
    return "; ".join(steps)


# docs/databases.md#applying-a-driver-plan: how long the pools may take to listen again.
RELOAD_WAIT_TENTHS = 50


def reload_steps(service: str, sockets: tuple[str, ...]) -> list[str]:
    service = _check(_SERVICE, service, "unit name")
    if not sockets:
        raise ValueError("A reload waits for at least one socket.")
    listed = " ".join(_check(_SOCKET, socket, "socket") for socket in sockets)
    return [
        f"systemctl reload {service} || exit {Exit.RELOAD_FAILED}",
        (
            f"i=0; while [ $i -lt {RELOAD_WAIT_TENTHS} ]; do r=0; for s in {listed}; do "
            '[ -n "$(ss -Hlx src "$s")" ] || r=1; done; [ $r -eq 0 ] && break; '
            "sleep 0.1; i=$((i + 1)); done"
        ),
        f"[ $i -lt {RELOAD_WAIT_TENTHS} ] || exit {Exit.RELOAD_FAILED}",
    ]


def package_revalidation(apt: str, packages: str, scope: str) -> list[str]:
    """Exit DRIFT unless the APT digest and the package digest ``scope`` are the reviewed ones."""
    apt = _check(_DIGEST, apt, "digest")
    packages = _check(_DIGEST, packages, "digest")
    if not re.fullmatch(r"\{ .{1,4000} \} 2>/dev/null \| sha256sum", scope, re.DOTALL):
        raise ValueError("Not a valid package digest.")
    return [
        f'[ "$({APT_DIGEST} | cut -d" " -f1)" = {apt} ] || exit {Exit.DRIFT}',
        f'[ "$({scope} | cut -d" " -f1)" = {packages} ] || exit {Exit.DRIFT}',
    ]


def archive_cache(unit: str) -> str:
    _check(_UNIT, unit, "unit name")
    return f"/run/barectl-apt-{unit.removeprefix(UNIT_PREFIX).removesuffix('.service')}/archives/"


def digest_preconditions(checks: tuple[tuple[str, str], ...]) -> list[str]:
    steps: list[str] = []
    for script, digest in checks:
        _check(_DIGEST, digest, "digest")
        if len(script.encode()) > 4000 or not script.endswith("| sha256sum"):
            raise ValueError("Not a fixed digest precondition.")
        steps.append(f'[ "$( {script} | cut -d" " -f1)" = {digest} ] || exit {Exit.DRIFT}')
    return steps


def archive_cache_steps(unit: str) -> list[str]:
    root = archive_cache(unit).removesuffix("archives/").rstrip("/")
    return [
        f"d={root}",
        '[ ! -L "$d" ] || exit 21',
        "[ \"$(stat -c '%F %u %g %a' \"$d\")\" = 'directory 0 0 755' ] || exit 21",
        '[ -z "$(find "$d" -mindepth 1 -maxdepth 1 -print -quit)" ] || exit 21',
        "trap 'rm -rf -- \"$d\"' EXIT",
        "trap 'exit 20' HUP INT TERM",
        'mkdir -m 0755 "$d/archives" || exit 23',
        'mkdir -m 0700 "$d/archives/partial" || exit 23',
        'chown _apt:root "$d/archives/partial" || exit 23',
    ]


def install_steps(
    roots: list[tuple[str, str]],
    actions: list[PackageAction],
    *,
    refuse: str = "",
    archives: str = ARCHIVES,
) -> list[str]:
    """docs/adr/0007-admit-exact-package-transactions-with-an-inline-apt-guard.md#installation

    ``refuse`` runs before each exit that means dpkg changed nothing, such as undoing a
    caller's own preparation.
    """
    requested = " ".join(
        f"{_check(_PACKAGE, name, 'package name')}={_check(_VERSION, version, 'version')}"
        for name, version in roots
    )
    if not requested:
        raise ValueError("A package transaction needs its root packages.")

    def unchanged(code: int) -> str:
        return f"{{ {refuse}exit {code}; }}" if refuse else f"exit {code}"

    options = " ".join(shlex.quote(option) for option in INSTALL_OPTIONS)
    if archives != ARCHIVES:
        options += " " + shlex.join(
            [
                "-o",
                f"Dir::Cache::Archives={archives}",
                "-o",
                "Acquire::ForceHash=SHA256",
                "-o",
                "APT::Sandbox::User=_apt",
            ]
        )
    hook = shlex.quote(f"DPkg::Pre-Install-Pkgs::={guard(actions, archives=archives)}")
    version = shlex.quote(f"DPkg::Tools::Options::{GUARD_NAME}()::Version=3")
    return [
        f"b=$(sha256sum {DPKG_STATUS} | cut -d' ' -f1)",
        (
            f'o=$({STATUS_VARIABLE}="$b" DEBIAN_FRONTEND=noninteractive apt-get {options} '
            f"-o {hook} -o {version} install {requested} 2>&1 </dev/null); s=$?"
        ),
        f"printf '%s\\n' \"$o\" | tail -c {MAX_JOURNAL_OUTPUT}",
        f"a=$(sha256sum {DPKG_STATUS} | cut -d' ' -f1)",
        (
            'if [ "$a" = "$b" ]; then '
            f"printf '%s\\n' \"$o\" | grep -q '^{GUARD_REFUSED} ' "
            f"&& {unchanged(Exit.TRANSACTION_REFUSED)}; "
            f"case \"$o\" in *'Could not get lock'*) {unchanged(Exit.PACKAGE_MANAGER_BUSY)};; "
            "esac; "
            f'[ "$s" -eq 0 ] && {unchanged(Exit.DRIFT)}; {unchanged(Exit.INSTALL_NOT_STARTED)}; fi'
        ),
        f"m=$(printf '%s\\n' \"$o\" | grep -cx '{GUARD_ADMITTED}')",
        f'[ "$s" -eq 0 ] && [ "$m" -eq 1 ] || exit {Exit.INSTALL_FAILED}',
    ]


@dataclass(frozen=True)
class ClearTarget:
    unit: str
    invocation_id: str


def clear_results(
    unit: str, boot_id: str, deadline_centiseconds: int, targets: list[ClearTarget]
) -> str:
    if not targets or len(targets) > CLEANUP_BATCH:
        raise ValueError("Not a valid list of units to clear.")
    entries = []
    for target in targets:
        name = _check(_UNIT, target.unit, "unit name")
        if name == unit:
            raise ValueError("A cleanup cannot clear its own unit.")
        entries.append(f"{name}:{_check(_INVOCATION, target.invocation_id, 'invocation ID')}")
    show = "systemctl show --value -p"
    steps = [
        *admission(unit, boot_id, deadline_centiseconds, capacity=CLEANUP_CEILING),
        f"t='{' '.join(entries)}'",
        (
            "for e in $t; do n=${e%%:*}; i=${e#*:}; "
            f'[ "$({show} LoadState "$n")" = not-found ] && continue; '
            f'[ "$({show} InvocationID "$n")" = "$i" ] || exit {Exit.DRIFT}; '
            f'case "$({show} ActiveState "$n")/$({show} SubState "$n")" in '
            f"active/exited|failed/*|inactive/*) ;; *) exit {Exit.DRIFT};; esac; "
            f'c=$({show} ControlGroup "$n"); v="/sys/fs/cgroup$c/cgroup.events"; '
            'if [ -n "$c" ] && [ -e "$v" ]; then '
            f'grep -qx \'populated 0\' "$v" 2>/dev/null || [ ! -e "$v" ] || exit {Exit.DRIFT}; '
            "fi; done"
        ),
        (
            "for e in $t; do n=${e%%:*}; "
            f'[ "$({show} LoadState "$n")" = not-found ] && continue; '
            f'if [ "$({show} ActiveState "$n")" = active ]; then '
            f'systemctl stop "$n" || exit {Exit.CLEANUP_FAILED}; '
            f'else systemctl reset-failed "$n" || exit {Exit.CLEANUP_FAILED}; fi; done'
        ),
        f"exit {Exit.SUCCESS}",
    ]
    return "; ".join(steps)


class Probe(IntEnum):
    LOCKED = 0
    LOCK_CONFLICT = Exit.LOCK_CONFLICT
    UNSAFE_LOCK = Exit.UNSAFE_LOCK


def closure_probe(unit: str) -> list[str]:
    """docs/adr/0006-use-native-bootstrap-execution.md#unknown-outcomes"""
    unit = _check(_UNIT, unit, "unit name")
    steps = [
        *_lock(),
        "cat /proc/sys/kernel/random/boot_id",
        "cut -d' ' -f1 /proc/uptime | tr -d .",
        (
            f'p=0; for e in {_UNIT_EVENTS}; do [ -e "$e" ] || continue; '
            'grep -qx \'populated 1\' "$e" && p=$((p + 1)); done; echo "populated $p"'
        ),
        f"systemctl show --value -p LoadState {unit}",
        _RENEWAL,
        'echo "renewal $r"',
        f"exit {Probe.LOCKED}",
    ]
    return ["/usr/bin/sh", "-c", "; ".join(steps)]


@dataclass(frozen=True)
class ProbeEvidence:
    boot_id: str
    uptime_centiseconds: int
    # Bootstrap units whose control groups still have processes.
    populated: int
    unit_loaded: bool
    # Certbot's renewal service still has processes.
    renewal_active: bool


def parse_probe(text: str) -> ProbeEvidence:
    lines = text.splitlines()
    if (
        len(lines) != 5
        or not _BOOT.fullmatch(lines[0])
        or not re.fullmatch(r"\d{1,15}", lines[1])
        or not (populated := re.fullmatch(r"populated (\d{1,4})", lines[2]))
        or not re.fullmatch(r"[a-z-]{1,30}", lines[3])
        or not (renewal := re.fullmatch(r"renewal ([01])", lines[4]))
    ):
        raise Unreadable("The closure probe is not in its expected form.")
    return ProbeEvidence(
        lines[0], int(lines[1]), int(populated[1]), lines[3] != "not-found", renewal[1] == "1"
    )


def submission(unit: str, script: str, *, isolated_archives: bool = False) -> list[str]:
    """docs/adr/0006-use-native-bootstrap-execution.md#submission"""
    _check(_UNIT, unit, "unit name")
    if len(script.encode()) > MAX_PAYLOAD:
        raise PayloadTooLarge
    runtime = []
    if isolated_archives:
        directory = archive_cache(unit).split("/")[2]
        runtime = [
            f"--property=RuntimeDirectory={directory}",
            "--property=RuntimeDirectoryMode=0755",
            "--property=RuntimeDirectoryPreserve=no",
        ]
    return [
        SYSTEMD_RUN,
        f"--unit={unit}",
        "--description=Barectl reviewed apply",
        "--quiet",
        "--expand-environment=no",
        "--service-type=exec",
        "--remain-after-exit",
        "--property=ExitType=cgroup",
        "--property=Restart=no",
        f"--property=RuntimeMaxSec={RUNTIME_MAX}",
        f"--property=TimeoutStopSec={TIMEOUT_STOP}",
        "--property=KillMode=control-group",
        "--property=StandardInput=null",
        "--property=StandardOutput=journal",
        "--property=StandardError=journal",
        *runtime,
        "/usr/bin/sh",
        "-c",
        script,
    ]


def privileged(argv: list[str], *, root: bool) -> str:
    command = shlex.join(argv)
    return command if root else f"sudo -n {command}"


def authorization(argv: list[str]) -> str:
    """Lists whether sudo authorizes exactly ``argv`` without a password; runs nothing."""
    return f"sudo -n -l {shlex.join(argv)}"


def is_root(shell: RemoteShell) -> bool | None:
    result = shell.run(USER_ID)
    if result.exit_status != 0 or result.truncated:
        return None
    return result.stdout.strip() == "0"


def retained_units(shell: RemoteShell) -> int | None:
    result = shell.run(RETAINED_UNITS)
    if result.exit_status != 0 or result.truncated:
        return None
    return sum(1 for line in result.stdout.splitlines() if UNIT_PREFIX in line)


def inspection(unit: str) -> str:
    _check(_UNIT, unit, "unit name")
    return f"cat /proc/sys/kernel/random/boot_id; {_unit_report(unit)}"


@dataclass(frozen=True)
class UnitEvidence:
    unit: str
    boot_id: str
    found: bool
    active_state: str
    sub_state: str
    result: str
    exec_main_code: int
    exec_main_status: int
    invocation_id: str
    # The unit's control group still has processes.
    populated: bool

    @property
    def terminal(self) -> bool:
        if not self.found or self.populated:
            return False
        exited = self.active_state == "active" and self.sub_state == "exited"
        return exited or self.active_state in {"failed", "inactive"}

    @property
    def execution(self) -> Execution:
        if not self.found:
            return Execution.NOT_FOUND
        if not self.terminal:
            return Execution.RUNNING
        if self.result == "timeout":
            return Execution.TIMED_OUT
        if self.exec_main_code in _CLD_SIGNALLED:
            return Execution.KILLED
        if self.exec_main_code != CLD_EXITED:
            # The main process never ran, such as a unit that failed to start.
            return Execution.FAILED
        try:
            outcome = _EXECUTIONS[Exit(self.exec_main_status)]
        except ValueError:
            return Execution.FAILED
        if outcome == Execution.SUCCEEDED and self.result != "success":
            return Execution.FAILED
        return outcome


def parse_inspection(text: str, unit: str) -> UnitEvidence:
    lines = text.splitlines()
    if len(lines) != len(_PROPERTIES) + 2 or not _BOOT.fullmatch(lines[0]):
        raise Unreadable("The unit inspection is not in systemd's form.")
    return _parse_unit(lines[0], lines[1:], unit)


def _parse_unit(boot_id: str, lines: list[str], unit: str | None) -> UnitEvidence:
    """``unit`` is the expected name, or ``None`` for any bootstrap unit."""
    values: dict[str, str] = {}
    for line in lines[:-1]:
        key, separator, value = line.partition("=")
        if not separator or key not in _PROPERTIES or len(value) > 200:
            raise Unreadable("The unit inspection is not in systemd's form.")
        values[key] = value
    populated = re.fullmatch(r"populated ([01])", lines[-1])
    if set(values) != set(_PROPERTIES) or populated is None:
        raise Unreadable("The unit inspection is not in systemd's form.")
    expected = values["Id"] == unit if unit is not None else _UNIT.fullmatch(values["Id"])
    if not expected:
        raise Unreadable("The unit inspection is not in systemd's form.")
    token = re.compile(r"[a-z-]{1,30}")
    states = (values["LoadState"], values["ActiveState"], values["SubState"], values["Result"])
    codes = (values["ExecMainCode"], values["ExecMainStatus"])
    if not all(token.fullmatch(state) for state in states) or not all(
        re.fullmatch(r"\d{1,3}", code) for code in codes
    ):
        raise Unreadable("The unit inspection is not in systemd's form.")
    if not re.fullmatch(r"[0-9a-f]{32}|", values["InvocationID"]):
        raise Unreadable("The unit inspection is not in systemd's form.")
    return UnitEvidence(
        unit=values["Id"],
        boot_id=boot_id,
        found=values["LoadState"] != "not-found",
        active_state=values["ActiveState"],
        sub_state=values["SubState"],
        result=values["Result"],
        exec_main_code=int(values["ExecMainCode"]),
        exec_main_status=int(values["ExecMainStatus"]),
        invocation_id=values["InvocationID"],
        populated=populated[1] == "1",
    )


def _unit_report(unit: str) -> str:
    """``unit`` is a validated name, or the quoted shell variable holding one."""
    properties = " ".join(f"-p {name}" for name in _PROPERTIES)
    events = '"/sys/fs/cgroup$cg/cgroup.events"'
    # docs/adr/0006-use-native-bootstrap-execution.md#inspection-and-outcomes
    return (
        f"systemctl show {properties} {unit}; "
        f"cg=$(systemctl show -p ControlGroup --value {unit}); "
        f'if [ -n "$cg" ] && [ -r {events} ]; then '
        f"grep '^populated ' {events} 2>/dev/null "
        f"|| {{ [ ! -e {events} ] && echo 'populated 0'; }}; "
        "else echo 'populated 0'; fi"
    )


RETAINED_STATES: Final = (
    "cat /proc/sys/kernel/random/boot_id; "
    f"for u in $({RETAINED_UNITS} | cut -d' ' -f1); do {_unit_report('"$u"')}; done"
)


def parse_retained_states(text: str) -> tuple[str, list[UnitEvidence]]:
    lines = text.splitlines()
    size = len(_PROPERTIES) + 1
    if not lines or not _BOOT.fullmatch(lines[0]) or (len(lines) - 1) % size:
        raise Unreadable("The retained units are not in systemd's form.")
    return lines[0], [
        _parse_unit(lines[0], lines[start : start + size], None)
        for start in range(1, len(lines), size)
    ]


def inspect(shell: RemoteShell, unit: str) -> UnitEvidence:
    result = shell.run(inspection(unit))
    if result.exit_status != 0 or result.truncated:
        raise Unreadable("The unit could not be inspected.")
    return parse_inspection(result.stdout, unit)
