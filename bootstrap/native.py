"""The released stack's package payloads: APT revalidation, the inline package guard and
package transactions (docs/adr/0007-admit-exact-package-transactions-with-an-inline-apt-guard.md).

They run through the change engine's native adapter in ``operations.native``. The legacy
kinds reach the adapter through this module until they are deleted with the released stack
(#341); new code imports ``operations.native`` directly.
"""

import re
import shlex
from dataclasses import dataclass
from typing import Final

from operations.native import (
    CLD_EXITED,
    CLEANUP_BATCH,
    CLEANUP_CEILING,
    LOCK_DIRECTORY,
    LOCK_FILE,
    MAX_BODY,
    MAX_JOURNAL_OUTPUT,
    MAX_PAYLOAD,
    RETAINED_LIMIT,
    RETAINED_STATES,
    RETAINED_UNITS,
    RUNTIME_MAX,
    SYSTEMD_RUN,
    UNIT_PREFIX,
    USER_ID,
    Exit,
    Limits,
    PayloadTooLarge,
    Probe,
    ProbeEvidence,
    UnitEvidence,
    Unreadable,
    admission,
    archive_cache,
    authorization,
    checked,
    closure_probe,
    digest_preconditions,
    inspect,
    inspection,
    is_root,
    lock_steps,
    new_unit_name,
    parse_digest,
    parse_inspection,
    parse_probe,
    parse_retained_states,
    privileged,
    renewal_check,
    retained_units,
    staged,
    submission,
)

# The adapter names the legacy kinds use through this module.
__all__ = [
    "CLD_EXITED",
    "CLEANUP_BATCH",
    "CLEANUP_CEILING",
    "LOCK_DIRECTORY",
    "LOCK_FILE",
    "MAX_BODY",
    "MAX_JOURNAL_OUTPUT",
    "MAX_PAYLOAD",
    "RETAINED_LIMIT",
    "RETAINED_STATES",
    "RETAINED_UNITS",
    "RUNTIME_MAX",
    "SYSTEMD_RUN",
    "UNIT_PREFIX",
    "USER_ID",
    "Exit",
    "Limits",
    "PayloadTooLarge",
    "Probe",
    "ProbeEvidence",
    "UnitEvidence",
    "Unreadable",
    "admission",
    "archive_cache",
    "authorization",
    "checked",
    "closure_probe",
    "digest_preconditions",
    "inspect",
    "inspection",
    "is_root",
    "lock_steps",
    "new_unit_name",
    "parse_digest",
    "parse_inspection",
    "parse_probe",
    "parse_retained_states",
    "privileged",
    "renewal_check",
    "retained_units",
    "staged",
    "submission",
]

_DIGEST = re.compile(r"[0-9a-f]{64}")
_UNIT = re.compile(r"barectl-apply-[0-9a-f]{32}\.service")
_INVOCATION = re.compile(r"[0-9a-f]{32}")

# docs/adr/0006-use-native-bootstrap-execution.md#payload
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


def metadata_refresh(
    unit: str,
    boot_id: str,
    deadline_centiseconds: int,
    apt: str,
    *,
    preconditions: tuple[tuple[str, str], ...] = (),
) -> str:
    apt = checked(_DIGEST, apt, "digest")
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
        checked(_EXECUTABLE, executable, "check command")
        for argument in arguments:
            if len(argument) > self.limit:
                raise ValueError("Not a valid check argument.")
            checked(_ARGUMENT, argument, "check argument")
        if self.expected is not None:
            checked(_OUTPUT, self.expected, "expected check output")
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
        package = checked(_PACKAGE, self.package, "package name")
        version = checked(_VERSION, self.version, "version")
        architecture = checked(_ARCHITECTURE, self.architecture, "architecture")
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
    services = " ".join(checked(_SERVICE, unit, "unit name") for unit in units)
    roots_text = " ".join(checked(_TREE, tree, "configuration directory") for tree in trees)
    hidden = [checked(_PATH, path, "configuration file") for path in private]
    skipped = "".join(f" ! -path {path}" for path in hidden)
    listed = " ".join(checked(_PATH, tree, "listed directory") for tree in listings)
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
        named = " ".join(checked(_PATH, tree, "listed directory") for tree in data_listings)
        parts.append(
            f"find {named} -mindepth 1 -maxdepth 1 ! -name '.*' -printf '%p\\n' | LC_ALL=C sort"
        )
    if ucf:
        parts.append("sha256sum /var/lib/ucf/hashfile")
    if port is not None:
        parts.append(f"ss -Hltn sport = :{int(port)} | awk '{{print $4}}' | LC_ALL=C sort")
    if socket is not None:
        path = checked(_SOCKET, socket, "socket path")
        parts.append(f"ss -Hlx src {path} | awk '{{print $5}}' | LC_ALL=C sort")
    if hidden:
        parts.append(f"stat -c '%s %Y %n' -- {' '.join(hidden)}")
    if paths:
        named = " ".join(checked(_PATH, path, "path") for path in paths)
        parts.append(f"stat -c '%F %U %n' -- {named}")
    if hashed:
        named = " ".join(checked(_PATH, path, "file") for path in hashed)
        parts.append(f"sha256sum -- {named}")
    if resolved:
        named = " ".join(checked(_PATH, path, "link") for path in resolved)
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
        checked(_SERVICE, service, "unit name")
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
    service = checked(_SERVICE, service, "unit name")
    if not sockets:
        raise ValueError("A reload waits for at least one socket.")
    listed = " ".join(checked(_SOCKET, socket, "socket") for socket in sockets)
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
    apt = checked(_DIGEST, apt, "digest")
    packages = checked(_DIGEST, packages, "digest")
    if not re.fullmatch(r"\{ .{1,4000} \} 2>/dev/null \| sha256sum", scope, re.DOTALL):
        raise ValueError("Not a valid package digest.")
    return [
        f'[ "$({APT_DIGEST} | cut -d" " -f1)" = {apt} ] || exit {Exit.DRIFT}',
        f'[ "$({scope} | cut -d" " -f1)" = {packages} ] || exit {Exit.DRIFT}',
    ]


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
        f"{checked(_PACKAGE, name, 'package name')}={checked(_VERSION, version, 'version')}"
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
        name = checked(_UNIT, target.unit, "unit name")
        if name == unit:
            raise ValueError("A cleanup cannot clear its own unit.")
        entries.append(f"{name}:{checked(_INVOCATION, target.invocation_id, 'invocation ID')}")
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
