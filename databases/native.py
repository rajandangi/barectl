"""A database binding's apply payload and its verification read.

docs/databases.md#applying-a-binding-plan; the boundaries are recorded in
docs/adr/0013-create-a-database-binding-statement-by-statement.md.
"""

import re
import shlex
from dataclasses import dataclass

from bootstrap import native as bootstrap_native
from bootstrap import profiles
from bootstrap.releases import RELEASES
from discovery.models import DatabaseEngine
from sites import native as site_native
from sites.convention import SitePaths

from . import binding

_DIGEST = re.compile(r"[0-9a-f]{64}")
_VERSION = re.compile(r"[A-Za-z0-9.+~:-]{1,100}")
# How much of the catalog read a failed statement prints to the unit's journal.
JOURNAL_CATALOG = 16 * 1024


class Exit:
    """docs/databases.md#recovering-a-partial-binding: the payload's boundaries."""

    DRIFT = bootstrap_native.Exit.DRIFT
    DRIVER_UNAVAILABLE = 32
    PRINCIPAL_CONFLICT = 33
    PRINCIPAL_REFUSED = 34
    PRINCIPAL_UNKNOWN = 56
    DATABASE_EXISTS = 57
    DATABASE_FAILED = 58
    PRIVILEGES_FAILED = 59
    SCHEMA_FAILED = 60
    AFTER_STATE = 61
    PROOF_FAILED = 62
    PROBE_LEFT = 63
    PROBE_FAILED = 64


@dataclass(frozen=True)
class BindingChange:
    """What one reviewed binding creates and rechecks, as the payload needs it."""

    release: str
    identifier: str
    engine: DatabaseEngine
    uid: int
    gid: int
    token: str
    probe: str
    site_digest: str
    engine_digest: str
    catalog_before: str
    catalog_after: str
    # Whether the other engine is installed, so the read also covers it.
    other: bool
    # The driver package's version, which must still be installed.
    driver_version: str
    # PostgreSQL: template1's reviewed libc locale; empty for MariaDB.
    locale: str
    statements: tuple[binding.Statement, ...]

    @property
    def paths(self) -> SitePaths:
        return SitePaths(self.identifier, RELEASES[self.release].php)

    @property
    def principal(self) -> str:
        return binding.principal(self.identifier)

    @property
    def probe_path(self) -> str:
        return binding.probe_path(self.identifier, self.token)

    @property
    def probe_sha256(self) -> str:
        return binding.digest(self.probe)


@dataclass(frozen=True)
class Step:
    name: str
    text: str


def _check(change: BindingChange) -> None:
    """Every value the payload interpolates is the reviewed convention's, or it is refused."""
    name = change.principal
    for value in (
        change.site_digest,
        change.engine_digest,
        change.catalog_before,
        change.catalog_after,
    ):
        if not _DIGEST.fullmatch(value):
            raise ValueError("Not a valid digest.")
    if change.statements != binding.statements(change.engine, name, change.locale):
        raise ValueError("The statements are not the convention's.")
    if change.probe != binding.render_probe(change.engine, name, change.token):
        raise ValueError("The probe is not the convention's.")
    if not (0 < change.uid < 2**31 and 0 < change.gid < 2**31):
        raise ValueError("Not valid IDs.")
    if change.release not in RELEASES or not _VERSION.fullmatch(change.driver_version):
        raise ValueError("Not a reviewed release or driver version.")


def _statement(change: BindingChange, statement: binding.Statement) -> str:
    text = shlex.quote(statement.text)
    if change.engine == DatabaseEngine.MARIADB:
        return f"q {text}"
    return f"q {statement.database} {text}"


def _client(engine: DatabaseEngine) -> str:
    """``q``: one statement through the engine's administrator, printing its errors."""
    if engine == DatabaseEngine.MARIADB:
        return f'q(){{ {binding.client(engine)} "$1" 2>&1; }}'
    return f'q(){{ {binding.client(engine)} -v VERBOSITY=sqlstate -d "$1" -c "$2" 2>&1; }}'


def _statements(change: BindingChange) -> list[Step]:
    """Each statement in its own invocation, classified at its boundary."""
    engine = change.engine
    duplicate = {
        DatabaseEngine.MARIADB: ("ERROR 1396 (", "ERROR 1007 ("),
        DatabaseEngine.POSTGRESQL: ("ERROR:  42710", "ERROR:  42P04"),
    }[engine]
    principal, database, *rest = change.statements
    before = change.catalog_before
    steps = [
        Step(
            "principal",
            f"o=$({_statement(change, principal)}) || {{ printf '%s\\n' \"$o\"; "
            f"case \"$o\" in *'{duplicate[0]}'*) x {Exit.PRINCIPAL_CONFLICT};; esac; "
            f"[ \"$(c | sha256sum | cut -d' ' -f1)\" = {before} ] && "
            f"x {Exit.PRINCIPAL_REFUSED}; y {Exit.PRINCIPAL_UNKNOWN}; }}",
        ),
        Step(
            "database",
            f"o=$({_statement(change, database)}) || {{ printf '%s\\n' \"$o\"; "
            f"case \"$o\" in *'{duplicate[1]}'*) y {Exit.DATABASE_EXISTS};; esac; "
            f"y {Exit.DATABASE_FAILED}; }}",
        ),
    ]
    codes = (Exit.PRIVILEGES_FAILED, Exit.SCHEMA_FAILED)
    for statement, code in zip(rest, codes, strict=False):
        steps.append(
            Step(
                statement.step.value,
                f"o=$({_statement(change, statement)}) || {{ printf '%s\\n' \"$o\"; y {code}; }}",
            )
        )
    return steps


def binding_steps(unit: str, boot_id: str, deadline: int, change: BindingChange) -> list[Step]:
    """docs/databases.md#applying-a-binding-plan: each named fragment, in order."""
    _check(change)
    paths, release = change.paths, RELEASES[change.release]
    php = paths.php
    probe = change.probe_path
    suffix = unit.removeprefix(bootstrap_native.UNIT_PREFIX).removesuffix(".service")
    spec = binding.ENGINES[change.engine]
    engine_scope = profiles.profile(release, spec.profile).revalidation
    driver = profiles.profile(release, spec.driver).roots[0]
    catalog = "\"$(c | sha256sum | cut -d' ' -f1)\""
    pre = binding.expected_pre(change.token, change.uid, change.gid, change.engine)
    proof = binding.expected_proof(change.token, change.uid, change.engine, change.principal)
    lines = " ".join(shlex.quote(line) for line in change.probe.removesuffix("\n").split("\n"))
    owner = f"root:{change.principal}"
    request = f"f {paths.socket} {probe}"
    return [
        Step("admission", "; ".join(bootstrap_native.admission(unit, boot_id, deadline))),
        Step(
            "helpers",
            "; ".join(
                (
                    "export LC_ALL=C PATH=/usr/sbin:/usr/bin; umask 077; set -C",
                    (
                        'a(){ for d in "$@"; do while :; do [ ! -L "$d" ] && '
                        "[ \"$(stat -c '%F %u' -- \"$d\")\" = 'directory 0' ] && "
                        "[ $((0$(stat -c '%a' -- \"$d\") & 022)) -eq 0 ] || return 1; "
                        '[ "$d" = / ] && break; d=$(dirname -- "$d"); done; done; }'
                    ),
                    (
                        f"r(){{ if [ -f {probe} ] && [ ! -L {probe} ] && "
                        f"[ \"$(sha256sum <{probe} | cut -d' ' -f1)\" = {change.probe_sha256} ]; "
                        f"then rm -f -- {probe}; fi; [ ! -e {probe} ] && [ ! -L {probe} ]; }}"
                    ),
                    f'x(){{ r || exit {Exit.PROBE_LEFT}; exit "$1"; }}',
                    f'y(){{ c | head -c {JOURNAL_CATALOG}; x "$1"; }}',
                    site_native.writer(suffix),
                    _client(change.engine),
                    binding.catalog_function(change.principal, change.engine, change.other),
                    binding.fastcgi_client(php),
                )
            ),
        ),
        Step(
            "revalidation",
            "; ".join(
                (
                    (
                        f'[ "$({site_native.site_digest(paths)} | cut -d" " -f1)" = '
                        f"{change.site_digest} ] || exit {Exit.DRIFT}"
                    ),
                    (
                        f'[ "$({engine_scope} | cut -d" " -f1)" = {change.engine_digest} ] '
                        f"|| exit {Exit.DRIFT}"
                    ),
                    (
                        f"[ \"$(dpkg-query -W -f='${{db:Status-Abbrev}}${{Version}}' {driver})\" "
                        f"= 'ii {change.driver_version}' ] || exit {Exit.DRIFT}"
                    ),
                    f"[ {catalog} = {change.catalog_before} ] || exit {Exit.DRIFT}",
                    (
                        f"[ ! -e {probe} ] && [ ! -L {probe} ] && a {paths.boundary} "
                        f"|| exit {Exit.DRIFT}"
                    ),
                    (
                        f'for b in /usr/bin/php{php} /usr/sbin/runuser; do [ -x "$b" ] '
                        f"|| exit {Exit.DRIFT}; done"
                    ),
                )
            ),
        ),
        Step(
            "probe",
            f"printf '%s\\n' {lines} | w {paths.boundary} {probe.rpartition('/')[2]} "
            f"{owner} 0640 {change.probe_sha256} || x {Exit.PROBE_FAILED}",
        ),
        Step(
            "pre-check",
            f'[ "$({request} pre)" = {shlex.quote(pre)} ] || x {Exit.DRIVER_UNAVAILABLE}',
        ),
        Step("recheck", f"[ {catalog} = {change.catalog_before} ] || x {Exit.DRIFT}"),
        *_statements(change),
        Step("after-state", f"[ {catalog} = {change.catalog_after} ] || y {Exit.AFTER_STATE}"),
        Step("proof", f'[ "$({request} full)" = {shlex.quote(proof)} ] || x {Exit.PROOF_FAILED}'),
        Step(
            "probe removal",
            f"r || exit {Exit.PROBE_LEFT}; echo 'barectl-database: verified'; exit 0",
        ),
    ]


def binding_payload(unit: str, boot_id: str, deadline: int, change: BindingChange) -> str:
    return "; ".join(step.text for step in binding_steps(unit, boot_id, deadline, change))


# Verification --------------------------------------------------------------------------


def state(change: BindingChange) -> list[str]:
    """docs/databases.md#applying-a-binding-plan: the binding's native state after a run,
    read as root: the catalog read, whether the probe remains, the administrator's
    readiness check and the services."""
    release = RELEASES[change.release]
    spec = binding.ENGINES[change.engine]
    profile = profiles.profile(release, spec.profile)
    probe = change.probe_path
    units = " ".join((profile.serving_unit, change.paths.fpm_service))
    return site_native.script(
        "; ".join(
            (
                "export LC_ALL=C PATH=/usr/sbin:/usr/bin",
                binding.catalog_function(change.principal, change.engine, change.other),
                "c",
                "echo '== readiness'",
                f"{profile.check.command} 2>/dev/null",
                "echo '== state'",
                (
                    f'if [ -e {probe} ] || [ -L {probe} ]; then echo "probe present"; '
                    'else echo "probe absent"; fi'
                ),
                (
                    f'for u in {units}; do echo "unit $u '
                    '$(systemctl show -p ActiveState --value "$u")/'
                    '$(systemctl show -p SubState --value "$u")"; done'
                ),
                f'echo "listening $(ss -Hlx src {change.paths.socket} | grep -c .)"',
            )
        )
    )
