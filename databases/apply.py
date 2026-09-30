"""Applying a reviewed binding plan: its payload, outcome and verification.

docs/databases.md#applying-a-binding-plan; the boundaries are recorded in
docs/adr/0013-create-a-database-binding-statement-by-statement.md.
"""

from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone

from bootstrap import native as bootstrap_native
from bootstrap import profiles
from bootstrap.models import ApplyRun, ConfigurationPlan, Execution, PlanEvidence, Verification
from bootstrap.native import UnitEvidence
from bootstrap.releases import RELEASES
from discovery.models import DatabaseEngine
from discovery.observations.databases import (
    BindingState,
    CatalogFormatError,
    parse_mariadb,
    recognize_mariadb,
)
from discovery.ssh import RemoteShell
from operations.lifecycle import OperationRefused

from . import binding, native
from .models import (
    BindingRecord,
    DatabaseRunResult,
    RunDatabaseBinding,
    RunDatabaseStatement,
)

Exit = native.Exit
Kind = PlanEvidence.Kind
EVIDENCE_FAILURE = (
    "The reviewed binding plan is incomplete or differs from the convention, so Barectl "
    "submitted nothing. Prepare a new database plan."
)
VERIFY_PRIVILEGE = (
    "The SSH user is not root, and sudo -n -l does not authorize the fixed read-only command "
    "that verifies the binding afterwards, so Barectl submitted nothing. Barectl never "
    "installs a sudo policy or asks for a password."
)
VERIFICATION_FAILED = (
    "The binding was created, but it does not match the review: {problems} Barectl does not "
    "repair or drop anything; inspect the server through ordinary administration. The "
    "refreshed discovery shows what is there now."
)
_REFUSED = {
    Exit.DRIVER_UNAVAILABLE: Execution.DRIVER_UNAVAILABLE,
    Exit.PRINCIPAL_CONFLICT: Execution.PRINCIPAL_CONFLICT,
    Exit.PRINCIPAL_REFUSED: Execution.STATEMENT_REFUSED,
}
_PARTIAL = frozenset(range(Exit.PRINCIPAL_UNKNOWN, Exit.PROBE_FAILED + 1))
_AFTER = (
    " Barectl never drops, replaces or resumes what exists, and never retries the run. A "
    "new database plan shows what exists; it is refused as a partial binding until ordinary "
    "administration completes or removes it (docs/databases.md#recovering-a-partial-binding)."
)


def execution(evidence: UnitEvidence) -> Execution:
    """The binding payload's own exit codes; every other outcome as bootstrap reads it."""
    exited = evidence.exec_main_code == bootstrap_native.CLD_EXITED
    terminal = evidence.found and evidence.terminal and exited
    if terminal and evidence.exec_main_status in _REFUSED:
        return _REFUSED[evidence.exec_main_status]
    if terminal and evidence.exec_main_status in _PARTIAL:
        return Execution.PARTIAL
    return evidence.execution


def _boundaries(record: BindingRecord) -> dict[int, str]:
    """docs/databases.md#recovering-a-partial-binding: what exists after each boundary."""
    name, engine = record.principal, DatabaseEngine(record.engine).label
    probe = record.probe_path
    return {
        Exit.PRINCIPAL_UNKNOWN: (
            f"Creating the principal {name} failed, but the catalog changed, so a principal "
            f"may exist whose origin is unknown. Inspect it through {engine}'s administration."
        ),
        Exit.DATABASE_EXISTS: (
            f"The principal {name} was created, but a database {name} already existed and was "
            "not adopted; nothing was granted."
        ),
        Exit.DATABASE_FAILED: (
            f"The principal {name} was created, but creating the database {name} failed; the "
            "database may exist. Nothing was granted."
        ),
        Exit.PRIVILEGES_FAILED: (
            f"The principal and database {name} exist, but granting the convention's "
            "privileges failed."
        ),
        Exit.SCHEMA_FAILED: (
            f"The principal and database {name} exist with their database privileges, but "
            "revoking PUBLIC's rights on the public schema failed."
        ),
        Exit.AFTER_STATE: (
            f"Every statement succeeded, but the catalog under {name} differs from the reviewed "
            "result, such as an extra grant another administrator added meanwhile."
        ),
        Exit.PROOF_FAILED: (
            f"The binding exists, but the site's pool could not use it as reviewed: its "
            f"identity, a table it creates and drops, the refused operations or the refused "
            f"password-less TCP login differ. A table named barectl_{record.probe_token} may "
            f"remain in {name}. The probe was removed."
        ),
        Exit.PROBE_LEFT: (
            f"The run stopped after writing the temporary probe {probe}, which could not be "
            "removed or had changed, so verification is incomplete. Inspect the probe, then "
            f"remove it with rm {probe}."
        ),
        Exit.PROBE_FAILED: (
            f"Publishing the temporary probe {probe} failed before any statement ran, so the "
            f"catalog is unchanged; a staged .dbprobe-{record.probe_token}.php.<unit> file may "
            f"remain in /var/www/{record.identifier}."
        ),
    }


_REFUSALS = {
    Execution.LOCK_CONFLICT: (
        "Another change held Barectl's mutation lock on the server, so the run stopped before "
        "changing anything. Prepare a new plan after that change finishes."
    ),
    Execution.UNSAFE_LOCK: (
        "The lock directory /run/lock/barectl or its lock file is not a root-owned private "
        "directory with an empty lock file, so the run stopped before changing anything."
    ),
    Execution.BOOT_CHANGED: (
        "The server restarted after the plan was reviewed, so the run stopped before changing "
        "anything. Prepare a new plan."
    ),
    Execution.EXPIRED: (
        "The plan's admission deadline had passed on the server's clock when the run started, "
        "so it stopped before changing anything. Prepare a new plan."
    ),
    Execution.OTHER_RUN_ACTIVE: (
        "Another Barectl run still had processes on the server, so this run stopped before "
        "changing anything. Prepare a new plan after it finishes."
    ),
    Execution.CAPACITY: (
        "The server kept too many finished runs when this run held the lock, so it stopped "
        "before changing anything. Clear finished runs with a reviewed cleanup, then prepare "
        "again."
    ),
    Execution.DRIFT: (
        "The site, the engine's packages, services or configuration, the driver, the catalog "
        "under the site's name or the probe's path changed after review, so the run stopped "
        "before any statement. Prepare a new database plan to review the current state."
    ),
    Execution.DRIVER_UNAVAILABLE: (
        "The site's pool did not run the probe as the site user with the driver loaded, so "
        "the run removed the probe and stopped before any statement. Check PHP-FPM and the "
        "driver, then prepare a new database plan."
    ),
    Execution.PRINCIPAL_CONFLICT: (
        "The engine refused to create the principal because it already existed: another "
        "administrator created it after the last check. Barectl never adopts it; nothing was "
        "created, and the probe was removed. Prepare a new database plan to review it."
    ),
    Execution.STATEMENT_REFUSED: (
        "The engine rejected the statement that creates the principal, and the catalog is "
        "unchanged, so nothing was created and the probe was removed. Inspect the unit's "
        "journal, then prepare a new database plan."
    ),
}


def failure(run: ApplyRun, outcome: Execution, exit_status: int | None) -> str:
    record = RunDatabaseBinding.objects.filter(run=run).first()
    if outcome in _REFUSALS:
        return _REFUSALS[outcome]
    if outcome == Execution.PARTIAL and record is not None and exit_status is not None:
        text = _boundaries(record).get(exit_status, "")
        return f"Stopped at exit status {exit_status}: {text}{_AFTER}"
    if outcome == Execution.SUCCEEDED:
        return ""
    if outcome == Execution.TIMED_OUT:
        limit = bootstrap_native.RUNTIME_MAX
        return f"The run reached its {limit} limit and systemd stopped it.{_AFTER}"
    if outcome == Execution.KILLED:
        return f"The run was terminated by a signal before it finished.{_AFTER}"
    return f"The run failed. Inspect its unit with systemctl status and journalctl.{_AFTER}"


# Audit ------------------------------------------------------------------------------------


def reviewed_changes(plan: ConfigurationPlan) -> str:
    record = plan.binding
    lines = [
        f"Run {statement.text}" + (f" in {statement.database}" if statement.database else "")
        for statement in plan.binding_statements.all()
    ]
    lines.append(
        f"Publish {record.probe_path}, root:{record.principal} 0640, SHA-256 "
        f"{record.probe_sha256}, removed before success"
    )
    return "\n".join(lines)


_COPIED = (
    "identifier",
    "engine",
    "php_version",
    "site_user",
    "uid",
    "gid",
    "principal",
    "database",
    "authentication",
    "character_set",
    "collation",
    "engine_version",
    "driver_version",
    "other_engine",
    "probe_token",
    "probe_path",
    "probe_content",
    "probe_sha256",
)


def copy_audit(plan: ConfigurationPlan, run: ApplyRun) -> None:
    record = plan.binding
    RunDatabaseBinding.objects.create(run=run, **{name: getattr(record, name) for name in _COPIED})
    RunDatabaseStatement.objects.bulk_create(
        RunDatabaseStatement(
            run=run,
            position=item.position,
            step=item.step,
            database=item.database,
            text=item.text,
        )
        for item in plan.binding_statements.all()
    )


# Payload ----------------------------------------------------------------------------------


def _change(record: BindingRecord, release: str, digests: dict[str, str]) -> native.BindingChange:
    engine = DatabaseEngine(record.engine)
    return native.BindingChange(
        release=release,
        identifier=record.identifier,
        engine=engine,
        uid=record.uid,
        gid=record.gid,
        token=record.probe_token,
        probe=record.probe_content,
        site_digest=digests.get(Kind.SITE_REVALIDATION, ""),
        engine_digest=digests.get(Kind.PACKAGE_REVALIDATION, ""),
        driver_version=record.driver_version,
        catalog_before=digests.get(Kind.CATALOG_REVALIDATION, ""),
        catalog_after=digests.get(Kind.CATALOG_AFTER, ""),
        other=record.other_engine,
        statements=binding.statements(engine, record.principal),
    )


def payload(run: ApplyRun, plan: ConfigurationPlan) -> str:
    try:
        record = plan.binding
        digests = dict(plan.evidence.values_list("kind", "fingerprint"))
        reviewed = tuple(plan.binding_statements.values_list("step", "database", "text"))
        change = _change(record, run.release, digests)
        expected = tuple((s.step.value, s.database, s.text) for s in change.statements)
        if reviewed != expected or record.probe_sha256 != binding.digest(record.probe_content):
            raise ValueError("The reviewed statements or probe differ.")
        return native.binding_payload(
            run.unit_name, run.boot_id, run.admission_deadline_centiseconds, change
        )
    except ValueError, KeyError, ObjectDoesNotExist:
        raise OperationRefused(EVIDENCE_FAILURE) from None


def _state_argv(run: ApplyRun) -> list[str]:
    record = run.binding
    engine = DatabaseEngine(record.engine)
    change = native.BindingChange(
        release=run.release,
        identifier=record.identifier,
        engine=engine,
        uid=record.uid,
        gid=record.gid,
        token=record.probe_token,
        probe=record.probe_content,
        site_digest="0" * 64,
        engine_digest="0" * 64,
        driver_version=record.driver_version,
        catalog_before="0" * 64,
        catalog_after="0" * 64,
        other=record.other_engine,
        statements=binding.statements(engine, record.principal),
    )
    return native.state(change)


def admit(shell: RemoteShell, run: ApplyRun, *, root: bool) -> None:
    if root:
        return
    if shell.run(bootstrap_native.authorization(_state_argv(run))).exit_status != 0:
        raise OperationRefused(VERIFY_PRIVILEGE)


# Verification ------------------------------------------------------------------------------


def _read(shell: RemoteShell, run: ApplyRun) -> str | None:
    root = bootstrap_native.is_root(shell)
    argv = _state_argv(run)
    if root is None or (
        not root and shell.run(bootstrap_native.authorization(argv)).exit_status != 0
    ):
        return None
    result = shell.run(bootstrap_native.privileged(argv, root=root))
    if result.exit_status or result.truncated:
        return None
    return result.stdout


def _problems(
    record: RunDatabaseBinding, release: str, text: str
) -> tuple[list[str], dict[str, str]]:
    engine = DatabaseEngine(record.engine)
    name = record.principal
    catalog, _, rest = text.partition("== readiness\n")
    readiness, _, state = rest.partition("== state\n")
    own, other = binding.sections(catalog, engine)
    found = recognize_mariadb(parse_mariadb(own, (name,)), name)
    problems = []
    if found.state != BindingState.SATISFIED:
        problems.append(
            f"The catalog under {name} is {found.state.value}: {' '.join(found.problems)}"
        )
    if other.strip():
        problems.append(f"{binding.other_engine(engine).label} holds something under {name}.")
    problems += found.exposures
    spec = binding.ENGINES[engine]
    profile = profiles.profile(RELEASES[release], spec.profile)
    if readiness.strip() != profile.check.expected:
        problems.append(f"{engine.label}'s administration no longer shows the qualified output.")
    lines = set(state.splitlines())
    if "probe absent" not in lines:
        problems.append(f"The temporary probe {record.probe_path} remains.")
    problems += [
        f"{unit} is not active and running."
        for unit in (*profile.units, f"php{record.php_version}-fpm.service")
        if f"unit {unit} active/running" not in lines
    ]
    if "listening 0" in lines:
        problems.append("The site's pool is not listening.")
    details = {
        "principal": found.principal,
        "authentication": found.authentication,
        "privileges": found.privileges,
        "character_set": found.character_set,
        "collation": found.collation,
    }
    return problems, details


def verify(shell: RemoteShell, run: ApplyRun) -> Verification:
    """docs/databases.md#applying-a-binding-plan: fresh reads as root after a success."""
    record = RunDatabaseBinding.objects.filter(run=run).first()
    text = None if record is None else _read(shell, run)
    if record is None or text is None:
        return Verification.UNAVAILABLE
    try:
        problems, details = _problems(record, run.release, text)
    except CatalogFormatError, ValueError:
        return Verification.UNAVAILABLE
    if not DatabaseRunResult.objects.filter(run=run).exists():
        DatabaseRunResult.objects.create(
            run=run,
            probe_absent=not any("probe" in problem for problem in problems),
            problems="\n".join(problems),
            verified_at=timezone.now(),
            **details,
        )
    return Verification.FAILED if problems else Verification.PASSED


def audit(run: ApplyRun) -> list[str]:
    result = DatabaseRunResult.objects.filter(run=run).first()
    if result is None:
        return []
    lines = [
        f"Verified {timezone.localtime(result.verified_at):%b %-d, %Y, %H:%M:%S %Z}.",
        (
            f"{result.principal or 'The principal'} authenticates by "
            f"{result.authentication or 'an unknown method'}."
        ),
        f"Privileges: {result.privileges or 'none read'}.",
        f"Character set {result.character_set} with {result.collation}."
        if result.character_set
        else "The database's character set could not be read.",
        "The temporary probe was removed."
        if result.probe_absent
        else "The temporary probe still exists.",
    ]
    lines += result.problems.splitlines()
    return lines


def verification_failure(run: ApplyRun) -> str:
    result = DatabaseRunResult.objects.filter(run=run).first()
    problems = " ".join((result.problems if result else "").splitlines())
    return VERIFICATION_FAILED.format(problems=problems or "see the site's discovery.")
