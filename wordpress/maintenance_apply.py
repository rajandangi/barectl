"""Applying a reviewed WordPress maintenance action: its payload, outcome, result and
verification.

docs/wordpress.md#maintaining-wordpress. The payload revalidates the reviewed evidence under
the mutation lock, runs the one fixed WP-CLI command as the site user and publishes one bounded
record; this module binds the run to the reviewed rows and pins, separates the refusals that ran
no application code from the failures after it, and retrieves the run's result. The three
outcomes stay separate: execution comes from systemd's unit and cgroup evidence, verification
from the run's residue, and the result from the journal.
"""

from datetime import UTC, datetime

from django.utils import timezone

from bootstrap import native as bootstrap_native
from bootstrap.models import ApplyRun, ConfigurationPlan, Execution, PlanEvidence, Verification
from bootstrap.native import Limits, UnitEvidence
from discovery.ssh import RemoteShell
from operations.lifecycle import OperationRefused

from . import execution as shared
from . import inspection, inspection_native, maintenance_native, setup_native
from .maintenance_models import (
    MaintenanceResult,
    MaintenanceReview,
    Operation,
    PlanWordpressMaintenance,
    RunWordpressMaintenance,
)

Kind = PlanEvidence.Kind
Exit = shared.Exit
COMMAND_EXIT = maintenance_native.Exit.COMMAND
EVIDENCE_FAILURE = (
    "The reviewed WordPress maintenance is incomplete, or its pins or payload differ from this "
    "version's, so Barectl submitted nothing. Prepare a new review."
)
VERIFY_PRIVILEGE = (
    "The SSH user is not root, and sudo -n -l does not authorize the fixed read-only command "
    "that retrieves the maintenance result afterwards, so Barectl submitted nothing."
)
VERIFICATION_FAILED = (
    "The maintenance ran, but its staging directory is still on the server. It is safe to "
    "remove; Barectl removes nothing itself."
)
_REFUSALS: dict[int, str] = {
    Exit.TOOLS: (
        "The server lacks a native tool the run needs (python3, timeout, runuser, mariadb, the "
        "site's PHP CLI or the WP-CLI file), so the run stopped before running any application "
        "code. Restore it through ordinary administration, then prepare a new review."
    ),
    Exit.STAGING: (
        "The run's private staging area could not be created, or a WP-CLI configuration file "
        "exists in or above the site, which WP-CLI would read, so the run stopped before "
        "running any application code."
    ),
}
_DRIFT = (
    "The site, the tool, the application's configuration, core release, schema, extensions or "
    "the must-use and drop-in files changed after review, or the payload itself did, so the "
    "run stopped before running any application code. Prepare a new review."
)
_UNPRODUCED = (
    "The run executed, but its trusted projection produced no valid result record, so none was "
    "published. Whether the command took effect is unknown. Barectl does not run it again: "
    "inspect the application, then prepare a new review if you still want it."
)
_COMMAND_FAILED = (
    "The command did not complete: WP-CLI exited with an error, or the command ran past its "
    "time or file-size limit, so the flush may not have taken effect. The run published one "
    "record saying which, in the unit's journal. Barectl does not run it again: check the "
    "application, then prepare a new review if you still want it."
)
_TIMED_OUT = (
    "The run reached its {limit} limit and systemd stopped it. It ran application code and "
    "published no result, so whether the command took effect is unknown. Its staging "
    "directory was cleaned when systemd ended it."
)
_KILLED = (
    "The run was terminated by a signal before it finished and published no result, so "
    "whether the command took effect is unknown. A staging directory named .wp-<unit> in the "
    "site directory may remain and is safe to remove."
)
_INCOMPLETE = (
    "The run did not complete. It ran application code and published no result, so whether "
    "the command took effect is unknown: inspect its unit with systemctl status and "
    "journalctl, and the site directory for a leftover .wp-* staging directory (safe to "
    "remove)."
)
_COMMON = {
    Execution.LOCK_CONFLICT: shared.COMMON_REFUSALS["lock_conflict"],
    Execution.UNSAFE_LOCK: shared.COMMON_REFUSALS["unsafe_lock"],
    Execution.BOOT_CHANGED: shared.COMMON_REFUSALS["boot_changed"],
    Execution.EXPIRED: shared.COMMON_REFUSALS["expired"],
    Execution.OTHER_RUN_ACTIVE: shared.COMMON_REFUSALS["other_run_active"],
    Execution.RENEWAL_ACTIVE: shared.COMMON_REFUSALS["renewal_active"],
    Execution.CAPACITY: shared.COMMON_REFUSALS["capacity"],
}


def execution(evidence: UnitEvidence) -> Execution:
    """The payload's own exit statuses; every other outcome as bootstrap reads it."""
    exited = evidence.exec_main_code == bootstrap_native.CLD_EXITED
    if not (evidence.found and evidence.terminal and exited):
        return evidence.execution
    if evidence.exec_main_status in {Exit.TOOLS, Exit.STAGING}:
        return Execution.MAINTENANCE_REFUSED
    return evidence.execution


def failure(run: ApplyRun | None, outcome: Execution, exit_status: int | None) -> str:
    code = exit_status if exit_status is not None else -1
    if outcome == Execution.MAINTENANCE_REFUSED:
        return _REFUSALS.get(code, "")
    if outcome == Execution.DRIFT:
        return _DRIFT
    if outcome in _COMMON:
        return _COMMON[outcome]
    if outcome == Execution.FAILED and code == Exit.PROJECTION:
        return _UNPRODUCED
    if outcome == Execution.FAILED and code == COMMAND_EXIT:
        return _COMMAND_FAILED
    return {
        Execution.TIMED_OUT: _TIMED_OUT.format(limit=bootstrap_native.RUNTIME_MAX),
        Execution.KILLED: _KILLED,
        Execution.VALIDATION_FAILED: _INCOMPLETE,
        Execution.FAILED: _INCOMPLETE,
    }.get(outcome, "")


# Audit --------------------------------------------------------------------------------------


def reviewed_changes(plan: ConfigurationPlan) -> str:
    row = PlanWordpressMaintenance.objects.filter(plan=plan).first()
    if row is None:
        return ""
    command = maintenance_native.COMMANDS[Operation(row.operation)]
    return "\n".join(
        (
            f"Run WP-CLI {row.tool_version} as {row.site_user} against {row.url}: {command}",
            (
                "Publish one validated result record of at most "
                f"{shared.MAX_RECORD // 1024} KiB and change nothing else on the server"
            ),
        )
    )


def copy_audit(plan: ConfigurationPlan, run: ApplyRun) -> None:
    """Keep the plan's exact review with the run, so the audit outlives the plan."""
    row = PlanWordpressMaintenance.objects.filter(plan=plan).first()
    if row is None:
        raise OperationRefused(EVIDENCE_FAILURE)
    RunWordpressMaintenance.objects.create(
        run=run,
        **{field.name: getattr(row, field.name) for field in MaintenanceReview._meta.local_fields},
    )


# Payload ------------------------------------------------------------------------------------


def _evidence(plan: ConfigurationPlan) -> inspection_native.Evidence:
    evidence = inspection.evidence_of(dict(plan.evidence.values_list("kind", "fingerprint")))
    if evidence is None:
        raise OperationRefused(EVIDENCE_FAILURE)
    return evidence


def _pinned(row: MaintenanceReview) -> bool:
    """Whether the review still names exactly this version's pins, limits and budgets."""
    return (
        row.tool_version == setup_native.VERSION
        and row.tool_path == setup_native.PHAR
        and row.tool_sha256 == setup_native.SHA256
        and row.core_locale == "en_US"
        and row.core_qualified
        and (row.max_file_bytes, row.memory_max_bytes) == maintenance_native.limits()
        and row.runtime_limit_seconds == maintenance_native.RUNTIME_LIMIT_SECONDS
        and row.command_seconds == maintenance_native.COMMAND_SECONDS
        and row.budget_seconds == maintenance_native.BUDGET_SECONDS
        and row.operation in set(Operation)
    )


def payload(run: ApplyRun, plan: ConfigurationPlan) -> str:
    row = PlanWordpressMaintenance.objects.filter(plan=plan).first()
    if row is None or not _pinned(row):
        raise OperationRefused(EVIDENCE_FAILURE)
    try:
        text, body = maintenance_native.staged(
            run.unit_name,
            run.boot_id,
            run.admission_deadline_centiseconds,
            row,
            _evidence(plan),
        )
    except ValueError:
        raise OperationRefused(EVIDENCE_FAILURE) from None
    if inspection.digest(body) != row.body_sha256:
        raise OperationRefused(EVIDENCE_FAILURE)
    return text


def limits(run: ApplyRun) -> Limits:
    row = RunWordpressMaintenance.objects.filter(run=run).first()
    if row is None or (row.max_file_bytes, row.memory_max_bytes) != maintenance_native.limits():
        raise OperationRefused(EVIDENCE_FAILURE)
    return Limits(row.max_file_bytes, row.memory_max_bytes)


def admit(shell: RemoteShell, run: ApplyRun, *, root: bool) -> None:
    row = RunWordpressMaintenance.objects.filter(run=run).first()
    if row is None:
        raise OperationRefused(EVIDENCE_FAILURE)
    if root:
        return
    argv = shared.retrieval_argv(run.unit_name, row.identifier)
    if shell.run(bootstrap_native.authorization(argv)).exit_status:
        raise OperationRefused(VERIFY_PRIVILEGE)


# Result and verification ---------------------------------------------------------------------


def _recorded_invocation(run: ApplyRun) -> str:
    """The invocation the worker recorded when it saw the unit; the in-memory run may predate
    it."""
    return ApplyRun.objects.filter(pk=run.pk).values_list("invocation_id", flat=True).first() or ""


def _store(
    run: ApplyRun,
    row: RunWordpressMaintenance,
    record: maintenance_native.Record | None,
    why: str,
) -> None:
    now = timezone.now()
    if record is None or record.state != "ok":
        MaintenanceResult.objects.create(
            run=run,
            operation=row.operation,
            state=MaintenanceResult.State.UNAVAILABLE,
            why=why or (record.why if record is not None else "invalid"),
            retrieved_at=now,
            reported_at=None if record is None else datetime.fromtimestamp(record.at, UTC),
        )
        return
    MaintenanceResult.objects.create(
        run=run,
        operation=row.operation,
        state=MaintenanceResult.State.AVAILABLE,
        retrieved_at=now,
        reported_at=datetime.fromtimestamp(record.at, UTC),
        rules=record.rules,
    )


def verify(shell: RemoteShell, run: ApplyRun) -> Verification:
    """docs/wordpress.md#maintaining-wordpress: a fresh read after a successful run. The run
    passes when its staging directory is gone; the result is retrieved and stored apart, so a
    rotated journal makes the result unavailable without touching the execution outcome."""
    row = RunWordpressMaintenance.objects.filter(run=run).first()
    invocation = _recorded_invocation(run)
    root = bootstrap_native.is_root(shell)
    if row is None or root is None or not shared.INVOCATION.fullmatch(invocation):
        return Verification.UNAVAILABLE
    argv = shared.retrieval_argv(run.unit_name, row.identifier)
    if not root and shell.run(bootstrap_native.authorization(argv)).exit_status != 0:
        return Verification.UNAVAILABLE
    answer = shell.run(shared.retrieval_command(argv, invocation, root=root))
    if answer.exit_status or answer.truncated:
        return Verification.UNAVAILABLE
    try:
        retrieved = shared.parse_retrieval(answer.stdout, unit=run.unit_name, invocation=invocation)
    except shared.Unreadable:
        return Verification.UNAVAILABLE
    record = None
    why = retrieved.why
    if retrieved.record is not None:
        try:
            record = maintenance_native.parse_record(retrieved.record, row.operation)
        except inspection_native.InvalidRecord:
            why = "invalid"
    if not MaintenanceResult.objects.filter(run=run).exists():
        _store(run, row, record, why)
    return Verification.FAILED if retrieved.residue else Verification.PASSED


def audit(run: ApplyRun) -> list[str]:
    result = MaintenanceResult.objects.filter(run=run).first()
    if result is None:
        return []
    when = f"{timezone.localtime(result.retrieved_at):%b %-d, %Y, %H:%M:%S %Z}"
    if result.state == MaintenanceResult.State.UNAVAILABLE:
        return [f"Result unavailable ({result.why}); checked {when}."]
    return [f"Result retrieved {when}."]


def verification_failure(run: ApplyRun) -> str:
    return VERIFICATION_FAILED
