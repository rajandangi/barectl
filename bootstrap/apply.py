"""The apply kind of remote operation: run a reviewed plan revision through native execution.

Views call ``request_apply`` to queue one reviewed revision, ``request_check`` to ask for
a reconciling run's outcome, and ``read_apply`` and ``apply_history`` to show runs.
``servers.registration`` calls ``keep_apply_audit`` when removing a server. The lifecycle
belongs to ``operations.lifecycle``, which claims a run in the durable worker and runs
``_apply``, or ``_check`` for a reconciling run.

Only reviewed package metadata refreshes can be applied, and only while
``settings.METADATA_REFRESH_APPLY`` is on; it stays off until cross-controller
coordination is qualified, so production installations offer no apply control.

The worker checks the requesting account again, connects with the plan's alias, verifies
the reviewed host key and the privilege for the exact submission, and records the
dispatch before sending the transient unit through ``bootstrap.native``. From then on
only native evidence of that same unit closes the run: a lost acknowledgement, a lost
connection or a stopped worker leaves it reconciling, and nothing is ever submitted
again. No local transaction is held open while the worker is connected.
"""

import logging
import time
from dataclasses import dataclass
from datetime import timedelta

from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser
from django.db import IntegrityError, transaction
from django.utils import timezone

from discovery import ssh
from discovery.models import DiscoverySnapshot
from discovery.ssh import ConnectionFailed, RemoteShell
from operations import lifecycle
from operations.lifecycle import OperationBusy, OperationRefused, recovers_first
from operations.models import RemoteOperation
from servers.models import Server

from . import inspection, native, profiles
from .evidence import Unreadable, parse_architecture, parse_index_targets
from .models import (
    Action,
    ApplyRun,
    ConfigurationPlan,
    Execution,
    PlanEvidence,
    Verification,
)
from .presentation import ApplyView, apply_view

logger = logging.getLogger(__name__)

Status = RemoteOperation.Status

# What applying requires of the account, checked again when the worker starts.
APPLY_PERMISSIONS = (
    "servers.view_server",
    "bootstrap.view_configurationplan",
    "bootstrap.apply_configurationplan",
)
# The worker watches a submitted run over its connection for at most this long, well
# within the connection's own limit (ssh.SESSION_TIMEOUT); a longer run is reconciling.
WATCH_LIMIT = timedelta(minutes=4)
POLL_INTERVAL = 2.0
# Longer than the worker's connection limit: a run still marked running after this was
# abandoned by its worker. Undispatched runs are failed; dispatched ones reconcile.
STALE_AFTER = timedelta(minutes=10)

UNEXPECTED_FAILURE = (
    "Applying stopped because of an unexpected error. Barectl did not record the error "
    "details, which could include remote output. The worker log names the error type."
)
INTERRUPTED_FAILURE = (
    "The worker stopped before it submitted anything to the server, so nothing changed. "
    "Prepare a new plan to apply it."
)
UNCERTAIN = (
    "The run may have reached the server, and its outcome is not established yet. Barectl "
    "never submits it again; Check outcome inspects the same native unit."
)
REVOKED_FAILURE = (
    "The account that requested this run is no longer active or no longer allowed to "
    "apply plans, so Barectl did not connect to the server."
)
DISABLED_FAILURE = (
    "Applying metadata refresh plans is not available in this installation, so Barectl did "
    "not connect to the server."
)
PLAN_GONE_FAILURE = "The reviewed plan is no longer recorded, so Barectl did not connect."
EVIDENCE_FAILURE = (
    "The reviewed plan has no APT evidence to recheck on the server, so Barectl did not "
    "submit it. Prepare a new plan."
)
TOO_LARGE_FAILURE = (
    "The reviewed action is larger than Barectl submits in one run, so nothing was sent. "
    "Barectl never splits a reviewed action."
)
HOST_KEY_FAILURE = (
    "The server presented a different host key from the one the plan was reviewed with, so "
    "Barectl submitted nothing. Prepare a new plan after confirming the server's identity."
)
PRIVILEGE_FAILURE = (
    "The SSH user is not root, and sudo -n -l does not authorize the exact submission "
    "without a password, so Barectl submitted nothing. Barectl never installs a sudo policy "
    "or asks for a password."
)
UNREADABLE_FAILURE = (
    "Barectl could not read the server's state before submitting, so it submitted nothing."
)
RETAINED_FAILURE = (
    f"The server keeps {native.RETAINED_LIMIT} or more finished bootstrap runs, so Barectl "
    "submitted nothing. Clear finished runs through ordinary administration, such as "
    "systemctl reset-failed and systemctl stop for exited units, then prepare again."
)
REJECTED_FAILURE = (
    "systemd refused the submission and no unit was created, so nothing ran on the server. "
    "Prepare a new plan to try again."
)
LOST_ACKNOWLEDGEMENT = (
    "The connection ended while the run was being submitted, so Barectl does not know "
    "whether the server received it."
)
STILL_RUNNING = (
    "The run was still running on the server when the worker stopped watching it. It "
    "continues there, owned by systemd."
)
NOT_FOUND = (
    "The server has no unit with this run's name. The submission may not have been "
    "delivered, or the unit's record was cleared. A delayed delivery still stops at the "
    "admission deadline without changes."
)
RESTARTED = (
    "The server restarted after this run was submitted. Transient units do not survive a "
    "restart, so native evidence of this run is gone and its outcome is unknown."
)
MISMATCH = (
    "The native unit with this run's name reports a different invocation from the one "
    "Barectl recorded, so its evidence cannot be attributed to this run."
)
UNREADABLE_EVIDENCE = "The unit's native state could not be read."
_EXECUTION_FAILURES = {
    Execution.LOCK_CONFLICT: (
        "Another change held Barectl's mutation lock on the server, so the run stopped before "
        "changing anything. Prepare a new plan after that change finishes."
    ),
    Execution.UNSAFE_LOCK: (
        "The lock directory /run/lock/barectl or its lock file is not a root-owned private "
        "directory with an empty lock file, so the run stopped before changing anything. "
        "Remove it through ordinary administration, then prepare again."
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
        "Another bootstrap run still had processes on the server, so this run stopped before "
        "changing anything. Prepare a new plan after it finishes."
    ),
    Execution.DRIFT: (
        "The APT configuration, hooks or sources changed after review, so the run stopped "
        "before changing anything. Prepare a new plan to review the current configuration."
    ),
    Execution.PACKAGE_MANAGER_BUSY: (
        "Another package-manager operation held APT's lock, so the run stopped before changing "
        "anything; Barectl does not wait for it. Prepare a new plan after it finishes."
    ),
    Execution.FAILED: (
        "The update failed or reported errors or warnings, so some indexes may be missing or "
        "old. Barectl does not restore the previous indexes. Inspect the unit with systemctl "
        "status and journalctl on the server."
    ),
    Execution.TIMED_OUT: (
        f"The run reached its {native.RUNTIME_MAX} limit and systemd stopped it. Some indexes "
        "may be missing or old; no rollback happens."
    ),
    Execution.KILLED: (
        "The run was terminated by a signal before it finished. Some indexes may be missing "
        "or old; no rollback happens."
    ),
}
VERIFICATION_FAILED = (
    "The update completed, but its postconditions do not hold: the authenticated Ubuntu "
    "indexes are missing or a package changed. Inspect the server through ordinary "
    "administration."
)
VERIFICATION_UNAVAILABLE = (
    "The update completed, but Barectl could not check its postconditions. Prepare a new "
    "plan before any later change."
)


@dataclass(frozen=True)
class ApplyRequest:
    """What ``request_apply`` did: the run for the revision, or why there is none."""

    run: ApplyRun | None
    problem: str = ""


def apply_available(plan: ConfigurationPlan) -> bool:
    """Whether ``plan`` is a kind this installation may apply at all."""
    return settings.METADATA_REFRESH_APPLY and plan.action == Action.METADATA_REFRESH


@recovers_first
def request_apply(plan: ConfigurationPlan, user: AbstractBaseUser) -> ApplyRequest:
    """Queue the run of the reviewed ``plan``, or return the run already recorded for it.

    Repeated requests for one revision converge on its one run. Raises
    ``Server.DoesNotExist`` when a concurrent request removed the server.
    """
    existing = ApplyRun.objects.filter(plan_number=plan.pk).first()
    if existing is not None:
        return ApplyRequest(existing)
    problem = _refusal(plan)
    if problem:
        return ApplyRequest(None, problem)
    server = plan.preparation.server
    if server is None:
        raise Server.DoesNotExist
    try:
        run = lifecycle.queue(
            ApplyRun,
            server,
            plan=plan,
            plan_number=plan.pk,
            requested_by=user,
            requested_by_name=user.get_username(),
            server_name=server.name,
            action=plan.action,
            intent=plan.intent,
            profile_revision=plan.profile_revision,
            reviewed_host_key=plan.host_key,
            boot_id=plan.boot_id,
            admission_deadline_centiseconds=plan.admission_deadline_centiseconds,
            admission_expires_at=plan.admission_expires_at,
            effects="\n".join(
                f"{effect.get_kind_display()}. {effect.text}" for effect in plan.effects.all()
            ),
            unit_name=native.new_unit_name(),
        )
    except OperationBusy, IntegrityError:
        existing = ApplyRun.objects.filter(plan_number=plan.pk).first()
        if existing is not None:
            return ApplyRequest(existing)
        return ApplyRequest(
            None,
            "Barectl is running another remote operation for this server. Apply the plan "
            "after it finishes, if its admission deadline has not passed.",
        )
    return ApplyRequest(run)


def _refusal(plan: ConfigurationPlan) -> str:
    if not apply_available(plan):
        return "This plan cannot be applied in this installation."
    if not plan.eligible or plan.no_changes:
        return "Only an eligible plan with changes can be applied."
    if timezone.now() >= plan.admission_expires_at:
        return "This plan's admission deadline has passed. Prepare a new plan."
    return ""


@recovers_first
def request_check(operation_id: int) -> bool:
    """Ask the worker to check a reconciling run's outcome; return whether it was asked."""
    run = ApplyRun.objects.filter(pk=operation_id).first()
    return run is not None and lifecycle.check(run)


@recovers_first
def read_apply(operation_id: int) -> ApplyView | None:
    """One apply run with its server's snapshot time, or ``None`` if there is none."""
    run = ApplyRun.objects.filter(pk=operation_id).first()
    if run is None:
        return None
    snapshot = None
    if run.server_id is not None:
        snapshot = (
            DiscoverySnapshot.objects.filter(server_id=run.server_id)
            .values_list("collected_at", flat=True)
            .first()
        )
    return apply_view(run, snapshot)


@recovers_first
def apply_history() -> list[ApplyView]:
    """Every apply run for Activity, newest recorded first, including removed servers'."""
    return [apply_view(run) for run in ApplyRun.objects.all()]


@recovers_first
def keep_apply_audit(server: Server) -> None:
    """Keep the server's finished apply runs as audit without the server.

    Call inside the transaction that deletes the server. Active runs stay attached and
    protect the server, so the database refuses the removal while one remains.
    """
    lifecycle.detach(RemoteOperation.objects.filter(server=server, kind=RemoteOperation.Kind.APPLY))


def _record(operation_id: int, source: RemoteOperation.Status, **changes: object) -> bool:
    """Record run details only while the run is still in ``source``."""
    with transaction.atomic():
        if not RemoteOperation.objects.filter(pk=operation_id, status=source).exists():
            return False
        ApplyRun.objects.filter(pk=operation_id).update(**changes)
    return True


def _authorize(run: ApplyRun) -> None:
    requester = run.requested_by
    if not settings.METADATA_REFRESH_APPLY or run.action != Action.METADATA_REFRESH:
        raise OperationRefused(DISABLED_FAILURE)
    if requester is None or not requester.is_active or not requester.has_perms(APPLY_PERMISSIONS):
        raise OperationRefused(REVOKED_FAILURE)


def _apply(run: ApplyRun) -> None:
    """Submit the reviewed run once, then watch its native unit until it is terminal."""
    _authorize(run)
    plan = run.plan
    if plan is None:
        raise OperationRefused(PLAN_GONE_FAILURE)
    digest = (
        plan.evidence.filter(kind=PlanEvidence.Kind.APT_REVALIDATION)
        .values_list("fingerprint", flat=True)
        .first()
    )
    if not digest:
        raise OperationRefused(EVIDENCE_FAILURE)
    script = native.metadata_refresh(
        run.unit_name, run.boot_id, run.admission_deadline_centiseconds, digest
    )
    try:
        argv = native.submission(run.unit_name, script)
    except native.PayloadTooLarge:
        raise OperationRefused(TOO_LARGE_FAILURE) from None
    with ssh.connect_alias(run.ssh_alias) as shell:
        if shell.host_key != run.reviewed_host_key:
            raise OperationRefused(HOST_KEY_FAILURE)
        root = _admit(shell, argv)
        before = _dpkg_status(shell)
        if before is None:
            raise OperationRefused(UNREADABLE_FAILURE)
        _record(run.pk, Status.RUNNING, dpkg_status_before=before)
        # Recorded before anything is sent; a recovery that already failed the run wins.
        if not lifecycle.dispatch(run.pk, host_key=shell.host_key):
            return
        try:
            result = shell.run(native.privileged(argv, root=root))
        except ConnectionFailed:
            lifecycle.reconcile(run.pk, f"{LOST_ACKNOWLEDGEMENT} {UNCERTAIN}")
            return
        acknowledged = result.exit_status == 0
        _record(
            run.pk,
            Status.RUNNING,
            execution=Execution.SUBMITTED,
            acknowledged_at=timezone.now() if acknowledged else None,
        )
        _watch(shell, run, acknowledged=acknowledged)


def _admit(shell: RemoteShell, argv: list[str]) -> bool:
    """Check privilege for the exact submission and the retained units; return root."""
    root = native.is_root(shell)
    if root is None:
        raise OperationRefused(UNREADABLE_FAILURE)
    if not root and shell.run(native.authorization(argv)).exit_status != 0:
        raise OperationRefused(PRIVILEGE_FAILURE)
    retained = native.retained_units(shell)
    if retained is None:
        raise OperationRefused(UNREADABLE_FAILURE)
    if retained >= native.RETAINED_LIMIT:
        raise OperationRefused(RETAINED_FAILURE)
    return root


def _dpkg_status(shell: RemoteShell) -> str | None:
    result = shell.run(native.DPKG_STATUS_DIGEST)
    if result.exit_status != 0 or result.truncated:
        return None
    try:
        return native.parse_digest(result.stdout)
    except native.Unreadable:
        return None


def _watch(shell: RemoteShell, run: ApplyRun, *, acknowledged: bool) -> None:
    """Inspect the submitted unit until it is terminal or the watch limit passes."""
    deadline = time.monotonic() + WATCH_LIMIT.total_seconds()
    while True:
        try:
            evidence = native.inspect(shell, run.unit_name)
        except native.Unreadable:
            lifecycle.reconcile(run.pk, f"{UNREADABLE_EVIDENCE} {UNCERTAIN}")
            return
        if not evidence.found:
            if acknowledged:
                lifecycle.reconcile(run.pk, f"{NOT_FOUND} {UNCERTAIN}")
            else:
                _conclude_rejected(run)
            return
        if not _record(run.pk, Status.RUNNING, invocation_id=evidence.invocation_id):
            return
        if evidence.terminal:
            _conclude(shell, run, evidence, Status.RUNNING)
            return
        _record(run.pk, Status.RUNNING, execution=Execution.RUNNING)
        if time.monotonic() >= deadline:
            lifecycle.reconcile(run.pk, f"{STILL_RUNNING} {UNCERTAIN}")
            return
        time.sleep(POLL_INTERVAL)


def _conclude_rejected(run: ApplyRun) -> None:
    """systemd refused the submission and created no unit: nothing ran."""
    with transaction.atomic():
        if lifecycle.finish(run.pk, Status.RUNNING, succeeded=False, failure=REJECTED_FAILURE):
            ApplyRun.objects.filter(pk=run.pk).update(
                execution=Execution.NOT_SUBMITTED, verification=Verification.NOT_APPLICABLE
            )


def _check(run: ApplyRun) -> None:
    """Establish a reconciling run's outcome from its native unit, with a new connection.

    Only the unit with the run's recorded name is inspected, and its invocation must be
    the recorded one once one was recorded. Evidence that is missing or still running
    leaves the run reconciling with an explanation; closing a run whose native evidence
    is gone is not available.
    """
    with ssh.connect_alias(run.ssh_alias) as shell:
        if shell.host_key != run.reviewed_host_key:
            raise OperationRefused(HOST_KEY_FAILURE)
        try:
            evidence = native.inspect(shell, run.unit_name)
        except native.Unreadable:
            raise OperationRefused(UNREADABLE_EVIDENCE) from None
        if not evidence.found:
            reason = RESTARTED if evidence.boot_id != run.boot_id else NOT_FOUND
            lifecycle.note(run.pk, f"{reason} {UNCERTAIN}")
            return
        if run.invocation_id and evidence.invocation_id != run.invocation_id:
            lifecycle.note(run.pk, f"{MISMATCH} {UNCERTAIN}")
            return
        if not _record(run.pk, Status.RECONCILING, invocation_id=evidence.invocation_id):
            return
        if not evidence.terminal:
            _record(run.pk, Status.RECONCILING, execution=Execution.RUNNING)
            lifecycle.note(run.pk, f"{STILL_RUNNING} Check its outcome again later.")
            return
        _conclude(shell, run, evidence, Status.RECONCILING)


def _conclude(
    shell: RemoteShell,
    run: ApplyRun,
    evidence: native.UnitEvidence,
    source: RemoteOperation.Status,
) -> None:
    """Record terminal execution evidence, verify a success, and close the run."""
    execution = evidence.execution
    verification = Verification.NOT_APPLICABLE
    failure = _EXECUTION_FAILURES.get(execution, "")
    if execution == Execution.SUCCEEDED:
        try:
            verification = _verify(shell, run)
        except ConnectionFailed:
            verification = Verification.UNAVAILABLE
        if verification == Verification.FAILED:
            failure = VERIFICATION_FAILED
        elif verification == Verification.UNAVAILABLE:
            failure = VERIFICATION_UNAVAILABLE
    succeeded = execution == Execution.SUCCEEDED and verification == Verification.PASSED
    with transaction.atomic():
        if not lifecycle.finish(run.pk, source, succeeded=succeeded, failure=failure):
            return
        ApplyRun.objects.filter(pk=run.pk).update(
            execution=execution,
            verification=verification,
            invocation_id=evidence.invocation_id,
        )
    logger.info("Apply run %s finished: %s", run.pk, execution)


def _verify(shell: RemoteShell, run: ApplyRun) -> Verification:
    """Check the refresh's postconditions with fresh reads.

    The noble, noble-updates and noble-security main indexes for the server's
    architecture must be authenticated Ubuntu indexes, and dpkg's status must be unchanged
    since before submission. A read that fails makes verification unavailable.
    """
    before = ApplyRun.objects.values_list("dpkg_status_before", flat=True).get(pk=run.pk)
    after = _dpkg_status(shell)
    targets = shell.run(inspection.INDEX_TARGETS)
    architecture = shell.run(inspection.ARCHITECTURE)
    if after is None or not before or targets.exit_status or targets.truncated:
        return Verification.UNAVAILABLE
    try:
        found = parse_index_targets(targets.stdout.replace("|", "\t"))
        arch = parse_architecture(architecture.stdout)
    except Unreadable:
        return Verification.UNAVAILABLE
    authenticated = all(
        any(
            target.origin == "Ubuntu"
            and target.codename == "noble"
            and target.suite == suite
            and target.component == "main"
            and target.architecture == arch
            and target.trusted
            for target in found
        )
        for suite in profiles.REQUIRED_SUITES
    )
    return Verification.PASSED if authenticated and after == before else Verification.FAILED


lifecycle.register(
    ApplyRun,
    _apply,
    interrupted=INTERRUPTED_FAILURE,
    unexpected=UNEXPECTED_FAILURE,
    stale_after=STALE_AFTER,
    uncertain=UNCERTAIN,
    reconcile=_check,
)
