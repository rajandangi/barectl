"""The apply kind of remote operation: run a reviewed plan revision through native execution.

Views call ``request_apply`` to queue one reviewed revision, ``request_check`` to ask for
a reconciling run's outcome, ``request_closure`` to acknowledge that a run's outcome is
unknown, and ``read_apply`` and ``apply_history`` to show runs. ``servers.registration``
calls ``keep_apply_audit`` when removing a server. The lifecycle belongs to
``operations.lifecycle``, which claims a run in the durable worker and runs ``_apply``, or
``_check`` for a reconciling run.

Two reviewed actions can be applied: a package metadata refresh, and clearing finished
bootstrap runs from the server's systemd. Package profiles cannot be applied yet.

The worker checks the requesting account again, connects with the plan's alias, verifies
the reviewed host key and the privilege for the exact submission, and records the
dispatch before sending the transient unit through ``bootstrap.native``. From then on
only native evidence of that same unit closes the run: a lost acknowledgement, a lost
connection or a stopped worker leaves it reconciling, and nothing is ever submitted
again. When no native record of the unit remains, the run stays reconciling until an
operator allowed to apply its action acknowledges that its outcome is unknown and a check
proves, under the server's mutation lock, that it can no longer start or still be
running; it then closes as failed with outcome unknown. No local transaction is held open
while the worker is connected.
"""

import logging
import time
from dataclasses import dataclass
from datetime import datetime, timedelta

from django.contrib.auth.models import AbstractBaseUser, User
from django.db import IntegrityError, transaction
from django.db.models import Q
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

# The actions that can be applied, and what applying each requires of the account, checked
# again when the worker starts and when an acknowledgement of an unknown outcome is used.
APPLIABLE = frozenset({Action.METADATA_REFRESH, Action.CLEAR_RESULTS})
_VIEW = ("servers.view_server", "bootstrap.view_configurationplan")
APPLY_PERMISSIONS = (*_VIEW, "bootstrap.apply_configurationplan")
CLEAR_PERMISSIONS = (*_VIEW, "bootstrap.clear_native_results")
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
    "apply this plan, so Barectl did not connect to the server."
)
DISABLED_FAILURE = (
    "Applying this kind of plan is not available in this installation, so Barectl did "
    "not connect to the server."
)
PLAN_GONE_FAILURE = "The reviewed plan is no longer recorded, so Barectl did not connect."
EVIDENCE_FAILURE = (
    "The reviewed plan has no evidence to recheck on the server, so Barectl did not "
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
    "submitted nothing. Prepare and apply a plan to clear finished bootstrap runs, then "
    "prepare this plan again."
)
CLEANUP_CEILING_FAILURE = (
    f"The server keeps {native.CLEANUP_CEILING} or more bootstrap runs, more than a reviewed "
    "cleanup may add to, so Barectl submitted nothing. Clear finished runs through ordinary "
    "administration: systemctl reset-failed for failed units and systemctl stop for exited "
    "ones, after checking that none still has processes."
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
    "delivered, or the unit's record was cleared after it ran. A delayed delivery still "
    "stops at the admission deadline without changes."
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
OUTCOME_UNKNOWN = (
    "Outcome unknown. No native record of this run remains, so Barectl cannot tell whether "
    "it changed the server; it may have. An operator acknowledged this after Barectl proved "
    "that the run can no longer start or still be running. Inspect the server through "
    "ordinary administration and prepare a new plan before any later change."
)
# Why a closure attempt left the run reconciling. Acknowledging again asks for another.
CLOSURE_ACCOUNT = (
    "The account that acknowledged the unknown outcome is no longer active or allowed to "
    "apply this plan, so Barectl did not close the run."
)
CLOSURE_PRIVILEGE = (
    "The SSH user is not root, and sudo -n -l does not authorize the lock probe without a "
    "password, so Barectl could not prove that nothing runs and did not close the run."
)
CLOSURE_LOCK_HELD = (
    "Another change held Barectl's mutation lock on the server, so Barectl could not prove "
    "that nothing runs and did not close the run. Acknowledge again after it finishes."
)
CLOSURE_UNSAFE_LOCK = (
    "The lock directory /run/lock/barectl or its lock file is not safe to use, so Barectl "
    "could not take the mutation lock and did not close the run."
)
CLOSURE_ACTIVE = (
    "A bootstrap run still has processes on the server, so Barectl did not close the run. "
    "Acknowledge again after it finishes."
)
CLOSURE_FOUND = (
    "The run's unit appeared on the server while Barectl held the lock. Check its outcome instead."
)
CLOSURE_UNREADABLE = (
    "Barectl could not read what the lock probe reported, so it did not close the run."
)
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
    Execution.CAPACITY: (
        "The server kept too many finished bootstrap runs when this run held the lock, so it "
        "stopped before changing anything. Clear finished runs with a reviewed cleanup, then "
        "prepare again."
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
_CLEANUP_FAILURES = {
    Execution.DRIFT: (
        "A reviewed unit changed after review: it has another invocation, is no longer "
        "finished, or has processes. The cleanup stopped before clearing anything. Prepare a "
        "new cleanup plan."
    ),
    Execution.FAILED: (
        "systemd refused to clear a reviewed unit, so some units may be cleared and others "
        "not. Prepare a new cleanup plan to review what remains."
    ),
    Execution.TIMED_OUT: (
        f"The cleanup reached its {native.RUNTIME_MAX} limit and systemd stopped it; some units "
        "may remain. Prepare a new cleanup plan to review what remains."
    ),
    Execution.KILLED: (
        "The cleanup was terminated by a signal before it finished; some units may remain. "
        "Prepare a new cleanup plan to review what remains."
    ),
}
VERIFICATION_FAILED = (
    "The update completed, but its postconditions do not hold: the authenticated Ubuntu "
    "indexes are missing or a package changed. Inspect the server through ordinary "
    "administration."
)
CLEANUP_VERIFICATION_FAILED = (
    "The cleanup completed, but a reviewed unit is still retained. Prepare a new cleanup "
    "plan to review it."
)
VERIFICATION_UNAVAILABLE = (
    "The run completed on the server, but Barectl could not check its postconditions, so it "
    "records the run as failed with verification unavailable. Prepare a new plan before any "
    "later change."
)


@dataclass(frozen=True)
class ApplyRequest:
    """What ``request_apply`` did: the run for the revision, or why there is none."""

    run: ApplyRun | None
    problem: str = ""


def required_permissions(action: str) -> tuple[str, ...]:
    """What applying ``action`` requires of an account, besides being active."""
    return CLEAR_PERMISSIONS if action == Action.CLEAR_RESULTS else APPLY_PERMISSIONS


def apply_available(plan: ConfigurationPlan) -> bool:
    """Whether ``plan`` is a kind this installation may apply at all."""
    return plan.action in APPLIABLE


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
def request_closure(operation_id: int, user: User) -> bool:
    """Record ``user``'s acknowledgement that the run's outcome is unknown, and ask a check
    to close it; return whether the run was still reconciling without native evidence.

    The acknowledgement alone closes nothing: the check closes the run only with the
    proofs ``_close_unknown`` establishes, and uses the acknowledgement once.
    """
    run = ApplyRun.objects.filter(pk=operation_id).first()
    if run is None or not user.has_perms(required_permissions(run.action)):
        return False
    now = timezone.now()
    with transaction.atomic():
        acknowledged = ApplyRun.objects.filter(
            pk=operation_id,
            status=Status.RECONCILING,
            execution=Execution.NOT_FOUND,
        ).update(
            unknown_acknowledged_by=user,
            unknown_acknowledged_by_name=user.get_username(),
            unknown_acknowledged_at=now,
            closure_requested_at=now,
            closure_blocked="",
        )
    return bool(acknowledged) and lifecycle.check(run)


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


def current_units() -> frozenset[str]:
    """The units of this installation's runs that are not finished, on any server.

    A cleanup plan never clears them: their runs still need their native evidence.
    """
    return frozenset(
        ApplyRun.objects.filter(status__in=RemoteOperation.ACTIVE).values_list(
            "unit_name", flat=True
        )
    )


def _record(
    operation_id: int,
    source: RemoteOperation.Status,
    revision: int | None = None,
    **changes: object,
) -> bool:
    """Record run details only while the run is still in ``source``, at ``revision`` if given."""
    condition = Q(pk=operation_id, status=source)
    if revision is not None:
        condition &= Q(revision=revision)
    with transaction.atomic():
        if not RemoteOperation.objects.filter(condition).exists():
            return False
        ApplyRun.objects.filter(pk=operation_id).update(**changes)
    return True


def _authorized(user: User | None, action: str) -> bool:
    return user is not None and user.is_active and user.has_perms(required_permissions(action))


def _authorize(run: ApplyRun) -> None:
    if run.action not in APPLIABLE:
        raise OperationRefused(DISABLED_FAILURE)
    if not _authorized(run.requested_by, run.action):
        raise OperationRefused(REVOKED_FAILURE)


def _payload(run: ApplyRun, plan: ConfigurationPlan) -> str:
    """The reviewed action's payload, bound to the plan's boot, deadline and evidence."""
    deadline = run.admission_deadline_centiseconds
    if run.action == Action.CLEAR_RESULTS:
        targets = [
            native.ClearTarget(unit.unit_name, unit.invocation_id)
            for unit in plan.native_units.all()
        ]
        if not targets:
            raise OperationRefused(EVIDENCE_FAILURE)
        return native.clear_results(run.unit_name, run.boot_id, deadline, targets)
    digest = (
        plan.evidence.filter(kind=PlanEvidence.Kind.APT_REVALIDATION)
        .values_list("fingerprint", flat=True)
        .first()
    )
    if not digest:
        raise OperationRefused(EVIDENCE_FAILURE)
    return native.metadata_refresh(run.unit_name, run.boot_id, deadline, digest)


def _apply(run: ApplyRun) -> None:
    """Submit the reviewed run once, then watch its native unit until it is terminal."""
    _authorize(run)
    plan = run.plan
    if plan is None:
        raise OperationRefused(PLAN_GONE_FAILURE)
    script = _payload(run, plan)
    try:
        argv = native.submission(run.unit_name, script)
    except native.PayloadTooLarge:
        raise OperationRefused(TOO_LARGE_FAILURE) from None
    with ssh.connect_alias(run.ssh_alias) as shell:
        if shell.host_key != run.reviewed_host_key:
            raise OperationRefused(HOST_KEY_FAILURE)
        root = _admit(shell, argv, run.action)
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


def _root(shell: RemoteShell, argv: list[str]) -> bool | None:
    """Whether ``argv`` runs as root: ``True`` for root, ``False`` through sudo, ``None``
    when neither is available. Raises ``OperationRefused`` if the user cannot be read."""
    root = native.is_root(shell)
    if root is None:
        raise OperationRefused(UNREADABLE_FAILURE)
    if root:
        return True
    return False if shell.run(native.authorization(argv)).exit_status == 0 else None


def _admit(shell: RemoteShell, argv: list[str], action: str) -> bool:
    """Check privilege for the exact submission and the retained units; return root.

    A cleanup is admitted above the retained limit, up to the cleanup ceiling, so it
    remains available when the server is at capacity.
    """
    root = _root(shell, argv)
    if root is None:
        raise OperationRefused(PRIVILEGE_FAILURE)
    retained = native.retained_units(shell)
    if retained is None:
        raise OperationRefused(UNREADABLE_FAILURE)
    if action == Action.CLEAR_RESULTS:
        if retained >= native.CLEANUP_CEILING:
            raise OperationRefused(CLEANUP_CEILING_FAILURE)
    elif retained >= native.RETAINED_LIMIT:
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
    the recorded one once one was recorded. Every record is conditional on the run still
    reconciling at this check's revision, so an older check never overwrites a newer
    one's evidence. Evidence that is still running leaves the run reconciling. Missing
    evidence leaves it reconciling too, unless an acknowledgement asked this check to
    close it and ``_close_unknown`` proves it safe.
    """
    revision = run.revision
    closing = run.closure_requested_at
    try:
        with ssh.connect_alias(run.ssh_alias) as shell:
            if shell.host_key != run.reviewed_host_key:
                raise OperationRefused(HOST_KEY_FAILURE)
            try:
                evidence = native.inspect(shell, run.unit_name)
            except native.Unreadable:
                raise OperationRefused(UNREADABLE_EVIDENCE) from None
            if not evidence.found:
                reason = RESTARTED if evidence.boot_id != run.boot_id else NOT_FOUND
                if not _record(run.pk, Status.RECONCILING, revision, execution=Execution.NOT_FOUND):
                    return
                lifecycle.note(run.pk, f"{reason} {UNCERTAIN}", revision=revision)
                if closing is not None:
                    _close_unknown(shell, run, revision)
                return
            if run.invocation_id and evidence.invocation_id != run.invocation_id:
                lifecycle.note(run.pk, f"{MISMATCH} {UNCERTAIN}", revision=revision)
                return
            if not _record(
                run.pk, Status.RECONCILING, revision, invocation_id=evidence.invocation_id
            ):
                return
            if not evidence.terminal:
                _record(run.pk, Status.RECONCILING, revision, execution=Execution.RUNNING)
                lifecycle.note(
                    run.pk, f"{STILL_RUNNING} Check its outcome again later.", revision=revision
                )
                return
            _conclude(shell, run, evidence, Status.RECONCILING, revision)
    finally:
        if closing is not None:
            # The acknowledgement was used, whatever the check found; a newer one waits
            # for its own check.
            ApplyRun.objects.filter(pk=run.pk, closure_requested_at=closing).update(
                closure_requested_at=None
            )


def _close_unknown(shell: RemoteShell, run: ApplyRun, revision: int) -> None:
    """Close a run without native evidence as outcome unknown, if every proof holds.

    The acknowledging account must still be active and allowed to apply the run's action.
    Then a finite probe takes the same mutation lock every payload takes, without waiting,
    and while holding it shows that the server restarted since the run's boot or that its
    admission deadline passed on the server's clock, so a delayed delivery can no longer
    start; that no bootstrap unit has processes; and that the run's unit is still absent.
    Otherwise the run stays reconciling with the missing proof.
    """
    reason = _closure_blocked(shell, run)
    with transaction.atomic():
        if reason:
            _record(run.pk, Status.RECONCILING, revision, closure_blocked=reason)
            return
        if lifecycle.finish(
            run.pk, Status.RECONCILING, succeeded=False, failure=OUTCOME_UNKNOWN, revision=revision
        ):
            ApplyRun.objects.filter(pk=run.pk).update(
                execution=Execution.OUTCOME_UNKNOWN,
                verification=Verification.UNAVAILABLE,
                closure_blocked="",
            )
            logger.info("Apply run %s closed as outcome unknown", run.pk)


def _closure_blocked(shell: RemoteShell, run: ApplyRun) -> str:
    """The proof a closure of ``run`` lacks, or an empty string when every proof holds."""
    if not _authorized(run.unknown_acknowledged_by, run.action):
        return CLOSURE_ACCOUNT
    argv = native.closure_probe(run.unit_name)
    root = _root(shell, argv)
    if root is None:
        return CLOSURE_PRIVILEGE
    result = shell.run(native.privileged(argv, root=root))
    if result.exit_status == native.Probe.LOCK_CONFLICT:
        return CLOSURE_LOCK_HELD
    if result.exit_status == native.Probe.UNSAFE_LOCK:
        return CLOSURE_UNSAFE_LOCK
    if result.exit_status != native.Probe.LOCKED or result.truncated:
        return CLOSURE_UNREADABLE
    try:
        probe = native.parse_probe(result.stdout)
    except native.Unreadable:
        return CLOSURE_UNREADABLE
    if probe.unit_loaded:
        return CLOSURE_FOUND
    if probe.populated:
        return CLOSURE_ACTIVE
    restarted = probe.boot_id != run.boot_id
    if not restarted and probe.uptime_centiseconds < run.admission_deadline_centiseconds:
        return _not_fenced(run.admission_expires_at)
    return ""


def _not_fenced(expires: datetime) -> str:
    return (
        "The server has not restarted since the run's boot, and its admission deadline has "
        "not passed on the server's clock, so a delayed delivery could still start. Barectl "
        "did not close the run. Acknowledge again after the deadline, about "
        f"{timezone.localtime(expires):%H:%M:%S %Z}."
    )


def _conclude(
    shell: RemoteShell,
    run: ApplyRun,
    evidence: native.UnitEvidence,
    source: RemoteOperation.Status,
    revision: int | None = None,
) -> None:
    """Record terminal execution evidence, verify a success, and close the run.

    A controller-side failure while verifying never becomes a remote failure: the known
    execution outcome is kept and verification is recorded as unavailable.
    """
    execution = evidence.execution
    verification = Verification.NOT_APPLICABLE
    failure = _failure(run.action, execution)
    if execution == Execution.SUCCEEDED:
        try:
            verification = _verify(shell, run)
        except ConnectionFailed:
            verification = Verification.UNAVAILABLE
        if verification == Verification.FAILED:
            failure = (
                CLEANUP_VERIFICATION_FAILED
                if run.action == Action.CLEAR_RESULTS
                else VERIFICATION_FAILED
            )
        elif verification == Verification.UNAVAILABLE:
            failure = VERIFICATION_UNAVAILABLE
    succeeded = execution == Execution.SUCCEEDED and verification == Verification.PASSED
    with transaction.atomic():
        if not lifecycle.finish(
            run.pk, source, succeeded=succeeded, failure=failure, revision=revision
        ):
            return
        ApplyRun.objects.filter(pk=run.pk).update(
            execution=execution,
            verification=verification,
            invocation_id=evidence.invocation_id,
        )
    logger.info("Apply run %s finished: %s", run.pk, execution)


def _failure(action: str, execution: Execution) -> str:
    if action == Action.CLEAR_RESULTS and execution in _CLEANUP_FAILURES:
        return _CLEANUP_FAILURES[execution]
    return _EXECUTION_FAILURES.get(execution, "")


def _verify(shell: RemoteShell, run: ApplyRun) -> Verification:
    """Check the action's postconditions with fresh reads; a failed read is unavailable."""
    if run.action == Action.CLEAR_RESULTS:
        return _verify_cleanup(shell, run)
    return _verify_refresh(shell, run)


def _verify_cleanup(shell: RemoteShell, run: ApplyRun) -> Verification:
    """None of the reviewed units is retained any more."""
    plan = run.plan
    result = shell.run(native.RETAINED_STATES)
    if plan is None or result.exit_status != 0 or result.truncated:
        return Verification.UNAVAILABLE
    try:
        _, retained = native.parse_retained_states(result.stdout)
    except native.Unreadable:
        return Verification.UNAVAILABLE
    reviewed = set(plan.native_units.values_list("unit_name", flat=True))
    remaining = reviewed & {unit.unit for unit in retained}
    return Verification.FAILED if remaining else Verification.PASSED


def _verify_refresh(shell: RemoteShell, run: ApplyRun) -> Verification:
    """The noble, noble-updates and noble-security main indexes for the server's
    architecture must be authenticated Ubuntu indexes, and dpkg's status must be unchanged
    since before submission.
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
