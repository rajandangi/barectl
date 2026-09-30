"""docs/ssh-connections.md#applying-reviewed-plans"""

import logging
import re
import time
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta

from django.contrib.auth.models import AbstractBaseUser, User
from django.db import IntegrityError, transaction
from django.db.models import Q
from django.utils import timezone

from discovery import ssh
from discovery.models import DiscoverySnapshot
from discovery.services import DiscoveryBusy, queue_discovery
from discovery.ssh import ConnectionFailed, RemoteShell
from operations import lifecycle
from operations.lifecycle import OperationBusy, OperationRefused, recovers_first
from operations.models import RemoteOperation
from servers.models import Server

from . import actions, inspection, native, profiles, releases
from .evidence import (
    Unreadable,
    parse_architecture,
    parse_file_type,
    parse_index_targets,
    parse_lines,
    parse_listeners,
    parse_package_states,
    parse_path,
    parse_socket_listeners,
    parse_unit,
)
from .models import (
    Action,
    ApplyRun,
    ConfigurationPlan,
    Execution,
    PackageTransition,
    PlanEffect,
    PlanEvidence,
    Privilege,
    Verification,
)
from .presentation import ApplyView, apply_view

logger = logging.getLogger(__name__)

Status = RemoteOperation.Status

PACKAGE_ACTIONS = profiles.PACKAGE_ACTIONS
AUTO_MARKS_DIGEST = "apt-mark showauto | LC_ALL=C sort | sha256sum"
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
INVALIDATED = (
    "A later package metadata refresh may have changed the package indexes this plan was "
    "reviewed against. Prepare a new plan."
)
# The failures of a package profile's run, where they differ from a refresh's.
_PACKAGE_FAILURES = {
    Execution.DRIFT: (
        "The APT configuration, package state, automatic marks, package indexes, service "
        "units, configuration or listeners changed after review, or APT had nothing left to "
        "do, so the run stopped before changing any package. Prepare a new plan to review "
        "the current state."
    ),
    Execution.PACKAGE_MANAGER_BUSY: (
        "Another package-manager operation held dpkg's frontend lock, so the run stopped "
        "before changing any package; Barectl does not wait for it. Prepare a new plan after "
        "it finishes."
    ),
    Execution.TRANSACTION_REFUSED: (
        "APT's actual transaction differed from the reviewed one, so Barectl's pre-install "
        "guard stopped APT before dpkg changed any package. APT may have downloaded archives "
        "into its cache and debconf may have recorded default answers. Prepare a new plan to "
        "review the transaction APT now proposes."
    ),
    Execution.INSTALL_NOT_STARTED: (
        "APT failed before dpkg changed any package, for example while downloading or "
        "because a package is held. Inspect the unit with systemctl status and journalctl on "
        "the server, then prepare a new plan."
    ),
    Execution.INSTALL_FAILED: (
        "dpkg changed packages, but the installation did not complete. Packages may be "
        "unpacked but not configured. Barectl does not roll back or repair: inspect the unit "
        "with journalctl, and complete the installation with apt and dpkg through ordinary "
        "administration before preparing a new plan."
    ),
    Execution.SERVICE_FAILED: (
        "systemd refused to enable or start the service. Barectl does not retry or roll back: "
        "inspect it with systemctl status and journalctl, then prepare a new plan."
    ),
    Execution.VALIDATION_FAILED: (
        "The changes were made, but the service's own syntax check rejected the "
        "configuration afterwards. Barectl does not roll back: inspect the configuration "
        "and the unit's journal, repair it through ordinary administration, then prepare a "
        "new plan."
    ),
    Execution.RELOAD_FAILED: (
        "The changes were made and the configuration check passed, but systemd could not "
        "reload the service, or a reviewed socket did not listen again within "
        f"{native.RELOAD_WAIT_TENTHS / 10:g} seconds. Barectl does not retry or roll back: "
        "inspect the service with systemctl status and journalctl, repair it through ordinary "
        "administration, then prepare a new plan."
    ),
    Execution.TIMED_OUT: (
        f"The run reached its {native.RUNTIME_MAX} limit and systemd stopped it. Packages may "
        "be partly installed; no rollback happens. Complete or repair them with apt and dpkg."
    ),
    Execution.KILLED: (
        "The run was terminated by a signal before it finished. Packages may be partly "
        "installed; no rollback happens. Complete or repair them with apt and dpkg."
    ),
    Execution.FAILED: (
        "The run failed. Inspect the unit with systemctl status and journalctl on the server."
    ),
}
PACKAGE_VERIFICATION_FAILED = (
    "The run completed, but the profile's postconditions do not hold: a package is not "
    "installed at its reviewed version, dpkg reports a problem, an earlier package's "
    "automatic mark changed, the service is not enabled and active, the default listeners or "
    "the default pool's socket are missing, or the command-line runtime reports another "
    "version. Barectl does not repair or roll back; inspect the server through ordinary "
    "administration. The refreshed discovery shows what is there now."
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


NOT_APPLICABLE = (
    "Barectl does not apply this kind of plan yet. The plan remains a review record of "
    "what applying would change."
)


def required_permissions(action: str) -> tuple[str, ...]:
    return actions.authority(action).apply


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
    handler = actions.extension(plan.action)
    try:
        with transaction.atomic():
            run = _queue(plan, server, user, handler)
            if handler is not None:
                handler.copy_audit(plan, run)
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


def _queue(
    plan: ConfigurationPlan,
    server: Server,
    user: AbstractBaseUser,
    handler: actions.ActionHandler | None,
) -> ApplyRun:
    changes = handler.reviewed_changes(plan) if handler is not None else reviewed_changes(plan)
    return lifecycle.queue(
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
        release=plan.release,
        reviewed_host_key=plan.host_key,
        boot_id=plan.boot_id,
        admission_deadline_centiseconds=plan.admission_deadline_centiseconds,
        admission_expires_at=plan.admission_expires_at,
        effects="\n".join(
            f"{effect.get_kind_display()}. {effect.text}" for effect in plan.effects.all()
        ),
        reviewed_changes=changes,
        unit_name=native.new_unit_name(),
    )


def reviewed_changes(plan: ConfigurationPlan) -> str:
    """The plan's exact changes, one per line, copied so the audit outlives the plan."""
    if plan.action == Action.CLEAR_RESULTS:
        return "\n".join(
            f"Clear {unit.unit_name}, invocation {unit.invocation_id}"
            for unit in plan.native_units.all()
        )
    return "\n".join(
        f"{transition.get_step_display()} {transition.package} {transition.version} "
        f"({transition.architecture}) from {', '.join(transition.origins.splitlines())}"
        for transition in plan.transitions.all()
    )


def _refusal(plan: ConfigurationPlan) -> str:
    if not actions.applicable(plan.action):
        return NOT_APPLICABLE
    if not plan.eligible or plan.no_changes:
        return "Only an eligible plan with changes can be applied."
    if timezone.now() >= plan.admission_expires_at:
        return "This plan's admission deadline has passed. Prepare a new plan."
    if invalidated(plan):
        return INVALIDATED
    return ""


def invalidated(plan: ConfigurationPlan) -> bool:
    """Whether a later metadata refresh may have changed a package plan's indexes."""
    server_id = plan.preparation.server_id
    return (
        plan.action in PACKAGE_ACTIONS
        and server_id is not None
        and any(dispatched > plan.collected_at for dispatched in index_changes(server_id))
    )


def index_changes(server_id: int) -> list[datetime]:
    """When the server's metadata refreshes that may have changed its indexes were sent.

    docs/ssh-connections.md#applying-reviewed-plans
    """
    refused = Execution.refused_before_changes()
    return [
        dispatched
        for dispatched in ApplyRun.objects.filter(
            server_id=server_id, action=Action.METADATA_REFRESH, dispatched_at__isnull=False
        )
        .exclude(execution__in=refused)
        .exclude(execution=Execution.NOT_SUBMITTED, status=RemoteOperation.Status.FAILED)
        .values_list("dispatched_at", flat=True)
        if dispatched is not None
    ]


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
def apply_history(shown: Iterable[str]) -> list[ApplyView]:
    """Every apply run of the ``shown`` actions for Activity, newest recorded first,
    including removed servers'."""
    return [apply_view(run) for run in ApplyRun.objects.filter(action__in=list(shown))]


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
    if not _authorized(run.requested_by, run.action):
        raise OperationRefused(REVOKED_FAILURE)
    if run.plan is not None and invalidated(run.plan):
        raise OperationRefused(INVALIDATED)


def _payload(run: ApplyRun, plan: ConfigurationPlan, handler: actions.ActionHandler | None) -> str:
    if not actions.applicable(run.action):
        raise OperationRefused(NOT_APPLICABLE)
    if handler is not None:
        return handler.payload(run, plan)
    deadline = run.admission_deadline_centiseconds
    if run.action in PACKAGE_ACTIONS:
        return package_payload(run, plan)
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


def _fingerprint(plan: ConfigurationPlan, kind: PlanEvidence.Kind) -> str:
    return plan.evidence.filter(kind=kind).values_list("fingerprint", flat=True).first() or ""


def package_payload(
    run: ApplyRun, plan: ConfigurationPlan, *, sockets: tuple[str, ...] = ()
) -> str:
    """A package plan's payload; a profile that reloads its service waits for its own
    socket and ``sockets`` to listen again."""
    profile = _profile(run)
    if profile is None:
        raise OperationRefused(EVIDENCE_FAILURE)
    apt = _fingerprint(plan, PlanEvidence.Kind.APT_REVALIDATION)
    packages = _fingerprint(plan, PlanEvidence.Kind.PACKAGE_REVALIDATION)
    if not apt or not packages:
        raise OperationRefused(EVIDENCE_FAILURE)
    actions = [
        native.PackageAction(
            transition.step == PackageTransition.Step.INSTALL,
            transition.package,
            transition.version,
            transition.architecture,
        )
        for transition in plan.transitions.all()
    ]
    roots = [(root.name, root.version) for root in plan.roots.all() if not root.installed]
    effects = set(plan.effects.values_list("kind", flat=True))
    try:
        return native.package_change(
            run.unit_name,
            run.boot_id,
            run.admission_deadline_centiseconds,
            apt=apt,
            packages=packages,
            scope=profile.revalidation,
            roots=roots,
            actions=actions,
            services=profile.units,
            enable=not actions and PlanEffect.Kind.SERVICE_ENABLE in effects,
            start=not actions and PlanEffect.Kind.SERVICE_START in effects,
            check=profile.check,
            reload=profile.reload,
            sockets=(*((profile.socket,) if profile.socket else ()), *sockets),
        )
    except ValueError:
        raise OperationRefused(EVIDENCE_FAILURE) from None


def _profile(run: ApplyRun) -> profiles.Profile | None:
    """The reviewed profile on the release the plan was reviewed against, if supported."""
    release = releases.RELEASES.get(run.release)
    return profiles.profile(release, Action(run.action)) if release is not None else None


def _apply(run: ApplyRun) -> None:
    """Submit the reviewed run once, then watch its native unit until it is terminal."""
    _authorize(run)
    plan = run.plan
    if plan is None:
        raise OperationRefused(PLAN_GONE_FAILURE)
    handler = actions.extension(run.action)
    script = _payload(run, plan, handler)
    try:
        argv = native.submission(run.unit_name, script)
    except native.PayloadTooLarge:
        raise OperationRefused(TOO_LARGE_FAILURE) from None
    with ssh.connect_alias(run.ssh_alias) as shell:
        if shell.host_key != run.reviewed_host_key:
            raise OperationRefused(HOST_KEY_FAILURE)
        root = _admit(shell, argv, run.action)
        if handler is not None:
            handler.admit(shell, run, root=root)
        before = _dpkg_status(shell)
        if before is None:
            raise OperationRefused(UNREADABLE_FAILURE)
        marks = ""
        if run.action in PACKAGE_ACTIONS:
            marks = _digest_of(shell, AUTO_MARKS_DIGEST) or ""
            if not marks:
                raise OperationRefused(UNREADABLE_FAILURE)
        _record(run.pk, Status.RUNNING, dpkg_status_before=before, auto_marks_before=marks)
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
    """Check privilege for the exact submission and the retained units; return root."""
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
    return _digest_of(shell, native.DPKG_STATUS_DIGEST)


def _digest_of(shell: RemoteShell, command: str) -> str | None:
    result = shell.run(command)
    if result.exit_status != 0 or result.truncated:
        return None
    try:
        return native.parse_digest(result.stdout)
    except native.Unreadable:
        return None


def _watch(shell: RemoteShell, run: ApplyRun, *, acknowledged: bool) -> None:
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
    """docs/ssh-connections.md#applying-reviewed-plans"""
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
    """docs/adr/0006-use-native-bootstrap-execution.md#unknown-outcomes"""
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
    """A controller-side failure while verifying never becomes a remote failure: the known
    execution outcome is kept and verification is recorded as unavailable.
    """
    handler = actions.extension(run.action)
    execution = evidence.execution if handler is None else handler.execution(evidence)
    exited = evidence.exec_main_code == native.CLD_EXITED
    exit_status = evidence.exec_main_status if exited else None
    verification = Verification.NOT_APPLICABLE
    if handler is None:
        failure = _failure(run, execution)
    else:
        failure = handler.failure(run, execution, exit_status)
    if execution == Execution.SUCCEEDED:
        try:
            verification = _verify(shell, run) if handler is None else handler.verify(shell, run)
        except ConnectionFailed:
            verification = Verification.UNAVAILABLE
        if verification == Verification.FAILED:
            failure = (
                _verification_failure(run) if handler is None else handler.verification_failure(run)
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
            exit_status=exit_status,
        )
    logger.info("Apply run %s finished: %s", run.pk, execution)
    changes = run.action in PACKAGE_ACTIONS or handler is not None
    if changes and execution not in Execution.refused_before_changes():
        _refresh_discovery(run)


def _refresh_discovery(run: ApplyRun) -> None:
    """Queue discovery after a run that may have changed the server.

    The run has closed, so its server's active slot is free; an operation someone queued
    meanwhile is left alone, and the page says when the snapshot is older than the run.
    """
    if run.server_id is None:
        return
    server = Server.objects.filter(pk=run.server_id).first()
    if server is None:
        return
    try:
        queue_discovery(server)
    except DiscoveryBusy, Server.DoesNotExist:
        logger.info("Discovery after apply run %s was not queued", run.pk)


def _verification_failure(run: ApplyRun) -> str:
    if run.action == Action.CLEAR_RESULTS:
        return CLEANUP_VERIFICATION_FAILED
    if run.action in PACKAGE_ACTIONS:
        return package_verification_failure(run)
    return VERIFICATION_FAILED


def package_verification_failure(run: ApplyRun) -> str:
    profile = _profile(run)
    return (profile and profile.verification_failure) or PACKAGE_VERIFICATION_FAILED


def package_failure(run: ApplyRun, execution: Execution) -> str:
    return _failure(run, execution)


def _failure(run: ApplyRun, execution: Execution) -> str:
    action = run.action
    if action == Action.CLEAR_RESULTS and execution in _CLEANUP_FAILURES:
        return _CLEANUP_FAILURES[execution]
    if action in PACKAGE_ACTIONS and execution in _PACKAGE_FAILURES:
        profile = _profile(run)
        if execution == Execution.VALIDATION_FAILED and profile and profile.check_failure:
            return profile.check_failure
        return _PACKAGE_FAILURES[execution]
    return _EXECUTION_FAILURES.get(execution, "")


def _verify(shell: RemoteShell, run: ApplyRun) -> Verification:
    """Check the action's postconditions with fresh reads; a failed read is unavailable."""
    if run.action == Action.CLEAR_RESULTS:
        return _verify_cleanup(shell, run)
    if run.action in PACKAGE_ACTIONS:
        return verify_profile(shell, run)
    return _verify_refresh(shell, run)


def verify_profile(shell: RemoteShell, run: ApplyRun) -> Verification:
    """docs/ssh-connections.md#applying-package-profiles

    The service's syntax check already ran as root at the end of the payload, whose
    success this follows.
    """
    plan = run.plan
    profile = _profile(run)
    if plan is None or profile is None:
        return Verification.UNAVAILABLE
    roots = list(plan.roots.all())
    expected = {root.name: root.version for root in roots}
    new_roots = sorted(root.name for root in roots if not root.installed)
    installs = list(
        plan.transitions.filter(step=PackageTransition.Step.INSTALL).values_list(
            "package", "version"
        )
    )
    expected.update(installs)
    dependencies = sorted({name for name, _ in installs} - set(new_roots))
    try:
        checks = [
            _packages_installed(shell, expected),
            _marks_kept(shell, run, new_roots, dependencies),
            *(
                _unit_running(shell, unit, serving=unit == profile.serving_unit)
                for unit in profile.units
            ),
        ]
        if profile.port is not None:
            checks.append(_default_listeners(shell, profile))
        if profile.data is not None:
            checks.append(_data_initialized(shell, profile.data))
            checks.append(_listings_kept(shell, profile.data))
        checks.append(_configuration_kept(shell, profile))
        if profile.socket is not None:
            checks.append(_socket_listening(shell, profile.socket))
        if profile.runtime is not None:
            checks.append(_runtime_matches(shell, profile.runtime, expected))
        if profile.modules:
            checks.append(_modules_enabled(shell, profile))
    except Unreadable:
        return Verification.UNAVAILABLE
    return Verification.PASSED if all(checks) else Verification.FAILED


def _read(shell: RemoteShell, command: str, *, ok: tuple[int, ...] = (0,)) -> str:
    result = shell.run(command)
    if result.exit_status not in ok or result.truncated:
        raise Unreadable("A postcondition could not be read.")
    return result.stdout


def _packages_installed(shell: RemoteShell, expected: dict[str, str]) -> bool:
    states = parse_package_states(
        _read(shell, inspection.package_states(sorted(expected)), ok=(0, 1))
    )
    found = {state.name: state for state in states}
    audit = _read(shell, inspection.DPKG_AUDIT)
    return not audit.strip() and all(
        name in found and found[name].installed and found[name].version == version
        for name, version in expected.items()
    )


_MARKED = re.compile(r"[a-z0-9][a-z0-9+.-]{0,99}(:[a-z0-9-]{1,20})?")


def _marks_kept(
    shell: RemoteShell, run: ApplyRun, roots: list[str], dependencies: list[str]
) -> bool:
    """The new roots are manual, the new dependencies automatic, and the others unchanged."""
    before = ApplyRun.objects.values_list("auto_marks_before", flat=True).get(pk=run.pk)
    if not before:
        raise Unreadable("The automatic marks before submission were not recorded.")
    others = AUTO_MARKS_DIGEST
    if dependencies:
        excluded = " ".join(f"-e {name}" for name in dependencies)
        others = f"apt-mark showauto | grep -vxF {excluded} | LC_ALL=C sort | sha256sum"
    try:
        kept = native.parse_digest(_read(shell, others)) == before
    except native.Unreadable:
        raise Unreadable("The automatic marks are in an unknown form.") from None
    automatic: tuple[str, ...] = ()
    if dependencies:
        automatic = parse_lines(
            _read(shell, inspection.automatic_marks(dependencies)), _MARKED, "An automatic mark"
        )
    manual: tuple[str, ...] = ()
    if roots:
        manual = parse_lines(_read(shell, inspection.manual_marks(roots)), _MARKED, "A manual mark")
    return kept and set(automatic) == set(dependencies) and set(manual) == set(roots)


def _unit_running(shell: RemoteShell, name: str, *, serving: bool) -> bool:
    """The distribution's unit, enabled and active; running when it is the serving unit."""
    unit = parse_unit(_read(shell, inspection.unit_state(name)), name)
    return (
        unit.load_state == "loaded"
        and unit.active_state == "active"
        and (unit.sub_state == "running" or not serving)
        and unit.unit_file_state in {"enabled", "enabled-runtime"} & profiles.enablements(name)
        and unit.fragment_path == profiles.unit_file(name)
        and not unit.drop_in_paths
    )


def _default_listeners(shell: RemoteShell, profile: profiles.Profile) -> bool:
    """The service listens on the distribution's default addresses, and on no other when
    the profile is exclusive."""
    port = profile.port or 0
    listeners = parse_listeners(
        _read(shell, inspection.listeners(port, Privilege.UNAVAILABLE, attributed=False)),
        port,
        attributed=False,
    )
    found = {listener.address for listener in listeners}
    if profile.exclusive:
        return bool(found) and found <= profile.addresses
    return profile.addresses <= found


def _file_type(shell: RemoteShell, path: str) -> str:
    """The type and owner of ``path``, such as ``directory mysql``; empty when absent."""
    found = shell.run(inspection.present(path)).exit_status
    if found == 1:
        return ""
    if found != 0:
        raise Unreadable("A postcondition could not be read.")
    return parse_file_type(_read(shell, inspection.file_type(path)))


def _data_initialized(shell: RemoteShell, data: profiles.DataSpec) -> bool:
    """The data directory and its initialization marker exist and belong to the engine."""
    return _file_type(shell, data.directory) == f"directory {data.owner}" and (
        _file_type(shell, data.marker) == f"{data.marker_type} {data.owner}"
    )


def _listings_kept(shell: RemoteShell, data: profiles.DataSpec) -> bool:
    """Each data listing holds only its allowed entries, besides dot files."""
    for directory, allowed in data.listings:
        names = parse_lines(
            _read(shell, inspection.entries(directory)), _ENTRY, f"An entry of {directory}"
        )
        if not {name for name in names if not name.startswith(".")} <= allowed:
            return False
    return True


_ENTRY = re.compile(r"[A-Za-z0-9._+-]{1,100}")


def _configuration_kept(shell: RemoteShell, profile: profiles.Profile) -> bool:
    """The server reads the distribution's option files, and no forbidden path exists."""
    if any(_file_type(shell, path) for path in profile.forbidden):
        return False
    wanted = profile.alternative
    if wanted is not None:
        resolved = parse_path(_read(shell, inspection.resolve(wanted.link), ok=(0, 1)))
        if resolved != wanted.value:
            return False
    defaults = profile.defaults
    if defaults is None:
        return True
    shown = _read(shell, defaults.command)
    return profile.effective(shown) == defaults.expected


def _socket_listening(shell: RemoteShell, socket: str) -> bool:
    """A Unix socket listens at the default pool's path."""
    return socket in parse_socket_listeners(_read(shell, inspection.socket_listeners(socket)))


def _runtime_matches(
    shell: RemoteShell, runtime: profiles.Runtime, versions: dict[str, str]
) -> bool:
    """The runtime's first line names its package's upstream version, without the epoch
    and the Debian revision."""
    version = versions.get(runtime.package)
    if version is None:
        return False
    upstream = re.sub(r"-[^-]*\Z", "", re.sub(r"\A[0-9]+:", "", version))
    first = _read(shell, runtime.command).partition("\n")[0]
    return first.startswith(runtime.first_line.format(version=upstream))


def _modules_enabled(shell: RemoteShell, profile: profiles.Profile) -> bool:
    """Each SAPI's conf.d links every module to its module file, and the service lists it."""
    mods = next(spec.root for spec in profile.trees if spec.root.endswith("/mods-available"))
    for spec in profile.trees:
        if spec.root == mods:
            continue
        for link, module in profile.modules:
            path = f"{spec.root}/conf.d/{link}.ini"
            if parse_path(_read(shell, inspection.resolve(path), ok=(0, 1))) != (
                f"{mods}/{module}.ini"
            ):
                return False
    listed = {line.strip().casefold() for line in _read(shell, profile.module_list).splitlines()}
    return all(module.casefold() in listed for _, module in profile.modules)


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
    """The main indexes of the release's suites, such as noble, noble-updates and
    noble-security, for the server's architecture must be authenticated Ubuntu indexes,
    and dpkg's status must be unchanged since before submission.
    """
    release = releases.RELEASES.get(run.release)
    before = ApplyRun.objects.values_list("dpkg_status_before", flat=True).get(pk=run.pk)
    after = _dpkg_status(shell)
    targets = shell.run(inspection.INDEX_TARGETS)
    architecture = shell.run(inspection.ARCHITECTURE)
    if release is None or after is None or not before or targets.exit_status or targets.truncated:
        return Verification.UNAVAILABLE
    try:
        found = parse_index_targets(targets.stdout.replace("|", "\t"))
        arch = parse_architecture(architecture.stdout)
    except Unreadable:
        return Verification.UNAVAILABLE
    authenticated = all(
        any(
            target.origin == "Ubuntu"
            and target.codename == release.codename
            and target.suite == suite
            and target.component == "main"
            and target.architecture == arch
            and target.trusted
            for target in found
        )
        for suite in release.suites
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
