"""docs/adr/0035-one-change-engine-with-effect-derived-consent.md

The one change engine: it prepares, reviews, applies natively, verifies and reconciles
every change behind a four-member kind seam (inspect, review, body, verify). A review is
stored once; a run keeps a protected reference to it. Consent is derived from the review's
declared effects, and the affected sites a Shared change lists are rechecked under the
mutation lock before anything changes.
"""

import hashlib
import json
import logging
import re
import shlex
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Final

from django.contrib.auth.models import User
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from discovery import ssh
from discovery.ssh import ConnectionFailed, RemoteShell
from operations import apt, lifecycle, native
from operations.lifecycle import OperationRefused
from operations.models import RemoteOperation

from .consent import (
    CONSENT_PERMISSIONS,
    PREPARE_PERMISSIONS,
    DeclaredEffect,
    affected_sites_of,
    consent_of,
)
from .inputs import InputShape, PreparationInputs, decode_inputs
from .models import (
    ADMISSION_CENTISECONDS,
    ChangePreparation,
    ChangeReview,
    ChangeRun,
    Consent,
    Result,
    Verification,
)

logger = logging.getLogger(__name__)

Status = RemoteOperation.Status
ADMISSION_SECONDS: Final = ADMISSION_CENTISECONDS // 100

# The worker watches a submitted run over its connection for at most this long, well
# within the connection's own limit (ssh.SESSION_TIMEOUT); a longer run is reconciling.
WATCH_LIMIT = timedelta(minutes=4)
POLL_INTERVAL = 2.0
JOURNAL_SETTLE_SECONDS = 3.0
STALE_AFTER = timedelta(minutes=10)

UNEXPECTED_FAILURE = (
    "Applying stopped because of an unexpected error. Barectl did not record the error "
    "details, which could include remote output. The worker log names the error type."
)
PREPARATION_UNEXPECTED_FAILURE = (
    "Change preparation stopped because of an unexpected error. Barectl did not record "
    "the error details, which could include remote output. The worker log names the "
    "error type."
)
INTERRUPTED_FAILURE = (
    "The worker stopped before it submitted anything to the server, so nothing changed. "
    "Prepare a new review to apply it."
)
PREPARATION_INTERRUPTED_FAILURE = (
    "The worker stopped before finishing this preparation. Preparation only reads the "
    "server, so nothing changed there. Prepare the change again."
)
UNCERTAIN = (
    "The run may have reached the server, and its outcome is not established yet. Barectl "
    "never submits it again; Check outcome reads the same unit's journal and state."
)
REVOKED_FAILURE = (
    "The account that requested this run is no longer active or no longer allowed to "
    "apply this change, so Barectl did not connect to the server."
)
PREPARATION_REVOKED_FAILURE = (
    "The account that requested this preparation is no longer active or no longer allowed "
    "to prepare changes, so Barectl did not connect to the server."
)
UNKNOWN_KIND = (
    "This kind of change is no longer known to this Barectl installation, so nothing was "
    "sent. Prepare the change again with a current installation."
)
TOO_LARGE_FAILURE = (
    "The reviewed change is larger than Barectl submits in one run, so nothing was sent. "
    "Barectl never splits a reviewed change."
)
HOST_KEY_FAILURE = (
    "The server presented a different host key from the one the review was made with, so "
    "Barectl submitted nothing. Prepare the change again after confirming the server's "
    "identity."
)
PRIVILEGE_FAILURE = (
    "The SSH user is not root, and sudo -n -l does not authorize the exact submission "
    "without a password, so Barectl submitted nothing. Barectl never installs a sudo policy "
    "or asks for a password."
)
UNREADABLE_FAILURE = (
    "Barectl could not read the server's state before submitting, so it submitted nothing."
)
EVIDENCE_FAILURE = (
    "The reviewed change body or its native evidence no longer matches the review, so the "
    "run stopped before changing anything. Prepare a new review."
)
RETAINED_FAILURE = (
    f"The server keeps {native.RETAINED_LIMIT} or more finished barectl runs, so Barectl "
    "submitted nothing. Prepare and apply a change that clears finished runs, then prepare "
    "this change again."
)
CEILING_FAILURE = (
    f"The server keeps {native.CLEANUP_CEILING} or more barectl runs, more than a reviewed "
    "cleanup may add to, so Barectl submitted nothing. Clear finished runs through ordinary "
    "administration: journalctl and systemctl, after checking that none still has processes."
)
REJECTED_FAILURE = (
    "systemd refused the submission and no unit was created, so nothing ran on the server. "
    "Prepare a new review to try again."
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
    "The server has no unit with this run's name and no result line in its journal. The "
    "submission may not have been delivered. A delayed delivery still stops at the "
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
OUTCOME_UNKNOWN = (
    "Outcome unknown. No native record of this run remains, so Barectl cannot tell whether "
    "it changed the server; it may have. An operator acknowledged this after Barectl proved "
    "that the run can no longer start or still be running. Inspect the server through "
    "ordinary administration and prepare a new review before any later change."
)

AFFECTED_SITES_CHANGED = (
    "Affected sites changed, review again: the sites this shared change reaches differ "
    "from the reviewed list, so the run stopped before changing anything."
)
_REFUSED_REASONS: Final[dict[str, str]] = {
    "runtime_cache": (
        "The locked runtime closure is unavailable from the signed cache. Nothing changed."
    ),
    "apt_active": (
        "Package maintenance still has processes. Wait for it to finish and review again."
    ),
    "apt_unreadable": "Package maintenance process state could not be read. Review again.",
    "unsafe_lock": (
        "The lock directory /run/lock/barectl or its lock file is not a root-owned private "
        "directory with an empty lock file, so the run stopped before changing anything. "
        "Remove it through ordinary administration, then prepare again."
    ),
    "boot": (
        "The server restarted after the change was reviewed, so the run stopped before "
        "changing anything. Prepare a new review."
    ),
    "deadline": (
        "The review's admission deadline had passed on the server's clock when the run "
        "started, so it stopped before changing anything. Prepare a new review."
    ),
    "active_run": (
        "Another barectl run still had processes on the server, so this run stopped before "
        "changing anything. Prepare a new review after it finishes."
    ),
    "capacity": (
        "The server kept too many finished barectl runs when this run held the lock, so it "
        "stopped before changing anything. Clear finished runs with a reviewed cleanup, "
        "then prepare again."
    ),
    "affected_sites": AFFECTED_SITES_CHANGED,
    "evidence": (
        "The reviewed evidence changed on the server, so the run stopped before changing "
        "anything. Prepare a new review."
    ),
}
_FAILURES: Final[dict[Result, str]] = {
    Result.REFUSED: "The run stopped before changing anything.",
    Result.LOCK_BUSY: (
        "Another change held Barectl's mutation lock on the server, so the run stopped "
        "before changing anything. Prepare a new review after that change finishes."
    ),
    Result.PARTIAL: (
        "The run stopped after changing the server, so the change is partly applied and "
        "no rollback happens. Read the unit's journal on the server, then prepare a new "
        "review of what remains."
    ),
    Result.FAILED: (
        "The run failed without reporting how far it got, so what changed is unknown and "
        "no rollback happens. Read the unit's journal on the server, then prepare a new "
        "review before any later change."
    ),
    Result.TIMED_OUT: (
        f"The run reached its {native.RUNTIME_MAX} limit and systemd stopped it; what "
        "changed is unknown and no rollback happens. Read the unit's journal on the "
        "server, then prepare a new review."
    ),
}
VERIFICATION_FAILED = (
    "The run completed, but its postconditions do not hold. Inspect the server through "
    "ordinary administration, then prepare a new review."
)
VERIFICATION_UNAVAILABLE = (
    "The run completed on the server, but Barectl could not check its postconditions, so "
    "it records the run as failed with verification unavailable. Prepare a new review "
    "before any later change."
)

# Why a closure attempt left the run reconciling. Acknowledging again asks for another.
CLOSURE_ACCOUNT = (
    "The account that acknowledged the unknown outcome is no longer active or allowed to "
    "apply this change, so Barectl did not close the run."
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
    "A barectl run still has processes on the server, so Barectl did not close the run. "
    "Acknowledge again after it finishes."
)
CLOSURE_RENEWAL_ACTIVE = (
    "Certbot's scheduled renewal service still has processes on the server, so Barectl did "
    "not close the run. Acknowledge again after it finishes."
)
CLOSURE_FOUND = (
    "The run's unit appeared on the server while Barectl held the lock. Check its outcome instead."
)
CLOSURE_UNREADABLE = (
    "Barectl could not read what the lock probe reported, so it did not close the run."
)


# The kind seam -----------------------------------------------------------------------------


@dataclass(frozen=True)
class ReviewDraft:
    """A review before it is stored: what the kind read, what it proposes and what it
    declares. Consent is not among the fields; the engine derives it from ``effects``."""

    kind: str
    intent: str
    effects: tuple[DeclaredEffect, ...] = ()
    stages: tuple[str, ...] = ()
    postconditions: tuple[str, ...] = ()
    refusals: tuple[str, ...] = ()
    boot_id: str = ""
    uptime_centiseconds: int | None = None
    # The fixed command that lists the affected sites, one per line; empty when the
    # change names no site. The engine digests its output at review and rechecks the
    # digest under the mutation lock.
    sites_read: str = ""
    current_sites: tuple[str, ...] | None = None
    # The kind's own versioned document, stored whole and read by its pages and body.
    document: dict[str, object] = field(default_factory=dict)

    @property
    def eligible(self) -> bool:
        return not self.refusals

    @property
    def no_changes(self) -> bool:
        return self.eligible and not self.effects


@dataclass(frozen=True)
class BodyContext:
    """What the engine tells a kind about the run that carries its body."""

    unit: str
    boot_id: str
    deadline_centiseconds: int


@dataclass(frozen=True)
class NativeBody:
    """A checked-in script and its reviewed, non-secret positional arguments."""

    source: bytes
    arguments: tuple[str, ...] = ()


@dataclass(frozen=True)
class ChangeKind:
    """A kind of change behind the engine's four-member seam: an inspection of current
    evidence, a pure review of it, the native body that runs under the mutation lock once
    the engine has admitted the review, and the verification of its postconditions."""

    slug: str
    label: str
    inspect: Callable[[RemoteShell, PreparationInputs], object]
    review: Callable[[object, PreparationInputs], ReviewDraft]
    body: Callable[[dict[str, object], BodyContext], NativeBody]
    verify: Callable[[RemoteShell, ChangeReview], bool | None]
    # How many retained barectl units admission still accepts for this kind.
    capacity: int = native.RETAINED_LIMIT
    refresh_discovery: bool = False
    input_choices: tuple[str, ...] = ()
    input_shape: InputShape = InputShape.SELECTION


_KINDS: dict[str, ChangeKind] = {}
_ACTIVE_UNIT_READERS: list[Callable[[], frozenset[str]]] = []


def register_kind(kind: ChangeKind) -> None:
    _KINDS[kind.slug] = kind


def kind_of(slug: str) -> ChangeKind | None:
    return _KINDS.get(slug)


def registered_kinds() -> tuple[ChangeKind, ...]:
    return tuple(_KINDS.values())


def register_active_units(reader: Callable[[], frozenset[str]]) -> None:
    """Let another app's unfinished runs keep their units out of reviews.

    Bootstrap's legacy apply runs share the unit namespace and the mutation lock; its
    reader is registered from its app config so a cleanup review never clears a unit a
    legacy run still needs.
    """
    if reader not in _ACTIVE_UNIT_READERS:
        _ACTIVE_UNIT_READERS.append(reader)


def current_units() -> frozenset[str]:
    """The units of this installation's runs that are not finished, on any server."""
    units = set(
        ChangeRun.objects.filter(status__in=RemoteOperation.ACTIVE).values_list(
            "unit_name", flat=True
        )
    )
    for reader in _ACTIVE_UNIT_READERS:
        units |= reader()
    return frozenset(units)


# The structured result line -----------------------------------------------------------------

RESULT_PREFIX: Final = "barectl-result "
RESULT_CLASSES: Final = frozenset(
    {"succeeded", "refused", "partial", "failed", "lock_busy", "timed_out"}
)
RESULT_REASONS: Final = frozenset(
    {
        "",
        "unsafe_lock",
        "boot",
        "deadline",
        "active_run",
        "capacity",
        "affected_sites",
        "evidence",
        "cleanup",
        "precondition",
        "privilege",
        "platform",
        "headroom",
        "nix_incomplete",
        "foreign_stack",
        "download",
        "installer_digest",
        "foundation",
        "apt_active",
        "apt_unreadable",
        "runtime_cache",
        "runtime_realise",
        "runtime_config",
        "runtime_start",
        "site_create",
        "site_caddy",
    }
)


@dataclass(frozen=True)
class ResultLine:
    """The one structured line a payload prints to the journal before it exits."""

    result_class: str
    reason: str


def parse_result_line(text: str) -> ResultLine | None:
    """The last result line of ``text``, or ``None`` when there is none.

    Raises ``native.Unreadable`` when a line is present but not in the engine's form:
    a malformed line is evidence of an outcome, not the absence of one.
    """
    for line in reversed(text.splitlines()):
        if not line.startswith(RESULT_PREFIX):
            continue
        try:
            value = json.loads(line[len(RESULT_PREFIX) :])
        except json.JSONDecodeError as error:
            raise native.Unreadable("The result line is not in the engine's form.") from error
        if not isinstance(value, dict):
            raise native.Unreadable("The result line is not in the engine's form.")
        result_class = value.get("class")
        if not isinstance(result_class, str) or result_class not in RESULT_CLASSES:
            raise native.Unreadable("The result line is not in the engine's form.")
        reason = value.get("reason", "")
        if not isinstance(reason, str) or reason not in RESULT_REASONS:
            raise native.Unreadable("The result line is not in the engine's form.")
        return ResultLine(result_class, reason)
    return None


def journal_argv(unit: str) -> list[str]:
    return [
        "/usr/bin/journalctl",
        "-u",
        native.check_unit(unit),
        "-n",
        "20",
        "--grep",
        "^barectl-(stage |result )",
        "--no-pager",
        "-o",
        "cat",
    ]


def parse_progress(text: str, stages: object) -> str:
    if not isinstance(stages, list):
        return ""
    allowed = {stage for stage in stages if isinstance(stage, str) and len(stage) <= 160}
    for line in reversed(text.splitlines()):
        if line.startswith("barectl-stage "):
            stage = line.removeprefix("barectl-stage ")
            return stage if stage in allowed else ""
    return ""


def _read_journal(shell: RemoteShell, unit: str) -> str:
    argv = journal_argv(unit)
    root = native.is_root(shell)
    if root is None:
        return ""
    if not root and shell.run(native.authorization(argv)).exit_status != 0:
        return ""
    result = shell.run(native.privileged(argv, root=root))
    if result.exit_status != 0 or result.truncated:
        return ""
    return result.stdout


def read_result(shell: RemoteShell, unit: str) -> ResultLine | None:
    try:
        return parse_result_line(_read_journal(shell, unit))
    except native.Unreadable:
        return None


def _line_result(line: ResultLine) -> tuple[Result, str]:
    return Result(line.result_class), line.reason


def _unit_result(evidence: native.UnitEvidence) -> tuple[Result, str]:
    if evidence.result == "timeout":
        return Result.TIMED_OUT, ""
    if evidence.exec_main_code != native.CLD_EXITED:
        return Result.FAILED, ""
    try:
        code = native.Code(evidence.exec_main_status)
    except ValueError:
        return Result.FAILED, ""
    return (
        {
            native.Code.SUCCESS: Result.SUCCEEDED,
            native.Code.REFUSED: Result.REFUSED,
            native.Code.PARTIAL: Result.PARTIAL,
            native.Code.FAILED: Result.FAILED,
            native.Code.LOCK_BUSY: Result.LOCK_BUSY,
        }
    )[code], ""


# The payload -------------------------------------------------------------------------------

_RESULT_FUNCTION: Final = "r() { printf 'barectl-result %s\\n' \"$1\"; }"


def _refused(reason: str) -> str:
    return f'{{ r \'{{"class":"refused","reason":"{reason}"}}\'; exit {native.Code.REFUSED}; }}'


def _lock_busy() -> str:
    return f'{{ r \'{{"class":"lock_busy"}}\'; exit {native.Code.LOCK_BUSY}; }}'


def _sites_step(review: ChangeReview) -> list[str]:
    if not review.sites_read:
        return []
    read = review.sites_read
    if len(read.encode()) > 4000 or "\0" in read:
        raise ValueError("Not a fixed affected-sites read.")
    return [
        f"sites=$({read}) || {_refused('affected_sites')}",
        (
            'if [ -n "$sites" ]; then '
            'digest=$(printf \'%s\\n\' "$sites" | sha256sum | cut -d" " -f1); '
            'else digest=$(printf %s "$sites" | sha256sum | cut -d" " -f1); fi'
        ),
        f'[ "$digest" = {review.sites_digest} ] || {_refused("affected_sites")}',
    ]


def body_path(unit: str) -> str:
    unit = native.check_unit(unit)
    suffix = unit.removeprefix(native.UNIT_PREFIX).removesuffix(".service")
    return f"{native.LOCK_DIRECTORY}/body-{suffix}.sh"


def stage_command(path: str, digest: str) -> list[str]:
    """Fixed root-owned staging command. Body bytes arrive only through RemoteShell stdin."""
    if not re.fullmatch(r"/run/lock/barectl/body-[0-9a-f]{32}\.sh", path):
        raise ValueError("Not a staging path.")
    native.check_digest(digest)
    temp = f"{path}.tmp"
    script = "; ".join(
        [
            f"d={native.LOCK_DIRECTORY}",
            f"f={shlex.quote(path)}",
            f"t={shlex.quote(temp)}",
            'mkdir -m 0700 "$d" 2>/dev/null || :',
            "[ \"$(stat -c '%F %u %a' \"$d\")\" = 'directory 0 700' ] || exit 1",
            '[ ! -e "$f" ] && [ ! -L "$f" ] || exit 1',
            '[ ! -e "$t" ] && [ ! -L "$t" ] || exit 1',
            'trap \'rm -f -- "$t" "$f"\' EXIT',
            "umask 077",
            '/usr/bin/tee -- "$t" >/dev/null || exit 1',
            'chmod 0600 -- "$t" || exit 1',
            "[ \"$(stat -c '%F %u %a' \"$t\")\" = 'regular file 0 600' ] || exit 1",
            f'[ "$(sha256sum -- "$t" | cut -d" " -f1)" = {digest} ] || exit 1',
            'mv -- "$t" "$f" || exit 1',
            "[ \"$(stat -c '%F %u %a' \"$f\")\" = 'regular file 0 600' ] || exit 1",
            "trap - EXIT",
        ]
    )
    return ["/usr/bin/sh", "-c", script]


def payload(
    kind: ChangeKind,
    review: ChangeReview,
    context: BodyContext,
    body: NativeBody,
    path: str,
) -> str:
    """The run's whole payload: engine admission around the kind's body.

    The engine takes the lock, admits the review (boot, deadline, other runs, capacity)
    and rechecks the affected-sites digest, all before the kind's checked-in body staged
    from SSH standard input runs in the same shell; every exit path reports one result line.
    """
    digest = hashlib.sha256(body.source).hexdigest()
    reviewed_digest = review.document.get("body_sha256")
    if not isinstance(reviewed_digest, str) or reviewed_digest != digest:
        raise OperationRefused(EVIDENCE_FAILURE)
    if len(body.source) > native.MAX_BODY:
        raise native.PayloadTooLarge
    if path != body_path(context.unit):
        raise ValueError("The staged body path does not belong to this run.")
    own = f"/sys/fs/cgroup/system.slice/{context.unit}/cgroup.events"
    steps = [
        _RESULT_FUNCTION,
        f"trap 'rm -f -- {shlex.quote(path)}' EXIT",
        *native.lock_steps(_refused("unsafe_lock"), _lock_busy()),
        (
            f'[ "$(cat /proc/sys/kernel/random/boot_id)" = {shlex.quote(context.boot_id)} ] '
            f"|| {_refused('boot')}"
        ),
        (
            f"[ \"$(cut -d' ' -f1 /proc/uptime | tr -d .)\" -lt {context.deadline_centiseconds} ]"
            f" || {_refused('deadline')}"
        ),
        (
            f"for e in /sys/fs/cgroup/system.slice/{native.UNIT_PREFIX}*.service/cgroup.events; do "
            f'[ "$e" = {own} ] && continue; [ -e "$e" ] || continue; '
            f"grep -qx 'populated 1' \"$e\" && {_refused('active_run')}; done"
        ),
        (f"n=$({native.RETAINED_UNITS} | grep -c .)"),
        f'[ "$((n - 1))" -lt {kind.capacity} ] || {_refused("capacity")}',
        *_sites_step(review),
        (
            f"sh -c {shlex.quote(apt.PROCESS_PROBE)}; apt_status=$?; "
            f'[ "$apt_status" -ne 1 ] || {_refused("apt_active")}; '
            f'[ "$apt_status" -eq 0 ] || {_refused("apt_unreadable")}'
        ),
        (
            f'[ "$(sha256sum -- {shlex.quote(path)} | cut -d" " -f1)" = {digest} ] '
            f"|| {_refused('evidence')}"
        ),
        ("exec " + shlex.join(["/usr/bin/sh", path, *body.arguments])),
    ]
    script = "; ".join(steps)
    if len(script.encode()) > native.MAX_PAYLOAD:
        raise native.PayloadTooLarge
    return script


# Preparation --------------------------------------------------------------------------------


def _sites_digest(shell: RemoteShell, draft: ReviewDraft) -> str:
    affected = (
        draft.current_sites if draft.current_sites is not None else affected_sites_of(draft.effects)
    )
    if not draft.sites_read:
        if affected or draft.current_sites is not None:
            raise OperationRefused(UNREADABLE_FAILURE)
        return ""
    if len(draft.sites_read.encode()) > 4000 or "\0" in draft.sites_read:
        raise OperationRefused(UNREADABLE_FAILURE)
    result = shell.run(draft.sites_read)
    if result.exit_status != 0 or result.truncated:
        raise OperationRefused(UNREADABLE_FAILURE)
    sites = result.stdout.splitlines()
    if (
        any(not re.fullmatch(r"[a-z][a-z0-9]{2,23}", site) for site in sites)
        or sites != sorted(set(sites))
        or result.stdout != ("\n".join(sites) + ("\n" if sites else ""))
        or tuple(sites) != affected
    ):
        raise OperationRefused(UNREADABLE_FAILURE)
    return hashlib.sha256(result.stdout.encode()).hexdigest()


def save_review(
    preparation: ChangePreparation,
    draft: ReviewDraft,
    *,
    host_key: str,
    collected_at: datetime,
    sites_digest: str,
) -> ChangeReview:
    """Store the review once, deriving its consent and its deadline from the draft.

    The kind's document keeps its own versioned content; the shared wording every page
    shows (stages, postconditions, refusal reasons) is merged in under fixed keys.
    """
    expires = collected_at + timedelta(seconds=ADMISSION_SECONDS)
    document = dict(draft.document)
    if draft.current_sites is not None:
        document["current_sites"] = list(draft.current_sites)
    document["stages"] = list(draft.stages)
    document["postconditions"] = list(draft.postconditions)
    document["refusals"] = list(draft.refusals)
    return ChangeReview.objects.create(
        preparation=preparation,
        kind_slug=draft.kind,
        intent=draft.intent,
        eligible=draft.eligible,
        no_changes=draft.no_changes,
        consent=consent_of(draft.effects),
        affected_sites=list(affected_sites_of(draft.effects)),
        effects=[
            {
                "scope": effect.scope.value,
                "text": effect.text,
                "sites": list(effect.sites),
                "destroys_data": effect.destroys_data,
            }
            for effect in draft.effects
        ],
        ssh_alias=preparation.ssh_alias,
        host_key=host_key,
        boot_id=draft.boot_id,
        uptime_centiseconds=draft.uptime_centiseconds,
        admission_deadline_centiseconds=(
            draft.uptime_centiseconds + ADMISSION_CENTISECONDS
            if draft.uptime_centiseconds is not None
            else None
        ),
        collected_at=collected_at,
        admission_expires_at=expires,
        sites_read=draft.sites_read,
        sites_digest=sites_digest,
        document=document,
    )


def _prepare(preparation: ChangePreparation) -> None:
    requester = preparation.requested_by
    if requester is None or not requester.is_active or not requester.has_perms(PREPARE_PERMISSIONS):
        raise OperationRefused(PREPARATION_REVOKED_FAILURE)
    kind = kind_of(preparation.kind_slug)
    if kind is None:
        raise OperationRefused(UNKNOWN_KIND)
    try:
        inputs = decode_inputs(preparation.inputs, kind.input_choices, kind.input_shape)
    except ValueError as error:
        raise OperationRefused(str(error)) from error
    collected_at = timezone.now()
    with ssh.connect_operation(preparation) as shell:
        evidence = kind.inspect(shell, inputs)
        draft = kind.review(evidence, inputs)
        host_key = shell.host_key
        sites_digest = _sites_digest(shell, draft)
    if draft.eligible and (not draft.boot_id or draft.uptime_centiseconds is None):
        raise OperationRefused(UNREADABLE_FAILURE)
    # Publish the review and the outcome together; a recovery that already marked this
    # preparation interrupted wins, so a stale worker never records a review after it.
    with transaction.atomic():
        if not lifecycle.succeed(preparation.pk, timezone.now(), host_key=host_key):
            return
        save_review(
            preparation,
            draft,
            host_key=host_key,
            collected_at=collected_at,
            sites_digest=sites_digest,
        )
    logger.info("Change preparation %s succeeded", preparation.pk)


# Applying -----------------------------------------------------------------------------------


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
        ChangeRun.objects.filter(pk=operation_id).update(**changes)
    return True


def _authorized(user: User | None, review: ChangeReview) -> bool:
    return (
        user is not None
        and user.is_active
        and user.has_perms(CONSENT_PERMISSIONS[Consent(review.consent)])
    )


def _root(shell: RemoteShell) -> bool | None:
    """Whether the connection is root: ``True`` for root, ``False`` for a sudo user,
    ``None`` when the user cannot be read."""
    root = native.is_root(shell)
    if root is None:
        raise OperationRefused(UNREADABLE_FAILURE)
    return root


def _admit(
    shell: RemoteShell,
    stage_argv: list[str],
    submission_argv: list[str],
    remove_argv: list[str],
    result_argv: list[str],
    kind: ChangeKind,
) -> bool:
    """Check privilege for the exact staging, submission and cleanup commands."""
    root = _root(shell)
    if root is None:
        raise OperationRefused(UNREADABLE_FAILURE)
    if root is False and any(
        shell.run(native.authorization(argv)).exit_status != 0
        for argv in (stage_argv, submission_argv, remove_argv, result_argv)
    ):
        raise OperationRefused(PRIVILEGE_FAILURE)
    retained = native.retained_units(shell)
    if retained is None:
        raise OperationRefused(UNREADABLE_FAILURE)
    if retained >= kind.capacity:
        raise OperationRefused(
            CEILING_FAILURE if kind.capacity >= native.CLEANUP_CEILING else RETAINED_FAILURE
        )
    return root


def _remove_body(shell: RemoteShell, path: str, *, root: bool) -> None:
    """Best-effort cleanup after a known refusal before the transient unit owns the body."""
    argv = ["/usr/bin/rm", "-f", "--", path]
    with suppress(ConnectionFailed):
        shell.run(native.privileged(argv, root=root))


def _admit_connection(run: ChangeRun) -> None:
    preparation = run.review.preparation
    if (
        preparation is None
        or not lifecycle.connection_current(preparation)
        or run.connection_id != preparation.connection_id
    ):
        raise OperationRefused("The connection changed. Prepare a new review before applying.")


def _apply(run: ChangeRun) -> None:
    """Submit the reviewed run once, then watch its native unit until it is terminal."""
    review = run.review
    _admit_connection(run)
    if not _authorized(run.requested_by, review):
        raise OperationRefused(REVOKED_FAILURE)
    kind = kind_of(review.kind_slug)
    if kind is None:
        raise OperationRefused(UNKNOWN_KIND)
    context = BodyContext(
        unit=run.unit_name,
        boot_id=review.boot_id,
        deadline_centiseconds=review.admission_deadline_centiseconds or 0,
    )
    path = body_path(run.unit_name)
    try:
        body = kind.body(review.document, context)
        script = payload(kind, review, context, body, path)
        stage_argv = stage_command(path, hashlib.sha256(body.source).hexdigest())
        submit_argv = native.submission(run.unit_name, script, collect=True)
        remove_argv = ["/usr/bin/rm", "-f", "--", path]
        result_argv = journal_argv(run.unit_name)
    except native.PayloadTooLarge:
        raise OperationRefused(TOO_LARGE_FAILURE) from None
    with ssh.connect_operation(run) as shell:
        if shell.host_key != review.host_key:
            raise OperationRefused(HOST_KEY_FAILURE)
        root = _admit(shell, stage_argv, submit_argv, remove_argv, result_argv, kind)
        try:
            staged = shell.run(native.privileged(stage_argv, root=root), stdin=body.source)
        except ConnectionFailed:
            raise
        if staged.exit_status != 0 or staged.truncated:
            _remove_body(shell, path, root=root)
            raise OperationRefused(UNREADABLE_FAILURE)
        # Recorded before anything is sent; a recovery that already failed the run wins.
        if not lifecycle.dispatch(run.pk, host_key=shell.host_key):
            _remove_body(shell, path, root=root)
            return
        try:
            result = shell.run(native.privileged(submit_argv, root=root))
        except ConnectionFailed:
            lifecycle.reconcile(run.pk, f"{LOST_ACKNOWLEDGEMENT} {UNCERTAIN}")
            return
        acknowledged = result.exit_status == 0
        if not acknowledged:
            _remove_body(shell, path, root=root)
        _record(
            run.pk,
            Status.RUNNING,
            execution=Result.SUBMITTED,
            acknowledged_at=timezone.now() if acknowledged else None,
        )
        _watch(shell, run, kind, acknowledged=acknowledged)


def _watch(shell: RemoteShell, run: ChangeRun, kind: ChangeKind, *, acknowledged: bool) -> None:
    deadline = time.monotonic() + WATCH_LIMIT.total_seconds()
    missing_since: float | None = None
    while True:
        try:
            evidence = native.inspect(shell, run.unit_name)
        except native.Unreadable:
            lifecycle.reconcile(run.pk, f"{UNREADABLE_EVIDENCE} {UNCERTAIN}")
            return
        if not evidence.found:
            # A collecting unit unloads itself once it is done, so its outcome lives in
            # the journal. Allow systemd's journal to publish the result line after the
            # unit has been collected before treating it as missing evidence.
            line = read_result(shell, run.unit_name)
            if line is not None:
                _conclude(shell, run, kind, None, line, Status.RUNNING)
            elif acknowledged:
                missing_since = missing_since or time.monotonic()
                if time.monotonic() - missing_since < JOURNAL_SETTLE_SECONDS:
                    time.sleep(min(0.1, JOURNAL_SETTLE_SECONDS))
                    continue
                lifecycle.reconcile(run.pk, f"{NOT_FOUND} {UNCERTAIN}")
            else:
                _conclude_rejected(run)
            return
        missing_since = None
        if not _record(run.pk, Status.RUNNING, invocation_id=evidence.invocation_id):
            return
        stage = parse_progress(
            _read_journal(shell, run.unit_name), run.review.document.get("stages")
        )
        _record(run.pk, Status.RUNNING, progress_stage=stage)
        if evidence.terminal:
            line = read_result(shell, run.unit_name)
            _conclude(shell, run, kind, evidence, line, Status.RUNNING)
            return
        _record(run.pk, Status.RUNNING, execution=Result.RUNNING)
        if time.monotonic() >= deadline:
            lifecycle.reconcile(run.pk, f"{STILL_RUNNING} {UNCERTAIN}")
            return
        time.sleep(POLL_INTERVAL)


def _conclude_rejected(run: ChangeRun) -> None:
    """systemd refused the submission and created no unit: nothing ran."""
    with transaction.atomic():
        if lifecycle.finish(run.pk, Status.RUNNING, succeeded=False, failure=REJECTED_FAILURE):
            ChangeRun.objects.filter(pk=run.pk).update(
                execution=Result.NOT_SUBMITTED, verification=Verification.NOT_APPLICABLE
            )


def _failure(outcome: Result, reason: str) -> str:
    if outcome == Result.REFUSED and reason in _REFUSED_REASONS:
        return _REFUSED_REASONS[reason]
    return _FAILURES.get(outcome, "")


def _conclude(
    shell: RemoteShell,
    run: ChangeRun,
    kind: ChangeKind,
    evidence: native.UnitEvidence | None,
    line: ResultLine | None,
    source: RemoteOperation.Status,
    revision: int | None = None,
) -> None:
    """A controller-side failure while verifying never becomes a remote failure: the known
    outcome is kept and verification is recorded as unavailable."""
    if line is not None:
        outcome, reason = _line_result(line)
    elif evidence is not None:
        outcome, reason = _unit_result(evidence)
    else:
        raise ValueError("A conclusion needs the unit's evidence or its result line.")
    exited = evidence is not None and evidence.exec_main_code == native.CLD_EXITED
    exit_status: int | None = evidence.exec_main_status if evidence is not None and exited else None
    verification = Verification.NOT_APPLICABLE
    failure = _failure(outcome, reason)
    if outcome == Result.SUCCEEDED:
        try:
            passed = kind.verify(shell, run.review)
        except ConnectionFailed:
            passed = None
        verification = {
            True: Verification.PASSED,
            False: Verification.FAILED,
            None: Verification.UNAVAILABLE,
        }[passed]
        if verification == Verification.FAILED:
            failure = VERIFICATION_FAILED
        elif verification == Verification.UNAVAILABLE:
            failure = VERIFICATION_UNAVAILABLE
    succeeded = outcome == Result.SUCCEEDED and verification == Verification.PASSED
    if succeeded:
        failure = ""
    with transaction.atomic():
        if not lifecycle.finish(
            run.pk, source, succeeded=succeeded, failure=failure, revision=revision
        ):
            return
        ChangeRun.objects.filter(pk=run.pk).update(
            execution=outcome,
            exit_status=exit_status,
            result_reason=reason,
            verification=verification,
            invocation_id=evidence.invocation_id if evidence is not None else run.invocation_id,
        )
    logger.info("Change run %s finished: %s", run.pk, outcome)
    if succeeded and kind.refresh_discovery:
        _refresh_discovery(run)


def _refresh_discovery(run: ChangeRun) -> None:
    from discovery.services import request_discovery

    if run.server is None:
        return
    connection = run.connection
    if connection is None or connection.revision == run.server.connection_revision:
        request_discovery(run.server, user=run.requested_by)


# Checking and closing ------------------------------------------------------------------------


def _check(run: ChangeRun) -> None:
    """Establish a reconciling run's outcome from native evidence, and close it as
    outcome unknown only with the proofs of ``_close_unknown``."""
    revision = run.revision
    closing = run.closure_requested_at
    review = run.review
    kind = kind_of(review.kind_slug)
    if kind is None:
        raise OperationRefused(UNKNOWN_KIND)
    try:
        with ssh.connect_operation(run) as shell:
            if shell.host_key != review.host_key:
                raise OperationRefused(HOST_KEY_FAILURE)
            try:
                evidence = native.inspect(shell, run.unit_name)
            except native.Unreadable:
                raise OperationRefused(UNREADABLE_EVIDENCE) from None
            if evidence.found and run.invocation_id and evidence.invocation_id != run.invocation_id:
                lifecycle.note(run.pk, f"{MISMATCH} {UNCERTAIN}", revision=revision)
                return
            if not evidence.found:
                _check_missing(shell, run, kind, evidence, revision, closing is not None)
                return
            if not _record(
                run.pk, Status.RECONCILING, revision, invocation_id=evidence.invocation_id
            ):
                return
            if not evidence.terminal:
                _record(run.pk, Status.RECONCILING, revision, execution=Result.RUNNING)
                lifecycle.note(
                    run.pk, f"{STILL_RUNNING} Check its outcome again later.", revision=revision
                )
                return
            line = read_result(shell, run.unit_name)
            _conclude(shell, run, kind, evidence, line, Status.RECONCILING, revision)
    finally:
        if closing is not None:
            # The acknowledgement was used, whatever the check found; a newer one waits
            # for its own check.
            ChangeRun.objects.filter(pk=run.pk, closure_requested_at=closing).update(
                closure_requested_at=None
            )


def _check_missing(
    shell: RemoteShell,
    run: ChangeRun,
    kind: ChangeKind,
    evidence: native.UnitEvidence,
    revision: int,
    closing: bool,
) -> None:
    """The unit is gone: its journal's result line settles the outcome, and an
    acknowledgement may close it as unknown once the proofs hold."""
    line = read_result(shell, run.unit_name)
    if line is not None:
        if _record(run.pk, Status.RECONCILING, revision):
            _conclude(shell, run, kind, None, line, Status.RECONCILING, revision)
        return
    reason = RESTARTED if evidence.boot_id != run.review.boot_id else NOT_FOUND
    if not _record(run.pk, Status.RECONCILING, revision, execution=Result.NOT_FOUND):
        return
    lifecycle.note(run.pk, f"{reason} {UNCERTAIN}", revision=revision)
    if closing:
        _close_unknown(shell, run, revision)


def _close_unknown(shell: RemoteShell, run: ChangeRun, revision: int) -> None:
    """docs/adr/0006-use-native-bootstrap-execution.md#unknown-outcomes"""
    reason = _closure_blocked(shell, run)
    with transaction.atomic():
        if reason:
            _record(run.pk, Status.RECONCILING, revision, closure_blocked=reason)
            return
        if lifecycle.finish(
            run.pk, Status.RECONCILING, succeeded=False, failure=OUTCOME_UNKNOWN, revision=revision
        ):
            ChangeRun.objects.filter(pk=run.pk).update(
                execution=Result.OUTCOME_UNKNOWN,
                verification=Verification.UNAVAILABLE,
                closure_blocked="",
            )
            logger.info("Change run %s closed as outcome unknown", run.pk)


def _closure_blocked(shell: RemoteShell, run: ChangeRun) -> str:
    """The proof a closure of ``run`` lacks, or an empty string when every proof holds."""
    if not _authorized(run.unknown_acknowledged_by, run.review):
        return CLOSURE_ACCOUNT
    probe = _probe(shell, run)
    if isinstance(probe, str):
        return probe
    if probe.unit_loaded:
        return CLOSURE_FOUND
    if probe.populated:
        return CLOSURE_ACTIVE
    if probe.renewal_active:
        return CLOSURE_RENEWAL_ACTIVE
    restarted = probe.boot_id != run.review.boot_id
    if not restarted and probe.uptime_centiseconds < (
        run.review.admission_deadline_centiseconds or 0
    ):
        return _not_fenced(run.review.admission_expires_at)
    return ""


def _probe(shell: RemoteShell, run: ChangeRun) -> native.ProbeEvidence | str:
    """What the closure probe read under the lock, or why it could not read it."""
    argv = native.closure_probe(run.unit_name)
    root = _root(shell)
    if root is None:
        return CLOSURE_PRIVILEGE
    if root is False and shell.run(native.authorization(argv)).exit_status != 0:
        return CLOSURE_PRIVILEGE
    result = shell.run(native.privileged(argv, root=root))
    if result.exit_status == native.Probe.LOCK_CONFLICT:
        return CLOSURE_LOCK_HELD
    if result.exit_status == native.Probe.UNSAFE_LOCK:
        return CLOSURE_UNSAFE_LOCK
    if result.exit_status != native.Probe.LOCKED or result.truncated:
        return CLOSURE_UNREADABLE
    try:
        return native.parse_probe(result.stdout)
    except native.Unreadable:
        return CLOSURE_UNREADABLE


def _not_fenced(expires: datetime) -> str:
    return (
        "The server has not restarted since the run's boot, and its admission deadline has "
        "not passed on the server's clock, so a delayed delivery could still start. Barectl "
        "did not close the run. Acknowledge again after the deadline, about "
        f"{timezone.localtime(expires):%H:%M:%S %Z}."
    )


lifecycle.register(
    ChangePreparation,
    _prepare,
    interrupted=PREPARATION_INTERRUPTED_FAILURE,
    unexpected=PREPARATION_UNEXPECTED_FAILURE,
    stale_after=STALE_AFTER,
)
lifecycle.register(
    ChangeRun,
    _apply,
    interrupted=INTERRUPTED_FAILURE,
    unexpected=UNEXPECTED_FAILURE,
    stale_after=STALE_AFTER,
    uncertain=UNCERTAIN,
    reconcile=_check,
)
