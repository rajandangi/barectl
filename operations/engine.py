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
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Final

from django.contrib.auth.models import User
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from discovery import ssh
from discovery.ssh import ConnectionFailed, RemoteShell
from operations import apt, confidential, lifecycle, native, reasons, revert
from operations.lifecycle import OperationRefused
from operations.models import RemoteOperation

from .consent import (
    PREPARE_PERMISSIONS,
    DeclaredEffect,
    Scope,
    affected_sites_of,
    consent_of,
    permissions_for,
)
from .inputs import InputShape, PreparationInputs, decode_inputs
from .models import (
    ADMISSION_CENTISECONDS,
    MANAGE_SECRETS,
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
# A started revert waits for the confirmation's lock, so it restores just after the script
# exits. This is the bounded chance the worker gives the page to say Put back.
WINDOW_SETTLE_SECONDS = 10.0
STALE_AFTER = timedelta(minutes=10)
# docs/security.md#restart: policy, ten minutes. A restart never retries itself.
REBOOT_TIMEOUT_SECONDS = 600
REBOOT_POLL_SECONDS = 3.0

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
NEVER_AGAIN = (
    "Barectl never submits it again; Check outcome reads the same unit's journal and state."
)
UNCERTAIN = (
    f"The run may have reached the server, and its outcome is not established yet. {NEVER_AGAIN}"
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
CONFIDENTIAL_EXPIRED_FAILURE = (
    "The confidential value this change carries is no longer readable: the worker that "
    "sealed it restarted, or its 10-minute lifetime passed. No plaintext was stored and "
    "nothing was sent. Prepare a new review and type the value again."
)
CONFIDENTIAL_MISSING_FAILURE = (
    "This change writes a secret, but the run carries no confidential value, so Barectl "
    "sent nothing. Prepare a new review and type the value again."
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
STOPPED_SILENTLY = (
    "The run reached the server: its journal holds the stages it reported, but no result "
    "line, and systemd no longer has its unit. It stopped before reporting how it ended, "
    "so what it changed is unknown."
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
UNREADABLE_RESULT = "Unreadable result line"
UNREADABLE_RESULT_FAILURE = (
    f"{UNREADABLE_RESULT}. Barectl could not read the server's own result line, so it "
    "cannot say what the run reported. The outcome comes from the server's exit evidence."
)
_ACKNOWLEDGED = (
    "An operator acknowledged this after Barectl proved that the run can no longer start or "
    "still be running. Inspect the server through ordinary administration and prepare a new "
    "review before any later change."
)
OUTCOME_UNKNOWN = (
    "Outcome unknown. No native record of this run remains, so Barectl cannot tell whether "
    f"it changed the server; it may have. {_ACKNOWLEDGED}"
)
OUTCOME_UNKNOWN_REACHED = (
    "Outcome unknown. The run reached the server and its journal keeps the stages it "
    "reported, but it stopped before reporting how it ended, so Barectl cannot tell what it "
    f"changed. {_ACKNOWLEDGED}"
)

# Compatibility aliases while each area ticket moves its kinds onto their own declaration
# (#495). Ticket #506 deletes these names and the legacy fallback in ``operations.reasons``.
AFFECTED_SITES_CHANGED = reasons.AFFECTED_SITES_CHANGED
_REFUSED_REASONS = reasons._LEGACY_SENTENCES
_FAILURES = reasons.OUTCOME_SENTENCES

VERIFICATION_FAILED = (
    "The run completed, but its postconditions do not hold. Inspect the server through "
    "ordinary administration, then prepare a new review."
)
VERIFICATION_UNAVAILABLE = (
    "The run completed on the server, but Barectl could not check its postconditions, so "
    "it records the run as failed with verification unavailable. Prepare a new review "
    "before any later change."
)
WINDOW_PUT_BACK = (
    "The server put the change back: Barectl could not confirm access over a new "
    "connection inside the five-minute window, so the previous firewall or sign-in "
    "configuration is in place again. Review the access settings and prepare a new change."
)
WINDOW_NOT_CONFIRMED = (
    "The change reached the server, but Barectl could not confirm access over a new "
    "connection inside the five-minute window. The server puts the change back on its own "
    "unless a new verified connection confirms it. Check the server through ordinary "
    "administration, then prepare a new review."
)
RESTART_UNKNOWN = (
    "Outcome unknown. The server did not answer over a new verified connection within ten "
    "minutes of the restart, so Barectl cannot tell whether it came back. Use your server "
    "provider's console to check it. Barectl does not try the restart again."
)
RESTART_NO_RESULT = (
    "Outcome unknown. The server answered on a new boot, but Barectl found no result line "
    "from the restart, so it cannot tell what happened. Check the server through ordinary "
    "administration; Barectl does not try the restart again."
)
RESTART_VERIFICATION_FAILED = (
    "The server came back with a new boot, but its web, PHP, database or cache services, or "
    "one of its sites, did not answer as expected. Check the server through ordinary "
    "administration before preparing another change."
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
    # A kind whose secret use depends on the review overrides the kind's fixed flag: a
    # settings review that only removes keys needs no confidential value (Phase B #383).
    writes_secrets: bool | None = None

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
    # The root-only staged file holding this run's confidential value, when it writes one;
    # empty otherwise. The kind's body consumes and removes it (docs/adr/0032).
    secret_path: str = ""


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
    # The kind writes a secret through the confidential input channel, so its review needs
    # the manage-secrets permission and its body receives the staged file path
    # (docs/adr/0032-keep-secrets-in-private-native-files.md).
    writes_secrets: bool = False
    # The kind can cut off the connection that would repair it. Its body saves a recovery
    # preimage and arms the five-minute revert timer, and after success the worker confirms
    # access over a new verified connection (docs/adr/0023).
    access_changing: bool = False
    # The kind restarts the host, so the connection that watched the run ends with it.
    # Success means a new boot ID on a fresh verified connection, and no connection within
    # the ten-minute policy leaves the outcome unknown (docs/security.md#restart).
    restarts_host: bool = False
    # The reasons this kind's staged body can print, declared by the fragments it stages.
    # Registration merges the engine's admission vocabulary and indexes each sentence by
    # reason and outcome (#495).
    reasons: tuple[reasons.ResultReason, ...] = ()
    # The repository-relative body text files this kind stages. The composer manifest reads
    # them and proves the declaration matches what the text can print.
    body_sources: tuple[str, ...] = ()


_KINDS: dict[str, ChangeKind] = {}


def register_kind(kind: ChangeKind) -> None:
    _KINDS[kind.slug] = kind
    reasons.register_kind(kind)


def kind_of(slug: str) -> ChangeKind | None:
    return _KINDS.get(slug)


def current_units() -> frozenset[str]:
    """The units of this installation's runs that are not finished, on any server."""
    return frozenset(
        ChangeRun.objects.filter(status__in=RemoteOperation.ACTIVE).values_list(
            "unit_name", flat=True
        )
    )


# The structured result line -----------------------------------------------------------------

RESULT_PREFIX: Final = "barectl-result "
SITE_IDENTIFIER: Final = re.compile(r"[a-z][a-z0-9]{2,23}")
RESULT_CLASSES: Final = frozenset(
    {"succeeded", "refused", "partial", "failed", "lock_busy", "timed_out"}
)
RESULT_REASONS: Final = reasons.accepted_reasons()


@dataclass(frozen=True)
class ResultLine:
    """The one structured line a payload prints to the journal before it exits.

    ``change_kind`` is the registered slug of the kind whose body ran, and ``sites`` are
    the site identifiers the stored review declared; both are empty on a run that predates
    the fields (docs/adr/0035-one-change-engine-with-effect-derived-consent.md).
    """

    result_class: str
    reason: str
    change_kind: str = ""
    sites: tuple[str, ...] = ()


def parse_result_line(text: str) -> ResultLine | None:
    """The newest result line of the journal read ``text``, or ``None`` when there is none.

    Raises ``native.Unreadable`` when a line is present but not in the engine's form:
    a malformed line is evidence of an outcome, not the absence of one.
    """
    for line in text.splitlines():
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
        if not isinstance(reason, str) or not reasons.accepted(reason):
            raise native.Unreadable("The result line is not in the engine's form.")
        change_kind = value.get("change_kind", "")
        if not isinstance(change_kind, str) or (change_kind and kind_of(change_kind) is None):
            raise native.Unreadable("The result line is not in the engine's form.")
        sites = value.get("sites", [])
        if not isinstance(sites, list) or any(
            not isinstance(site, str) or SITE_IDENTIFIER.fullmatch(site) is None for site in sites
        ):
            raise native.Unreadable("The result line is not in the engine's form.")
        # A full capture or restore records the pause before it starts copying so discovery
        # can name an interrupted run. It is not the run's outcome: the final result follows.
        if reason in ("backup_paused", "restore_paused"):
            continue
        return ResultLine(result_class, reason, change_kind, tuple(sites))
    return None


def journal_argv(unit: str) -> list[str]:
    return [
        "/usr/bin/journalctl",
        "-u",
        native.check_unit(unit),
        "-n",
        "20",
        # Newest first: systemd 259 already prints a --grep read with -n in that order.
        "--reverse",
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
    for line in text.splitlines():
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


class ResultEvidence(StrEnum):
    """What a run's journal holds about its result: a line, an unreadable line or none."""

    PRESENT = "present"
    UNREADABLE = "unreadable"
    ABSENT = "absent"


@dataclass(frozen=True)
class JournalEvidence:
    """What a run's journal holds: its result line, and the last reviewed stage it reported.

    ``result_evidence`` keeps the parser's refusal distinct from an absent line, so a run
    that printed something Barectl could not read is never described as printing nothing.
    """

    line: ResultLine | None
    stage: str
    result_evidence: ResultEvidence = ResultEvidence.ABSENT


def read_journal(shell: RemoteShell, unit: str, stages: object) -> JournalEvidence:
    text = _read_journal(shell, unit)
    stage = parse_progress(text, stages)
    try:
        line = parse_result_line(text)
    except native.Unreadable:
        return JournalEvidence(None, stage, ResultEvidence.UNREADABLE)
    return JournalEvidence(
        line,
        stage,
        ResultEvidence.PRESENT if line is not None else ResultEvidence.ABSENT,
    )


def read_result(shell: RemoteShell, unit: str) -> ResultLine | None:
    """The journal's result line, or ``None`` when it holds none.

    Raises ``native.Unreadable`` when a line is present but not in the engine's form, so a
    caller cannot mistake unreadable evidence for absence.
    """
    journal = read_journal(shell, unit, ())
    if journal.result_evidence is ResultEvidence.UNREADABLE:
        raise native.Unreadable("The result line is not in the engine's form.")
    return journal.line


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


# The engine writes the change's registered slug and its reviewed site identifiers into
# every result line, including one the kind's body prints, so another controller can name
# the work without the starting controller's database
# (docs/adr/0035-one-change-engine-with-effect-derived-consent.md).
def _review_sites(review: ChangeReview) -> str:
    sites = review.affected_sites
    if not isinstance(sites, list) or any(
        not isinstance(site, str) or SITE_IDENTIFIER.fullmatch(site) is None for site in sites
    ):
        raise ValueError("The review's affected sites are not site identifiers.")
    return json.dumps(sites, separators=(",", ":"))


def _result_fields(kind: ChangeKind, review: ChangeReview) -> tuple[str, str]:
    return kind.slug, _review_sites(review)


def _result_function(kind: ChangeKind, review: ChangeReview) -> str:
    slug, sites = _result_fields(kind, review)
    return (
        f'r() {{ printf \'barectl-result {{"change_kind":"{slug}","sites":{sites},%s\\n\' '
        '"${1#\\{}"; }'
    )


def _body_step(
    kind: ChangeKind, review: ChangeReview, path: str, arguments: tuple[str, ...]
) -> str:
    """Run the kind's body with the engine's fields on every result line it prints.

    ``sed -u`` streams each line to the journal without waiting, and ``bash -o pipefail``
    keeps the body's exit status as the unit's even though sed is the last pipeline stage.
    """
    slug, sites = _result_fields(kind, review)
    substitution = (
        's/^barectl-result [{]/barectl-result {"change_kind":"' + slug + '","sites":' + sites + ",/"
    )
    command = (
        shlex.join(["/usr/bin/sh", path, *arguments])
        + " | /usr/bin/sed -u "
        + shlex.quote(substitution)
    )
    return "exec " + shlex.join(["/bin/bash", "-o", "pipefail", "-c", command])


def _refused(reason: str) -> str:
    return f'{{ r \'{{"class":"refused","reason":"{reason}"}}\'; exit {native.Code.REFUSED}; }}'


def _lock_busy() -> str:
    return f'{{ r \'{{"class":"lock_busy"}}\'; exit {native.Code.LOCK_BUSY}; }}'


def _backup_step(review: ChangeReview) -> list[str]:
    """A running scheduled backup is busy for every change that names its site (#402)."""
    sites = [
        site
        for site in review.affected_sites
        if isinstance(site, str) and re.fullmatch(r"[a-z][a-z0-9]{2,23}", site)
    ]
    if not sites:
        return []
    paths = " ".join(
        f"/sys/fs/cgroup/system.slice/barectl-site-{site}-backup.service/cgroup.events"
        for site in sites
    )
    return [
        (
            f'for e in {paths}; do [ -e "$e" ] || continue; '
            f"grep -qx 'populated 1' \"$e\" && {_refused('active_backup')}; done"
        )
    ]


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


def secret_path(unit: str) -> str:
    """The root-only tmpfs file a run's confidential value is staged into."""
    unit = native.check_unit(unit)
    suffix = unit.removeprefix(native.UNIT_PREFIX).removesuffix(".service")
    return f"{native.CONFIDENTIAL_DIRECTORY}/{suffix}"


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


def stage_secret_command(path: str, size: int) -> list[str]:
    """Fixed root-owned staging command for one run's confidential value.

    The value arrives only through ``RemoteShell`` standard input and lands in a root-only
    tmpfs file that the transient unit consumes and removes on every exit path
    (docs/adr/0032-keep-secrets-in-private-native-files.md).
    """
    if not re.fullmatch(r"/run/barectl/secrets/[0-9a-f]{32}", path):
        raise ValueError("Not a confidential staging path.")
    if not 0 < size <= confidential.MAX_SECRET_BYTES:
        raise ValueError("Not a valid confidential value size.")
    temporary = f"{path}.tmp"
    script = "; ".join(
        [
            f"d={native.CONFIDENTIAL_DIRECTORY}",
            f"f={shlex.quote(path)}",
            f"t={shlex.quote(temporary)}",
            'mkdir -p -m 0700 "$d" 2>/dev/null || :',
            "[ \"$(stat -c '%F %u %a' \"$d\")\" = 'directory 0 700' ] || exit 1",
            '[ ! -e "$f" ] && [ ! -L "$f" ] || exit 1',
            '[ ! -e "$t" ] && [ ! -L "$t" ] || exit 1',
            'trap \'rm -f -- "$t" "$f"\' EXIT',
            "umask 077",
            '/usr/bin/tee -- "$t" >/dev/null || exit 1',
            'chmod 0600 -- "$t" || exit 1',
            "[ \"$(stat -c '%F %u %a' \"$t\")\" = 'regular file 0 600' ] || exit 1",
            f'[ "$(wc -c < "$t")" -eq {size} ] || exit 1',
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
    secret: str = "",
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
    if secret and secret != secret_path(context.unit):
        raise ValueError("The staged secret path does not belong to this run.")
    removals = f"rm -f -- {shlex.quote(path)}" + (f" {shlex.quote(secret)}" if secret else "")
    steps = [
        _result_function(kind, review),
        f"trap '{removals}' EXIT",
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
        revert.refusal_step(_refused("revert_active")),
        *_backup_step(review),
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
        _body_step(kind, review, path, body.arguments),
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
    writes_secrets: bool = False,
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
        writes_secrets=writes_secrets,
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


def _planned(shell: RemoteShell, draft: ReviewDraft) -> ReviewDraft:
    """Record what this change pauses, read once from the sites its own effects name.

    docs/adr/0036. The plan belongs to ``automation``: the engine only asks which sites a
    Site effect names, so a change that names no site (a server-wide one) pauses nothing.
    An unreadable answer refuses the review rather than fencing blind, because a stopped
    unit is not a reboot fence and guessing what was on would be worse.
    """
    from automation import fence

    sites = fence.fenced_sites(
        draft.kind,
        tuple(
            sorted(
                {
                    site
                    for effect in draft.effects
                    if effect.scope is Scope.SITE
                    for site in effect.sites
                }
            )
        ),
    )
    if draft.refusals or not draft.effects or not sites:
        return draft
    plan = fence.plan(shell, sites)
    if plan is None:
        return replace(draft, effects=(), refusals=(*draft.refusals, fence.UNREADABLE_REFUSAL))
    return replace(draft, document={**draft.document, "automation_fence": plan})


def _prepare(preparation: ChangePreparation) -> None:
    requester = preparation.requested_by
    kind = kind_of(preparation.kind_slug)
    if kind is None:
        raise OperationRefused(UNKNOWN_KIND)
    permissions = (
        (*PREPARE_PERMISSIONS, MANAGE_SECRETS) if kind.writes_secrets else PREPARE_PERMISSIONS
    )
    if requester is None or not requester.is_active or not requester.has_perms(permissions):
        raise OperationRefused(PREPARATION_REVOKED_FAILURE)
    try:
        inputs = decode_inputs(preparation.inputs, kind.input_choices, kind.input_shape)
    except ValueError as error:
        raise OperationRefused(str(error)) from error
    collected_at = timezone.now()
    with ssh.connect_operation(preparation) as shell:
        evidence = kind.inspect(shell, inputs)
        draft = _planned(shell, kind.review(evidence, inputs))
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
            writes_secrets=(
                kind.writes_secrets if draft.writes_secrets is None else draft.writes_secrets
            ),
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
    permissions = permissions_for(Consent(review.consent), writes_secrets=review.writes_secrets)
    return user is not None and user.is_active and user.has_perms(permissions)


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
    secret_argv: list[str] | None = None,
    window_argv: tuple[list[str], ...] = (),
) -> bool:
    """Check privilege for the exact staging, submission, cleanup and window commands."""
    root = _root(shell)
    if root is None:
        raise OperationRefused(UNREADABLE_FAILURE)
    authorized = [stage_argv, submission_argv, remove_argv, result_argv]
    if secret_argv is not None:
        authorized.append(secret_argv)
    authorized.extend(window_argv)
    if root is False and any(
        shell.run(native.authorization(argv)).exit_status != 0 for argv in authorized
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


def _remove_body(shell: RemoteShell, *paths: str, root: bool) -> None:
    """Best-effort cleanup after a known refusal before the transient unit owns the body."""
    argv = ["/usr/bin/rm", "-f", "--", *paths]
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


@dataclass(frozen=True)
class _Submission:
    """Everything one reviewed run stages, submits, cleans up and reads back."""

    body: NativeBody
    stage: list[str]
    secret_stage: list[str] | None
    submit: list[str]
    remove: list[str]
    result: list[str]
    paths: tuple[str, ...]


def _reviewed_submission(
    run: ChangeRun,
    review: ChangeReview,
    kind: ChangeKind,
    staged_secret: str,
    secret: bytes | None,
) -> _Submission:
    context = BodyContext(
        unit=run.unit_name,
        boot_id=review.boot_id,
        deadline_centiseconds=review.admission_deadline_centiseconds or 0,
        secret_path=staged_secret,
    )
    path = body_path(run.unit_name)
    try:
        body = kind.body(review.document, context)
        script = payload(kind, review, context, body, path, secret=staged_secret)
        stage = stage_command(path, hashlib.sha256(body.source).hexdigest())
        secret_stage = (
            stage_secret_command(staged_secret, len(secret))
            if staged_secret and secret is not None
            else None
        )
        submit = native.submission(run.unit_name, script, collect=True)
    except native.PayloadTooLarge:
        raise OperationRefused(TOO_LARGE_FAILURE) from None
    remove = ["/usr/bin/rm", "-f", "--", path, *([staged_secret] if staged_secret else [])]
    paths = (path, *([staged_secret] if staged_secret else ()))
    return _Submission(
        body, stage, secret_stage, submit, remove, journal_argv(run.unit_name), paths
    )


def _stage_payloads(
    shell: RemoteShell, root: bool, submission: _Submission, secret: bytes | None, run_id: int
) -> None:
    """Stage the reviewed body, then the run's confidential value, over standard input."""
    try:
        staged = shell.run(
            native.privileged(submission.stage, root=root), stdin=submission.body.source
        )
    except ConnectionFailed:
        raise
    if staged.exit_status != 0 or staged.truncated:
        _remove_body(shell, *submission.paths, root=root)
        raise OperationRefused(UNREADABLE_FAILURE)
    if submission.secret_stage is None or secret is None:
        return
    try:
        placed = shell.run(native.privileged(submission.secret_stage, root=root), stdin=secret)
    except ConnectionFailed:
        _remove_body(shell, *submission.paths, root=root)
        raise
    if placed.exit_status != 0 or placed.truncated:
        _remove_body(shell, *submission.paths, root=root)
        raise OperationRefused(UNREADABLE_FAILURE)
    # Sent to the server: the stored value is cleared before the unit is submitted.
    _record(run_id, Status.RUNNING, secret_sealed="", secret_expires_at=None)


def _apply(run: ChangeRun) -> None:
    """Submit the reviewed run once, then watch its native unit until it is terminal."""
    review = run.review
    _admit_connection(run)
    if not _authorized(run.requested_by, review):
        raise OperationRefused(REVOKED_FAILURE)
    kind = kind_of(review.kind_slug)
    if kind is None:
        raise OperationRefused(UNKNOWN_KIND)
    secret, plaintext = _confidential_value(run, review)
    staged_secret = secret_path(run.unit_name) if review.writes_secrets else ""
    submission = _reviewed_submission(run, review, kind, staged_secret, secret)
    try:
        with ssh.connect_operation(run) as shell:
            if shell.host_key != review.host_key:
                raise OperationRefused(HOST_KEY_FAILURE)
            root = _admit(
                shell,
                submission.stage,
                submission.submit,
                submission.remove,
                submission.result,
                kind,
                submission.secret_stage,
                (
                    (
                        revert.confirmation(run.unit_name),
                        revert.evidence_command(run.unit_name),
                    )
                    if kind.access_changing
                    else ()
                ),
            )
            _stage_payloads(shell, root, submission, secret, run.pk)
            # Recorded before anything is sent; a recovery that already failed the run wins.
            if not lifecycle.dispatch(run.pk, host_key=shell.host_key):
                _remove_body(shell, *submission.paths, root=root)
                return
            _submit_and_watch(shell, run, kind, submission, root)
    except ConnectionFailed:
        # A restart ends the watching connection. If the run already has an outcome the
        # closed connection is part of the change, not a reason to report a new failure.
        still_active = ChangeRun.objects.filter(
            pk=run.pk, status__in=RemoteOperation.ACTIVE
        ).exists()
        if not kind.restarts_host or still_active:
            raise
    _scrub_run(run.pk, plaintext)


def _submit_and_watch(
    shell: RemoteShell, run: ChangeRun, kind: ChangeKind, submission: _Submission, root: bool
) -> None:
    try:
        result = shell.run(native.privileged(submission.submit, root=root))
    except ConnectionFailed:
        if kind.restarts_host:
            # The restart can end this connection just after systemd accepts the unit.
            # The fresh connection and the journal decide the outcome; nothing is retried.
            _record(run.pk, Status.RUNNING, execution=Result.SUBMITTED)
            _watch_reboot(run, kind)
            return
        lifecycle.reconcile(run.pk, f"{LOST_ACKNOWLEDGEMENT} {UNCERTAIN}")
        return
    acknowledged = result.exit_status == 0
    if not acknowledged:
        _remove_body(shell, *submission.paths, root=root)
    _record(
        run.pk,
        Status.RUNNING,
        execution=Result.SUBMITTED,
        acknowledged_at=timezone.now() if acknowledged else None,
    )
    if kind.restarts_host:
        if acknowledged:
            _watch_reboot(run, kind)
        else:
            _conclude_rejected(run)
        return
    _watch(shell, run, kind, acknowledged=acknowledged)


def _watch_reboot(run: ChangeRun, kind: ChangeKind) -> None:
    """Wait for a new boot over a fresh verified connection, within the ten-minute policy.

    The body writes its result line before asking the server to restart, so the journal is
    the run's evidence after the watching connection ends. A connection on the old boot is
    not evidence that the restart finished, and a missing one is never reported as success.
    """
    review = run.review
    deadline = time.monotonic() + REBOOT_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        try:
            with ssh.connect_operation(run) as shell:
                if shell.host_key != review.host_key:
                    _reboot_unknown(run)
                    return
                boot_id = _boot_id(shell)
                if boot_id and boot_id != review.boot_id:
                    journal = read_journal(shell, run.unit_name, run.review.document.get("stages"))
                    if journal.result_evidence is ResultEvidence.ABSENT:
                        # The unit's journal may still be publishing its last line as the
                        # server boots; give it one short settle before calling it unknown.
                        time.sleep(JOURNAL_SETTLE_SECONDS)
                        journal = read_journal(
                            shell, run.unit_name, run.review.document.get("stages")
                        )
                    if journal.result_evidence is ResultEvidence.UNREADABLE:
                        _reboot_unknown(run, failure=UNREADABLE_RESULT_FAILURE)
                        return
                    if journal.result_evidence is ResultEvidence.ABSENT:
                        _reboot_unknown(run, failure=RESTART_NO_RESULT)
                        return
                    _conclude(
                        shell,
                        run,
                        kind,
                        None,
                        journal.line,
                        Status.RUNNING,
                        result_evidence=journal.result_evidence,
                    )
                    return
        except ConnectionFailed:
            pass
        time.sleep(REBOOT_POLL_SECONDS)
    _reboot_unknown(run)


def _boot_id(shell: RemoteShell) -> str:
    result = shell.run("cat /proc/sys/kernel/random/boot_id")
    if result.exit_status != 0 or result.truncated:
        return ""
    return result.stdout.strip()


def _reboot_unknown(run: ChangeRun, *, failure: str = RESTART_UNKNOWN) -> None:
    with transaction.atomic():
        if lifecycle.finish(run.pk, Status.RUNNING, succeeded=False, failure=failure):
            ChangeRun.objects.filter(pk=run.pk).update(
                execution=Result.OUTCOME_UNKNOWN,
                verification=Verification.UNAVAILABLE,
            )
    logger.info("Restart run %s closed as outcome unknown", run.pk)


def _confidential_value(
    run: ChangeRun, review: ChangeReview
) -> tuple[bytes | None, tuple[str, ...]]:
    """The run's confidential value and the plaintext to scrub, or refuse as expired.

    A kind that writes secrets must carry a sealed value only this worker's key can open;
    a key that changed, an absent value, or a passed deadline refuses before anything is
    sent (docs/adr/0032-keep-secrets-in-private-native-files.md).
    """
    if not review.writes_secrets:
        if run.secret_sealed:
            raise OperationRefused(CONFIDENTIAL_MISSING_FAILURE)
        return None, ()
    if run.secret_sealed and run.secret_expires_at is not None:
        if timezone.now() >= run.secret_expires_at:
            _clear_secret(run.pk)
            raise OperationRefused(CONFIDENTIAL_EXPIRED_FAILURE)
        plaintext = confidential.unseal(run.secret_sealed)
        if plaintext is not None:
            return plaintext, (plaintext.decode("utf-8", "replace"),)
        _clear_secret(run.pk)
        raise OperationRefused(CONFIDENTIAL_EXPIRED_FAILURE)
    raise OperationRefused(CONFIDENTIAL_MISSING_FAILURE)


def _clear_secret(operation_id: int) -> None:
    ChangeRun.objects.filter(pk=operation_id).update(secret_sealed="", secret_expires_at=None)


def _scrub_run(operation_id: int, secrets: tuple[str, ...]) -> None:
    """Replace any known submitted value in the run's stored output and audit."""
    if not secrets:
        return
    run = ChangeRun.objects.filter(pk=operation_id).first()
    if run is None:
        return
    ChangeRun.objects.filter(pk=operation_id).update(
        failure=confidential.scrub(run.failure, secrets),
        progress_stage=confidential.scrub(run.progress_stage, secrets),
    )


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
            journal = read_journal(shell, run.unit_name, run.review.document.get("stages"))
            if _journal_settles_missing(shell, run, kind, journal):
                return
            if acknowledged:
                missing_since = missing_since or time.monotonic()
                if time.monotonic() - missing_since < JOURNAL_SETTLE_SECONDS:
                    time.sleep(min(0.1, JOURNAL_SETTLE_SECONDS))
                    continue
                _reconcile_missing(run, journal.stage)
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
            journal = read_journal(shell, run.unit_name, run.review.document.get("stages"))
            _conclude(
                shell,
                run,
                kind,
                evidence,
                journal.line,
                Status.RUNNING,
                result_evidence=journal.result_evidence,
            )
            return
        _record(run.pk, Status.RUNNING, execution=Result.RUNNING)
        if time.monotonic() >= deadline:
            lifecycle.reconcile(run.pk, f"{STILL_RUNNING} {UNCERTAIN}")
            return
        time.sleep(POLL_INTERVAL)


def _journal_settles_missing(
    shell: RemoteShell, run: ChangeRun, kind: ChangeKind, journal: JournalEvidence
) -> bool:
    """Conclude a missing unit from a present or unreadable result line, if it has one."""
    if journal.result_evidence is ResultEvidence.PRESENT:
        _conclude(
            shell,
            run,
            kind,
            None,
            journal.line,
            Status.RUNNING,
            result_evidence=journal.result_evidence,
        )
        return True
    if journal.result_evidence is ResultEvidence.UNREADABLE:
        _reconcile_unreadable(run, journal.stage)
        return True
    return False


def _reconcile_missing(run: ChangeRun, stage: str) -> None:
    """The unit is gone without a result line; stage lines still show that it ran."""
    if not stage:
        lifecycle.reconcile(run.pk, f"{NOT_FOUND} {UNCERTAIN}")
        return
    _record(run.pk, Status.RUNNING, progress_stage=stage)
    lifecycle.reconcile(run.pk, f"{STOPPED_SILENTLY} {NEVER_AGAIN}")


def _reconcile_unreadable(run: ChangeRun, stage: str) -> None:
    """The unit is gone, but its journal holds a result line Barectl could not read."""
    if stage:
        _record(run.pk, Status.RUNNING, progress_stage=stage)
    lifecycle.reconcile(run.pk, UNREADABLE_RESULT_FAILURE)


def _conclude_rejected(run: ChangeRun) -> None:
    """systemd refused the submission and created no unit: nothing ran."""
    with transaction.atomic():
        if lifecycle.finish(run.pk, Status.RUNNING, succeeded=False, failure=REJECTED_FAILURE):
            ChangeRun.objects.filter(pk=run.pk).update(
                execution=Result.NOT_SUBMITTED, verification=Verification.NOT_APPLICABLE
            )


def _failure(outcome: Result, reason: str) -> str:
    return reasons.sentence(outcome, reason)


def reason_text(result_class: str, reason: str) -> str:
    """The plain sentence the run screens use for a result class and reason."""
    try:
        outcome = Result(result_class)
    except ValueError:
        return ""
    return _failure(outcome, reason)


def _fixed_privileged(shell: RemoteShell, argv: list[str]) -> str | None:
    """Run one fixed command with root or the authorized sudo; ``None`` when unreadable."""
    root = _root(shell)
    if root is None:
        raise OperationRefused(UNREADABLE_FAILURE)
    if root is False and shell.run(native.authorization(argv)).exit_status != 0:
        raise OperationRefused(PRIVILEGE_FAILURE)
    result = shell.run(native.privileged(argv, root=root))
    if result.exit_status != 0 or result.truncated:
        return None
    return result.stdout


def _window(run: ChangeRun, *, confirm: bool) -> revert.Window | None:
    """The window's native evidence over a new verified connection.

    Confirmation stops the timer and removes the preimage only when the revert service has
    not started. A started revert is left alone; a short bounded wait lets it finish so the
    page can say Put back instead of Not known.
    """
    try:
        with ssh.connect_operation(run) as shell:
            if shell.host_key != run.review.host_key:
                return revert.Window.NOT_KNOWN
            argv = (
                revert.confirmation(run.unit_name)
                if confirm
                else revert.evidence_command(run.unit_name)
            )
            text = _fixed_privileged(shell, argv)
            if text is None:
                return revert.Window.NOT_KNOWN
            window = revert.parse_window(text)
            if window is None:
                return revert.Window.NOT_KNOWN if confirm else None
            if not confirm or window is not revert.Window.NOT_KNOWN:
                return window
            deadline = time.monotonic() + WINDOW_SETTLE_SECONDS
            while time.monotonic() < deadline:
                time.sleep(0.2)
                evidence = _fixed_privileged(shell, revert.evidence_command(run.unit_name))
                settled = revert.parse_window(evidence) if evidence is not None else None
                if settled is revert.Window.PUT_BACK:
                    return settled
                if settled is None:
                    break
            return window
    except ConnectionFailed, OperationRefused:
        return revert.Window.NOT_KNOWN


def _conclude(  # noqa: C901 - the one conclusion every outcome class shares
    shell: RemoteShell,
    run: ChangeRun,
    kind: ChangeKind,
    evidence: native.UnitEvidence | None,
    line: ResultLine | None,
    source: RemoteOperation.Status,
    revision: int | None = None,
    *,
    result_evidence: ResultEvidence = ResultEvidence.PRESENT,
) -> None:
    """A controller-side failure while verifying never becomes a remote failure: the known
    outcome is kept and verification is recorded as unavailable.

    The execution outcome comes from the result line when it parsed and from the native
    unit otherwise. A line Barectl could not read keeps that same execution outcome but
    words its failure as unreadable evidence, never as the absence of a result.
    """
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
    window: revert.Window | None = None
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
            failure = RESTART_VERIFICATION_FAILED if kind.restarts_host else VERIFICATION_FAILED
        elif verification == Verification.UNAVAILABLE:
            failure = VERIFICATION_UNAVAILABLE
        if kind.access_changing:
            window = _window(run, confirm=verification == Verification.PASSED)
    elif kind.access_changing and outcome in (
        Result.PARTIAL,
        Result.FAILED,
        Result.TIMED_OUT,
    ):
        window = _window(run, confirm=False)
    if outcome == Result.SUCCEEDED and window is revert.Window.PUT_BACK:
        verification = Verification.FAILED
        failure = WINDOW_PUT_BACK
    elif (
        outcome == Result.SUCCEEDED
        and window is revert.Window.NOT_KNOWN
        and verification == Verification.PASSED
    ):
        verification = Verification.UNAVAILABLE
        failure = WINDOW_NOT_CONFIRMED
    if result_evidence is ResultEvidence.UNREADABLE:
        failure = UNREADABLE_RESULT_FAILURE
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
            window_outcome=window.value if window is not None else "",
            invocation_id=evidence.invocation_id if evidence is not None else run.invocation_id,
        )
    logger.info("Change run %s finished: %s", run.pk, outcome)
    if succeeded and kind.refresh_discovery:
        _refresh_discovery(run)


def _refresh_discovery(run: ChangeRun) -> None:
    from discovery.services import CHANGE_REFRESH_AUTHORITY, DiscoveryBusy, queue_discovery

    if run.server is None:
        return
    actor_id = run.requested_by_id
    if actor_id is None:
        return
    actor = User.objects.filter(pk=actor_id).first()
    if actor is None:
        return
    connection = run.connection
    if connection is not None and connection.revision != run.server.connection_revision:
        return
    try:
        queue_discovery(
            run.server,
            user=actor,
            authority=CHANGE_REFRESH_AUTHORITY,
        )
    except DiscoveryBusy, lifecycle.OperationRefused:
        logger.info("Automatic observation for change run %s was not queued", run.pk)


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
            journal = read_journal(shell, run.unit_name, run.review.document.get("stages"))
            _conclude(
                shell,
                run,
                kind,
                evidence,
                journal.line,
                Status.RECONCILING,
                revision,
                result_evidence=journal.result_evidence,
            )
    finally:
        if closing is not None:
            # The acknowledgement was used, whatever the check found; a newer one waits
            # for its own check.
            ChangeRun.objects.filter(pk=run.pk, closure_requested_at=closing).update(
                closure_requested_at=None
            )


def _missing_journal(
    shell: RemoteShell,
    run: ChangeRun,
    kind: ChangeKind,
    journal: JournalEvidence,
    revision: int,
    closing: bool,
) -> bool:
    """Conclude from a missing unit's present or unreadable result line, if it has one."""
    if journal.result_evidence is ResultEvidence.PRESENT:
        if _record(run.pk, Status.RECONCILING, revision):
            _conclude(
                shell,
                run,
                kind,
                None,
                journal.line,
                Status.RECONCILING,
                revision,
                result_evidence=journal.result_evidence,
            )
        return True
    if journal.result_evidence is ResultEvidence.UNREADABLE:
        if _record_missing(run, journal, revision, UNREADABLE_RESULT_FAILURE) and closing:
            _close_unknown(shell, run, revision, reached=bool(journal.stage))
        return True
    return False


def _record_missing(run: ChangeRun, journal: JournalEvidence, revision: int, failure: str) -> bool:
    """Record a missing unit's outcome and explanation, keeping any stage it reported."""
    changes: dict[str, object] = {"execution": Result.NOT_FOUND}
    if journal.stage:
        changes["progress_stage"] = journal.stage
    if not _record(run.pk, Status.RECONCILING, revision, **changes):
        return False
    lifecycle.note(run.pk, failure, revision=revision)
    return True


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
    journal = read_journal(shell, run.unit_name, run.review.document.get("stages"))
    if _missing_journal(shell, run, kind, journal, revision, closing):
        return
    if evidence.boot_id != run.review.boot_id:
        reason = f"{RESTARTED} {UNCERTAIN}"
    elif journal.stage:
        reason = f"{STOPPED_SILENTLY} {NEVER_AGAIN}"
    else:
        reason = f"{NOT_FOUND} {UNCERTAIN}"
    if _record_missing(run, journal, revision, reason) and closing:
        _close_unknown(shell, run, revision, reached=bool(journal.stage))


def _close_unknown(shell: RemoteShell, run: ChangeRun, revision: int, *, reached: bool) -> None:
    """docs/adr/0006-use-native-bootstrap-execution.md#unknown-outcomes"""
    reason = _closure_blocked(shell, run)
    with transaction.atomic():
        if reason:
            _record(run.pk, Status.RECONCILING, revision, closure_blocked=reason)
            return
        if lifecycle.finish(
            run.pk,
            Status.RECONCILING,
            succeeded=False,
            failure=OUTCOME_UNKNOWN_REACHED if reached else OUTCOME_UNKNOWN,
            revision=revision,
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
