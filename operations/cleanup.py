"""The change engine's first kind: clearing the finished barectl runs systemd retains.

docs/ssh-connections.md#clearing-finished-runs. The kind supplies the engine's
four members: the retained-unit inspection, its pure review, the native body
(operations/bodies/clear_runs.sh, staged and digest-bound from SSH standard input) and the
verification that none of the reviewed units is retained any more.
"""

import hashlib
import importlib.resources
from dataclasses import dataclass
from typing import Final

from discovery.ssh import RemoteShell
from operations.inputs import EMPTY_INPUTS, PreparationInputs

from . import native
from .consent import DeclaredEffect, Scope
from .engine import BodyContext, ChangeKind, NativeBody, ReviewDraft, current_units
from .models import ChangeReview

LABEL: Final = "Clear finished barectl runs"
INTENT: Final = "Clear finished barectl runs that the server's systemd retains."
SLUG: Final = "cleanup_runs"

BODY: Final = importlib.resources.files("operations.bodies").joinpath("clear_runs.sh").read_text()
BODY_BYTES: Final = BODY.rstrip("\n").encode()
BODY_SHA256: Final = hashlib.sha256(BODY_BYTES).hexdigest()

STAGES: Final = (
    "Take the mutation lock and admit the reviewed change",
    "Verify each reviewed unit still matches its review",
    "Clear the verified units: systemctl stop for exited ones, reset-failed for others",
    "Verify none of the reviewed units is retained any more",
)

UNREADABLE_UNITS = "Barectl could not read the retained barectl runs."
UNREADABLE_CLOCK = "Barectl could not read the server's clock."
NO_CHANGES_NOTE = "The server retains no finished barectl run to clear."


@dataclass(frozen=True)
class CleanupEvidence:
    """What the inspection read: the server's boot and its retained barectl units."""

    boot_id: str
    uptime_centiseconds: int | None
    # The retained units as inspection reported them, or ``None`` when they were unreadable.
    units: tuple[native.UnitEvidence, ...] | None
    active_units: frozenset[str]


UPTIME: Final = "cut -d' ' -f1 /proc/uptime | tr -d ."


def inspect(shell: RemoteShell, inputs: PreparationInputs = EMPTY_INPUTS) -> CleanupEvidence:
    states = shell.run(native.RETAINED_STATES)
    uptime = shell.run(UPTIME)
    try:
        boot_id, found = native.parse_retained_states(states.stdout)
    except native.Unreadable:
        return CleanupEvidence("", None, None, current_units())
    units = tuple(found)
    if (
        states.exit_status != 0
        or states.truncated
        or uptime.exit_status != 0
        or uptime.truncated
        or not uptime.stdout.strip().isdigit()
    ):
        return CleanupEvidence(boot_id, None, units, current_units())
    return CleanupEvidence(boot_id, int(uptime.stdout.strip()), units, current_units())


def review(evidence: object, inputs: PreparationInputs = EMPTY_INPUTS) -> ReviewDraft:
    """docs/ssh-connections.md#clearing-finished-runs"""
    if not isinstance(evidence, CleanupEvidence):
        raise ValueError("Not the cleanup inspection's evidence.")
    if evidence.units is None:
        return refused(UNREADABLE_UNITS, evidence)
    if evidence.uptime_centiseconds is None:
        return refused(UNREADABLE_CLOCK, evidence)
    units = sorted(evidence.units, key=lambda unit: unit.unit)
    current = evidence.active_units
    running = [unit for unit in units if not unit.terminal]
    ours = [unit for unit in units if unit.terminal and unit.unit in current]
    unidentified = [
        unit
        for unit in units
        if unit.terminal and unit.unit not in current and not unit.invocation_id
    ]
    finished = [
        unit for unit in units if unit.terminal and unit.unit not in current and unit.invocation_id
    ]
    targets = finished[: native.CLEANUP_BATCH]
    left = len(finished) - len(targets)
    fingerprint = hashlib.sha256(
        "\n".join(
            sorted(
                f"{unit.unit} {unit.invocation_id} {unit.active_state}/{unit.sub_state} "
                f"{unit.result} {unit.exec_main_status} {int(unit.populated)}"
                for unit in units
            )
        ).encode()
    ).hexdigest()
    kept = []
    if running:
        kept.append(f"{len(running)} still running or with processes left")
    if ours:
        kept.append(f"{len(ours)} whose runs this installation is still establishing")
    if unidentified:
        kept.append(f"{len(unidentified)} without an invocation to recheck")
    if left:
        kept.append(f"{left} beyond the {native.CLEANUP_BATCH} one cleanup clears")
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": BODY_SHA256,
        "targets": [
            {
                "unit": unit.unit,
                "invocation": unit.invocation_id,
                "active_state": unit.active_state,
                "sub_state": unit.sub_state,
                "result": unit.result,
                "exec_main_code": unit.exec_main_code,
                "exec_main_status": unit.exec_main_status,
                "populated": int(unit.populated),
                "failed": unit.active_state != "active",
            }
            for unit in targets
        ],
        "kept": kept,
        "retained_units": fingerprint,
    }
    if not targets:
        document["note"] = NO_CHANGES_NOTE
        return ReviewDraft(
            kind=SLUG,
            intent=INTENT,
            stages=STAGES,
            refusals=(),
            boot_id=evidence.boot_id,
            uptime_centiseconds=evidence.uptime_centiseconds,
            document=document,
        )
    exited = sum(1 for unit in targets if unit.active_state == "active")
    failed = len(targets) - exited
    effects = (
        DeclaredEffect(
            Scope.SHARED,
            (
                f"Clear {len(targets)} finished barectl runs from systemd: systemctl stop "
                f"for {exited} successful units kept after exit, and systemctl reset-failed "
                f"for {failed} others. Under the mutation lock the run first rechecks that "
                "each still shows the reviewed invocation, has finished and has no "
                "processes, and clears none if any changed. Units already gone are skipped."
            ),
        ),
        DeclaredEffect(
            Scope.SHARED,
            (
                "systemd forgets these units' states and exit results; this cannot be "
                "undone. Their journal entries stay as long as the server's journal "
                "retention keeps them. Another Barectl installation that still needs one "
                "of them to check a run's outcome can then only close that run as outcome "
                "unknown. Barectl's own records of its runs are kept."
            ),
        ),
    )
    return ReviewDraft(
        kind=SLUG,
        intent=INTENT,
        effects=effects,
        stages=STAGES,
        postconditions=("systemd retains none of the listed units.",),
        refusals=(),
        boot_id=evidence.boot_id,
        uptime_centiseconds=evidence.uptime_centiseconds,
        document=document,
    )


def refused(reason: str, evidence: CleanupEvidence) -> ReviewDraft:
    return ReviewDraft(
        kind=SLUG,
        intent=INTENT,
        stages=STAGES,
        refusals=(reason,),
        boot_id=evidence.boot_id,
        uptime_centiseconds=evidence.uptime_centiseconds,
    )


def body(document: dict[str, object], context: BodyContext) -> NativeBody:
    targets = document.get("targets")
    if not isinstance(targets, list) or not targets:
        raise ValueError("A cleanup body needs its reviewed targets.")
    entries = []
    for target in targets:
        if not isinstance(target, dict):
            raise ValueError("Not a reviewed cleanup target.")
        name = native.check_unit(str(target["unit"]))
        if name == context.unit:
            raise ValueError("A cleanup cannot clear its own unit.")
        invocation = native.check_invocation(str(target["invocation"]))
        active = str(target["active_state"])
        sub = str(target["sub_state"])
        result = str(target["result"])
        code = str(target["exec_main_code"])
        status = str(target["exec_main_status"])
        populated = str(target["populated"])
        for value in (active, sub, result, code, status, populated):
            if not value or any(
                character not in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in value
            ):
                raise ValueError("Not reviewed unit state.")
        if populated != "0":
            raise ValueError("A cleanup target cannot have processes.")
        entries.append("|".join((name, invocation, active, sub, result, code, status, populated)))
    return NativeBody(BODY_BYTES, (" ".join(entries),))


def verify(shell: RemoteShell, review: ChangeReview) -> bool | None:
    """None of the reviewed units is retained any more; ``None`` when unreadable."""
    targets = review.document.get("targets")
    if not isinstance(targets, list):
        return None
    result = shell.run(native.RETAINED_STATES)
    if result.exit_status != 0 or result.truncated:
        return None
    try:
        _, retained = native.parse_retained_states(result.stdout)
    except native.Unreadable:
        return None
    reviewed = {str(target["unit"]) for target in targets if isinstance(target, dict)}
    return not reviewed & {unit.unit for unit in retained}


CLEANUP_RUNS: Final = ChangeKind(
    slug=SLUG,
    label=LABEL,
    inspect=inspect,
    review=review,
    body=body,
    verify=verify,
    capacity=native.CLEANUP_CEILING,
)
