"""Drive the four operational change members against one real scenario server."""

import shlex
import time
from dataclasses import dataclass

from discovery.ssh import RemoteShell
from operations import engine, native
from operations.inputs import PreparationInputs
from operations.models import ChangeReview

from .scenario_testing import ScenarioTestCase


@dataclass(frozen=True)
class Submitted:
    review: ChangeReview
    unit: str
    no_changes: bool


def submit_change(
    test: ScenarioTestCase,
    kind: engine.ChangeKind,
    inputs: PreparationInputs,
    *,
    secret: bytes | None = None,
) -> Submitted:
    """Review and submit one change, returning the transient unit without waiting."""
    with test.shell() as shell:
        # The worker also records the reviewed fence (automation/fence.py) before it stores
        # the review, so a scenario that applies a fenced change uses the same review.
        draft = engine._planned(shell, kind.review(kind.inspect(shell, inputs), inputs))
        return submit_draft(test, shell, kind, draft, secret=secret)


def submit_draft(
    test: ScenarioTestCase,
    shell: RemoteShell,
    kind: engine.ChangeKind,
    draft: engine.ReviewDraft,
    *,
    secret: bytes | None = None,
    acknowledge: bool = True,
) -> Submitted:
    """Stage and submit an already reviewed draft, without refreshing its evidence."""
    test.assertTrue(draft.eligible, draft.refusals)
    stored = ChangeReview(
        document=draft.document,
        sites_read=draft.sites_read,
        sites_digest=engine._sites_digest(shell, draft),
    )
    if draft.no_changes:
        return Submitted(stored, "", True)
    if draft.uptime_centiseconds is None:
        test.fail("No native clock.")
    unit = native.new_unit_name()
    staged_secret = engine.secret_path(unit)
    context = engine.BodyContext(
        unit,
        draft.boot_id,
        draft.uptime_centiseconds + 90000,
        secret_path=staged_secret if secret is not None else "",
    )
    body = kind.body(draft.document, context)
    path = engine.body_path(context.unit)
    digest = str(draft.document["body_sha256"])
    test.assertEqual(
        shell.run(shlex.join(engine.stage_command(path, digest)), stdin=body.source).exit_status,
        0,
    )
    if secret is not None:
        test.assertEqual(
            shell.run(
                shlex.join(engine.stage_secret_command(staged_secret, len(secret))),
                stdin=secret,
            ).exit_status,
            0,
        )
    payload = engine.payload(
        kind,
        stored,
        context,
        body,
        path,
        secret=staged_secret if secret is not None else "",
    )
    result = shell.run(shlex.join(native.submission(context.unit, payload, collect=True)))
    if acknowledge:
        test.assertEqual(result.exit_status, 0)
    return Submitted(stored, context.unit, False)


def wait_result(
    test: ScenarioTestCase,
    submitted: Submitted,
    *,
    timeout: float = 30,
    expected: str = "succeeded",
    reason: str = "",
) -> None:
    with test.shell() as shell:
        end = time.monotonic() + timeout
        result = engine.read_result(shell, submitted.unit)
        while result is None and time.monotonic() < end:
            time.sleep(0.05)
            result = engine.read_result(shell, submitted.unit)
        if result is None:
            test.fail("No native outcome: " + test.native(f"journalctl -u {submitted.unit} -n 30"))
        if result.result_class != expected or (reason and result.reason != reason):
            test.fail(
                f"{result.result_class} {result.reason}: "
                + test.native(f"journalctl -u {submitted.unit} -n 40")
            )
        # The result line is printed before the unit exits and releases the native lock. The
        # worker closes a run from the ended unit's evidence, so the harness waits for the
        # same end; a read taken while the unit still holds the lock reports "could not read"
        # instead of the postcondition.
        wait_inactive(shell, submitted.unit)


def wait_inactive(shell: RemoteShell, unit: str, timeout: float = 30) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = shell.run(f"systemctl is-active {shlex.quote(unit)}").stdout.strip()
        if state in ("", "inactive", "failed"):
            return
        time.sleep(0.1)


def apply_change(
    test: ScenarioTestCase,
    kind: engine.ChangeKind,
    inputs: PreparationInputs,
    *,
    timeout: float = 30,
    secret: bytes | None = None,
    expected: str = "succeeded",
    reason: str = "",
) -> ChangeReview:
    submitted = submit_change(test, kind, inputs, secret=secret)
    if not submitted.no_changes:
        wait_result(test, submitted, timeout=timeout, expected=expected, reason=reason)
    if expected == "succeeded":
        with test.shell() as shell:
            verified = kind.verify(shell, submitted.review)
            if verified is None:
                # Verification is a fresh read, and a read the server did not answer is not
                # evidence about the postcondition: retry it once. A false answer still fails.
                time.sleep(0.5)
                verified = kind.verify(shell, submitted.review)
            test.assertTrue(verified)
    return submitted.review
