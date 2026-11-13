"""Shared native-result and rendered-recovery contracts for interrupted changes.

Access-changing kinds use :func:`assert_access_failure`; a run that an abrupt termination
left without a terminal result uses :func:`assert_abrupt_run`. Both compare independently
established effects with the emitted result and render the real recovery template, so a
page cannot claim success or "nothing changed" for an outcome the evidence does not support.
"""

from collections.abc import Mapping
from enum import StrEnum
from unittest import TestCase

from django.template.loader import render_to_string
from django.urls import reverse
from django.utils.html import escape

from .engine import ResultLine
from .models import (
    ChangePreparation,
    ChangeReview,
    ChangeRun,
    Consent,
    RemoteOperation,
    Result,
    WindowOutcome,
)
from .presentation import run_view
from .revert import Window


class FailurePhase(StrEnum):
    PREFLIGHT = "preflight"
    UNCERTAIN_WRITE = "uncertain_write"
    AFTER_WRITE = "after_write"


_FAILURE_RESULTS = {
    FailurePhase.PREFLIGHT: Result.REFUSED,
    FailurePhase.UNCERTAIN_WRITE: Result.FAILED,
    FailurePhase.AFTER_WRITE: Result.PARTIAL,
}


def assert_access_failure(
    test: TestCase,
    result: ResultLine,
    *,
    phase: FailurePhase,
    kind_slug: str,
    window: Window | None,
    stopped_step: str = "",
) -> None:
    """Compare an emitted result with known effects and the operator's recovery message."""
    test.assertEqual(result.result_class, _FAILURE_RESULTS[phase])
    preparation = ChangePreparation(pk=1, kind_slug=kind_slug)
    review = ChangeReview(
        preparation=preparation,
        kind_slug=kind_slug,
        consent=Consent.SHARED,
        document={"stages": ["apply", "verify"]},
    )
    run = ChangeRun(
        pk=1,
        review=review,
        status=RemoteOperation.Status.FAILED,
        execution=result.result_class,
        result_reason=result.reason,
        window_outcome=window.value if window is not None else "",
        progress_stage="verify" if phase is FailurePhase.AFTER_WRITE else "apply",
        server_name="Contract server",
        failure="The requested change stopped.",
    )
    view = run_view(run)
    page = " ".join(
        render_to_string("operations/_run_status.html", {"run": view, "plain": view.plain}).split()
    )
    test.assertIn("Try again", page)
    action = view.plain.next
    if action is None:
        test.fail("An access failure has no recovery action.")
    test.assertEqual(action.label, "Try again")
    test.assertEqual(action.kind, "again")
    retry_url = reverse("change_prepare_again", args=[preparation.pk])
    test.assertEqual(action.url, retry_url)
    test.assertIn(f'<form class="usa-form" method="post" action="{retry_url}">', page)
    if phase is FailurePhase.PREFLIGHT:
        test.assertEqual(view.plain.result, "Nothing changed")
        test.assertIn("Nothing changed", page)
        test.assertIn("stopped before making any requested change", page)
        test.assertIsNone(window)
        test.assertNotIn("Access check:", page)
    else:
        test.assertEqual(view.plain.result, "Stopped")
        test.assertTrue(
            stopped_step, "The caller must name the independently expected stopped step."
        )
        sentence = f"This stopped after {stopped_step.lower()}. Nothing after it ran."
        test.assertEqual(view.plain.sentence, sentence)
        test.assertIn(f"<p>{sentence}</p>", page)
        test.assertNotIn("Nothing changed", page)
        test.assertNotIn("stopped before making any requested change", page)
        test.assertIsNotNone(window)
        label = WindowOutcome(window.value).label if window is not None else ""
        test.assertIn(f"Access check: {label}", page)
        explanation = (
            "The server put the earlier settings back because a new connection did not confirm "
            "the change."
            if window is Window.PUT_BACK
            else "Barectl could not confirm access. The server puts the change back on its own "
            "unless a new verified connection confirms it."
        )
        test.assertIn(explanation, page)


def assert_abrupt_run(
    test: TestCase,
    recorded: Mapping[str, object],
    *,
    result: str,
    action: str,
    action_kind: str,
    changed_possible: bool,
) -> None:
    """Render an abruptly ended run and check its one recovery action and result words.

    ``recorded`` is the run's stored state: ``status``, ``execution``, ``failure``,
    ``progress_stage``, ``kind_slug``, ``consent``, ``document``, ``preparation`` and
    ``server_name``. ``changed_possible`` is the evidence boundary: an undispatched run may
    say nothing changed, while a dispatched run or a stopped body may not.
    """
    kind_slug = str(recorded["kind_slug"])
    preparation_id = recorded.get("preparation")
    preparation = ChangePreparation(
        pk=preparation_id if isinstance(preparation_id, int) else 1,
        kind_slug=kind_slug,
    )
    review = ChangeReview(
        preparation=preparation,
        kind_slug=kind_slug,
        consent=str(recorded["consent"]),
        document=recorded["document"] if isinstance(recorded["document"], dict) else {},
    )
    run = ChangeRun(
        pk=1,
        review=review,
        status=str(recorded["status"]),
        execution=str(recorded["execution"]),
        result_reason=str(recorded.get("result_reason", "")),
        window_outcome="",
        progress_stage=str(recorded.get("progress_stage", "")),
        server_name=str(recorded.get("server_name", "Contract server")),
        failure=str(recorded.get("failure", "")),
    )
    view = run_view(run)
    page = " ".join(
        render_to_string("operations/_run_status.html", {"run": view, "plain": view.plain}).split()
    )
    test.assertEqual(view.plain.result, result)
    test.assertNotEqual(view.plain.result, "Done")
    test.assertNotIn("Barectl finished this change", page)
    test.assertNotIn("Applied and verified", page)
    next_action = view.plain.next
    if next_action is None:
        test.fail("An abruptly ended run has no recovery action.")
    test.assertEqual(next_action.label, action)
    test.assertEqual(next_action.kind, action_kind)
    test.assertIn(action, page)
    if changed_possible:
        test.assertNotIn("Nothing changed", page)
        test.assertNotIn("stopped before making any requested change", page)
    else:
        test.assertIn("nothing changed", page)


def assert_policy_failure(
    test: TestCase,
    run: ChangeRun,
    *,
    sentence: str,
) -> None:
    """Render a failed non-access run and check its complete reason and retry action.

    A policy failure has no access window: the page must show the reason's whole sentence
    and one "Try again" action, never claim that nothing changed.
    """
    view = run_view(run)
    page = " ".join(
        render_to_string("operations/_run_status.html", {"run": view, "plain": view.plain}).split()
    )
    test.assertEqual(view.plain.result, "Stopped")
    test.assertEqual(view.plain.sentence, sentence)
    test.assertIn(escape(sentence), page)
    test.assertNotIn("Nothing changed", page)
    next_action = view.plain.next
    if next_action is None:
        test.fail("A stopped policy run has no recovery action.")
    test.assertEqual(next_action.label, "Try again")
    test.assertEqual(next_action.kind, "again")
    preparation_id = run.review.preparation_id
    if preparation_id is None:
        test.fail("A stopped policy run has no preparation to retry.")
    retry_url = reverse("change_prepare_again", args=[preparation_id])
    test.assertEqual(next_action.url, retry_url)
    test.assertIn(f'<form class="usa-form" method="post" action="{retry_url}">', page)
