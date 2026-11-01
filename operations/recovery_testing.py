"""Shared native-result and rendered-recovery contract for access-changing kinds."""

from enum import StrEnum
from unittest import TestCase

from django.template.loader import render_to_string
from django.urls import reverse

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
