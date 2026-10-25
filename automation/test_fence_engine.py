"""What a review records about the site's background work, and when it refuses (#395)."""

import hashlib
import json
from collections.abc import Callable
from typing import override

from django.test import SimpleTestCase

from automation import fence, observation
from automation.testing import automation, show
from discovery.fakes import FakeServer
from discovery.ssh import CommandResult
from operations import engine
from operations.consent import DeclaredEffect, Scope
from operations.fakes import BOOT_ID, ChangeTestCase
from operations.inputs import PreparationInputs

SHOP = "shop"
SITES_READ = "printf 'shop\\n' | LC_ALL=C sort"
SITES_OUTPUT = "shop\n"
BODY = b"#!/bin/sh\nexit 0"
Review = Callable[[object, PreparationInputs], engine.ReviewDraft]


def fenced_review(evidence: object, inputs: PreparationInputs) -> engine.ReviewDraft:
    return engine.ReviewDraft(
        kind="set_site_php",
        intent="Move shop to another PHP runtime.",
        effects=(DeclaredEffect(Scope.SITE, "Move the site's runtime.", (SHOP,)),),
        stages=("preflight", "verify"),
        boot_id=BOOT_ID,
        uptime_centiseconds=500025,
        sites_read=SITES_READ,
        current_sites=(SHOP,),
        document={"version": 1, "body_sha256": hashlib.sha256(BODY).hexdigest()},
    )


def no_change_review(evidence: object, inputs: PreparationInputs) -> engine.ReviewDraft:
    return engine.ReviewDraft(
        kind="fixture_no_change",
        intent="Nothing to do.",
        boot_id=BOOT_ID,
        uptime_centiseconds=500025,
        document={"version": 1, "body_sha256": hashlib.sha256(BODY).hexdigest()},
    )


def server_wide_review(evidence: object, inputs: PreparationInputs) -> engine.ReviewDraft:
    return engine.ReviewDraft(
        kind="fixture_server_wide",
        intent="Restart the server's shared proxy.",
        effects=(DeclaredEffect(Scope.SERVER, "Restart the shared proxy."),),
        stages=("preflight",),
        boot_id=BOOT_ID,
        uptime_centiseconds=500025,
        document={"version": 1, "body_sha256": hashlib.sha256(BODY).hexdigest()},
    )


def _body(document: dict[str, object], context: engine.BodyContext) -> engine.NativeBody:
    return engine.NativeBody(BODY)


def kind(slug: str, review: Review) -> engine.ChangeKind:
    return engine.ChangeKind(
        slug=slug,
        label="Fixture change",
        inspect=lambda shell, inputs: None,
        review=review,
        body=_body,
        verify=lambda shell, review: True,
    )


class FencedReviewCase(ChangeTestCase):
    """One fenced kind and one site's automation evidence, for the tests below."""

    @override
    def assert_read_only(self) -> None:
        # The fixture's fixed affected-sites read is part of preparing its review.
        self.remote.commands[:] = [
            command for command in self.remote.commands if command != SITES_READ
        ]
        super().assert_read_only()

    @override
    def setUp(self) -> None:
        super().setUp()
        self.replace("set_site_php", kind("set_site_php", fenced_review))
        self.answer(automation(identifier=SHOP, timer=show(active="active")))

    def replace(self, slug: str, replacement: engine.ChangeKind) -> None:
        """Register ``replacement`` for this test and put the installation's kind back."""
        previous = engine._KINDS.get(slug)
        engine.register_kind(replacement)
        self.addCleanup(self._put_back, slug, previous)

    def _put_back(self, slug: str, previous: engine.ChangeKind | None) -> None:
        if previous is None:
            engine._KINDS.pop(slug, None)
        else:
            engine._KINDS[slug] = previous

    def answer(self, value: dict[str, object] | None, *, status: int = 0) -> None:
        self.remote.results[SITES_READ] = CommandResult(0, SITES_OUTPUT)
        self.remote.answer_root(
            observation.read_command(),
            CommandResult(status, "" if value is None else json.dumps(value)),
        )


class FencedReviewTests(FencedReviewCase):
    """The engine reads the plan once per eligible site change and records it."""

    def test_the_review_records_what_it_pauses_and_starts_again(self) -> None:
        review = self.change("set_site_php")
        self.assertEqual(
            review.document["automation_fence"],
            {
                "version": 1,
                "sites": [
                    {
                        "identifier": SHOP,
                        "slice": f"barectl-site-{SHOP}.slice",
                        "timers": [f"barectl-site-{SHOP}-wpcron.timer"],
                        "services": [f"barectl-site-{SHOP}-wpcron.service"],
                        "resume": [f"barectl-site-{SHOP}-wpcron.timer"],
                        "budget_seconds": fence.FENCE_BUDGET_SECONDS,
                    }
                ],
            },
        )

    def test_a_site_with_no_automation_records_an_empty_plan(self) -> None:
        self.answer(automation(identifier=SHOP, units=[]))
        review = self.change("set_site_php")
        self.assertEqual(review.document["automation_fence"], {"version": 1, "sites": []})

    def test_unreadable_automation_refuses_the_change_with_nothing_planned(self) -> None:
        self.answer(None, status=1)
        preparation = self.prepare("set_site_php")
        review = preparation.review
        self.assertFalse(review.eligible)
        self.assertEqual(review.effects, [])
        self.assertEqual(review.document["refusals"], [fence.UNREADABLE_REFUSAL])
        self.assertNotIn("automation_fence", review.document)

    def test_a_change_with_no_effects_reads_no_automation(self) -> None:
        self.replace("fixture_no_change", kind("fixture_no_change", no_change_review))
        self.change("fixture_no_change")
        self.assertNotIn(observation.read_command(), self.remote.commands)

    def test_a_server_wide_change_names_no_site_and_pauses_nothing(self) -> None:
        self.replace("fixture_server_wide", kind("fixture_server_wide", server_wide_review))
        review = self.change("fixture_server_wide")
        self.assertNotIn("automation_fence", review.document)
        self.assertNotIn(observation.read_command(), self.remote.commands)


class FencePageTests(FencedReviewCase):
    """The confirm screen says what pauses and what starts again, in plain words."""

    def test_the_confirm_screen_names_the_site_work_it_pauses(self) -> None:
        review = self.change("set_site_php")
        page = self.client.get(f"/changes/{review.preparation_id}/")
        self.assertEqual(page.status_code, 200)
        html = page.content.decode()
        self.assertIn("Pauses", html)
        self.assertIn("Starts again", html)
        self.assertIn("shop&#x27;s scheduled tasks", html)
        for term in ("systemd", "slice", "timer", "unit", "invocation", "journal"):
            self.assertNotIn(term, html.lower())

    def test_a_change_that_pauses_nothing_says_so(self) -> None:
        self.answer(automation(identifier=SHOP, units=[]))
        review = self.change("set_site_php")
        page = self.client.get(f"/changes/{review.preparation_id}/")
        html = page.content.decode()
        self.assertIn("This change touches no site's background work.", html)


class FenceSetTests(SimpleTestCase):
    """The specification names the changes that fence and the ones that never do."""

    def test_the_fencing_changes_are_the_ones_the_specification_names(self) -> None:
        self.assertEqual(
            fence.FENCING,
            {
                "set_site_php",
                "set_site_node",
                "set_site_pool",
                "deploy_laravel_site",
                "rollback_laravel_site",
                "edit_laravel_environment",
                "edit_wordpress_settings",
                "remove_site",
                "update_catalog",
            },
        )

    def test_the_two_wordpress_actions_never_fence(self) -> None:
        self.assertLessEqual({"reset_wordpress_password", "verify_wordpress_core"}, fence.NO_FENCE)

    def test_the_change_that_owns_the_units_never_fences_itself(self) -> None:
        self.assertIn("set_wordpress_server_cron", fence.NO_FENCE)

    def test_a_change_outside_the_set_pauses_nothing(self) -> None:
        self.assertEqual(fence.fenced_sites("cleanup_runs", ("shop",)), ())
        self.assertEqual(fence.fenced_sites("set_site_php", ("shop",)), ("shop",))


class FencePlanReadTests(SimpleTestCase):
    def test_no_named_site_reads_nothing(self) -> None:
        remote = FakeServer()
        self.assertEqual(fence.plan(remote, ()), {"version": 1, "sites": []})
        self.assertEqual(remote.commands, [])
