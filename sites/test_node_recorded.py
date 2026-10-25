"""Real native transcripts qualify site-only Node consent and interrupted PHP refusal."""

import contextlib
from unittest import mock

from django.test import SimpleTestCase

from automation.testing import AutomationReplay
from discovery.recorded import ReplayShell, load
from operations.consent import consent_of
from operations.fakes import ChangeTestCase
from operations.inputs import PreparationInputs
from operations.models import ChangeReview, Consent
from operations.services import request_prepare

from . import node_change


class RecordedNodeTests(SimpleTestCase):
    def test_installed_node_change_is_site_only_and_repeated_selection_is_read(self) -> None:
        for entry, consent, no_changes in (
            ("nodejs_24", Consent.SITE, False),
            ("nodejs_22", Consent.READ, True),
        ):
            with self.subTest(entry=entry):
                inputs = PreparationInputs(entry, "s7node")
                evidence = node_change.inspect(ReplayShell(load("site-node-26.04")), inputs)
                draft = node_change.review(evidence, inputs)
                self.assertTrue(draft.eligible, draft.refusals)
                self.assertEqual(consent_of(draft.effects), consent)
                self.assertEqual(draft.no_changes, no_changes)
                self.assertEqual(draft.current_sites, ("s7node",))

    def test_an_interrupted_php_transition_is_one_site_and_blocks_node_change(self) -> None:
        inputs = PreparationInputs("nodejs_24", "s7node")
        evidence = node_change.inspect(ReplayShell(load("site-node-interrupted-26.04")), inputs)
        draft = node_change.review(evidence, inputs)
        self.assertFalse(draft.eligible)
        self.assertIn("The PHP runtime transition is incomplete.", " ".join(draft.refusals))
        if evidence.state is None:
            self.fail("Native interrupted state disappeared.")
        sites = [
            site for site in evidence.state["native"]["sites"] if site["identifier"] == "s7node"
        ]
        self.assertEqual(len(sites), 1)


class RecordedNodeEngineTests(ChangeTestCase):
    def test_registered_kind_prepares_through_the_worker_with_site_consent(self) -> None:
        self.sign_in_with("view_server", "view_changes", "change_site")
        preparation = request_prepare(
            self.server,
            self.user,
            node_change.SLUG,
            inputs={"version": 1, "identifier": "s7node", "selection": "nodejs_24"},
        )
        if preparation is None:
            self.fail("No preparation was queued.")
        with mock.patch(
            "discovery.ssh.connect_operation",
            return_value=contextlib.nullcontext(
                AutomationReplay(ReplayShell(load("site-node-26.04")))
            ),
        ):
            self.run_worker()
        preparation.refresh_from_db()
        self.assertEqual(preparation.status, "succeeded", preparation.failure)
        review = ChangeReview.objects.get(preparation=preparation)
        self.assertTrue(review.eligible, review.document)
        self.assertEqual(review.consent, Consent.SITE)
        self.assertEqual(review.affected_sites, ["s7node"])
