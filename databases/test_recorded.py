"""A real native transcript qualifies the site-database review and its consent.

The recorded state is the prepared site with a satisfied MariaDB binding, so a fresh
review reconstructs the database, principal and privileges as no changes.
"""

import contextlib
from unittest import mock

from django.test import SimpleTestCase

from discovery.recorded import ReplayShell, load
from operations.consent import consent_of
from operations.fakes import ChangeTestCase
from operations.inputs import PreparationInputs
from operations.models import ChangeReview, Consent

from . import binding, site

STATE = "site-database-26.04"
IDENTIFIER = "sdbalpha"


class RecordedSiteDatabaseTests(SimpleTestCase):
    def test_a_satisfied_binding_reviews_as_no_changes(self) -> None:
        inputs = PreparationInputs("", IDENTIFIER)
        evidence = site.inspect(ReplayShell(load(STATE)), inputs)
        draft = site.review(evidence, inputs)
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertTrue(draft.no_changes)
        self.assertEqual(consent_of(draft.effects), Consent.READ)
        self.assertEqual(draft.current_sites, (IDENTIFIER,))
        self.assertIn("already exists", str(draft.document["note"]))
        self.assertEqual(draft.document["principal"], "ssdbalpha")
        self.assertEqual(draft.document["engine"], binding.MARIADB)


class RecordedSiteDatabaseWorkerTests(ChangeTestCase):
    def test_the_worker_prepares_the_review_from_the_server_alone(self) -> None:
        from operations.services import request_prepare

        self.sign_in_with("view_server", "view_changes", "change_site")
        queued = request_prepare(
            self.server,
            self.user,
            site.SLUG,
            inputs={"version": 1, "identifier": IDENTIFIER},
        )
        if queued is None:
            self.fail("No preparation was queued.")
        with mock.patch(
            "discovery.ssh.connect_operation",
            return_value=contextlib.nullcontext(ReplayShell(load(STATE))),
        ):
            self.run_worker()
        queued.refresh_from_db()
        self.assertEqual(queued.status, "succeeded", queued.failure)
        review = ChangeReview.objects.get(preparation=queued)
        self.assertTrue(review.eligible, review.document)
        self.assertEqual(review.consent, Consent.READ)
        self.assertTrue(review.no_changes)
