"""A real native transcript qualifies the Valkey install and a fresh controller.

The recorded state is the prepared site with Valkey installed, its shared unit masked and
inactive, and every PHP master and site proxy still verifiable after the transaction's
``daemon-reload``.
"""

import contextlib
from unittest import mock

from django.test import SimpleTestCase

from discovery.observations import collect
from discovery.recorded import ReplayShell, load
from operations.consent import consent_of
from operations.fakes import ChangeTestCase
from operations.inputs import PreparationInputs
from operations.models import ChangeReview, Consent

from . import engine, observation

STATE = "valkey-installed-26.04"


class RecordedValkeyTests(SimpleTestCase):
    def test_a_fresh_controller_reconstructs_installed_masked_valkey(self) -> None:
        shell = ReplayShell(load(STATE))
        collected = collect(shell)
        current = observation.installed(collected)
        if current is None:
            self.fail("The transcript does not reconstruct Valkey as installed.")
        self.assertTrue(current.present)
        self.assertTrue(current.managed)
        self.assertTrue(current.masked)
        self.assertTrue(current.inactive)
        self.assertGreater(len(current.version), 0)

    def test_a_repeated_review_proposes_nothing(self) -> None:
        inputs = PreparationInputs()
        shell = ReplayShell(load(STATE))
        draft = engine.review(engine.inspect(shell, inputs), inputs)
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertTrue(draft.no_changes)
        self.assertEqual(consent_of(draft.effects), Consent.READ)
        self.assertIn("already installed", str(draft.document["note"]))


class RecordedValkeyWorkerTests(ChangeTestCase):
    def test_the_worker_prepares_the_review_from_the_server_alone(self) -> None:
        from operations.services import request_prepare

        self.sign_in_with("view_server", "view_changes", "change_site")
        queued = request_prepare(
            self.server,
            self.user,
            engine.SLUG,
            inputs={"version": 1},
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


OBJECT_CACHE_STATE = "object-cache-26.04"
OBJECT_CACHE_EDITED_STATE = "object-cache-edited-26.04"
SITE = "l3wordpress"


class RecordedObjectCacheTests(SimpleTestCase):
    def test_a_fresh_controller_reconstructs_a_connected_site_cache(self) -> None:
        shell = ReplayShell(load(OBJECT_CACHE_STATE))
        collected = collect(shell)
        if observation.installed(collected) is None:
            self.fail("The transcript does not reconstruct Valkey as installed.")
        row = next(row for row in collected.cache.value if row.identifier == SITE)
        self.assertEqual(row.state, "on", row.problem)
        self.assertEqual(row.memory_mib, 64)
        self.assertEqual(row.plugin_version, "3.0.0")
        self.assertEqual(row.client, "phpredis")

    def test_a_repeated_review_proposes_nothing(self) -> None:
        from . import instance

        inputs = PreparationInputs(identifier=SITE, object_cache=True, cache_mib=64)
        shell = ReplayShell(load(OBJECT_CACHE_STATE))
        draft = instance.review(instance.inspect(shell, inputs), inputs)
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertTrue(draft.no_changes)

    def test_a_changed_user_is_reported_once_and_blocks_turning_it_on(self) -> None:
        from . import instance

        shell = ReplayShell(load(OBJECT_CACHE_EDITED_STATE))
        collected = collect(shell)
        row = next(row for row in collected.cache.value if row.identifier == SITE)
        self.assertEqual(row.state, "unsupported")
        self.assertIn("outside the supported convention", row.problem)
        on = PreparationInputs(identifier=SITE, object_cache=True, cache_mib=64)
        draft = instance.review(instance.inspect(shell, on), on)
        self.assertFalse(draft.eligible)
        off = PreparationInputs(identifier=SITE, object_cache=False)
        self.assertTrue(instance.review(instance.inspect(shell, off), off).eligible)


LARAVEL_OBJECT_CACHE_STATE = "object-cache-laravel-26.04"
LARAVEL_SITE = "sqwalpha"


class RecordedLaravelObjectCacheTests(SimpleTestCase):
    def test_a_fresh_controller_reconstructs_the_laravel_site_cache(self) -> None:
        shell = ReplayShell(load(LARAVEL_OBJECT_CACHE_STATE))
        collected = collect(shell)
        row = next(row for row in collected.cache.value if row.identifier == LARAVEL_SITE)
        self.assertEqual(row.state, "on", row.problem)
        self.assertEqual(row.memory_mib, 64)
        self.assertEqual(row.client, "phpredis")
        self.assertEqual(row.plugin_version, "")

    def test_a_repeated_laravel_review_proposes_nothing(self) -> None:
        from . import instance

        inputs = PreparationInputs(identifier=LARAVEL_SITE, object_cache=True, cache_mib=64)
        shell = ReplayShell(load(LARAVEL_OBJECT_CACHE_STATE))
        draft = instance.review(instance.inspect(shell, inputs), inputs)
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertTrue(draft.no_changes)
