"""The Valkey and object-cache vocabulary reads on the run screens (#495, #501).

Every assertion observes the sentence an operator sees for a reason the server printed,
not the shape of the declaration.
"""

from django.test import SimpleTestCase

from operations import engine, reasons
from operations.models import Result
from operations.reason_testing import assert_declared_sentences

from .engine import INSTALL
from .instance import SET_SITE_OBJECT_CACHE

KINDS = (INSTALL, SET_SITE_OBJECT_CACHE)


def _sentence(outcome: Result, reason: str) -> str:
    return engine.reason_text(outcome.value, reason)


class ValkeyReasonTests(SimpleTestCase):
    def test_the_server_mask_and_reload_steps_read_distinctly(self) -> None:
        server = _sentence(Result.PARTIAL, "valkey_server")
        mask = _sentence(Result.PARTIAL, "valkey_mask")
        reload = _sentence(Result.PARTIAL, "valkey_reload")

        self.assertEqual(len({server, mask, reload}), 3)
        self.assertIn("valkey", server.lower())
        self.assertIn("stop and mask the distribution's shared service", mask)
        self.assertIn("restart every running PHP master and site proxy", reload)

    def test_an_install_refusal_still_reads_as_the_reviewed_package_set(self) -> None:
        sentence = _sentence(Result.REFUSED, "valkey_server")

        self.assertIn("package set differs from the reviewed one", sentence)
        self.assertIn("before changing packages", sentence)


class ObjectCacheReasonTests(SimpleTestCase):
    def test_each_stopped_step_names_the_step_it_reached(self) -> None:
        for reason, step in (
            ("object_cache_instance", "instance"),
            ("object_cache_wiring", "wiring"),
            ("object_cache_plugin", "plugin"),
            ("object_cache_verify", "verify"),
            ("laravel_environment", "environment"),
        ):
            with self.subTest(reason=reason):
                sentence = _sentence(Result.PARTIAL, reason)
                self.assertIn(step, sentence.lower())
                self.assertNotIn("without reporting how far it got", sentence)

    def test_a_partial_object_cache_change_never_claims_nothing_changed(self) -> None:
        for reason in (
            "object_cache",
            "object_cache_instance",
            "object_cache_wiring",
            "object_cache_plugin",
            "object_cache_verify",
            "laravel_environment",
            "laravel_config",
            "laravel_worker",
        ):
            with self.subTest(reason=reason):
                self.assertNotIn("nothing changed", _sentence(Result.PARTIAL, reason).lower())


class CacheVocabularyTests(SimpleTestCase):
    def test_every_declared_cache_pair_has_its_own_sentence(self) -> None:
        assert_declared_sentences(self, tuple(kind.reasons for kind in KINDS))

    def test_every_cache_body_declares_what_it_prints(self) -> None:
        self.assertEqual(reasons.manifest_errors(), [])
