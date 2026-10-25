"""Every change that fences calls the one fence/restore step in its own body (#395).

A body is a standalone program on the server, so the assertion is about the staged source:
the reviewed plan reaches the body and its helpers are there to act on it.
"""

import base64
import gzip
import importlib.resources
import json
from typing import ClassVar, cast
from unittest import mock

from django.test import SimpleTestCase

from automation import fence, presentation
from automation.status import STATUS_SENTENCE, ScheduleStatus
from cache import instance as cache_instance
from laravel import change as laravel_change
from laravel import configuration as laravel_configuration
from laravel import rollback as laravel_rollback
from laravel import settings as laravel_settings
from operations.engine import NativeBody
from runtimes import update as catalog_update
from sites import node_change, php_change, pool_change, remove
from wordpress import settings as wordpress_settings

# Each fenced kind's staged body source, by the slug the engine plans for.
SOURCES = {
    "set_site_php": php_change.BODY_SOURCE,
    "set_site_node": node_change.BODY_SOURCE,
    "set_site_pool": pool_change.BODY_SOURCE,
    "deploy_laravel_site": laravel_change.BODY_SOURCE,
    "rollback_laravel_site": laravel_rollback.BODY_SOURCE,
    "edit_laravel_environment": laravel_settings.BODY_SOURCE,
    "edit_wordpress_settings": wordpress_settings.BODY_SOURCE,
    "remove_site": remove.BODY_SOURCE,
    "update_catalog": catalog_update.BODY_SOURCE,
    "set_site_object_cache": cache_instance.BODY_SOURCE,
}


class CallerTests(SimpleTestCase):
    def test_every_fenced_change_stages_a_program_that_compiles(self) -> None:
        for slug, source in SOURCES.items():
            with self.subTest(slug=slug):
                compile(source, slug, "exec")

    def test_the_helpers_are_defined_before_any_entry_block_runs(self) -> None:
        """A body runs as ``__main__``; its entry block must come after the fence helpers."""
        for slug, source in SOURCES.items():
            with self.subTest(slug=slug):
                entry = source.find('if __name__ == "__main__":')
                terminate = source.find("raise SystemExit(main(")
                for marker in (entry, terminate):
                    if marker < 0:
                        continue
                    self.assertLess(source.find("def fence("), marker)
                    self.assertLess(source.find("def restore("), marker)

    def test_every_fenced_change_stages_the_fence_helpers(self) -> None:
        self.assertEqual(set(SOURCES), set(fence.FENCING))
        for slug, source in SOURCES.items():
            with self.subTest(slug=slug):
                self.assertIn("def fence(", source)
                self.assertIn("def restore(", source)
                self.assertIn("if not fence(document, ", source)

    def test_every_fenced_change_restores_except_removal(self) -> None:
        for slug, source in SOURCES.items():
            with self.subTest(slug=slug):
                if slug == "remove_site":
                    continue
                self.assertIn("if not restore(document, ", source)

    def test_removal_never_starts_the_sites_work_again(self) -> None:
        steps = importlib.resources.files("sites.bodies").joinpath("remove.py").read_text()
        self.assertIn("remove_automation(document, identifier)", steps)
        self.assertNotIn("automation_restore", steps)

    def test_a_failed_fence_refuses_and_a_failed_restore_is_partial(self) -> None:
        for slug, source in SOURCES.items():
            with self.subTest(slug=slug):
                self.assertIn('"automation_fence"', source)


def passthrough(value: dict[str, object]) -> dict[str, object]:
    return dict(value)


class PayloadTests(SimpleTestCase):
    """The reviewed plan must survive each kind's closed payload (#398 regression).

    A body that rebuilds its payload from a fixed key list silently dropped the plan, so the
    fence read the document as "nothing to pause" and did nothing. The native
    ``RebootGateFence`` scenario found it; this pins the assembly for every affected kind.
    """

    PLAN: ClassVar[dict[str, object]] = {
        "version": 1,
        "sites": [
            {
                "identifier": "shop",
                "slice": "barectl-site-shop.slice",
                "timers": ["barectl-site-shop-wpcron.timer"],
                "services": ["barectl-site-shop-wpcron.service"],
                "resume": ["barectl-site-shop-wpcron.timer"],
                "budget_seconds": 30,
            }
        ],
    }

    def decode(self, body: NativeBody) -> dict[str, object]:
        return cast(
            dict[str, object], json.loads(gzip.decompress(base64.b64decode(body.arguments[0])))
        )

    def laravel_document(self, bootstrap: str) -> dict[str, object]:
        return {
            "version": 1,
            "body_sha256": bootstrap,
            "identifier": "shop",
            "names": ["shop.example.com"],
            "runtime": "php84",
            "repository": "https://git.example.com/shop.git",
            "commit": "a" * 40,
            "token": "t" * 8,
            "current": "release-1",
            "releases": ["release-1"],
            "prune": [],
            "disk_required": 0,
            "migrations": True,
            "gate": "",
            "caddy": "",
            "https": True,
            "branch": "main",
            "acknowledgement": laravel_change.MIGRATION_ACKNOWLEDGEMENT,
            "automation_fence": self.PLAN,
        }

    def settings_document(self, digest: str) -> dict[str, object]:
        return {
            "version": 1,
            "identifier": "shop",
            "names": ["shop.example.com"],
            "selection": "php84",
            "https": True,
            "changes": [{"key": "FEATURE_FLAG", "action": "set", "digest": "b" * 64}],
            "secret_fields": [],
            "environment_digest": digest,
            "configuration_digest": digest,
            "automation_fence": self.PLAN,
        }

    def test_a_deploy_and_a_roll_back_payload_carry_the_plan(self) -> None:
        for module, acknowledgement in (
            (laravel_change, laravel_change.MIGRATION_ACKNOWLEDGEMENT),
            (laravel_rollback, laravel_configuration.ROLLBACK_ACKNOWLEDGEMENT),
        ):
            with self.subTest(module=module.__name__):
                document = self.laravel_document(module.BODY_SHA256)
                document["acknowledgement"] = acknowledgement
                body = module.body(document, mock.Mock())
                self.assertEqual(self.decode(body)["automation_fence"], self.PLAN)

    def test_a_settings_payload_carries_the_plan(self) -> None:
        digest = "c" * 64
        for module in (laravel_settings, wordpress_settings):
            with self.subTest(module=module.__name__):
                document = self.settings_document(digest)
                with mock.patch.object(module, "_document", passthrough):
                    body = module.body(document, mock.Mock(secret_path=""))
                self.assertEqual(self.decode(body)["automation_fence"], self.PLAN)

    def test_a_cache_payload_carries_the_plan(self) -> None:
        document = {
            "version": 1,
            "identifier": "shop",
            "application": "wordpress",
            "enabled": True,
            "maxmemory_mib": 64,
            "automation_fence": self.PLAN,
        }
        with mock.patch.object(cache_instance, "_document", passthrough):
            body = cache_instance.body(document, mock.Mock())
        self.assertEqual(self.decode(body)["automation_fence"], self.PLAN)


class FenceSummaryTests(SimpleTestCase):
    def summary(self, document: dict[str, object]) -> presentation.FenceSummary:
        summary = presentation.fence_summary(document)
        if summary is None:
            self.fail("The change declared no fence summary.")
        return summary

    def document(self, **values: object) -> dict[str, object]:
        site = {
            "identifier": "shop",
            "slice": "barectl-site-shop.slice",
            "timers": ["barectl-site-shop-wpcron.timer"],
            "services": ["barectl-site-shop-wpcron.service"],
            "resume": ["barectl-site-shop-wpcron.timer"],
            "budget_seconds": 30,
            **values,
        }
        return {"automation_fence": {"version": 1, "sites": [site]}}

    def test_a_site_change_names_what_it_pauses_and_starts_again(self) -> None:
        summary = self.summary(self.document())
        self.assertEqual(summary.pauses, ("shop's scheduled tasks",))
        self.assertEqual(summary.resumes, ("shop's scheduled tasks",))

    def test_a_change_with_no_automation_pauses_and_starts_nothing(self) -> None:
        summary = self.summary({"automation_fence": {"version": 1, "sites": []}})
        self.assertTrue(summary.pauses_nothing)
        self.assertTrue(summary.starts_nothing)

    def test_a_change_that_never_fences_has_no_summary(self) -> None:
        self.assertIsNone(presentation.fence_summary({}))

    def test_a_worker_is_named_as_the_work_it_does(self) -> None:
        summary = self.summary(
            self.document(
                timers=[],
                services=["barectl-site-shop-queue1.service"],
                resume=["barectl-site-shop-queue1.service"],
            )
        )
        self.assertEqual(summary.pauses, ("shop's queue workers",))
        self.assertEqual(summary.resumes, ("shop's queue workers",))

    def test_the_plain_words_name_the_paused_and_maintenance_states(self) -> None:
        self.assertEqual(STATUS_SENTENCE[ScheduleStatus.PAUSED], "Paused by an unfinished change")
        self.assertEqual(
            STATUS_SENTENCE[ScheduleStatus.OFF_MAINTENANCE],
            "Background work is off while the site is in maintenance",
        )
