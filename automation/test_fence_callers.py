"""Every change that fences calls the one fence/restore step in its own body (#395).

A body is a standalone program on the server, so the assertion is about the staged source:
the reviewed plan reaches the body and its helpers are there to act on it.
"""

import importlib.resources

from django.test import SimpleTestCase

from automation import fence, presentation
from automation.status import STATUS_SENTENCE, ScheduleStatus
from laravel import change as laravel_change
from laravel import rollback as laravel_rollback
from laravel import settings as laravel_settings
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
