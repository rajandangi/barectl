"""The one requirement registry covers every registered change kind (spec #507).

`requirements_for` falls back to a plain server change for an unknown slug. That default is
safe for a server-only kind, but it would silently admit a new site or backup kind as a
server change. This test makes a new kind declare its dashboard requirements.
"""

from django.test import SimpleTestCase

from operations import change_requirements, engine
from operations.preparation import Need


class ChangeRequirementRegistryTests(SimpleTestCase):
    def registered(self) -> set[str]:
        return set(engine._KINDS)

    def test_every_registered_kind_has_an_explicit_requirement_set(self) -> None:
        registered = self.registered()
        mapped = set(change_requirements.REQUIREMENTS)
        self.assertEqual(
            sorted(registered - mapped),
            [],
            "every registered change kind declares its card requirements in "
            "operations/change_requirements.py; an unregistered kind would fall back to a "
            "plain server change",
        )
        self.assertEqual(
            sorted(mapped - registered),
            sorted(change_requirements.PENDING_KINDS),
            "the requirement registry may name only registered kinds and the documented "
            "forward declarations in operations/change_requirements.PENDING_KINDS",
        )

    def test_a_site_requirement_names_the_site_permission(self) -> None:
        for slug, requirements in change_requirements.REQUIREMENTS.items():
            if not requirements.site:
                continue
            with self.subTest(slug=slug):
                self.assertIn(Need.SITE, requirements.needs)
                self.assertIn(Need.CHANGE, requirements.needs)

    def test_a_secret_writing_kind_requires_the_secret_need(self) -> None:
        for slug in change_requirements.REQUIREMENTS:
            kind = engine.kind_of(slug)
            if kind is None or not kind.writes_secrets:
                continue
            with self.subTest(slug=slug):
                self.assertIn(Need.SECRET, change_requirements.requirements_for(slug).needs)

    def test_the_journal_retention_entry_declares_the_shared_need_for_551(self) -> None:
        requirements = change_requirements.requirements_for("set_journal_retention")
        self.assertEqual(requirements, change_requirements.JOURNAL_RETENTION)
        self.assertIn(Need.SHARED, requirements.needs)
        self.assertIn(Need.CHANGE, requirements.needs)
        self.assertTrue(requirements.target_stack)

    def test_the_cache_off_card_keeps_its_own_completion_rule(self) -> None:
        on = change_requirements.requirements_for("set_site_object_cache", {"object_cache": True})
        off = change_requirements.requirements_for("set_site_object_cache", {"object_cache": False})
        self.assertEqual(on, change_requirements.SITE_CACHE_ON)
        self.assertEqual(off, change_requirements.SITE_CACHE_OFF)
        self.assertFalse(off.state)
        self.assertTrue(off.allow_partly_applied)
