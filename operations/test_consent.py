from django.contrib.auth.models import Group
from django.test import SimpleTestCase, TestCase

from .consent import APPLY_PERMISSIONS, Consent, Effect, consent


class ConsentTests(SimpleTestCase):
    def test_the_level_follows_the_declared_effects(self) -> None:
        cases = {
            "nothing": ((), Consent.READ),
            "site-only": (
                (Effect("Create the site user.", site="a"), Effect("Add its pool.", site="a")),
                Consent.SITE,
            ),
            "server-wide": (
                (Effect("Add a pool.", site="a"), Effect("Reload the runtime's master.")),
                Consent.SHARED,
            ),
            "multi-site": (
                (Effect("Switch site a.", site="a"), Effect("Switch site b.", site="b")),
                Consent.SHARED,
            ),
            "data loss": (
                (Effect("Delete the site files.", site="a", data_loss=True),),
                Consent.DESTRUCTIVE,
            ),
        }
        for name, (effects, level) in cases.items():
            with self.subTest(name):
                self.assertEqual(consent(effects), level)

    def test_each_appliable_level_needs_its_own_permission(self) -> None:
        self.assertNotIn(Consent.READ, APPLY_PERMISSIONS)
        self.assertEqual(len(set(APPLY_PERMISSIONS.values())), 3)


class PresetTests(TestCase):
    def granted(self, name: str) -> set[str]:
        group = Group.objects.get(name=name)
        return {
            f"{permission.content_type.app_label}.{permission.codename}"
            for permission in group.permissions.select_related("content_type")
        }

    def test_presets_grant_access_by_scope(self) -> None:
        viewer = self.granted("Viewer")
        operator = self.granted("Site operator")
        administrator = self.granted("Administrator")
        self.assertIn("servers.view_server", viewer)
        self.assertFalse(viewer & {"operations.prepare_change", *APPLY_PERMISSIONS.values()})
        self.assertLess(viewer, operator)
        self.assertLess(operator, administrator)
        self.assertIn(APPLY_PERMISSIONS[Consent.SITE], operator)
        self.assertNotIn(APPLY_PERMISSIONS[Consent.SHARED], operator)
        self.assertNotIn(APPLY_PERMISSIONS[Consent.DESTRUCTIVE], operator)
        self.assertLessEqual(set(APPLY_PERMISSIONS.values()), administrator)
