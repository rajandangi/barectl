"""Consent is derived from declared effects, never chosen by a kind
(docs/adr/0035-one-change-engine-with-effect-derived-consent.md)."""

from django.contrib.auth.models import Group, Permission
from django.test import TestCase

from .consent import (
    CONSENT_PERMISSIONS,
    PREPARE_PERMISSIONS,
    DeclaredEffect,
    Scope,
    affected_sites_of,
    consent_of,
)
from .models import (
    CHANGE_DESTRUCTIVE,
    CHANGE_SHARED,
    CHANGE_SITE,
    MANAGE_SECRETS,
    VIEW_CHANGES,
    Consent,
)


def effect(scope: Scope, *sites: str) -> DeclaredEffect:
    return DeclaredEffect(scope, f"An effect on {scope.value}.", sites)


class ConsentDerivationTests(TestCase):
    def test_no_effects_is_a_read(self) -> None:
        self.assertEqual(consent_of(()), Consent.READ)

    def test_one_site_effect_is_site_consent(self) -> None:
        self.assertEqual(consent_of((effect(Scope.SITE, "alpha"),)), Consent.SITE)

    def test_one_shared_effect_is_shared_consent(self) -> None:
        consent = consent_of((effect(Scope.SHARED),))
        self.assertEqual(consent, Consent.SHARED)
        self.assertEqual(affected_sites_of((effect(Scope.SHARED),)), ())

    def test_multiple_sites_are_shared_with_the_sites_listed(self) -> None:
        effects = (effect(Scope.SITE, "beta"), effect(Scope.SITE, "alpha"))
        self.assertEqual(consent_of(effects), Consent.SHARED)
        self.assertEqual(affected_sites_of(effects), ("alpha", "beta"))

    def test_a_shared_effect_lists_its_sites(self) -> None:
        effects = (effect(Scope.SHARED, "beta", "alpha"),)
        self.assertEqual(consent_of(effects), Consent.SHARED)
        self.assertEqual(affected_sites_of(effects), ("alpha", "beta"))

    def test_a_server_wide_effect_is_shared(self) -> None:
        self.assertEqual(consent_of((effect(Scope.SERVER),)), Consent.SHARED)

    def test_a_server_wide_effect_leads_over_sites_and_shared(self) -> None:
        effects = (effect(Scope.SITE, "alpha"), effect(Scope.SHARED, "beta"), effect(Scope.SERVER))
        self.assertEqual(consent_of(effects), Consent.SHARED)

    def test_data_loss_requires_destructive_consent(self) -> None:
        effects = (
            effect(Scope.SERVER),
            DeclaredEffect(Scope.SITE, "Remove this site's data.", ("alpha",), destroys_data=True),
        )
        self.assertEqual(consent_of(effects), Consent.DESTRUCTIVE)

    def test_a_shared_effect_outranks_a_site_effect(self) -> None:
        effects = (effect(Scope.SITE, "alpha"), effect(Scope.SHARED))
        self.assertEqual(consent_of(effects), Consent.SHARED)

    def test_every_consent_level_maps_to_its_scope_permission(self) -> None:
        self.assertEqual(CONSENT_PERMISSIONS[Consent.READ], (VIEW_CHANGES,))
        self.assertEqual(CONSENT_PERMISSIONS[Consent.SITE], (VIEW_CHANGES, CHANGE_SITE))
        self.assertEqual(CONSENT_PERMISSIONS[Consent.SHARED], (VIEW_CHANGES, CHANGE_SHARED))
        self.assertEqual(
            CONSENT_PERMISSIONS[Consent.DESTRUCTIVE], (VIEW_CHANGES, CHANGE_DESTRUCTIVE)
        )
        self.assertEqual(
            PREPARE_PERMISSIONS,
            ("servers.view_server", VIEW_CHANGES, CHANGE_SITE),
        )


class ScopeGroupPresetsTests(TestCase):
    """The three presets the data migration creates from the five scope permissions."""

    @staticmethod
    def codenames(*names: str) -> set[str]:
        return set(Permission.objects.filter(codename__in=names).values_list("codename", flat=True))

    def test_the_three_presets_exist_with_their_permissions(self) -> None:
        expected = {
            "Viewer": self.codenames("view_changes") | {"view_server"},
            "Site operator": self.codenames("view_changes", "change_site") | {"view_server"},
            "Administrator": self.codenames(
                "view_changes",
                "change_site",
                "change_shared",
                "change_destructive",
                "manage_secrets",
            )
            | {"view_server"},
        }
        for name, permissions in expected.items():
            with self.subTest(group=name):
                group = Group.objects.get(name=name)
                self.assertEqual(
                    set(group.permissions.values_list("codename", flat=True)), permissions
                )

    def test_the_scopes_are_the_whole_permission_surface(self) -> None:
        engine_permissions = set(
            Permission.objects.filter(content_type__app_label="operations").values_list(
                "codename", flat=True
            )
        )
        self.assertEqual(
            engine_permissions,
            {
                "view_changes",
                "change_site",
                "change_shared",
                "change_destructive",
                MANAGE_SECRETS.rsplit(".", 1)[1],
            },
        )
