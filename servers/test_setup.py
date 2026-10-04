"""The Setup section: hosting summary, PHP driver card and originating-site context
(docs/bootstrap.md#review-apply-and-check)."""

from dataclasses import replace
from typing import ClassVar, override

from django.contrib.auth.models import Permission, User
from django.test import SimpleTestCase

from bootstrap.models import Action, PlanPreparation
from bootstrap.setup import SetupState, summary
from discovery.fakes import COLLECTED, FakeServer, run_worker
from discovery.models import ObservationOutcome, WebStackComponent
from discovery.presentation import present
from discovery.services import request_discovery
from discovery.snapshot import Observation, WebStackComponentObservation

from .models import Server
from .testing import HTMX_FRAGMENT, ControllerConfigTestCase


def component(
    kind: WebStackComponent, package: ObservationOutcome, service: ObservationOutcome
) -> WebStackComponentObservation:
    return WebStackComponentObservation(
        kind, Observation(package, (), "", ()), Observation(service, (), "", ())
    )


class SummaryTests(SimpleTestCase):
    def test_no_snapshot_requires_a_refresh_for_every_component(self) -> None:
        for item in summary(None):
            with self.subTest(component=item.label):
                self.assertEqual(item.state, SetupState.REFRESH)

    def test_observed_absent_and_unread_components_are_distinguished(self) -> None:
        components = (
            component(
                WebStackComponent.NGINX, ObservationOutcome.OBSERVED, ObservationOutcome.OBSERVED
            ),
            component(
                WebStackComponent.PHP_FPM, ObservationOutcome.ABSENT, ObservationOutcome.ABSENT
            ),
            component(
                WebStackComponent.MARIADB,
                ObservationOutcome.INACCESSIBLE,
                ObservationOutcome.INACCESSIBLE,
            ),
            component(
                WebStackComponent.POSTGRESQL,
                ObservationOutcome.UNSUPPORTED,
                ObservationOutcome.UNSUPPORTED,
            ),
        )
        shown = {
            item.label: item for item in summary(present(replace(COLLECTED, components=components)))
        }
        self.assertEqual(shown["Nginx"].state, SetupState.READY)
        self.assertEqual(shown["PHP-FPM"].state, SetupState.MISSING)
        self.assertEqual(shown["MariaDB"].state, SetupState.UNINSPECTABLE)
        self.assertEqual(shown["PostgreSQL"].state, SetupState.UNINSPECTABLE)
        # A missing package names its reviewed profile; an unread one never recommends it.
        self.assertEqual(shown["PHP-FPM"].action, Action.PHP)
        self.assertIn("not known to be missing", shown["MariaDB"].note)


class SetupPageTests(ControllerConfigTestCase):
    server: ClassVar[Server]

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        super().setUpTestData()
        cls.server = Server.objects.create(name="Web", ssh_alias="web.example.com")

    def test_setup_summarizes_evidence_and_offers_drivers_to_permitted_accounts(self) -> None:
        self.grant(
            "view_server", "view_configurationplan", "view_databaseplan", "prepare_databaseplan"
        )
        self.client.force_login(self.user)
        response = self.client.get(f"/servers/{self.server.pk}/setup/")
        self.assertContains(response, "Observed hosting")
        # No successful check yet, so every component asks for a refresh rather than a install.
        self.assertContains(response, "Refresh required")
        self.assertContains(response, "PHP database drivers")
        self.assertContains(response, "Prepare PHP MariaDB driver plan")
        self.assertContains(response, "Prepare PHP PostgreSQL driver plan")

    def test_setup_reflects_a_completed_observation(self) -> None:
        self.grant("view_server", "view_configurationplan")
        self.client.force_login(self.user)
        remote = FakeServer()
        with remote.substituted():
            request_discovery(self.server)
            run_worker()
        response = self.client.get(f"/servers/{self.server.pk}/setup/")
        self.assertContains(response, "Observed installed")
        self.assertNotContains(response, "Refresh required")

    def test_setup_omits_the_driver_card_without_database_permission(self) -> None:
        self.grant("view_server", "view_configurationplan")
        self.client.force_login(self.user)
        response = self.client.get(f"/servers/{self.server.pk}/setup/")
        self.assertNotContains(response, "PHP database drivers")
        self.assertNotContains(response, "Prepare PHP MariaDB driver plan")

    def test_return_context_is_validated_and_permission_scoped(self) -> None:
        self.grant("view_server", "view_configurationplan", "view_siteobservation")
        self.client.force_login(self.user)
        valid = self.client.get(f"/servers/{self.server.pk}/setup/?from=shop2")
        self.assertContains(valid, "Return to site shop2")
        # A caller-supplied value that is not a site identifier never becomes a link.
        for bad in ("../etc/passwd", "Bad", "shop2/../x"):
            with self.subTest(from_=bad):
                refused = self.client.get(f"/servers/{self.server.pk}/setup/?from={bad}")
                self.assertNotContains(refused, "Return to site")
        restricted = User.objects.create_user("restricted")
        restricted.user_permissions.add(Permission.objects.get(codename="view_server"))
        restricted.user_permissions.add(Permission.objects.get(codename="view_configurationplan"))
        self.client.force_login(restricted)
        self.assertNotContains(
            self.client.get(f"/servers/{self.server.pk}/setup/?from=shop2"), "Return to site"
        )


class DriverSetupTests(ControllerConfigTestCase):
    server: ClassVar[Server]

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        super().setUpTestData()
        cls.server = Server.objects.create(name="Web", ssh_alias="web.example.com")

    def grant_driver(self) -> None:
        self.grant(
            "view_server", "view_databaseplan", "prepare_databaseplan", "view_configurationplan"
        )

    def test_a_setup_driver_prepare_polls_its_own_section_and_returns_to_setup(self) -> None:
        self.grant_driver()
        self.client.force_login(self.user)
        url = f"/servers/{self.server.pk}/databases/prepare/"
        fragment = self.client.post(
            url, {"action": Action.PHP_MYSQL.value, "family": "drivers"}, headers=HTMX_FRAGMENT
        )
        self.assertEqual(fragment.status_code, 200)
        self.assertContains(fragment, 'id="driver-plans"')
        self.assertContains(fragment, "PHP database drivers")
        PlanPreparation.objects.all().delete()
        response = self.client.post(url, {"action": Action.PHP_PGSQL.value, "family": "drivers"})
        self.assertRedirects(response, f"/servers/{self.server.pk}/setup/#driver-plans")

    def test_setup_driver_prepare_requires_its_own_permission(self) -> None:
        self.grant("view_server", "view_databaseplan")
        self.client.force_login(self.user)
        response = self.client.post(
            f"/servers/{self.server.pk}/databases/prepare/",
            {"action": Action.PHP_MYSQL.value, "family": "drivers"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(PlanPreparation.objects.exists())

    def test_bootstrap_prepare_preserves_a_validated_return_context(self) -> None:
        self.grant("view_server", "view_configurationplan", "prepare_configurationplan")
        self.client.force_login(self.user)
        url = f"/servers/{self.server.pk}/plans/prepare/"
        response = self.client.post(url, {"action": Action.NGINX.value, "from": "shop2"})
        self.assertRedirects(response, f"/servers/{self.server.pk}/setup/?from=shop2#plans")
        PlanPreparation.objects.all().delete()
        refused = self.client.post(url, {"action": Action.METADATA_REFRESH.value, "from": "../x"})
        self.assertRedirects(refused, f"/servers/{self.server.pk}/setup/#plans")
