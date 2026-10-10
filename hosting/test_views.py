"""The minimal creation form and explicit administrator recovery contract."""

import base64
from typing import ClassVar, override
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.contrib.auth.models import Permission, User
from django.test import TestCase

from bootstrap.models import Action, PhpRuntimeSnapshot, PlanPreparation
from bootstrap.runtime_models import RuntimeChange
from discovery.fakes import COLLECTED, COLLECTED_AT, record_attempt
from discovery.models import DiscoveryAttempt, DiscoverySnapshot
from discovery.snapshot import save_snapshot
from servers.models import Server

from .creation import CreationInput
from .models import HostingCreation


class CreationViewTests(TestCase):
    public_key: ClassVar[str]

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=4096).public_key()
        cls.public_key = base64.b64encode(
            key.public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        ).decode("ascii")

    @override
    def setUp(self) -> None:
        self.user = User.objects.create_superuser("operator", "owner@example.com", "local-password")
        self.server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        attempt = record_attempt(self.server, DiscoveryAttempt.Status.SUCCEEDED)
        save_snapshot(attempt, COLLECTED, COLLECTED_AT)
        self.revision = attempt.snapshot.pk
        DiscoverySnapshot.objects.filter(pk=self.revision).update(
            arch_value="aarch64", os_version_id="24.04"
        )
        self.observed = PhpRuntimeSnapshot.objects.create(
            snapshot_id=self.revision, supply="ubuntu", default_branch="8.3"
        )
        self.client.force_login(self.user)
        self.url = f"/servers/{self.server.pk}/sites/new/"
        self.values = {
            "application": "wordpress",
            "discovery_revision": self.revision,
            "domain": "shop.example.com",
            "title": "Shop",
            "admin_login": "owner",
            "admin_email": "owner@example.com",
            "first_access_spki": self.public_key,
            "accept_agreement": "on",
        }

    def test_minimal_wordpress_form_queues_one_complete_intent(self) -> None:
        created = HostingCreation.objects.create(
            server=self.server,
            requested_by=self.user,
            ssh_alias=self.server.ssh_alias,
            host_key="ssh-ed25519 SHA256:view-test",
            identifier="shop",
            names="shop.example.com",
            application="wordpress",
            discovery_revision=self.revision,
        )
        with patch("hosting.views.request_creation", return_value=created) as create:
            response = self.client.post(self.url, self.values)
        self.assertRedirects(response, f"/servers/{self.server.pk}/sites/creation/{created.pk}/")
        create.assert_called_once()
        wanted = create.call_args.args[2]
        self.assertIsInstance(wanted, CreationInput)
        self.assertEqual(wanted.application, "wordpress")
        self.assertEqual(wanted.php_version, "")
        self.assertEqual(wanted.database_engine, "mariadb")
        self.assertTrue(wanted.https)
        self.assertEqual(wanted.email, "owner@example.com")
        self.assertEqual(wanted.first_access_spki, self.public_key)

    def test_invalid_details_are_retained_and_do_not_queue_remote_work(self) -> None:
        with patch("hosting.views.request_creation") as create:
            response = self.client.post(self.url, {**self.values, "title": ""})
        create.assert_not_called()
        self.assertContains(response, "Check the site details")
        self.assertContains(response, 'value="shop.example.com"')
        self.assertContains(response, 'id="id_title_error"')
        self.assertContains(response, 'aria-describedby="id_title_error"')

    def test_inventory_permission_does_not_authorize_creation_or_credential_reset(self) -> None:
        observer = User.objects.create_user("observer")
        observer.user_permissions.add(
            Permission.objects.get(codename="view_server"),
            Permission.objects.get(codename="view_siteobservation"),
        )
        self.client.force_login(observer)
        with patch("hosting.views.request_creation") as create:
            self.assertEqual(self.client.post(self.url, self.values).status_code, 403)
        create.assert_not_called()
        with patch("hosting.access_views.request_access_reset") as reset:
            response = self.client.post(
                f"/servers/{self.server.pk}/sites/shop/wordpress/access/reset/",
                {"admin_login": "owner", "first_access_spki": self.public_key},
            )
        self.assertEqual(response.status_code, 403)
        reset.assert_not_called()

    def test_explicit_reset_form_queues_one_request_without_a_password_input(self) -> None:
        prepared = PlanPreparation(action=Action.WORDPRESS_ACCESS)
        with patch("hosting.access_views.request_access_reset", return_value=prepared) as reset:
            response = self.client.post(
                f"/servers/{self.server.pk}/sites/shop/wordpress/access/reset/",
                {"admin_login": "owner", "first_access_spki": self.public_key},
            )
        self.assertEqual(response.status_code, 302)
        reset.assert_called_once_with(self.server, self.user.pk, "shop", "owner", self.public_key)

    def test_wordpress_override_offers_only_qualified_native_supply_versions(self) -> None:
        DiscoverySnapshot.objects.filter(pk=self.revision).update(
            arch_value="aarch64", os_version_id="24.04"
        )
        observed = self.observed
        response = self.client.get(self.url, {"application": "wordpress"})
        self.assertContains(response, '<option value="8.3">PHP 8.3</option>')
        self.assertNotContains(response, '<option value="8.4">')
        self.assertNotContains(response, '<option value="8.5">')
        observed.supply = "sury"
        observed.save(update_fields=("supply",))
        with patch(
            "wordpress.qualification.SOURCE_COMBINATIONS", (("24.04", "arm64", "8.4", "sury"),)
        ):
            response = self.client.get(self.url, {"application": "wordpress"})
            with patch("hosting.views.request_creation") as create:
                self.client.post(self.url, {**self.values, "php_version": "8.5"})
                self.client.post(self.url, {**self.values, "php_version": ""})
            create.assert_not_called()
        self.assertContains(response, '<option value="8.4">PHP 8.4</option>')
        self.assertNotContains(response, '<option value="8.3">')
        self.assertNotContains(response, '<option value="8.5">')

    def test_fresh_form_names_the_publisher_without_a_source_choice(self) -> None:
        PhpRuntimeSnapshot.objects.filter(pk=self.observed.pk).update(supply="sury", fresh=True)
        response = self.client.get(self.url)
        self.assertContains(response, "approved Surý publisher")
        self.assertContains(response, "signing key and package source setup")
        self.assertNotContains(response, 'name="php_supply"')

    def test_runtime_completion_refreshes_the_card_after_discovery_finishes(self) -> None:
        RuntimeChange.objects.create(
            server=self.server,
            requested_by=self.user,
            action=Action.PHP_DEFAULT,
            branch="8.4",
            ssh_alias=self.server.ssh_alias,
            status="succeeded",
        )
        url = f"/servers/{self.server.pk}/runtimes/progress/"
        queued = record_attempt(self.server, DiscoveryAttempt.Status.QUEUED)
        response = self.client.get(url, headers={"HX-Request": "true"})
        self.assertNotIn("HX-Refresh", response.headers)
        self.assertContains(response, 'hx-trigger="every 2s"')
        queued.status = DiscoveryAttempt.Status.SUCCEEDED
        queued.save(update_fields=("status",))
        response = self.client.get(url, headers={"HX-Request": "true"})
        self.assertEqual(response.headers["HX-Refresh"], "true")

    def test_server_node_authority_does_not_authorize_a_site_pin(self) -> None:
        operator = User.objects.create_user("server-operator")
        for codename in (
            "view_server",
            "view_siteobservation",
            "view_configurationplan",
            "prepare_configurationplan",
            "apply_configurationplan",
        ):
            operator.user_permissions.add(Permission.objects.get(codename=codename))
        self.client.force_login(operator)
        with patch("node_runtimes.changes.request_runtime_change", return_value=object()) as change:
            response = self.client.post(
                f"/servers/{self.server.pk}/sites/shop/runtimes/node/", {"version": "22.23.3"}
            )
            self.assertEqual(response.status_code, 403)
            change.assert_not_called()
            response = self.client.post(
                f"/servers/{self.server.pk}/runtimes/node/", {"version": "22.23.3"}
            )
        self.assertEqual(response.status_code, 302)
        change.assert_called_once_with(self.server, operator.pk, "22.23.3", identifier="")

    def test_unqualified_wordpress_form_has_no_create_action(self) -> None:
        with patch("wordpress.qualification.COMBINATIONS", ()):
            response = self.client.get(self.url, {"application": "wordpress"})
            with patch("hosting.views.request_creation") as create:
                posted = self.client.post(self.url, self.values)
        self.assertContains(response, "not yet qualified")
        self.assertNotContains(response, "data-first-access-create")
        self.assertEqual(posted.status_code, 409)
        create.assert_not_called()
