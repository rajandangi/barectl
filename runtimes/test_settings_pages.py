import re
from typing import override
from unittest import mock

from django.test import Client
from django.utils.html import strip_tags

from dashboard.browser_testing import NATIVE_TERMS
from operations.models import ChangePreparation
from servers.models import Server
from servers.testing import ControllerConfigTestCase
from sites.ui_testing import record_http_sites


class ServerSettingsPageTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant("view_server", "view_changes", "change_site")
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="Settings", ssh_alias="settings.example.com")
        record_http_sites(self.server)

    def test_php_versions_list_the_sites_using_each_and_offer_missing_versions(self) -> None:
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            page = self.client.get(f"/servers/{self.server.pk}/settings/")
            self.assertContains(page, "PHP versions")
            self.assertContains(page, "PHP 8.4")
            self.assertContains(page, "Used by 2 sites (alpha, beta)")
            self.assertContains(page, "Add PHP 8.5")
            self.assertNotContains(page, "Add PHP 8.4")
            response = self.client.post(
                f"/servers/{self.server.pk}/changes/prepare/",
                {"kind": "add_runtime", "selection": "php85"},
            )
        preparation = ChangePreparation.objects.get()
        self.assertEqual(preparation.kind_slug, "add_runtime")
        self.assertEqual(preparation.inputs, {"version": 1, "selection": "php85"})
        self.assertRedirects(response, f"/changes/{preparation.pk}/")

    def test_a_forged_version_outside_the_catalog_is_refused(self) -> None:
        response = self.client.post(
            f"/servers/{self.server.pk}/changes/prepare/",
            {"kind": "add_runtime", "selection": "php99"},
        )
        self.assertEqual(response.status_code, 302)
        self.assertFalse(ChangePreparation.objects.exists())

    def test_adding_a_version_needs_the_prepare_permission_and_csrf(self) -> None:
        change_site = self.user.user_permissions.get(codename="change_site")
        self.user.user_permissions.remove(change_site)
        response = self.client.post(
            f"/servers/{self.server.pk}/changes/prepare/",
            {"kind": "add_runtime", "selection": "php85"},
        )
        self.assertEqual(response.status_code, 403)
        self.user.user_permissions.add(change_site)
        protected = Client(enforce_csrf_checks=True)
        protected.force_login(self.user)
        response = protected.post(
            f"/servers/{self.server.pk}/changes/prepare/",
            {"kind": "add_runtime", "selection": "php85"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ChangePreparation.objects.exists())

    def test_settings_names_no_native_implementation_detail(self) -> None:
        page = self.client.get(f"/servers/{self.server.pk}/settings/")
        visible = strip_tags(page.content.decode()).lower()
        found = [
            term
            for term in NATIVE_TERMS
            if re.search(rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])", visible)
        ]
        self.assertEqual(found, [])

    def test_settings_keeps_native_runtime_detail_in_advanced(self) -> None:
        page = self.client.get(f"/servers/{self.server.pk}/settings/")
        for detail in ("Master state", "Site pools", "Store path", "Runtime catalog"):
            self.assertNotContains(page, detail)
        advanced = self.client.get(f"/servers/{self.server.pk}/advanced/?tab=php")
        self.assertContains(advanced, "Master state")
        self.assertContains(advanced, "Site pools")
