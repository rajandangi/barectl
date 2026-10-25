"""The site's Object cache card and Overview line (#392), without SSH on any GET."""

import re
from typing import override
from unittest import mock

from django.test import Client
from django.utils import timezone

from discovery.snapshot import ObservedCache, ObservedSetting
from operations.models import ChangePreparation
from servers.models import Server
from servers.testing import ControllerConfigTestCase
from sites.ui_testing import record_site_settings

from .instance import SLUG
from .models import CacheReading

BANNED = (
    "master",
    "pool",
    "fpm",
    "haproxy",
    "admission",
    "caddy",
    "nix",
    "store path",
    "catalog",
    "socket",
    "opcache",
    "systemd",
    "unit",
    "invocation",
    "journal",
    "stage",
    "standing",
    "foundation",
    "evidence",
    "consent level",
    "review",
    "plan",
    "digest",
    "known_hosts",
)


class ObjectCacheCardTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant(
            "view_server",
            "view_siteobservation",
            "view_changes",
            "change_site",
        )
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="Cache", ssh_alias="cache.example.com")
        self.settings_url = f"/servers/{self.server.pk}/sites/alpha/settings/"
        self.overview_url = f"/servers/{self.server.pk}/sites/alpha/"
        self.prepare_url = f"/servers/{self.server.pk}/sites/alpha/settings/object-cache/prepare/"
        self.read_url = f"/servers/{self.server.pk}/sites/alpha/settings/object-cache/read/"

    def record(
        self,
        *,
        state: str = "off",
        memory: int | None = None,
        client: str = "phpredis",
        installed: bool = True,
        reading: dict[str, object] | None = None,
    ) -> None:
        cache = (
            (ObservedCache("alpha", state, memory, "", "3.0.0", client, "active"),)
            if state != "off"
            else (ObservedCache("alpha", "off", None, "", "", client, ""),)
        )
        record_site_settings(
            self.server,
            identifier="alpha",
            application="wordpress",
            cache=cache,
            installed_valkey=installed,
            client=client,
        )
        if reading is not None:
            CacheReading.objects.create(
                server=self.server,
                ssh_alias=self.server.ssh_alias,
                identifier="alpha",
                reading=reading,
                reading_at=timezone.now(),
                status="succeeded",
            )

    def record_laravel(self, *, state: str = "off", memory: int | None = None) -> None:
        record_site_settings(
            self.server,
            identifier="alpha",
            application="plain",
            settings=(
                ObservedSetting("alpha", "laravel", "APP_NAME", "a" * 64, "Laravel"),
                ObservedSetting("alpha", "laravel", "APP_ENV", "b" * 64, "production"),
            ),
            cache=(ObservedCache("alpha", state, memory, "", "", "phpredis", "active"),),
            installed_valkey=True,
            client="phpredis",
        )

    def test_a_laravel_site_offers_the_cache_without_the_plugin_sentence(self) -> None:
        self.record_laravel()
        response = self.client.get(self.settings_url)
        self.assertContains(response, "Turn on object cache")
        self.assertNotContains(response, "WordPress uses the pinned")
        self.assertNotContains(response, "Redis Object Cache")

    def test_a_laravel_site_can_turn_a_partial_cache_off(self) -> None:
        self.record_laravel(state="partial", memory=64)
        response = self.client.get(self.settings_url)
        self.assertContains(response, "Turn off object cache")
        posted = self.client.post(self.prepare_url, {"action": "off"})
        self.assertEqual(posted.status_code, 302)
        preparation = ChangePreparation.objects.get()
        self.assertEqual(preparation.inputs["object_cache"], False)
        self.assertNotIn("cache_store_known", preparation.inputs)

    def test_an_off_site_offers_the_memory_limit_and_the_turn_on_action(self) -> None:
        self.record()
        response = self.client.get(self.settings_url)
        text = response.content.decode()
        self.assertContains(response, "Turn on object cache")
        self.assertContains(response, 'name="action" value="on"')
        for size in ("32 MiB", "64 MiB", "128 MiB", "256 MiB"):
            self.assertIn(size, text)

    def test_install_first_is_offered_when_valkey_is_missing(self) -> None:
        self.record(installed=False)
        response = self.client.get(self.settings_url)
        self.assertContains(response, "Install Valkey in Server Settings first")
        self.assertContains(response, "Install Valkey")

    def test_turning_on_queues_one_site_review_with_the_chosen_limit(self) -> None:
        self.record()
        response = self.client.post(self.prepare_url, {"action": "on", "memory": "128"})
        self.assertEqual(response.status_code, 302)
        preparation = ChangePreparation.objects.get()
        self.assertEqual(preparation.kind_slug, SLUG)
        self.assertEqual(
            preparation.inputs,
            {
                "version": 1,
                "identifier": "alpha",
                "object_cache": True,
                "maxmemory_mib": 128,
            },
        )

    def test_turning_off_queues_the_off_review(self) -> None:
        self.record(state="on", memory=64)
        response = self.client.post(self.prepare_url, {"action": "off"})
        self.assertEqual(response.status_code, 302)
        preparation = ChangePreparation.objects.get()
        self.assertEqual(preparation.kind_slug, SLUG)
        self.assertEqual(preparation.inputs["object_cache"], False)
        self.assertEqual(preparation.inputs["maxmemory_mib"], 0)

    def test_a_site_without_the_client_is_offered_the_client_action(self) -> None:
        self.record(client="")
        response = self.client.get(self.settings_url)
        self.assertContains(response, "Load the cache client")
        response = self.client.post(self.prepare_url, {"action": "client"})
        self.assertEqual(response.status_code, 302)
        preparation = ChangePreparation.objects.get()
        self.assertEqual(preparation.kind_slug, "set_site_php_client")
        self.assertEqual(preparation.inputs["php_client"], True)

    def test_a_viewer_is_refused_on_a_direct_prepare_post(self) -> None:
        self.record()
        self.user.user_permissions.remove(self.user.user_permissions.get(codename="change_site"))
        response = self.client.post(self.prepare_url, {"action": "on", "memory": "64"})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(ChangePreparation.objects.count(), 0)

    def test_csrf_is_required(self) -> None:
        self.record()
        csrf = Client(enforce_csrf_checks=True)
        csrf.force_login(self.user)
        self.assertEqual(
            csrf.post(self.prepare_url, {"action": "on", "memory": "64"}).status_code, 403
        )
        self.assertEqual(ChangePreparation.objects.count(), 0)

    def test_the_settings_screen_never_opens_a_connection(self) -> None:
        self.record(state="on", memory=64)
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            response = self.client.get(self.settings_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Turn off object cache")

    def test_an_on_site_shows_the_state_and_offers_a_reading(self) -> None:
        self.record(
            state="on",
            memory=64,
            reading={
                "state": "running",
                "used_memory": 1048576,
                "maxmemory": 67108864,
                "evicted_keys": 0,
                "connected_clients": 1,
            },
        )
        response = self.client.get(self.settings_url)
        self.assertContains(response, "Check the cache")
        self.assertNotContains(response, "Not readable")

    def test_a_reading_is_queued_only_on_the_post(self) -> None:
        self.record(state="on", memory=64)
        self.client.get(self.settings_url)
        self.assertEqual(CacheReading.objects.count(), 0)
        response = self.client.post(self.read_url)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(CacheReading.objects.get().identifier, "alpha")

    def test_the_overview_shows_one_plain_cache_line(self) -> None:
        self.record(state="on", memory=64)
        response = self.client.get(self.overview_url)
        self.assertContains(response, 'id="site-cache-line"')
        self.assertContains(response, "On.")
        self.assertContains(response, "Check the cache")

    def test_the_settings_default_text_avoids_native_terms(self) -> None:
        self.record(state="on", memory=64)
        response = self.client.get(self.settings_url)
        text = re.sub(r"<[^>]+>", " ", response.content.decode()).lower()
        for word in BANNED:
            with self.subTest(word=word):
                self.assertNotRegex(text, rf"\b{re.escape(word)}\b")

    def test_the_overview_default_text_avoids_native_terms(self) -> None:
        self.record(state="on", memory=64)
        response = self.client.get(self.overview_url)
        text = re.sub(r"<[^>]+>", " ", response.content.decode()).lower()
        for word in BANNED:
            with self.subTest(word=word):
                self.assertNotRegex(text, rf"\b{re.escape(word)}\b")
