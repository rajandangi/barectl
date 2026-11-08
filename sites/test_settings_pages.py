"""The Environment and WordPress settings pages and their permission gate (Phase B #383)."""

import hashlib
from dataclasses import replace
from typing import override
from unittest import mock

from django.contrib.auth.models import AnonymousUser
from django.test import SimpleTestCase
from django.utils import timezone

from discovery.fakes import COLLECTED, COLLECTED_AT, record_attempt
from discovery.models import DiscoveryAttempt, ObservationOutcome, SiteState
from discovery.snapshot import (
    ObservedCache,
    ObservedRelease,
    ObservedSetting,
    Snapshot,
    current_snapshot,
    save_snapshot,
)
from operations import preparation
from operations.preparation import ReasonName
from operations.services import ServerChanges, read_changes
from servers.discovery_state import DiscoveryState, server_state
from servers.models import Server
from servers.testing import ControllerConfigTestCase, assert_query_count_flat_as_history_grows
from sites.bodies.common import SITE_GATED
from sites.deploy_views import deploy_context
from sites.preparation import decide_for_site
from sites.ui_testing import record_older_snapshots, record_site_settings

DIGEST = "a" * 64


class SettingsPageTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant("view_server", "view_siteobservation", "view_changes", "change_site")
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="Web", ssh_alias="web.example.com")

    def laravel(self) -> None:
        record_site_settings(
            self.server,
            application="laravel",
            settings=(
                ObservedSetting("alpha", "laravel", "APP_URL", DIGEST, "https://alpha.example.com"),
                ObservedSetting("alpha", "laravel", "MAIL_PASSWORD", "b" * 64),
            ),
        )

    def wordpress(self) -> None:
        record_site_settings(
            self.server,
            application="wordpress",
            settings=(ObservedSetting("alpha", "wordpress", "MAIL_HOST", "c" * 64),),
        )

    def test_the_environment_page_shows_non_secret_values_and_hides_secrets(self) -> None:
        self.laravel()
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            response = self.client.get(f"/servers/{self.server.pk}/sites/alpha/environment/")
        self.assertContains(response, "Environment")
        self.assertContains(response, "APP_URL")
        self.assertContains(response, "https://alpha.example.com")
        self.assertContains(response, "MAIL_PASSWORD")
        self.assertContains(response, "Hidden, write-only")
        self.assertContains(response, "manage-secrets permission")

    def test_the_object_cache_keys_are_managed_and_never_show_their_values(self) -> None:
        from cache.laravel import laravel_values

        values = laravel_values("alpha")
        self.grant("manage_secrets")
        record_site_settings(
            self.server,
            application="laravel",
            settings=(
                *(
                    ObservedSetting(
                        "alpha",
                        "laravel",
                        key,
                        hashlib.sha256(value.encode()).hexdigest(),
                    )
                    for key, value in values.items()
                ),
                ObservedSetting(
                    "alpha",
                    "laravel",
                    "APP_URL",
                    DIGEST,
                    "https://alpha.example.com",
                ),
            ),
            cache=(ObservedCache("alpha", "on", 64, "", "", "phpredis", "active"),),
            installed_valkey=True,
            client="phpredis",
        )
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            response = self.client.get(f"/servers/{self.server.pk}/sites/alpha/environment/")
        self.assertContains(response, "Managed by the object cache", count=3)
        self.assertNotContains(response, ">redis<")
        self.assertNotContains(response, "/run/valkey/alpha/valkey.sock")
        self.assertContains(response, "APP_URL")
        self.assertContains(response, "https://alpha.example.com")

    def test_the_wordpress_page_lists_extra_constants_without_values(self) -> None:
        self.wordpress()
        response = self.client.get(f"/servers/{self.server.pk}/sites/alpha/wordpress/")
        self.assertContains(response, "WordPress settings")
        self.assertContains(response, "MAIL_HOST")
        self.assertContains(response, "write-only")

    def test_the_wordpress_settings_card_is_offered_with_manage_secrets(self) -> None:
        self.grant("manage_secrets")
        self.wordpress()
        response = self.client.get(f"/servers/{self.server.pk}/sites/alpha/wordpress/")
        self.assertContains(response, "Review adding the constant")
        self.assertContains(
            response,
            f"/servers/{self.server.pk}/sites/alpha/wordpress/settings/prepare/",
        )

    def test_the_wordpress_settings_withheld_card_shows_the_gate_sentence(self) -> None:
        self.wordpress()
        response = self.client.get(f"/servers/{self.server.pk}/sites/alpha/wordpress/")
        self.assertContains(response, "Changing this needs the manage-secrets permission.")
        self.assertNotContains(
            response,
            f"/servers/{self.server.pk}/sites/alpha/wordpress/settings/prepare/",
        )

    def test_a_withheld_wordpress_settings_form_uses_the_gate_sentence(self) -> None:
        from discovery.models import SiteState
        from discovery.snapshot import ObservedSetting
        from operations.services import read_changes

        self.grant("manage_secrets")
        record_site_settings(
            self.server,
            application="wordpress",
            state=SiteState.PARTLY_APPLIED,
            settings=(ObservedSetting("alpha", "wordpress", "MAIL_HOST", "c" * 64),),
        )
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/alpha/wordpress/settings/prepare/",
            {"key": "MAIL_HOST", "action": "set"},
            follow=True,
        )
        self.assertEqual(read_changes(self.server).rows, [])
        self.assertContains(
            response,
            "This site is partly applied; finish the change that is already in progress first.",
        )

    def test_the_environment_card_is_offered_with_manage_secrets(self) -> None:
        self.grant("manage_secrets")
        self.laravel()
        response = self.client.get(f"/servers/{self.server.pk}/sites/alpha/environment/")
        self.assertContains(response, "Review adding the key")
        self.assertContains(
            response,
            f"/servers/{self.server.pk}/sites/alpha/environment/prepare/",
        )

    def test_the_environment_withheld_card_shows_the_gate_sentence(self) -> None:
        self.laravel()
        response = self.client.get(f"/servers/{self.server.pk}/sites/alpha/environment/")
        self.assertContains(response, "Changing this needs the manage-secrets permission.")
        self.assertNotContains(
            response,
            f"/servers/{self.server.pk}/sites/alpha/environment/prepare/",
        )

    def test_a_withheld_environment_form_uses_the_gate_sentence(self) -> None:
        from discovery.models import SiteState
        from discovery.snapshot import ObservedSetting
        from operations.services import read_changes

        self.grant("manage_secrets")
        record_site_settings(
            self.server,
            application="laravel",
            state=SiteState.PARTLY_APPLIED,
            settings=(ObservedSetting("alpha", "laravel", "APP_URL", DIGEST),),
        )
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/alpha/environment/prepare/",
            {"key": "APP_URL", "action": "set"},
            follow=True,
        )
        self.assertEqual(read_changes(self.server).rows, [])
        self.assertContains(
            response,
            "This site is partly applied; finish the change that is already in progress first.",
        )

    def test_the_environment_review_needs_manage_secrets(self) -> None:
        self.laravel()
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/alpha/environment/prepare/",
            {"key": "APP_URL", "action": "set"},
        )
        self.assertEqual(response.status_code, 403)

    def test_the_wordpress_settings_review_needs_manage_secrets(self) -> None:
        self.wordpress()
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/alpha/wordpress/settings/prepare/",
            {"key": "MAIL_HOST", "action": "set"},
        )
        self.assertEqual(response.status_code, 403)

    def test_a_permitted_environment_review_keeps_values_out_of_the_inputs(self) -> None:
        from operations.services import read_changes

        self.grant("manage_secrets")
        self.laravel()
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/alpha/environment/prepare/",
            {"key": "APP_URL", "action": "set", "value": "should not persist"},
        )
        rows = read_changes(self.server).rows
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            rows[0].preparation.inputs,
            {
                "version": 1,
                "identifier": "alpha",
                "changes": [{"key": "APP_URL", "action": "set"}],
            },
        )
        self.assertRedirects(response, f"/changes/{rows[0].preparation.pk}/")

    def test_a_non_target_site_has_no_environment_page(self) -> None:
        self.wordpress()
        response = self.client.get(f"/servers/{self.server.pk}/sites/alpha/environment/")
        self.assertEqual(response.status_code, 404)

    def test_a_viewer_reads_the_certificate_releases_and_settings_keys(self) -> None:
        from discovery.snapshot import SiteCertificate

        from .ui_testing import record_laravel_releases

        self.user.user_permissions.remove(self.user.user_permissions.get(codename="change_site"))
        record_site_settings(
            self.server,
            application="laravel",
            certificate=SiteCertificate("issued", "CN=Pebble", 1_800_000_000),
            settings=(ObservedSetting("alpha", "laravel", "APP_ENV", DIGEST, "production"),),
        )
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            logs = self.client.get(f"/servers/{self.server.pk}/sites/alpha/logs/")
            environment = self.client.get(f"/servers/{self.server.pk}/sites/alpha/environment/")
        self.assertContains(logs, "Issued by CN=Pebble")
        self.assertContains(environment, "APP_ENV")
        self.assertContains(environment, "production")
        record_laravel_releases(self.server)
        deployments = self.client.get(f"/servers/{self.server.pk}/sites/alpha/deployments/")
        self.assertContains(deployments, f"{0:040x}")

    def test_the_settings_page_query_count_does_not_grow_with_recorded_attempts(self) -> None:
        self.laravel()
        url = f"/servers/{self.server.pk}/sites/alpha/settings/"
        assert_query_count_flat_as_history_grows(
            self.client, url, lambda: record_older_snapshots(self.server, 3)
        )

    def test_the_environment_page_query_count_does_not_grow_with_recorded_attempts(self) -> None:
        self.laravel()
        url = f"/servers/{self.server.pk}/sites/alpha/environment/"
        assert_query_count_flat_as_history_grows(
            self.client, url, lambda: record_older_snapshots(self.server, 3)
        )


class SettingsBuilderTests(SimpleTestCase):
    """A section renders from a literal read, with no server, worker or page."""

    def test_a_section_builder_renders_from_a_literal_read(self) -> None:
        from sites.domains_views import context_for_site as domains_context
        from sites.php_views import context_for_site as php_context

        state = DiscoveryState(
            server=Server(name="Web", ssh_alias="web.example.com"),
            attempt=None,
            snapshot=Snapshot(COLLECTED, COLLECTED_AT, "web"),
            history=[],
            alias_usable=True,
            changes=ServerChanges([], None),
        )
        user = AnonymousUser()
        php = php_context(state, "alpha", user)
        domains = domains_context(state, "alpha", user)
        self.assertEqual(php["site_php_current"], "php85")
        self.assertEqual(domains["site_domains"], ("alpha.test", "www.alpha.test"))


class ReadinessPageTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant("view_server", "view_siteobservation", "view_changes", "change_site")
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        self.settings_url = f"/servers/{self.server.pk}/sites/alpha/settings/"
        self.prepare_url = f"/servers/{self.server.pk}/sites/alpha/readiness/prepare/"

    def record_plain(self) -> None:
        record_site_settings(self.server, application="plain")

    def record_unreadable_laravel_releases(self) -> None:
        release = ObservedRelease("alpha", "release", "commit", 1, SiteState.MANAGED, True)
        record_site_settings(
            self.server,
            application="laravel",
            releases=(release,),
            settings=(ObservedSetting("alpha", "laravel", "APP_ENV", DIGEST, "production"),),
        )
        snapshot = current_snapshot(self.server)
        if snapshot is None:
            self.fail("No setup snapshot.")
        releases = replace(
            snapshot.collected.releases,
            outcome=ObservationOutcome.INACCESSIBLE,
            warning="Not readable.",
        )
        save_snapshot(
            record_attempt(self.server, DiscoveryAttempt.Status.SUCCEEDED),
            replace(snapshot.collected, releases=releases),
            timezone.now(),
        )

    def test_a_managed_plain_site_offers_the_readiness_form(self) -> None:
        self.record_plain()
        response = self.client.get(self.settings_url)
        self.assertContains(response, "Change readiness path")

    def test_unreadable_releases_withhold_readiness_and_deploy_with_one_reason(self) -> None:
        self.record_unreadable_laravel_releases()
        sentence = "Barectl could not read this site's releases."
        response = self.client.get(self.settings_url)
        self.assertNotContains(response, "Change readiness path")
        self.assertContains(response, sentence, html=True)
        refusal = self.client.post(self.prepare_url, {"readiness": "/health"}, follow=True)
        self.assertEqual(refusal.redirect_chain[0][0], self.settings_url)
        self.assertIn(sentence, [str(message) for message in refusal.context["messages"]])
        self.assertEqual(read_changes(self.server).rows, [])

        state = server_state(self.server)
        deploy = decide_for_site(
            state,
            self.user,
            "alpha",
            replace(
                preparation.SITE,
                application="laravel",
                releases_observed=True,
                current_release=True,
                open_site=True,
            ),
        )
        reason = deploy.reason
        assert reason is not None  # noqa: S101 - narrows the optional for mypy
        self.assertIs(reason.name, ReasonName.RELEASES_NOT_OBSERVED)
        self.assertEqual(reason.sentence, sentence)
        self.assertFalse(
            deploy_context(server_state(self.server), "alpha", self.user)["deploy_can_prepare"]
        )

    def test_a_partly_applied_laravel_site_withholds_the_automation_cards(self) -> None:
        release = ObservedRelease("alpha", "release", "commit", 1, SiteState.MANAGED, True)
        record_site_settings(
            self.server,
            application="laravel",
            releases=(release,),
            settings=(ObservedSetting("alpha", "laravel", "APP_ENV", DIGEST, "production"),),
        )
        snapshot = current_snapshot(self.server)
        if snapshot is None:
            self.fail("No setup snapshot.")
        observed = snapshot.collected.sites
        sites = tuple(
            replace(row, state=SiteState.PARTLY_APPLIED, missing=(SITE_GATED,))
            for row in observed.value
        )
        save_snapshot(
            record_attempt(self.server, DiscoveryAttempt.Status.SUCCEEDED),
            replace(snapshot.collected, sites=replace(observed, value=sites)),
            timezone.now(),
        )
        state = server_state(self.server)
        php_settings = decide_for_site(
            state, self.user, "alpha", replace(preparation.SITE, pool=True)
        )
        scheduled = decide_for_site(
            state,
            self.user,
            "alpha",
            replace(preparation.SITE, application="laravel", no_application_problem=True),
        )
        workers = decide_for_site(
            state,
            self.user,
            "alpha",
            replace(
                preparation.SITE,
                state=None,
                application="laravel",
                current_release=True,
                open_site=True,
            ),
        )
        assert php_settings.reason is not None  # noqa: S101 - narrows the optional for mypy
        assert scheduled.reason is not None  # noqa: S101 - narrows the optional for mypy
        assert workers.reason is not None  # noqa: S101 - narrows the optional for mypy
        self.assertIs(php_settings.reason.name, ReasonName.SITE_PARTLY_APPLIED)
        self.assertIs(scheduled.reason.name, ReasonName.SITE_PARTLY_APPLIED)
        self.assertFalse(workers.allowed)
        self.assertIs(workers.reason.name, ReasonName.SITE_PARTLY_APPLIED)
        self.assertEqual(workers.reason.sentence, scheduled.reason.sentence)
