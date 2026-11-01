"""The confirm screen and the run page as #179 describes them: plain words by default,
the full record under Show details and Logs, and the same stored review and run behind
both (docs/dashboard-workflows.md)."""

import hashlib
import re
from datetime import timedelta
from html.parser import HTMLParser
from typing import override
from unittest import mock

from django.test import SimpleTestCase
from django.utils import timezone

from operations import engine, lifecycle, plain_words
from operations.consent import DeclaredEffect, Scope
from operations.fakes import finished_unit
from operations.models import (
    ChangePreparation,
    ChangeReview,
    ChangeRun,
    RemoteOperation,
    Result,
)
from operations.plain_words import ChangeWords, Home
from operations.presentation import plain_change

from .fakes import APPLY_PERMISSIONS, BOOT_ID, PREPARE_PERMISSIONS, ChangeTestCase

FIXTURE_BODY = b"#!/bin/sh\nexit 0"
SITES_READ = "printf 'alpha\\nbeta\\n' | LC_ALL=C sort"


def _document() -> dict[str, object]:
    return {"version": 1, "body_sha256": hashlib.sha256(FIXTURE_BODY).hexdigest()}


def _site_review(evidence: object, inputs: object) -> engine.ReviewDraft:
    return engine.ReviewDraft(
        kind="fixture_site",
        intent="Create the site's resources.",
        effects=(DeclaredEffect(Scope.SITE, "Create the site's resources."),),
        stages=("preflight", "account", "verify"),
        boot_id=BOOT_ID,
        uptime_centiseconds=500025,
        document=_document(),
    )


def _shared_review(evidence: object, inputs: object) -> engine.ReviewDraft:
    return engine.ReviewDraft(
        kind="fixture_shared",
        intent="Reload the shared configuration.",
        effects=(
            DeclaredEffect(Scope.SHARED, "Reload the shared configuration.", ("alpha", "beta")),
        ),
        stages=("preflight", "verify"),
        boot_id=BOOT_ID,
        uptime_centiseconds=500025,
        sites_read=SITES_READ,
        document=_document(),
    )


def _shared_without_sites_review(evidence: object, inputs: object) -> engine.ReviewDraft:
    return engine.ReviewDraft(
        kind="fixture_shared_none",
        intent="Reload the shared configuration.",
        effects=(DeclaredEffect(Scope.SHARED, "Reload the shared configuration."),),
        stages=("preflight", "verify"),
        boot_id=BOOT_ID,
        uptime_centiseconds=500025,
        document=_document(),
    )


def _kind(slug: str, label: str, review: object) -> engine.ChangeKind:
    return engine.ChangeKind(
        slug=slug,
        label=label,
        inspect=lambda shell, inputs: None,
        review=review,  # type: ignore[arg-type]
        body=lambda document, context: engine.NativeBody(FIXTURE_BODY),
        verify=lambda shell, review: True,
    )


SITE_KIND = _kind("fixture_site", "Fixture site change", _site_review)
SHARED_KIND = _kind("fixture_shared", "Fixture shared change", _shared_review)
SHARED_EMPTY_KIND = _kind(
    "fixture_shared_none", "Fixture shared change without sites", _shared_without_sites_review
)

# #179 acceptance criterion 3, as whole words.
NATIVE_TERMS = (
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
_VOID = frozenset(
    {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "wbr"}
)


class _DefaultText(HTMLParser):
    """The text a page shows before the operator opens Show details or Logs."""

    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []
        self._open: list[tuple[str, str]] = []

    @override
    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _VOID:
            return
        self._open.append((tag, dict(attrs).get("id") or ""))

    @override
    def handle_endtag(self, tag: str) -> None:
        if self._open:
            self._open.pop()

    @override
    def handle_data(self, data: str) -> None:
        if any(
            name in {"script", "style"} or identifier == "show-details"
            for name, identifier in self._open
        ):
            return
        self.parts.append(data)


def default_text(html: str) -> str:
    parser = _DefaultText()
    parser.feed(html)
    return " ".join(" ".join(parser.parts).split())


def native_terms_in(text: str) -> list[str]:
    return [
        term
        for term in NATIVE_TERMS
        if re.search(rf"(?<![\w-]){re.escape(term)}(?![\w-])", text, re.IGNORECASE)
    ]


class PlainWordTests(SimpleTestCase):
    def test_the_named_kinds_have_plain_words(self) -> None:
        for slug in (
            "host_foundation",
            "add_runtime",
            "create_http_site",
            "set_site_php",
            "set_site_node",
            "set_site_object_cache",
            "install_database_engine",
            "install_valkey",
            "create_wordpress_site",
            "create_laravel_site",
            "check_for_ubuntu_updates",
            "install_ubuntu_updates",
        ):
            with self.subTest(kind=slug):
                words = plain_words.words_for(slug)
                if words is None:
                    self.fail(f"{slug} has no plain words.")
                self.assertTrue(words.title and words.action and words.summary)
                for label in words.steps.values():
                    self.assertTrue(label)
                    self.assertEqual(native_terms_in(label), [], label)

    def test_the_backup_before_a_deploy_reads_in_plain_words(self) -> None:
        words = plain_words.words_for("back_up_full_site")
        if words is None or words.before_deploy is None:
            self.fail("Back up first has no plain words.")
        variant = words.before_deploy
        self.assertEqual(variant.action, "Back up first")
        self.assertIn("before deploying", variant.title)
        for text in (variant.title, variant.action, *variant.summary):
            self.assertEqual(native_terms_in(text), [], text)

    def test_a_kind_without_words_falls_back_to_its_label_and_stage_names(self) -> None:
        self.assertIsNone(plain_words.words_for("unlisted_kind"))
        self.assertEqual(plain_words.step_label(None, "preflight", ""), "preflight")
        plain = plain_change("unlisted_kind", "Clear finished runs", None, "Web")
        self.assertEqual(plain.title, "Clear finished runs")
        self.assertEqual(plain.action, "Clear finished runs")

    def test_a_selection_is_named_in_words(self) -> None:
        self.assertEqual(plain_words.selection_label("php85"), "PHP 8.5")
        self.assertEqual(plain_words.selection_label("nodejs_22"), "Node.js 22")
        self.assertEqual(plain_words.selection_label("mariadb"), "MariaDB")
        self.assertEqual(plain_words.selection_label("postgresql"), "PostgreSQL")

    def test_the_title_names_the_server_or_the_site(self) -> None:
        server = plain_change("host_foundation", "Set up server", None, "Web")
        self.assertEqual(server.title, "Set up Web")
        self.assertEqual(server.action, "Set up server")
        preparation = ChangePreparation(
            kind_slug="create_http_site",
            inputs={
                "version": 1,
                "selection": "php84",
                "identifier": "shop",
                "names": ["shop.example.com"],
            },
        )
        site = plain_change("create_http_site", "Create PHP site", preparation, "Web")
        self.assertEqual(site.title, "Create shop.example.com")
        self.assertEqual(site.action, "Create site")
        self.assertIn("PHP 8.4", site.summary[0])

    def test_each_kind_returns_to_where_its_change_starts(self) -> None:
        preparation = ChangePreparation(kind_slug="set_site_php", inputs={"identifier": "shop"})
        preparation.server_id = 7
        plain = plain_change("set_site_php", "Switch runtime", preparation, "Web")
        self.assertEqual(plain.home_url, "/servers/7/sites/shop/")
        foundation = ChangePreparation(kind_slug="host_foundation", inputs={"version": 1})
        foundation.server_id = 7
        success = plain_change("host_foundation", "Set up server", foundation, "Web")
        self.assertEqual(success.home_url, "/servers/7/")
        self.assertEqual(success.after_label, "Create site")
        self.assertEqual(success.after_url, "/servers/7/sites/create/")
        self.assertEqual(success.after_permission, "operations.change_site")

    def test_a_full_backup_prepared_from_deploy_returns_to_deploy(self) -> None:
        preparation = ChangePreparation(
            kind_slug="back_up_full_site",
            inputs={"version": 1, "identifier": "shop", "from_deploy": True},
        )
        preparation.server_id = 7
        plain = plain_change("back_up_full_site", "Back up full site", preparation, "Web")
        self.assertEqual(plain.action, "Back up first")
        self.assertEqual(plain.home_url, "/servers/7/sites/shop/deployments/")
        self.assertEqual(plain.after_label, "Continue to Deploy")
        self.assertEqual(plain.after_url, "/servers/7/sites/shop/deployments/deploy/prepare/")
        self.assertTrue(plain.after_post)
        ordinary = ChangePreparation(kind_slug="back_up_full_site", inputs={"identifier": "shop"})
        ordinary.server_id = 7
        self.assertEqual(
            plain_change("back_up_full_site", "Back up full site", ordinary, "Web").action,
            "Back up now",
        )


class ExtraActionTests(SimpleTestCase):
    def test_a_deploy_review_with_pending_migrations_offers_back_up_first(self) -> None:
        from operations import presentation
        from operations.models import ChangeReview

        preparation = ChangePreparation(kind_slug="deploy_laravel_site", inputs={"version": 1})
        preparation.server_id = 7
        review = ChangeReview(
            preparation=preparation,
            kind_slug="deploy_laravel_site",
            intent="",
            eligible=True,
            consent="site",
            boot_id=BOOT_ID,
            admission_expires_at=timezone.now() + timedelta(minutes=5),
            document={"identifier": "shop", "back_up_first": True},
        )
        with mock.patch.object(lifecycle, "connection_current", return_value=True):
            view = presentation.review_view(review)
        if view.extra_action is None:
            self.fail("The Back up first action was not offered.")
        self.assertEqual(view.extra_action.label, "Back up first")
        self.assertEqual(
            view.extra_action.url, "/servers/7/sites/shop/backups/back-up-first/prepare/"
        )

    def test_a_review_without_pending_migrations_offers_no_extra_action(self) -> None:
        from operations import presentation
        from operations.models import ChangeReview

        review = ChangeReview(
            kind_slug="deploy_laravel_site",
            intent="",
            eligible=True,
            consent="site",
            boot_id=BOOT_ID,
            admission_expires_at=timezone.now() + timedelta(minutes=5),
            document={"identifier": "shop", "back_up_first": False},
        )
        with mock.patch.object(lifecycle, "connection_current", return_value=True):
            self.assertIsNone(presentation.review_view(review).extra_action)


class ScreenTestCase(ChangeTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        for kind in (SITE_KIND, SHARED_KIND, SHARED_EMPTY_KIND):
            engine.register_kind(kind)
            self.addCleanup(engine._KINDS.pop, kind.slug, None)
        from discovery.ssh import CommandResult

        self.remote.results[SITES_READ] = CommandResult(0, "alpha\nbeta\n")

    @override
    def assert_read_only(self) -> None:
        # The shared fixture reads the sites its change affects, as every Shared kind does.
        self.remote.commands[:] = [
            command for command in self.remote.commands if command != SITES_READ
        ]
        super().assert_read_only()


class ConfirmScreenTests(ScreenTestCase):
    def test_a_queued_preparation_says_it_is_checking_the_server_and_polls(self) -> None:
        self.sign_in_with(*PREPARE_PERMISSIONS)
        self.client.post(f"/servers/{self.server.pk}/changes/prepare/", {"kind": "cleanup_runs"})
        preparation = ChangePreparation.objects.get()
        page = self.client.get(f"/changes/{preparation.pk}/")
        self.assertContains(page, "Checking the server…")
        self.assertContains(page, f'hx-get="/changes/{preparation.pk}/"')
        self.assertContains(page, 'hx-trigger="every 2s"')
        fragment = self.client.get(
            f"/changes/{preparation.pk}/",
            headers={"HX-Request": "true", "HX-Request-Type": "partial"},
        )
        self.assertEqual(fragment.status_code, 200)
        self.assertNotContains(fragment, "<html")
        self.assertContains(fragment, "Checking the server…")

    def test_a_site_change_has_one_button_and_no_acknowledgement(self) -> None:
        review = self.change("fixture_site")
        self.assertEqual(review.consent, "site")
        self.sign_in_with("view_changes", "change_site")
        page = self.client.get(f"/changes/{review.preparation_id}/")
        content = page.content.decode()
        self.assertIn("Fixture site change", content)
        self.assertEqual(content.count('class="usa-button"'), 1)
        self.assertNotIn('name="affected_sites"', content)
        self.assertNotIn('name="acknowledged"', content)

    def test_a_shared_change_names_its_sites_and_requires_the_tick_box(self) -> None:
        review = self.change("fixture_shared")
        self.sign_in_with("view_changes", "change_shared")
        page = self.client.get(f"/changes/{review.preparation_id}/")
        content = page.content.decode()
        self.assertIn("This change also touches these sites:", content)
        self.assertIn("alpha, beta", content)
        self.assertIn('name="affected_sites"', content)
        self.assertIn("required", content)
        self.assertEqual(content.count('class="usa-button"'), 1)

    def test_a_shared_change_with_no_sites_says_so(self) -> None:
        review = self.change("fixture_shared_none")
        self.sign_in_with("view_changes", "change_shared")
        page = self.client.get(f"/changes/{review.preparation_id}/")
        self.assertContains(page, "This change also touches these sites:")
        self.assertContains(page, "none. It changes only what the server shares between sites.")

    def test_show_details_is_closed_and_holds_the_full_review(self) -> None:
        review = self.change("fixture_site")
        self.sign_in_with("view_changes", "change_site")
        page = self.client.get(f"/changes/{review.preparation_id}/")
        self.assertContains(page, 'aria-expanded="false"')
        self.assertContains(page, 'aria-controls="show-details"')
        self.assertContains(page, '<div id="show-details" class="usa-accordion__content" hidden>')
        for detail in (
            "Consent level",
            "Admission deadline",
            "Connection revision",
            "Change digest",
            "Stages",
            "Intent",
        ):
            self.assertContains(page, detail)

    def test_the_default_text_has_no_native_terms(self) -> None:
        review = self.change("fixture_site")
        self.sign_in_with("view_changes", "change_site")
        page = self.client.get(f"/changes/{review.preparation_id}/")
        self.assertEqual(native_terms_in(default_text(page.content.decode())), [])

    def test_an_expired_confirmation_offers_check_again_and_no_apply(self) -> None:
        review = self.change("fixture_site")
        ChangeReview.objects.filter(pk=review.pk).update(
            admission_expires_at=timezone.now() - timedelta(minutes=1)
        )
        self.sign_in_with("view_changes", "change_site")
        page = self.client.get(f"/changes/{review.preparation_id}/")
        content = page.content.decode()
        self.assertIn("This confirmation is out of date.", content)
        self.assertIn("Check again", content)
        self.assertNotIn(f'action="/changes/{review.preparation_id}/apply/"', content)

    def test_check_again_prepares_a_fresh_review_of_the_same_kind_and_inputs(self) -> None:
        review = self.change("fixture_site")
        ChangeReview.objects.filter(pk=review.pk).update(
            admission_expires_at=timezone.now() - timedelta(minutes=1)
        )
        old = review.preparation
        if old is None:
            self.fail("The review has no preparation.")
        self.sign_in_with(*PREPARE_PERMISSIONS)
        response = self.client.post(f"/changes/{old.pk}/again/")
        fresh = ChangePreparation.objects.exclude(pk=old.pk).get()
        self.assertRedirects(response, f"/changes/{fresh.pk}/")
        self.assertEqual(fresh.kind_slug, old.kind_slug)
        self.assertEqual(fresh.inputs, old.inputs)

    def test_a_role_without_permission_sees_the_reason_and_no_apply(self) -> None:
        review = self.change("fixture_site")
        self.user.user_permissions.clear()
        self.sign_in_with("view_changes")
        page = self.client.get(f"/changes/{review.preparation_id}/")
        content = page.content.decode()
        self.assertNotIn(f'action="/changes/{review.preparation_id}/apply/"', content)
        self.assertIn("Your role may view this change but not apply it.", content)

    def test_another_active_change_is_named_and_offers_check_again(self) -> None:
        review = self.change("fixture_site")
        self.sign_in_with(*PREPARE_PERMISSIONS, "view_changes", "change_site", "change_shared")
        self.client.post(f"/servers/{self.server.pk}/changes/prepare/", {"kind": "cleanup_runs"})
        content = self.client.get(f"/changes/{review.preparation_id}/").content.decode()
        self.assertIn("Another computer is changing this server.", content)
        self.assertIn("Check again", content)
        self.assertNotIn(f'action="/changes/{review.preparation_id}/apply/"', content)

    def test_the_old_review_url_resolves_to_the_confirm_screen(self) -> None:
        review = self.change("fixture_site")
        self.sign_in_with("view_changes", "change_site")
        response = self.client.get(f"/changes/{review.preparation_id}/")
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "operations/change.html")

    def test_opening_the_confirm_screen_makes_no_connection(self) -> None:
        review = self.change("fixture_site")
        self.sign_in_with("view_changes", "change_site")
        self.remote.commands.clear()
        self.client.get(f"/changes/{review.preparation_id}/")
        self.client.get(
            f"/changes/{review.preparation_id}/",
            headers={"HX-Request": "true", "HX-Request-Type": "partial"},
        )
        self.assertEqual(self.remote.commands, [])


class RunScreenTests(ScreenTestCase):
    def running(self, review: object) -> ChangeRun:
        if not isinstance(review, ChangeReview):
            self.fail("Expected a review.")
        run = self.apply(review)
        ChangeRun.objects.filter(pk=run.pk).update(
            status=RemoteOperation.Status.RUNNING, progress_stage="account"
        )
        return ChangeRun.objects.get(pk=run.pk)

    def test_progress_marks_the_current_step_and_polls(self) -> None:
        run = self.running(self.change("fixture_site"))
        page = self.client.get(f"/runs/{run.pk}/")
        self.assertContains(page, 'hx-trigger="every 2s"')
        self.assertContains(page, 'aria-current="step"')
        self.assertContains(page, "In progress")
        self.assertContains(page, "Done")
        self.assertContains(page, "Not started")
        self.assertContains(page, "Progress")

    def test_progress_maps_a_known_kind_into_plain_steps(self) -> None:
        words = ChangeWords(
            title="Create {site}",
            summary=("Barectl will create {site}.",),
            action="Create site",
            steps={
                "preflight": "Checking the server",
                "account": "Creating the account and folders",
                "verify": "Checking the site answers",
            },
            home=Home.SERVER_SITES,
        )
        self.enterContext(mock.patch.dict(plain_words._WORDS, {"fixture_site": words}))
        run = self.running(self.change("fixture_site"))
        page = self.client.get(f"/runs/{run.pk}/")
        self.assertContains(page, "Creating the account and folders")
        self.assertContains(page, "Checking the site answers")
        self.assertEqual(native_terms_in(default_text(page.content.decode())), [])

    def test_logs_hold_the_native_record_and_audit(self) -> None:
        run = self.running(self.change("fixture_site"))
        page = self.client.get(f"/runs/{run.pk}/?tab=logs")
        for detail in (
            "Systemd unit",
            run.unit_name,
            "Invocation",
            "Journal",
            "Consent level",
            "Connection",
            "connection revision",
            "Audit",
            "Requested by",
            "Stages",
        ):
            self.assertContains(page, detail)

    def test_progress_offers_one_next_action_when_the_run_stopped(self) -> None:
        review = self.change("fixture_site")
        self.systemd.result_class = "refused"
        self.systemd.reason = "precondition"
        run = self.apply(review)
        self.sign_in_with(*PREPARE_PERMISSIONS, "view_changes", "change_shared")
        page = self.client.get(f"/runs/{run.pk}/")
        content = page.content.decode()
        self.assertIn("Nothing changed", content)
        self.assertIn("Try again", content)
        self.assertEqual(content.count('class="usa-button"'), 1)

    def test_a_partly_applied_run_names_the_step_and_nothing_after_it(self) -> None:
        review = self.change("fixture_site")
        self.systemd.result_class = "failed"
        run = self.apply(review)
        ChangeRun.objects.filter(pk=run.pk).update(
            status=RemoteOperation.Status.FAILED,
            execution=Result.FAILED,
            progress_stage="account",
        )
        self.sign_in_with(*PREPARE_PERMISSIONS, "view_changes", "change_shared")
        content = self.client.get(f"/runs/{run.pk}/").content.decode()
        self.assertIn("This stopped after", content)
        self.assertIn("Nothing after it ran.", content)
        self.assertIn("Try again", content)

    def test_a_lost_run_says_so_and_offers_a_check_of_the_original(self) -> None:
        run = self.running(self.change("fixture_site"))
        ChangeRun.objects.filter(pk=run.pk).update(status=RemoteOperation.Status.RECONCILING)
        self.sign_in_with(*PREPARE_PERMISSIONS, "view_changes", "change_shared")
        content = self.client.get(f"/runs/{run.pk}/").content.decode()
        self.assertIn(
            "Barectl lost contact while this was running. It may have changed the server.",
            content,
        )
        self.assertIn("Check what happened", content)
        self.assertNotIn("Try again", content)

    def test_the_old_run_url_resolves_to_progress(self) -> None:
        run = self.running(self.change("fixture_site"))
        response = self.client.get(f"/runs/{run.pk}/")
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "operations/run.html")
        logs = self.client.get(f"/runs/{run.pk}/?tab=logs")
        self.assertTemplateUsed(logs, "operations/run.html")

    def test_opening_progress_or_logs_makes_no_connection(self) -> None:
        run = self.running(self.change("fixture_site"))
        self.remote.commands.clear()
        self.client.get(f"/runs/{run.pk}/")
        self.client.get(f"/runs/{run.pk}/?tab=logs")
        self.client.get(
            f"/runs/{run.pk}/status/",
            headers={"HX-Request": "true", "HX-Request-Type": "partial"},
        )
        self.assertEqual(self.remote.commands, [])


class RunRecoveryTests(ChangeTestCase):
    def test_a_reconciling_run_offers_check_what_happened(self) -> None:
        self.systemd.units["barectl-apply-" + "a" * 32 + ".service"] = finished_unit(1)
        review = self.change()
        self.systemd.lose_acknowledgement = True
        run = self.apply(review)
        self.assertEqual(run.status, RemoteOperation.Status.RECONCILING)
        self.sign_in_with(*APPLY_PERMISSIONS)
        page = self.client.get(f"/runs/{run.pk}/")
        self.assertContains(page, "Checking what happened")
        self.assertContains(page, "Check what happened")
