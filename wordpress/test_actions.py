"""A WordPress site's password reset and core verification (Phase B #381).

The fast layer proves the reviewed shapes, the refusals, the body's bounded results, the
confidential channel for the password, and the pages. The native WordPress scenario proves
the new password signs in and the checksum comparison on a real host.
"""

import base64
import gzip
import hashlib
import json
import pathlib
import subprocess
import tempfile
from collections.abc import Callable
from typing import cast, override
from unittest import mock

from django.test import SimpleTestCase

from bootstrap.standing import Standing
from discovery.ssh import CommandResult
from operations import services
from operations.consent import Scope
from operations.engine import BodyContext, ChangeKind
from operations.fakes import APPLY_PERMISSIONS, ChangeTestCase
from operations.inputs import InputShape, PreparationInputs
from operations.models import ChangeReview, ChangeRun
from servers.models import Server
from servers.testing import ControllerConfigTestCase
from sites.bodies.common import NativeState
from sites.change import membership_command
from sites.ui_testing import record_http_sites, record_wordpress_sites
from wordpress import actions
from wordpress.bodies import actions as body_actions
from wordpress.forms import WordPressPasswordForm

CANARY = "Barectl-Canary-4c1f8e2a"
OLD_HASH = "$P$B" + "a" * 30
NEW_HASH = "$P$B" + "b" * 30


def native(**overrides: object) -> NativeState:
    site: dict[str, object] = {
        "identifier": "shop",
        "names": ["shop.example.com"],
        "runtime": "php84",
        "node_runtime": "",
        "https": True,
        "readiness": "/",
        "certificate": None,
        "pool": None,
        "account": [4001, 4001, "/var/www/shop", "/usr/sbin/nologin", [4001]],
        "file": "/etc/caddy/sites/shop.caddy",
        "state": "complete",
        "problem": "",
        "application": "wordpress",
        "application_version": "7.1.3",
        "application_problem": "",
    }
    site.update(overrides)
    return cast(
        NativeState,
        {
            "version": 1,
            "boot": "00000000-0000-0000-0000-000000000000",
            "uptime": 1,
            "sites": [site],
            "current_sites": ["shop"],
            "disk_digest": "b" * 64,
            "digest": "a" * 64,
            "evidence": {},
            "next_id": 4002,
            "next_proxy_id": 4003,
            "validation": "not_requested",
            "pool_validation": "not_requested",
            "master_present": True,
        },
    )


def evidence(**overrides: object) -> actions.WordPressActionEvidence:
    return actions.WordPressActionEvidence(Standing.TARGET_STACK, native(**overrides))


def document(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "version": 1,
        "body_sha256": actions.BODY_SHA256,
        "identifier": "shop",
        "names": ["shop.example.com"],
        "selection": "php84",
        "https": True,
        "identity": 4001,
        "core_version": "7.1.3",
        "precondition_digest": "a" * 64,
        "admin_username": "shopadmin",
    }
    value.update(overrides)
    return value


def payload(body: object) -> dict[str, object]:
    from operations.engine import NativeBody

    if not isinstance(body, NativeBody):
        raise TypeError("Not a native body.")
    value = json.loads(gzip.decompress(base64.b64decode(body.arguments[0])))
    if not isinstance(value, dict):
        raise TypeError("The payload is not a JSON object.")
    return value


class WordPressInputTests(SimpleTestCase):
    def test_the_actions_decode_only_canonical_inputs(self) -> None:
        from operations.inputs import decode_inputs

        core = decode_inputs({"version": 1, "identifier": "shop"}, (), InputShape.WORDPRESS_CORE)
        self.assertEqual(core.identifier, "shop")
        password = decode_inputs(
            {"version": 1, "identifier": "shop", "admin_username": "shopadmin"},
            (),
            InputShape.WORDPRESS_PASSWORD,
        )
        self.assertEqual(password.admin_username, "shopadmin")
        self.assertEqual(
            password.document(),
            {"version": 1, "identifier": "shop", "admin_username": "shopadmin"},
        )
        for value in (
            {"version": 1, "identifier": "Shop"},
            {"version": 1, "identifier": "shop", "admin_username": "shop admin"},
            {"version": 1, "identifier": "shop", "selection": "php84"},
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                decode_inputs(value, (), InputShape.WORDPRESS_PASSWORD)

    def test_the_password_form_accepts_wordpress_logins_only(self) -> None:
        self.assertTrue(WordPressPasswordForm({"admin_username": "shop.admin@example"}).is_valid())
        self.assertFalse(WordPressPasswordForm({"admin_username": "shop admin"}).is_valid())


class WordPressReviewTests(SimpleTestCase):
    def test_a_password_reset_is_one_site_effect_with_a_confidential_value(self) -> None:
        draft = actions.password_review(
            evidence(), PreparationInputs("", "shop", admin_username="shopadmin")
        )
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual([effect.scope for effect in draft.effects], [Scope.SITE])
        self.assertEqual(draft.document["secret_label"], "New WordPress administrator password")
        self.assertTrue(draft.document["secret_generate"])
        self.assertEqual(draft.stages, ("preflight", "password", "verify"))
        self.assertEqual(draft.sites_read, membership_command("php84"))
        self.assertEqual(draft.current_sites, ("shop",))

    def test_core_verification_is_one_site_effect(self) -> None:
        draft = actions.core_review(evidence(), PreparationInputs("", "shop"))
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual([effect.scope for effect in draft.effects], [Scope.SITE])
        self.assertNotIn("secret_label", draft.document)
        self.assertEqual(draft.stages, ("preflight", "checksums"))

    def test_a_plain_php_site_is_refused(self) -> None:
        draft = actions.core_review(
            evidence(application="plain", application_version=""), PreparationInputs("", "shop")
        )
        self.assertFalse(draft.eligible)
        self.assertIn(
            "This site is not a WordPress application. These actions need a WordPress site.",
            draft.refusals,
        )

    def test_a_gated_or_partly_applied_install_is_refused(self) -> None:
        draft = actions.password_review(
            evidence(state="partial", problem="The maintenance gate is in place."),
            PreparationInputs("", "shop", admin_username="shopadmin"),
        )
        self.assertFalse(draft.eligible)
        self.assertIn("The maintenance gate is in place.", draft.refusals)
        # A refused review names no affected sites, so the engine stores it as refused
        # instead of failing its membership read.
        self.assertEqual(draft.sites_read, "")
        self.assertIsNone(draft.current_sites)

    def test_a_partly_applied_wordpress_install_names_its_problem(self) -> None:
        draft = actions.core_review(
            evidence(
                application="wordpress_partial",
                application_problem="The private WordPress configuration is missing.",
            ),
            PreparationInputs("", "shop"),
        )
        self.assertFalse(draft.eligible)
        self.assertIn("The private WordPress configuration is missing.", draft.refusals)


class WordPressBodyTests(SimpleTestCase):
    def captured(self) -> list[tuple[str, str]]:
        results: list[tuple[str, str]] = []
        for patcher in (
            mock.patch.object(
                body_actions,
                "result",
                lambda outcome, reason="": results.append((outcome, reason)),
            ),
            mock.patch.object(
                body_actions, "stage", lambda value: results.append(("stage", value))
            ),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        return results

    def test_the_password_reset_body_needs_a_staged_value(self) -> None:
        with self.assertRaises(ValueError):
            actions.password_body(document(), BodyContext("", "", 0))
        body = actions.password_body(
            document(), BodyContext("", "", 0, "/run/barectl/secrets/" + "a" * 32)
        )
        value = payload(body)
        self.assertEqual(value["secret_path"], "/run/barectl/secrets/" + "a" * 32)
        self.assertEqual(value["action"], "password")
        core = actions.core_body(document(), BodyContext("", "", 0))
        self.assertEqual(payload(core)["action"], "core")

    def test_a_tampered_review_is_refused(self) -> None:
        for key, value in (
            ("body_sha256", "0" * 64),
            ("precondition_digest", "not-a-digest"),
            ("identity", 1),
            ("core_version", "7.1.3\n"),
        ):
            with self.subTest(key=key), self.assertRaises(ValueError):
                actions.core_body(document(**{key: value}), BodyContext("", "", 0))

    def run_user(
        self, roles: str = "administrator", hashes: tuple[str, str] = (OLD_HASH, NEW_HASH)
    ) -> tuple[
        Callable[[object, list[str]], subprocess.CompletedProcess[bytes]],
        list[tuple[list[str], bytes | None]],
    ]:
        calls: list[tuple[list[str], bytes | None]] = []
        state = {"hashes": 0}

        def run(
            _settings: object,
            argv: list[str],
            *,
            input_data: bytes | None = None,
            cwd: str | pathlib.Path | None = None,
            timeout: int = 300,
        ) -> subprocess.CompletedProcess[bytes]:
            calls.append((argv, input_data))
            output = b""
            if "--field=roles" in argv:
                output = roles.encode()
            elif "--field=user_pass" in argv:
                output = hashes[min(state["hashes"], 1)].encode()
                state["hashes"] += 1
            return subprocess.CompletedProcess(argv, 0, output, b"")

        return run, calls

    def test_the_reset_passes_the_password_only_on_standard_input(self) -> None:
        results = self.captured()
        run, calls = self.run_user()

        with (
            mock.patch.object(body_actions, "native_state", return_value=native()),
            mock.patch.object(body_actions, "user_run", side_effect=run),
            mock.patch.object(body_actions, "_signs_in", return_value=True),
            tempfile.NamedTemporaryFile() as staged,
        ):
            staged.write(CANARY.encode())
            staged.flush()
            with mock.patch.object(body_actions, "_secret_path", return_value=staged.name):
                body_actions.reset_password(document())
            self.assertFalse(pathlib.Path(staged.name).exists())

        self.assertEqual(
            results,
            [
                ("stage", "preflight"),
                ("stage", "password"),
                ("stage", "verify"),
                ("succeeded", ""),
            ],
        )
        update = next(argv for argv, _input in calls if "update" in argv)
        self.assertNotIn(CANARY, " ".join(update))
        # The body's only stdout is its stages and result line; it never echoes the value.
        self.assertNotIn(CANARY, "\n".join(" ".join(item) for item in results))
        self.assertTrue(any(input_data == CANARY.encode() + b"\n" for _argv, input_data in calls))

    def test_a_non_administrator_is_refused_before_the_update(self) -> None:
        results = self.captured()
        run, calls = self.run_user(roles="subscriber")

        with (
            mock.patch.object(body_actions, "native_state", return_value=native()),
            mock.patch.object(body_actions, "user_run", side_effect=run),
            tempfile.NamedTemporaryFile() as staged,
        ):
            staged.write(CANARY.encode())
            staged.flush()
            with mock.patch.object(body_actions, "_secret_path", return_value=staged.name):
                body_actions.reset_password(document())
        self.assertEqual(results[-1], ("refused", "wordpress_password"))
        self.assertFalse(any("update" in argv for argv, _input in calls))

    def test_a_password_that_does_not_take_is_partly_applied(self) -> None:
        results = self.captured()
        run, _calls = self.run_user(hashes=(OLD_HASH, OLD_HASH))

        with (
            mock.patch.object(body_actions, "native_state", return_value=native()),
            mock.patch.object(body_actions, "user_run", side_effect=run),
            mock.patch.object(body_actions, "_signs_in", return_value=True),
            tempfile.NamedTemporaryFile() as staged,
        ):
            staged.write(CANARY.encode())
            staged.flush()
            with mock.patch.object(body_actions, "_secret_path", return_value=staged.name):
                body_actions.reset_password(document())
        self.assertEqual(results[-1], ("partial", "wordpress_password_unverified"))

    def test_a_failed_sign_in_after_the_update_is_partly_applied(self) -> None:
        results = self.captured()
        run, _calls = self.run_user()

        with (
            mock.patch.object(body_actions, "native_state", return_value=native()),
            mock.patch.object(body_actions, "user_run", side_effect=run),
            mock.patch.object(body_actions, "_signs_in", return_value=False),
            tempfile.NamedTemporaryFile() as staged,
        ):
            staged.write(CANARY.encode())
            staged.flush()
            with mock.patch.object(body_actions, "_secret_path", return_value=staged.name):
                body_actions.reset_password(document())
        self.assertEqual(results[-1], ("partial", "wordpress_password_unverified"))

    def test_changed_evidence_is_refused_before_reading_the_password(self) -> None:
        results = self.captured()
        changed = native()
        changed["digest"] = "c" * 64
        with (
            mock.patch.object(body_actions, "native_state", return_value=changed),
            mock.patch.object(
                body_actions, "_secret_path", return_value="/run/barectl/secrets/" + "a" * 32
            ),
        ):
            body_actions.reset_password(document())
        self.assertEqual(results, [("stage", "preflight"), ("refused", "evidence")])

    def test_core_verification_distinguishes_match_mismatch_and_unavailable(self) -> None:
        cases = (
            (0, b"Success: WordPress installation verifies against checksums.", "succeeded"),
            (
                1,
                b"Error: WordPress installation doesn't verify against checksums.",
                "wordpress_checksums",
            ),
            (
                1,
                b"Error: Couldn't fetch checksums from WordPress.org.",
                "wordpress_checksums_unavailable",
            ),
        )
        for status, output, expected in cases:
            with self.subTest(expected=expected):
                results = self.captured()
                completed = subprocess.CompletedProcess([], status, output, b"")
                with (
                    mock.patch.object(body_actions, "native_state", return_value=native()),
                    mock.patch.object(body_actions, "user_run", return_value=completed),
                ):
                    body_actions.verify_core(document())
                self.assertEqual(
                    results[-1],
                    ("succeeded", "") if expected == "succeeded" else ("refused", expected),
                )


class WordPressPagesTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant(
            "view_server",
            "view_siteobservation",
            "view_changes",
            "change_site",
            "manage_secrets",
        )
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="Web", ssh_alias="web.example.com")

    def test_the_section_offers_both_actions_without_ssh(self) -> None:
        record_wordpress_sites(self.server)
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            response = self.client.get(f"/servers/{self.server.pk}/sites/shop/wordpress/")
        self.assertContains(response, "WordPress 7.1.3")
        self.assertContains(response, "Reset administrator password")
        self.assertContains(response, "Verify core files")
        self.assertContains(response, 'name="admin_username"')
        self.assertContains(response, "Review password reset")
        self.assertContains(response, "Review core verification")
        self.assertContains(response, ">WordPress</a>")

    def test_a_plain_php_site_has_no_wordpress_section(self) -> None:
        record_http_sites(self.server)
        response = self.client.get(f"/servers/{self.server.pk}/sites/alpha/wordpress/")
        self.assertEqual(response.status_code, 404)

    def test_a_partly_applied_install_shows_the_problem_without_controls(self) -> None:
        record_wordpress_sites(self.server, application="wordpress_partial")
        response = self.client.get(f"/servers/{self.server.pk}/sites/shop/wordpress/")
        self.assertContains(response, "The WordPress core version file is missing or unreadable.")
        self.assertNotContains(response, "Review password reset")
        self.assertNotContains(response, "Review core verification")

    def test_preparing_a_reset_queues_only_the_username(self) -> None:
        record_wordpress_sites(self.server)
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/shop/wordpress/password/prepare/",
            {"admin_username": "shopadmin"},
        )
        rows = services.read_changes(self.server).rows
        self.assertEqual(len(rows), 1)
        self.assertRedirects(response, f"/changes/{rows[0].preparation.pk}/")
        self.assertEqual(
            rows[0].preparation.inputs,
            {"version": 1, "identifier": "shop", "admin_username": "shopadmin"},
        )

    def test_preparing_core_verification_queues_the_site_only(self) -> None:
        record_wordpress_sites(self.server)
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/shop/wordpress/core/prepare/",
            {},
        )
        rows = services.read_changes(self.server).rows
        self.assertEqual(len(rows), 1)
        self.assertRedirects(response, f"/changes/{rows[0].preparation.pk}/")
        self.assertEqual(rows[0].preparation.inputs, {"version": 1, "identifier": "shop"})

    def test_a_reset_needs_manage_secrets(self) -> None:
        record_wordpress_sites(self.server)
        self.user.user_permissions.remove(self.user.user_permissions.get(codename="manage_secrets"))
        self.client.force_login(self.user)
        response = self.client.get(f"/servers/{self.server.pk}/sites/shop/wordpress/")
        self.assertNotContains(response, "Review password reset")
        self.assertContains(response, "Review core verification")
        self.client.post(
            f"/servers/{self.server.pk}/sites/shop/wordpress/password/prepare/",
            {"admin_username": "shopadmin"},
        )
        self.assertEqual(services.read_changes(self.server).rows, [])


class WordPressSecretChannelTests(ChangeTestCase):
    """The reset carries its value through ADR 0032 and leaves no trace of it."""

    @override
    def setUp(self) -> None:
        super().setUp()
        from operations import confidential, engine

        confidential.reset()
        self.addCleanup(confidential.reset)
        site = native()
        test_kind = ChangeKind(
            actions.PASSWORD_SLUG,
            actions.PASSWORD_LABEL,
            lambda _shell, _inputs: actions.WordPressActionEvidence(Standing.TARGET_STACK, site),
            actions.password_review,
            actions.password_body,
            lambda _shell, _review: True,
            writes_secrets=True,
            input_shape=InputShape.WORDPRESS_PASSWORD,
        )
        engine.register_kind(test_kind)
        self.addCleanup(engine.register_kind, actions.RESET_PASSWORD)
        self.remote.results[membership_command("php84")] = CommandResult(0, "shop\n")

    def test_the_password_reaches_the_body_sealed_and_leaves_no_trace(self) -> None:
        from operations import engine

        self.sign_in_with("view_server", "view_changes", "change_site", "manage_secrets")
        preparation = services.request_prepare(
            self.server,
            self.user,
            actions.PASSWORD_SLUG,
            inputs={"version": 1, "identifier": "shop", "admin_username": "shopadmin"},
        )
        self.assertIsNotNone(preparation)
        self.run_worker()
        review = ChangeReview.objects.latest("pk")
        self.assertTrue(review.eligible, review.document.get("refusals"))
        self.assertTrue(review.writes_secrets)
        page = self.client.get(f"/changes/{review.preparation_id}/")
        self.assertContains(page, "New WordPress administrator password")
        self.assertContains(page, "Generate a strong password")
        self.sign_in_with(*APPLY_PERMISSIONS, "change_site", "manage_secrets")
        response = self.client.post(
            f"/changes/{review.preparation_id}/apply/", {"secret": CANARY}, follow=True
        )
        run = ChangeRun.objects.filter(review=review).first()
        if run is None:
            self.fail("No run was queued.")
        self.assertNotEqual(run.secret_sealed, "")
        self.run_worker()
        run.refresh_from_db()
        self.assertEqual(run.status, "succeeded", run.failure)
        self.assertEqual(run.secret_sealed, "")
        self.assertIn(hashlib.sha256(CANARY.encode()).hexdigest(), self.systemd.secret_digests)
        sources = [
            "\n".join(self.remote.commands),
            "\n".join(self.systemd.submissions),
            "\n".join(self.systemd.journals),
            "\n".join(self.systemd.systemctl_outputs),
            response.content.decode(),
            self.client.get(f"/changes/{review.preparation_id}/").content.decode(),
            self.client.get(f"/runs/{run.pk}/").content.decode(),
        ]
        for model in (ChangeReview, ChangeRun):
            sources.extend(
                " ".join(str(getattr(row, field.name)) for field in model._meta.fields)
                for row in model.objects.all()
            )
        for source in sources:
            self.assertNotIn(CANARY, source)
        self.assertEqual(self.systemd.secret_removals, [engine.secret_path(run.unit_name)])
