"""Remove a site: its review, destructive consent and typed apply confirmation (#385)."""

import tempfile
from pathlib import Path
from typing import cast, override
from unittest import mock

from django.test import SimpleTestCase

from bootstrap.standing import Standing
from databases import binding
from operations.consent import Scope
from operations.fakes import APPLY_PERMISSIONS, ChangeTestCase
from operations.inputs import InputShape, PreparationInputs, decode_inputs
from operations.models import ChangeReview, ChangeRun, Consent
from servers.models import Server
from servers.testing import ControllerConfigTestCase
from sites import remove
from sites.removal_testing import evidence
from sites.ui_testing import record_http_sites, record_shaped_sites


class RemovalReviewTests(SimpleTestCase):
    def test_the_review_lists_every_resource_and_needs_destructive_consent(self) -> None:
        draft = remove.review(evidence(), PreparationInputs("", "alpha"))
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertFalse(draft.no_changes)
        self.assertEqual(draft.document["confirmation"], "alpha.example.com")
        self.assertEqual([effect.scope for effect in draft.effects], [Scope.SITE, Scope.SHARED])
        self.assertTrue(draft.effects[0].destroys_data)
        details = cast(list[dict[str, str]], draft.document["details"])
        text = "\n".join(item["value"] for item in details)
        for expected in (
            "/var/www/alpha",
            "/etc/caddy/sites/alpha.caddy",
            "salpha: UID 1001",
            "palpha: UID 1002",
            "php-fpm-site-php84@alpha.service",
            "MariaDB: salpha database and principal",
            "alpha.example.com",
            "No backups exist for this site",
        ):
            self.assertIn(expected, text)
        self.assertEqual(draft.current_sites, ("alpha",))

    def test_the_review_removes_backup_units_and_keeps_the_repositories(self) -> None:
        draft = remove.review(evidence(backups=True), PreparationInputs("", "alpha"))
        self.assertTrue(draft.eligible, draft.refusals)
        details = cast(list[dict[str, str]], draft.document["details"])
        text = "\n".join(item["value"] for item in details)
        for unit in (
            "barectl-site-alpha-backup.timer",
            "barectl-site-alpha-copy.service",
            "barectl-site-alpha-check.timer",
            "barectl-site-alpha-checkoffsite.timer",
            "barectl-site-alpha-cleanup.timer",
            "barectl-site-alpha-cleanupoffsite.timer",
            "/etc/barectl/backups/schedule/alpha.sh",
        ):
            self.assertIn(unit, text)
        # The repositories are kept and named; the review never promises their deletion.
        self.assertIn("/var/lib/barectl-backups/alpha/onsite (onsite, kept)", text)
        self.assertIn("/etc/barectl/backups/alpha.key (its key, kept)", text)
        self.assertIn("its offsite copy stays in the bucket", text)
        self.assertNotIn("No backup", text)
        self.assertIn("Its backups are kept", str(draft.effects[0].text))
        self.assertIn("backup repositories are kept", " ".join(draft.postconditions))

    def test_nothing_left_proposes_no_changes(self) -> None:
        draft = remove.review(
            evidence(names=(), present=False, binding_state=""),
            PreparationInputs("", "alpha"),
        )
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertTrue(draft.no_changes)
        self.assertIn("Nothing of site alpha remains", str(draft.document["note"]))
        self.assertIsNone(draft.current_sites)
        self.assertEqual(draft.sites_read, "")

    def test_a_custom_database_binding_is_refused(self) -> None:
        draft = remove.review(evidence(binding_state="custom"), PreparationInputs("", "alpha"))
        self.assertFalse(draft.eligible)
        self.assertIn("does not follow the convention", " ".join(draft.refusals))

    def test_a_site_outside_the_target_stack_is_refused(self) -> None:
        observed = evidence()
        draft = remove.review(
            remove.RemovalEvidence(
                observed.architecture,
                Standing.NOT_MANAGEABLE,
                observed.inventory,
                observed.inventory_problem,
                observed.database,
            ),
            PreparationInputs("", "alpha"),
        )
        self.assertFalse(draft.eligible)
        self.assertIn("Set up and verify", " ".join(draft.refusals))

    def test_the_native_inventory_is_a_closed_shape(self) -> None:
        value = evidence().inventory
        self.assertIsNotNone(value)
        self.assertTrue(remove.valid_inventory(value, "alpha"))
        self.assertFalse(
            remove.valid_inventory({**cast(dict[str, object], value), "extra": 1}, "alpha")
        )

    def test_a_removal_never_deletes_a_backup_repository(self) -> None:
        import subprocess

        from sites.bodies import remove as native

        with (
            mock.patch.object(native, "daemon_reload", create=True),
            mock.patch.object(subprocess, "run"),
            mock.patch.object(native, "remove_path") as removed,
        ):
            native.remove_backup_units("alpha")
        deleted = {call.args[0] for call in removed.call_args_list}
        self.assertEqual(deleted, set(native.backup_paths("alpha")))
        for kept in (
            native.backup_repository("alpha"),
            native.backup_key("alpha"),
            "/var/lib/barectl-backups/alpha",
        ):
            self.assertNotIn(kept, deleted)
        self.assertNotIn(native.backup_repository("alpha"), set(native.site_paths("alpha")))


class RemovalApplyTests(ChangeTestCase):
    def test_a_forged_apply_without_the_typed_domain_is_refused(self) -> None:
        review = self.change()
        ChangeReview.objects.filter(pk=review.pk).update(
            consent=Consent.DESTRUCTIVE,
            affected_sites=[],
            eligible=True,
            no_changes=False,
            document={**review.document, "confirmation": "alpha.example.com"},
        )
        review.refresh_from_db()
        self.sign_in_with(*APPLY_PERMISSIONS, "change_destructive")
        response = self.client.post(f"/changes/{review.preparation_id}/apply/", {})
        self.assertEqual(response.status_code, 302)
        self.assertFalse(ChangeRun.objects.filter(review=review).exists())
        self.client.post(
            f"/changes/{review.preparation_id}/apply/",
            {"confirmation": "not-the-domain.example.com"},
        )
        self.assertFalse(ChangeRun.objects.filter(review=review).exists())
        self.client.post(
            f"/changes/{review.preparation_id}/apply/",
            {"confirmation": "alpha.example.com"},
        )
        self.assertTrue(ChangeRun.objects.filter(review=review).exists())

    def test_the_review_page_asks_for_the_typed_domain_without_ssh(self) -> None:
        review = self.change()
        ChangeReview.objects.filter(pk=review.pk).update(
            consent=Consent.DESTRUCTIVE,
            affected_sites=[],
            eligible=True,
            no_changes=False,
            document={
                **review.document,
                "confirmation": "alpha.example.com",
                "confirmation_label": "Type alpha.example.com to confirm this removal.",
            },
        )
        self.sign_in_with("view_server", "view_changes", "change_destructive")
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            response = self.client.get(f"/changes/{review.preparation_id}/")
        self.assertContains(response, 'name="confirmation"')
        self.assertContains(response, "Type alpha.example.com to confirm this removal.")


class RemovalPageTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.grant("view_server", "view_siteobservation", "view_changes", "change_site")
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        record_http_sites(self.server)

    def test_the_settings_page_warns_that_no_backup_exists_and_uses_no_ssh(self) -> None:
        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("Page used SSH")):
            response = self.client.get(f"/servers/{self.server.pk}/sites/alpha/settings/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Remove site")
        self.assertContains(response, "No backup exists")
        self.assertContains(response, "alpha.example.com")

    def test_the_prepare_request_queues_the_domain_without_ssh(self) -> None:
        from operations.services import read_changes

        with mock.patch("discovery.ssh.connect", side_effect=AssertionError("View used SSH")):
            response = self.client.post(
                f"/servers/{self.server.pk}/sites/alpha/settings/remove/prepare/"
            )
        rows = read_changes(self.server).rows
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].preparation.kind_slug, remove.SLUG)
        self.assertEqual(
            rows[0].preparation.inputs,
            {
                "version": 1,
                "identifier": "alpha",
                "primary": "alpha.example.com",
            },
        )
        self.assertRedirects(response, f"/changes/{rows[0].preparation.pk}/")

    def test_a_partial_site_without_a_domain_can_still_prepare_a_removal(self) -> None:
        from operations.services import read_changes

        record_shaped_sites(self.server)
        response = self.client.get(f"/servers/{self.server.pk}/sites/omega/settings/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'name="primary"')
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/omega/settings/remove/prepare/",
            {"primary": "omega.example.com"},
        )
        rows = read_changes(self.server).rows
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].preparation.inputs["primary"], "omega.example.com")
        self.assertRedirects(response, f"/changes/{rows[0].preparation.pk}/")

    def test_a_viewer_cannot_prepare_a_removal(self) -> None:
        from operations.services import read_changes

        self.user.user_permissions.remove(self.user.user_permissions.get(codename="change_site"))
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/alpha/settings/remove/prepare/"
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(read_changes(self.server).rows, [])


class RemovalNativeHelpersTests(SimpleTestCase):
    def test_a_certificate_directory_is_removed_with_its_caddy_files(self) -> None:
        from sites.bodies import remove as body

        with tempfile.TemporaryDirectory() as directory:
            certificate = Path(directory) / "certificates/acme/alpha.example.com"
            certificate.mkdir(parents=True)
            for name in (
                "alpha.example.com.crt",
                "alpha.example.com.key",
                "alpha.example.com.json",
            ):
                (certificate / name).write_text("value")
            self.assertEqual(body.remove_certificates({"certificates": [str(certificate)]}), "")
            self.assertFalse(certificate.exists())

    def test_an_unrecognized_certificate_file_stops_the_removal(self) -> None:
        from sites.bodies import remove as body

        with tempfile.TemporaryDirectory() as directory:
            certificate = Path(directory) / "certificates/acme/alpha.example.com"
            certificate.mkdir(parents=True)
            (certificate / "unknown.txt").write_text("value")
            self.assertEqual(
                body.remove_certificates({"certificates": [str(certificate)]}),
                "site_remove_certificate",
            )


class RemovalInputTests(SimpleTestCase):
    def test_the_primary_domain_fallback_round_trips(self) -> None:
        inputs = decode_inputs(
            {"version": 1, "identifier": "alpha", "primary": "alpha.example.com"},
            (),
            InputShape.SITE_REMOVE,
        )
        self.assertEqual(inputs.primary, "alpha.example.com")
        self.assertEqual(
            inputs.document(),
            {"version": 1, "identifier": "alpha", "primary": "alpha.example.com"},
        )

    def test_a_non_canonical_fallback_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            decode_inputs(
                {"version": 1, "identifier": "alpha", "primary": "not a domain"},
                (),
                InputShape.SITE_REMOVE,
            )


class DatabaseRemovalTests(SimpleTestCase):
    def test_each_engine_drops_only_the_site_database_and_principal(self) -> None:
        mariadb = binding.drop_statements("mariadb", "salpha")
        self.assertEqual(
            [(item.step, item.database, item.text) for item in mariadb],
            [
                ("database", "", "DROP DATABASE IF EXISTS `salpha`"),
                ("principal", "", "DROP USER IF EXISTS `salpha`@`localhost`"),
            ],
        )
        postgresql = binding.drop_statements("postgresql", "salpha")
        self.assertEqual(
            [(item.step, item.database, item.text) for item in postgresql],
            [
                ("database", "postgres", 'DROP DATABASE IF EXISTS "salpha" WITH (FORCE)'),
                ("principal", "postgres", 'DROP ROLE IF EXISTS "salpha"'),
            ],
        )
