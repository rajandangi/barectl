"""Restore database only: its review, destructive consent, bodies and pages (#400)."""

import importlib.resources
from dataclasses import replace
from datetime import timedelta
from typing import TYPE_CHECKING, cast
from unittest import mock

from django.test import Client, SimpleTestCase
from django.utils import timezone

if TYPE_CHECKING:
    from django.test.client import _MonkeyPatchedWSGIResponse

from bootstrap.standing import Standing
from discovery import ssh
from discovery.recorded import Recorded, ReplayShell, Transcript
from operations import engine
from operations.consent import Scope, consent_of
from operations.engine import BodyContext, ReviewDraft
from operations.fakes import ChangeTestCase
from operations.inputs import PreparationInputs
from operations.models import ChangePreparation, ChangeReview, ChangeRun, Consent
from runtimes.catalog import Architecture
from servers.models import Server

from . import check, convention, observation, presentation, restore
from .bodies import restore as restore_body
from .testing import point, record_backups, record_points, result

IDENTIFIER = "alpha"
BOOT = "8f14e45f-ea6f-4c1c-9b7b-2f0f4c1c9b7b"
SNAPSHOT = "a" * 64
POINT = "0123456789abcdef"


def fixture(name: str) -> str:
    return importlib.resources.files("backups.fixtures").joinpath(name).read_text(encoding="utf-8")


def site_record(**values: object) -> dict[str, object]:
    return {
        "identifier": IDENTIFIER,
        "names": [f"{IDENTIFIER}.test"],
        "runtime": "php84",
        "https": True,
        "readiness": "/",
        "application": "plain",
        "serving_form": "plain",
        "state": "complete",
        "problem": "",
        "account": [1001, 1001, f"/var/www/{IDENTIFIER}", "/usr/sbin/nologin", [1001]],
        **values,
    }


def evidence(
    *,
    target_empty: bool = False,
    point_version: str = "11.8.2-MariaDB-ubu2404",
    current_version: str = "11.8.2",
    point_data: dict[str, object] | None = None,
    current_sites: tuple[str, ...] = (IDENTIFIER,),
    disk_available: int = 2 * 1024 * 1024 * 1024,
) -> restore.RestoreEvidence:
    backup = observation.ObservedBackup(
        IDENTIFIER,
        "/nix/store/rac858616ds2w2z3db69kp80vr9s8mkp-restic-0.18.1",
        True,
        True,
        (),
        True,
        "",
        None,
    )
    selected = {"size": 4096, **(point_data or point())}
    return restore.RestoreEvidence(
        Architecture.X86_64,
        Standing.TARGET_STACK,
        "mariadb",
        "MariaDB",
        current_version,
        site_record(),
        backup,
        selected,
        str(selected["id"]),
        point_version,
        target_empty,
        "",
        disk_available,
        current_sites,
        BOOT,
        100,
    )


class RestorePointTests(SimpleTestCase):
    def test_the_recorded_full_listing_binds_its_database_snapshot(self) -> None:
        parsed = check.parse_listing(fixture("restic-full-snapshots.txt"))
        if parsed is None:
            self.fail("The recorded listing was refused.")
        self.assertEqual(
            restore._point_snapshot(parsed, "e1fa817d57ef0663"),
            "cc8dd12b140a7a7fa17b97fa5b7a16007eea2feda5d6bca3045923b71f6285a0",
        )
        self.assertEqual(restore._point_snapshot(parsed, "missing"), "")

    def test_the_recorded_dump_headers_name_their_engine_major(self) -> None:
        mariadb = fixture("restic-dump-mariadb.txt")
        postgresql = fixture("restic-dump-postgresql.txt")
        self.assertEqual(restore_body.dump_version("mariadb", mariadb), "11.8.2")
        self.assertEqual(restore_body.dump_version("postgresql", postgresql), "18.0")
        self.assertEqual(
            restore_body.engine_major("mariadb", restore_body.dump_version("mariadb", mariadb)),
            "11.8",
        )
        self.assertEqual(
            restore_body.engine_major(
                "postgresql", restore_body.dump_version("postgresql", postgresql)
            ),
            "18",
        )
        self.assertEqual(restore_body.dump_version("mariadb", "not a dump"), "")
        self.assertEqual(restore_body.engine_major("mariadb", "not a version"), "")

    def test_a_recorded_dump_header_replays_at_the_remote_shell_seam(self) -> None:
        command = restore.header_command(IDENTIFIER, SNAPSHOT, "salpha.sql")
        shell = ReplayShell(
            Transcript(
                "restore",
                {},
                "26.04",
                "x86_64",
                "ssh-ed25519 SHA256:x",
                (
                    ("id -u", Recorded(ssh.CommandResult(0, "0\n"))),
                    (command, Recorded(ssh.CommandResult(0, fixture("restic-dump-mariadb.txt")))),
                ),
            )
        )
        self.assertEqual(
            restore._point_version(shell, IDENTIFIER, SNAPSHOT, "salpha.sql", "mariadb"), "11.8.2"
        )

    def test_the_import_runs_as_the_site_principal_over_the_local_socket(self) -> None:
        argv = restore_body.import_argv("mariadb", IDENTIFIER)
        self.assertEqual(argv[:3], ["/usr/sbin/runuser", "-u", "s" + IDENTIFIER])
        self.assertIn("--protocol=socket", argv)
        self.assertNotIn("--user=root", argv)
        self.assertNotIn("root", argv)
        self.assertTrue(
            restore_body.count_command("mariadb", IDENTIFIER).startswith(
                "/usr/sbin/runuser -u salpha"
            )
        )

    def test_the_preparation_inputs_carry_one_recovery_point(self) -> None:
        from operations.inputs import InputShape, decode_inputs

        inputs = decode_inputs(
            {"version": 1, "identifier": IDENTIFIER, "point": POINT},
            (),
            InputShape.SITE_RECOVERY_POINT,
        )
        self.assertEqual(inputs.point, POINT)
        with self.assertRaises(ValueError):
            decode_inputs(
                {"version": 1, "identifier": IDENTIFIER, "point": "not-a-point"},
                (),
                InputShape.SITE_RECOVERY_POINT,
            )

    def test_the_import_replaces_only_the_sites_own_database(self) -> None:
        preamble = restore_body.import_preamble("mariadb", IDENTIFIER).decode()
        self.assertIn("DROP DATABASE IF EXISTS `salpha`", preamble)
        self.assertIn("CREATE DATABASE `salpha`", preamble)
        self.assertNotIn("mysql", preamble)
        self.assertIn(
            "DROP SCHEMA IF EXISTS public CASCADE",
            restore_body.import_preamble("postgresql", IDENTIFIER).decode(),
        )


class RestoreReviewTests(ChangeTestCase):
    def test_a_database_restore_is_destructive_and_binds_its_point(self) -> None:
        draft = restore.review(evidence(), PreparationInputs("", IDENTIFIER, point=POINT))
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(draft.effects[0].scope, Scope.SITE)
        self.assertTrue(draft.effects[0].destroys_data)
        self.assertEqual(consent_of(draft.effects), Consent.DESTRUCTIVE)
        self.assertEqual(draft.document["point"], POINT)
        self.assertEqual(draft.document["snapshot"], SNAPSHOT)
        rows = cast(list[dict[str, str]], draft.document["details"])
        values = "\n".join(row["value"] for row in rows)
        for expected in (
            "This site's database",
            "Other sites' databases are not touched",
            "Same site kind (plain PHP)",
            "MariaDB 11.8",
            "MiB free",
            "Visitors see a maintenance page",
            "Barectl takes and checks a database-only safety backup first",
        ):
            self.assertIn(expected, values)
        self.assertNotIn(SNAPSHOT, values)
        self.assertEqual(draft.document["confirmation"], "alpha.test")
        restore.body(draft.document, BodyContext("unit", BOOT, 0))

    def test_an_empty_target_skips_the_safety_backup_and_says_so(self) -> None:
        draft = restore.review(
            evidence(target_empty=True), PreparationInputs("", IDENTIFIER, point=POINT)
        )
        self.assertTrue(draft.eligible, draft.refusals)
        rows = cast(list[dict[str, str]], draft.document["details"])
        values = "\n".join(row["value"] for row in rows)
        self.assertIn("no safety backup is taken", values)
        self.assertTrue(draft.document["target_empty"])
        self.assertEqual(draft.document["safety_tags"], [])
        restore.body(draft.document, BodyContext("unit", BOOT, 0))

    def test_other_sites_make_the_caddy_step_shared(self) -> None:
        draft = restore.review(
            evidence(current_sites=(IDENTIFIER, "beta")),
            PreparationInputs("", IDENTIFIER, point=POINT),
        )
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual([effect.scope for effect in draft.effects], [Scope.SITE, Scope.SHARED])
        self.assertEqual(consent_of(draft.effects), Consent.DESTRUCTIVE)
        self.assertEqual(draft.current_sites, (IDENTIFIER, "beta"))

    def test_a_different_engine_major_is_refused(self) -> None:
        draft = restore.review(
            evidence(point_version="10.11.9-MariaDB"),
            PreparationInputs("", IDENTIFIER, point=POINT),
        )
        self.assertFalse(draft.eligible)
        self.assertIn("made by MariaDB 10.11", " ".join(draft.refusals))

    def test_a_missing_or_incomplete_point_is_refused(self) -> None:
        missing = evidence()
        missing = replace(missing, point=None, snapshot="")
        draft = restore.review(missing, PreparationInputs("", IDENTIFIER, point=POINT))
        self.assertFalse(draft.eligible)
        self.assertIn("no longer listed", " ".join(draft.refusals))
        incomplete = evidence(point_data=point(complete=False))
        draft = restore.review(incomplete, PreparationInputs("", IDENTIFIER, point=POINT))
        self.assertFalse(draft.eligible)
        self.assertIn("no complete database copy", " ".join(draft.refusals))

    def test_a_forged_restore_document_is_refused(self) -> None:
        draft = restore.review(evidence(), PreparationInputs("", IDENTIFIER, point=POINT))
        for key, value in (
            ("repository", "/var/lib/barectl-backups/other/onsite"),
            ("gate", "not the reviewed gate"),
            ("safety_tags", ["barectl", "site:other"]),
        ):
            with self.subTest(key=key):
                forged = dict(draft.document)
                forged[key] = value
                with self.assertRaises(ValueError):
                    restore.body(forged, BodyContext("unit", BOOT, 0))

    def test_a_forged_snapshot_is_refused_when_the_point_is_listed_again(self) -> None:
        draft = restore.review(evidence(), PreparationInputs("", IDENTIFIER, point=POINT))
        rows = [
            {
                "id": "b" * 64,
                "tags": [
                    "barectl",
                    "site:alpha",
                    "scope:database",
                    "part:database",
                    "origin:manual",
                    "capture:live",
                    "point:" + POINT,
                    "complete",
                ],
            }
        ]
        with mock.patch.object(restore_body, "snapshots", return_value=rows):
            self.assertFalse(
                restore_body.reviewed_point(
                    draft.document,
                    convention.repository(IDENTIFIER),
                    convention.server_key(IDENTIFIER),
                )
            )


class RestoreApplyTests(ChangeTestCase):
    def restore_review(self) -> ChangeReview:
        draft: ReviewDraft = restore.review(
            evidence(), PreparationInputs("", IDENTIFIER, point=POINT)
        )
        preparation = ChangePreparation.objects.create(
            server=self.server,
            kind_slug=restore.SLUG,
            requested_by=self.user,
            ssh_alias=self.server.ssh_alias,
            inputs={"version": 1, "identifier": IDENTIFIER, "point": POINT},
            status="succeeded",
        )
        now = timezone.now()
        return ChangeReview.objects.create(
            preparation=preparation,
            kind_slug=draft.kind,
            intent=draft.intent,
            eligible=True,
            consent=Consent.DESTRUCTIVE,
            affected_sites=[IDENTIFIER],
            effects=[
                {"scope": "site", "text": "Replace the database.", "sites": [IDENTIFIER]},
            ],
            ssh_alias=self.server.ssh_alias,
            host_key=self.remote.host_key,
            boot_id=BOOT,
            uptime_centiseconds=100,
            admission_deadline_centiseconds=100 + engine.ADMISSION_SECONDS * 100,
            collected_at=now,
            admission_expires_at=now + timedelta(minutes=15),
            document=draft.document,
        )

    def apply_review(
        self, review: ChangeReview, data: dict[str, str]
    ) -> _MonkeyPatchedWSGIResponse:
        return self.client.post(f"/changes/{review.preparation_id}/apply/", data)

    def test_site_consent_cannot_apply_a_restore(self) -> None:
        review = self.restore_review()
        self.sign_in_with("view_changes", "change_site")
        response = self.apply_review(review, {"confirmation": "alpha.test"})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ChangeRun.objects.exists())

    def test_a_restore_apply_needs_csrf(self) -> None:
        review = self.restore_review()
        self.sign_in_with("view_changes", "change_destructive")
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        response = client.post(
            f"/changes/{review.preparation_id}/apply/", {"confirmation": "alpha.test"}
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ChangeRun.objects.exists())

    def test_a_forged_apply_without_the_typed_domain_is_refused(self) -> None:
        review = self.restore_review()
        self.sign_in_with("view_changes", "change_destructive")
        for data in ({}, {"confirmation": "not-the-domain.example.com"}):
            with self.subTest(data=data):
                response = self.apply_review(review, data)
                self.assertEqual(response.status_code, 302)
                self.assertFalse(ChangeRun.objects.exists())
        response = self.apply_review(review, {"confirmation": "alpha.test"})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(ChangeRun.objects.filter(review=review).exists())

    def test_a_forged_document_never_reaches_ssh(self) -> None:
        review = self.restore_review()
        ChangeReview.objects.filter(pk=review.pk).update(
            document={**review.document, "repository": "/var/lib/barectl-backups/other/onsite"}
        )
        review.refresh_from_db()
        self.sign_in_with("view_changes", "change_destructive")
        self.apply_review(review, {"confirmation": "alpha.test"})
        run = ChangeRun.objects.get(review=review)
        self.remote.commands.clear()
        self.run_worker()
        run.refresh_from_db()
        self.assertEqual(run.status, "failed")
        self.assertEqual(self.remote.commands, [])


class RestorePageTests(ChangeTestCase):
    def store(self, *, gated: bool = False, last: observation.BackupResult | None = None) -> Server:
        server = self.server
        record_backups(server, identifier="shop", gated=gated, last=last or result())
        record_points(server, (point(),), identifier="shop")
        self.sign_in_with(
            "view_server",
            "view_changes",
            "view_siteobservation",
            "change_site",
            "change_destructive",
        )
        return server

    def test_a_listed_point_offers_restore_without_ssh_and_prepares_its_kind(self) -> None:
        server = self.store()
        self.remote.commands.clear()
        page = self.client.get(f"/servers/{server.pk}/sites/shop/backups/")
        self.assertEqual(page.status_code, 200)
        self.assertContains(page, "Restore")
        self.assertEqual(self.remote.commands, [])
        response = self.client.post(
            f"/servers/{server.pk}/sites/shop/backups/restore/prepare/", {"point": POINT}
        )
        self.assertEqual(response.status_code, 302)
        preparation = ChangePreparation.objects.get(server=server)
        self.assertEqual(preparation.kind_slug, restore.SLUG)
        self.assertEqual(preparation.inputs["point"], POINT)

    def test_a_forged_point_is_refused(self) -> None:
        server = self.store()
        response = self.client.post(
            f"/servers/{server.pk}/sites/shop/backups/restore/prepare/", {"point": "not-a-point"}
        )
        self.assertEqual(response.status_code, 404)
        self.assertFalse(ChangePreparation.objects.exists())

    def test_a_gated_restore_shows_one_sentence_and_one_reopen_action(self) -> None:
        server = self.store(
            gated=True,
            last=result(result_class="partial", reason="restore_paused"),
        )
        page = self.client.get(f"/servers/{server.pk}/sites/shop/backups/")
        self.assertContains(
            page,
            "This stopped after pausing the site to restore its database. Nothing after it ran.",
        )
        self.assertContains(page, "Reopen site")
        self.assertNotContains(page, "This stopped after pausing the site for a full backup.")
        overview = self.client.get(f"/servers/{server.pk}/sites/shop/")
        self.assertContains(
            overview,
            "This stopped after pausing the site to restore its database. Nothing after it ran.",
        )

    def test_a_successful_restore_is_a_separate_finding_from_a_saved_point(self) -> None:
        backup = observation.ObservedBackup(
            "shop",
            "/nix/store/rac858616ds2w2z3db69kp80vr9s8mkp-restic-0.18.1",
            True,
            True,
            (),
            True,
            "",
            result(result_class="succeeded", reason="restore_done"),
        )
        view = presentation.view(None, None, "shop", None, checking=False)
        self.assertIsNone(view.last)
        last = presentation.last_view(backup)
        if last is None:
            self.fail("The restore result was not shown.")
        self.assertEqual(last.headline, "Database restored.")
        self.assertFalse(last.failed)
