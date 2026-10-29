"""Export a recovery point: consent, archive exclusion, transfer and download (#409)."""

import base64
import importlib.resources
import json
import os
import pathlib
import tempfile
import time
from datetime import timedelta
from typing import TYPE_CHECKING, cast, override

from django.test import Client, SimpleTestCase, TestCase, override_settings
from django.utils import timezone

if TYPE_CHECKING:
    from django.test.client import _MonkeyPatchedWSGIResponse

from bootstrap.standing import Standing
from discovery.ssh import CommandResult
from operations import engine
from operations.consent import consent_of
from operations.engine import ReviewDraft
from operations.fakes import ChangeTestCase
from operations.inputs import PreparationInputs
from operations.models import ChangePreparation, ChangeReview, ChangeRun, Consent
from runtimes.catalog import Architecture
from servers.models import Server

from . import change, convention, downloads, export, observation
from .bodies import export as export_body
from .models import BackupExport
from .testing import point, record_backups, record_points

IDENTIFIER = "alpha"
BOOT = "8f14e45f-ea6f-4c1c-9b7b-2f0f4c1c9b7b"
SNAPSHOT = "a" * 64
FILES_SNAPSHOT = "b" * 64
POINT = "0123456789abcdef"
TOKEN = "c" * 32


def fixture(name: str) -> str:
    return importlib.resources.files("backups.fixtures").joinpath(name).read_text(encoding="utf-8")


def site_record(**values: object) -> dict[str, object]:
    return {
        "identifier": IDENTIFIER,
        "names": [f"{IDENTIFIER}.test"],
        "runtime": "php84",
        "https": True,
        "readiness": "/",
        "application": "laravel",
        "serving_form": "laravel",
        "state": "complete",
        "problem": "",
        "account": [1001, 1001, f"/var/www/{IDENTIFIER}", "/usr/sbin/nologin", [1001]],
        **values,
    }


def evidence(
    *,
    parts: tuple[str, ...] = ("database", "files"),
    point_data: dict[str, object] | None = None,
    application: str = "laravel",
    size: int = 4096,
    disk: int = 2 * 1024 * 1024 * 1024,
) -> export.ExportEvidence:
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
    selected = {"size": size, **(point_data or point(scope="full", parts=parts))}
    return export.ExportEvidence(
        Architecture.X86_64,
        Standing.TARGET_STACK,
        "mariadb",
        "MariaDB",
        "11.8.2",
        site_record(application=application),
        backup,
        selected,
        SNAPSHOT if "database" in parts else "",
        FILES_SNAPSHOT if "files" in parts else "",
        parts,
        disk,
        (IDENTIFIER,),
        BOOT,
        100,
    )


class ExportReviewTests(SimpleTestCase):
    def test_the_assembled_body_is_one_program(self) -> None:
        compile(export.EXPORT_SOURCE, "export-body", "exec")
        self.assertIn("def main(", export.EXPORT_SOURCE)
        self.assertTrue(export.EXPORT_BYTES.startswith(b"#!/bin/sh\n"))

    def test_the_review_names_one_site_but_derives_shared_consent(self) -> None:
        draft = export.review(evidence(), PreparationInputs("", IDENTIFIER, point=POINT))
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(consent_of(draft.effects), Consent.SHARED)
        self.assertEqual([effect.sites for effect in draft.effects], [(IDENTIFIER,)])
        self.assertTrue(draft.effects[0].leaves_server)
        self.assertIn("private configuration", draft.effects[0].text)
        self.assertIn("leaves_server", str(draft.effects[0]))
        self.assertEqual(draft.sites_read, change.ALL_SITES_READ)
        self.assertEqual(draft.current_sites, (IDENTIFIER,))

    def test_the_document_binds_the_point_and_the_bounded_transfer(self) -> None:
        draft = export.review(evidence(), PreparationInputs("", IDENTIFIER, point=POINT))
        document = draft.document
        self.assertEqual(document["snapshot"], SNAPSHOT)
        self.assertEqual(document["files_snapshot"], FILES_SNAPSHOT)
        self.assertEqual(document["point"], POINT)
        self.assertEqual(document["repository"], convention.repository(IDENTIFIER))
        self.assertEqual(document["server_key"], convention.server_key(IDENTIFIER))
        self.assertEqual(len(str(document["token"])), 32)
        self.assertEqual(document["stages"], list(export.STAGES))
        self.assertIn("30 minutes", str(document["details"]))

    def test_a_point_larger_than_the_bound_is_refused(self) -> None:
        draft = export.review(
            evidence(size=export_body.MAX_EXPORT_BYTES + 1),
            PreparationInputs("", IDENTIFIER, point=POINT),
        )
        self.assertFalse(draft.eligible)
        self.assertIn("larger than the largest export", " ".join(draft.refusals))

    def test_a_database_point_exports_only_its_dump(self) -> None:
        draft = export.review(
            evidence(parts=("database",), point_data=point()),
            PreparationInputs("", IDENTIFIER, point=POINT),
        )
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(draft.document["files_snapshot"], "")

    def test_a_forged_document_is_refused_by_the_body(self) -> None:
        draft = export.review(evidence(), PreparationInputs("", IDENTIFIER, point=POINT))
        for forged_value in (
            {"repository": "/var/lib/barectl-backups/other/onsite"},
            {"token": "not-a-token"},
            {"point": "not-a-point"},
        ):
            with self.subTest(change=forged_value):
                forged = {**draft.document, **forged_value}
                with self.assertRaises(ValueError):
                    export.body(forged, engine.BodyContext("unit", BOOT, 100))

    def test_the_recorded_dump_header_binds_the_reviewed_major(self) -> None:
        from .bodies import restore as restore_body

        for name, engine_name, major in (
            ("restic-dump-mariadb.txt", "mariadb", "11.8"),
            ("restic-dump-postgresql.txt", "postgresql", "18"),
        ):
            with self.subTest(name=name):
                text = fixture(name)
                self.assertEqual(
                    restore_body.engine_major(
                        engine_name, restore_body.dump_version(engine_name, text)
                    ),
                    major,
                )


class ExportArchiveTests(SimpleTestCase):
    def tree(
        self,
        application: str,
        secret: str = "production-only-secret-material",  # noqa: S107 - a canary
    ) -> tuple[pathlib.Path, pathlib.Path]:
        directory = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        stage = directory / "stage"
        base = stage / "var" / "www" / IDENTIFIER
        release = base / "releases" / "rel1"
        (release / "public").mkdir(parents=True)
        (release / "public" / "index.php").write_text("<?php echo 'hello';")
        (release / "artisan").write_text("<?php")
        if application == "laravel":
            (base / "private" / "storage" / "uploads").mkdir(parents=True)
            (base / "private" / "storage" / "uploads" / "image.bin").write_bytes(b"image")
            (base / "private" / "laravel.env").write_text(f"APP_KEY={secret}\n")
            (base / "private" / "cache").mkdir()
            (base / "private" / "cache" / "config.php").write_text(secret)
            (release / "storage").symlink_to(f"/var/www/{IDENTIFIER}/private/storage")
            (release / "bootstrap").mkdir()
            (release / "bootstrap" / "cache").symlink_to(f"/var/www/{IDENTIFIER}/private/cache")
        if application == "wordpress":
            (base / "private").mkdir(parents=True)
            (base / "private" / "wp-config.php").write_text(f"define('AUTH_KEY', '{secret}');")
        return stage, base

    def archive(self, application: str) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
        stage, base = self.tree(application)
        _base, release = export_body._admit(stage, IDENTIFIER, application)
        export_body._rewrite_links(base, release, application)
        archive = export_body._archive(
            stage, base, release, application, export_body.MAX_FILES_BYTES
        )
        return stage, base, archive

    def names(self, archive: pathlib.Path) -> list[str]:
        import tarfile

        with tarfile.open(archive, "r") as bundle:
            return bundle.getnames()

    def test_a_laravel_export_leaves_out_its_env_and_cached_configuration(self) -> None:
        _stage, base, archive = self.archive("laravel")
        names = self.names(archive)
        self.assertIn("releases/rel1/public/index.php", names)
        self.assertIn("private/storage/uploads/image.bin", names)
        self.assertNotIn("releases/rel1/bootstrap/cache", names)
        self.assertFalse(any("laravel.env" in name for name in names))
        self.assertFalse(any("private/cache" in name for name in names))
        self.assertNotIn(b"production-only-secret-material", archive.read_bytes())
        self.assertTrue(export_body._archive_is_clean(archive, base, "laravel"))

    def test_a_wordpress_export_leaves_out_its_private_configuration(self) -> None:
        _stage, base, archive = self.archive("wordpress")
        names = self.names(archive)
        self.assertIn("releases/rel1/public/index.php", names)
        self.assertFalse(any("wp-config.php" in name for name in names))
        self.assertNotIn(b"production-only-secret-material", archive.read_bytes())
        self.assertTrue(export_body._archive_is_clean(archive, base, "wordpress"))

    def test_a_leaky_archive_is_refused_by_the_canary(self) -> None:
        stage, base = self.tree("wordpress")
        archive = stage / "leaky.tar"
        import tarfile

        with tarfile.open(archive, "w") as bundle:
            bundle.add(base / "private" / "wp-config.php", arcname="private/wp-config.php")
        self.assertFalse(export_body._archive_is_clean(archive, base, "wordpress"))

    def test_an_archive_over_the_bound_is_refused(self) -> None:
        stage, base = self.tree("laravel")
        _base, release = export_body._admit(stage, IDENTIFIER, "laravel")
        export_body._rewrite_links(base, release, "laravel")
        with self.assertRaises(export_body.ExportRefused) as raised:
            export_body._archive(stage, base, release, "laravel", 10)
        self.assertEqual(raised.exception.reason, "export_size")

    def test_a_stale_stage_is_pruned_but_the_current_one_is_kept(self) -> None:
        directory = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        site_root = directory / IDENTIFIER
        site_root.mkdir()
        stale = site_root / ("a" * 32)
        stale.mkdir()
        os.utime(stale, (time.time() - export_body.STAGE_TTL_SECONDS - 10,) * 2)
        keep = site_root / TOKEN
        keep.mkdir()
        export_body._prune(site_root, keep)
        self.assertFalse(stale.exists())
        self.assertTrue(keep.exists())

    def test_the_manifest_carries_sizes_and_hashes_but_no_content(self) -> None:
        stage, _base, archive = self.archive("laravel")
        manifest = export_body._write_manifest(stage, IDENTIFIER, POINT, TOKEN, archive, None)
        value = json.loads(manifest.read_text())
        self.assertEqual(value["files"]["size"], archive.stat().st_size)
        self.assertEqual(len(value["files"]["sha256"]), 64)
        self.assertIsNone(value["database"])
        self.assertNotIn("production-only-secret-material", manifest.read_text())


class StageShell:
    """A server's export stage answering the bounded reads the controller makes."""

    host_key = "ssh-ed25519 SHA256:x"

    def __init__(
        self,
        stage: pathlib.Path,
        files: bytes = b"",
        database: bytes = b"",
        *,
        corrupt: bool = False,
    ) -> None:
        self.stage = stage
        self.files = files
        self.database = database
        self.corrupt = corrupt
        self.commands: list[str] = []
        self.manifest = stage / export_body.MANIFEST
        stage.mkdir(parents=True, exist_ok=True)

    def prepare(self, identifier: str = IDENTIFIER, token: str = TOKEN) -> None:
        import hashlib

        def entry(name: str, value: bytes) -> dict[str, object] | None:
            if not value:
                return None
            return {
                "name": name,
                "size": len(value),
                "sha256": hashlib.sha256(value).hexdigest(),
            }

        document = {
            "version": 1,
            "identifier": identifier,
            "point": POINT,
            "token": token,
            "files": entry(export_body.FILES_NAME, self.files),
            "database": entry(export_body.DATABASE_NAME, self.database),
        }
        self.manifest.write_text(json.dumps(document))

    def run(self, command: str, stdin: bytes | None = None) -> CommandResult:
        self.commands.append(command)
        if command == "id -u":
            return CommandResult(0, "0\n")
        if command.startswith("cat "):
            return CommandResult(0, self.manifest.read_text())
        if command.startswith("/usr/bin/dd "):
            path, index = self._read(command)
            value = self.files if path.endswith(export_body.FILES_NAME) else self.database
            start = index * downloads.CHUNK_BYTES
            chunk = value[start : start + downloads.CHUNK_BYTES]
            if self.corrupt and index == 0:
                chunk = b"x" * len(chunk)
            return CommandResult(0, base64.b64encode(chunk).decode())
        if command.startswith("/usr/bin/rm -rf -- "):
            return CommandResult(0, "")
        return CommandResult(1, "")

    def _read(self, command: str) -> tuple[str, int]:
        import shlex

        argv = shlex.split(command.partition(" | ")[0])
        values = {part.partition("=")[0]: part.partition("=")[2] for part in argv[1:]}
        return values["if"], int(values.get("skip", "0"))


class ExportTransferTests(TestCase):
    @override
    def setUp(self) -> None:
        self.root = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(override_settings(EXPORT_STAGING_PATH=str(self.root)))
        self.stage = self.root / "server" / IDENTIFIER / TOKEN

    def test_a_bounded_transfer_writes_both_artifacts_and_removes_the_stage(self) -> None:
        shell = StageShell(self.stage, b"files" * 20000, b"dump" * 20000)
        shell.prepare()
        moved = downloads.transfer(shell, IDENTIFIER, POINT, TOKEN)
        self.assertEqual(moved.files_bytes, len(shell.files))
        self.assertEqual(moved.database_bytes, len(shell.database))
        self.assertEqual(
            cast(pathlib.Path, moved.files).read_bytes(),
            shell.files,
        )
        self.assertEqual(
            cast(pathlib.Path, moved.database).read_bytes(),
            shell.database,
        )
        self.assertTrue(
            any(
                command.startswith(
                    f"/usr/bin/rm -rf -- {export_body.stage_path(IDENTIFIER, TOKEN)}"
                )
                for command in shell.commands
            )
        )

    def test_a_changed_chunk_fails_and_cleans_the_local_stage(self) -> None:
        shell = StageShell(self.stage, b"files" * 20000, corrupt=True)
        shell.prepare()
        with self.assertRaises(downloads.TransferFailed):
            downloads.transfer(shell, IDENTIFIER, POINT, TOKEN)
        self.assertFalse(downloads.local_root(TOKEN).exists())
        self.assertTrue(
            any(command.startswith("/usr/bin/rm -rf -- ") for command in shell.commands)
        )

    def test_a_manifest_over_the_bound_is_refused(self) -> None:
        shell = StageShell(self.stage, b"files")
        shell.prepare()
        value = json.loads(shell.manifest.read_text())
        value["files"]["size"] = export_body.MAX_FILES_BYTES + 1
        shell.manifest.write_text(json.dumps(value))
        with self.assertRaises(downloads.TransferFailed):
            downloads.transfer(shell, IDENTIFIER, POINT, TOKEN)
        self.assertFalse(downloads.local_root(TOKEN).exists())

    def test_a_verified_export_records_one_expiring_download(self) -> None:
        from django.contrib.auth.models import User

        from operations.models import ChangePreparation, ChangeReview

        shell = StageShell(self.stage, b"files" * 20, b"dump" * 20)
        draft = export.review(evidence(), PreparationInputs("", IDENTIFIER, point=POINT))
        shell.prepare(token=str(draft.document["token"]))
        user = User.objects.create_user("operator", password=None)
        preparation = ChangePreparation.objects.create(
            server=Server.objects.create(name="Web2", ssh_alias="web2.example.com"),
            kind_slug=export.SLUG,
            requested_by=user,
            ssh_alias="web2.example.com",
            inputs={"version": 1, "identifier": IDENTIFIER, "point": POINT},
            status="succeeded",
        )
        now = timezone.now()
        review = ChangeReview.objects.create(
            preparation=preparation,
            kind_slug=draft.kind,
            intent=draft.intent,
            eligible=True,
            consent=Consent.SHARED,
            affected_sites=[IDENTIFIER],
            effects=[{"scope": "site", "text": "Copy it.", "sites": [IDENTIFIER]}],
            ssh_alias=preparation.ssh_alias,
            host_key=shell.host_key,
            boot_id=BOOT,
            uptime_centiseconds=100,
            admission_deadline_centiseconds=100 + engine.ADMISSION_SECONDS * 100,
            collected_at=now,
            admission_expires_at=now + timedelta(minutes=15),
            document=draft.document,
        )
        self.assertTrue(export.verify(shell, review))
        row = BackupExport.objects.get(token=draft.document["token"])
        self.assertEqual(row.requested_by, user)
        self.assertEqual(row.files_bytes, len(shell.files))
        self.assertEqual(row.database_bytes, len(shell.database))
        self.assertGreater(row.expires_at, timezone.now())
        self.assertTrue(row.has_files and row.has_database)
        self.assertFalse(row.complete)

    def test_an_expired_or_cancelled_stage_is_removed_without_ssh(self) -> None:
        server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        directory = downloads.local_root(TOKEN)
        directory.mkdir(parents=True)
        (directory / export_body.FILES_NAME).write_bytes(b"files")
        row = BackupExport.objects.create(
            server=server,
            identifier=IDENTIFIER,
            point=POINT,
            token=TOKEN,
            files_bytes=5,
            expires_at=timezone.now() - timedelta(minutes=1),
        )
        downloads.expire(server)
        row.refresh_from_db()
        self.assertEqual(row.status, BackupExport.Status.EXPIRED)
        self.assertFalse(directory.exists())
        orphan = downloads.local_root("e" * 32)
        orphan.mkdir()
        os.utime(orphan, (time.time() - 7200,) * 2)
        downloads.expire(server)
        self.assertFalse(orphan.exists())

        directory.mkdir(parents=True)
        row.status = BackupExport.Status.READY
        row.expires_at = timezone.now() + timedelta(minutes=5)
        row.save()
        downloads.cancel(row)
        row.refresh_from_db()
        self.assertEqual(row.status, BackupExport.Status.CANCELLED)
        self.assertFalse(directory.exists())


class ExportRequestTests(ChangeTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        staging = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(override_settings(EXPORT_STAGING_PATH=str(staging)))

    def review(self, draft: ReviewDraft | None = None) -> ChangeReview:
        draft = draft or export.review(evidence(), PreparationInputs("", IDENTIFIER, point=POINT))
        preparation = ChangePreparation.objects.create(
            server=self.server,
            kind_slug=export.SLUG,
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
            consent=Consent.SHARED,
            affected_sites=[IDENTIFIER],
            effects=[
                {
                    "scope": "site",
                    "text": "Copy the point to this computer.",
                    "sites": [IDENTIFIER],
                    "leaves_server": True,
                },
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

    def post_apply(self, review: ChangeReview, data: dict[str, str]) -> _MonkeyPatchedWSGIResponse:
        return self.client.post(f"/changes/{review.preparation_id}/apply/", data)

    def test_site_consent_cannot_apply_an_export(self) -> None:
        review = self.review()
        self.sign_in_with("view_changes", "change_site")
        response = self.post_apply(review, {"affected_sites": "on"})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ChangeRun.objects.exists())

    def test_an_export_apply_needs_csrf(self) -> None:
        review = self.review()
        self.sign_in_with("view_changes", "change_shared")
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        response = client.post(f"/changes/{review.preparation_id}/apply/", {"affected_sites": "on"})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ChangeRun.objects.exists())

    def test_a_forged_export_document_never_reaches_ssh(self) -> None:
        review = self.review()
        ChangeReview.objects.filter(pk=review.pk).update(
            document={**review.document, "repository": "/var/lib/barectl-backups/other/onsite"}
        )
        review.refresh_from_db()
        self.sign_in_with("view_changes", "change_shared")
        self.post_apply(review, {"affected_sites": "on"})
        run = ChangeRun.objects.get(review=review)
        self.remote.commands.clear()
        self.run_worker()
        run.refresh_from_db()
        self.assertEqual(run.status, "failed")
        self.assertEqual(self.remote.commands, [])

    def test_the_backups_page_never_connects_and_offers_export(self) -> None:
        record_backups(self.server, identifier="shop", last=None)
        record_points(self.server, (point(),), identifier="shop")
        self.sign_in_with(
            "view_server", "view_changes", "view_siteobservation", "change_site", "change_shared"
        )
        self.remote.commands.clear()
        page = self.client.get(f"/servers/{self.server.pk}/sites/shop/backups/")
        self.assertEqual(page.status_code, 200)
        self.assertContains(page, "Export")
        self.assertEqual(self.remote.commands, [])

    def test_export_prepare_needs_the_shared_permission(self) -> None:
        record_backups(self.server, identifier="shop", last=None)
        record_points(self.server, (point(),), identifier="shop")
        self.sign_in_with("view_server", "view_changes", "view_siteobservation", "change_site")
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/shop/backups/export/prepare/",
            {"point": POINT},
        )
        self.assertEqual(response.status_code, 302)
        self.assertFalse(ChangePreparation.objects.exists())

    def test_cancel_export_needs_csrf_and_removes_the_copy(self) -> None:
        directory = downloads.local_root(TOKEN)
        directory.mkdir(parents=True)
        (directory / export_body.FILES_NAME).write_bytes(b"tar-content")
        row = BackupExport.objects.create(
            server=self.server,
            identifier=IDENTIFIER,
            point=POINT,
            token=TOKEN,
            files_bytes=11,
            expires_at=timezone.now() + timedelta(minutes=5),
        )
        url = f"/servers/{self.server.pk}/backups/exports/{TOKEN}/cancel/"
        self.sign_in_with("view_server", "view_changes", "view_siteobservation", "change_shared")
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        response = client.post(url)
        self.assertEqual(response.status_code, 403)
        self.assertTrue(directory.exists())
        response = self.client.post(url)
        self.assertEqual(response.status_code, 302)
        row.refresh_from_db()
        self.assertEqual(row.status, BackupExport.Status.CANCELLED)
        self.assertFalse(directory.exists())

    def test_an_export_download_is_authenticated_no_store_and_expiring(self) -> None:
        directory = downloads.local_root(TOKEN)
        directory.mkdir(parents=True)
        (directory / export_body.FILES_NAME).write_bytes(b"tar-content")
        row = BackupExport.objects.create(
            server=self.server,
            identifier=IDENTIFIER,
            point=POINT,
            token=TOKEN,
            files_bytes=11,
            expires_at=timezone.now() + timedelta(minutes=5),
        )
        url = f"/servers/{self.server.pk}/backups/exports/{TOKEN}/files/"
        self.client.logout()
        unauthenticated = self.client.get(url)
        self.assertEqual(unauthenticated.status_code, 302)
        self.assertIn("/accounts/login/", unauthenticated["Location"])
        self.sign_in_with("view_server", "view_changes", "view_siteobservation", "change_shared")
        self.remote.commands.clear()
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("no-store", response["Cache-Control"])
        self.assertIn("attachment", response["Content-Disposition"])
        self.assertEqual(b"".join(cast(object, response).streaming_content), b"tar-content")  # type: ignore[attr-defined]
        response.close()
        self.assertEqual(self.remote.commands, [])
        self.assertFalse((directory / export_body.FILES_NAME).exists())

        row.refresh_from_db()
        row.expires_at = timezone.now() - timedelta(minutes=1)
        row.save()
        expired = self.client.get(url)
        self.assertEqual(expired.status_code, 404)
