"""Restore database only: its review, destructive consent, bodies and pages (#400)."""

import importlib.resources
import os
import pathlib
import stat
import tempfile
from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace
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


FILES_SNAPSHOT = "b" * 64


def evidence(
    *,
    target_empty: bool = False,
    point_version: str = "11.8.2-MariaDB-ubu2404",
    current_version: str = "11.8.2",
    point_data: dict[str, object] | None = None,
    current_sites: tuple[str, ...] = (IDENTIFIER,),
    disk_available: int = 2 * 1024 * 1024 * 1024,
    parts: tuple[str, ...] = ("database",),
    application: str = "plain",
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
        site_record(application=application),
        backup,
        selected,
        str(selected["id"]) if "database" in parts else "",
        FILES_SNAPSHOT if "files" in parts else "",
        parts,
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

    def test_the_recorded_full_listing_binds_both_parts(self) -> None:
        parsed = check.parse_listing(fixture("restic-full-snapshots.txt"))
        if parsed is None:
            self.fail("The recorded listing was refused.")
        snapshots = restore._point_snapshots(parsed, "e1fa817d57ef0663")
        self.assertEqual(
            snapshots,
            {
                "database": "cc8dd12b140a7a7fa17b97fa5b7a16007eea2feda5d6bca3045923b71f6285a0",
                "files": "66ac9af32880e79c2f714f1ef737031ee7ea3e408947b2ca9201c1cfbcd59615",
            },
        )

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
        self.assertEqual(restore_body.engine_major("mariadb", "1:11.8.6-5ubuntu0.1"), "11.8")
        self.assertEqual(restore_body.engine_major("postgresql", "1:18.0-1"), "18")

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

    def test_the_restore_result_line_is_read_by_the_engine(self) -> None:
        from operations.engine import parse_result_line

        line = (
            'barectl-result {"class":"succeeded","reason":"restore_done","kind":"restore",'
            '"site":"alpha","scope":"database","origin":"","at":"2026-10-30T01:00:00+00:00",'
            '"point":"0123456789abcdef","snapshots":1,"bytes":4096}'
        )
        parsed = parse_result_line(line)
        if parsed is None:
            self.fail("The engine ignored the final restore result.")
        self.assertEqual(parsed.result_class, "succeeded")
        self.assertEqual(parsed.reason, "restore_done")

    def test_the_import_replaces_only_the_sites_own_database(self) -> None:
        preamble = restore_body.import_preamble("mariadb", IDENTIFIER).decode()
        self.assertIn("DROP DATABASE IF EXISTS `salpha`", preamble)
        self.assertIn("CREATE DATABASE `salpha`", preamble)
        self.assertNotIn("mysql", preamble)
        self.assertIn(
            "DROP SCHEMA IF EXISTS public CASCADE",
            restore_body.import_preamble("postgresql", IDENTIFIER).decode(),
        )


class RestoreRecordedTests(SimpleTestCase):
    """The recorded real restic output binds a WordPress and a Laravel full restore (#406)."""

    POINT = "e1fa817d57ef0663"
    DATABASE = "cc8dd12b140a7a7fa17b97fa5b7a16007eea2feda5d6bca3045923b71f6285a0"
    FILES = "66ac9af32880e79c2f714f1ef737031ee7ea3e408947b2ca9201c1cfbcd59615"

    def replay(self) -> ReplayShell:
        return ReplayShell(
            Transcript(
                "restore",
                {},
                "26.04",
                "x86_64",
                "ssh-ed25519 SHA256:x",
                (
                    ("id -u", Recorded(ssh.CommandResult(0, "0\n"))),
                    (
                        restore.point_listing_command(IDENTIFIER),
                        Recorded(
                            ssh.CommandResult(0, fixture("restic-full-snapshots.txt")),
                        ),
                    ),
                    ("id -u", Recorded(ssh.CommandResult(0, "0\n"))),
                    (
                        restore.header_command(IDENTIFIER, self.DATABASE, "salpha.sql"),
                        Recorded(ssh.CommandResult(0, fixture("restic-dump-mariadb.txt"))),
                    ),
                ),
            )
        )

    def test_a_recorded_full_point_binds_a_wordpress_and_a_laravel_restore(self) -> None:
        shell = self.replay()
        found, snapshots, size = restore._read_point(shell, IDENTIFIER, self.POINT)
        if found is None:
            self.fail("The recorded full point was not bound.")
        self.assertEqual(snapshots, {"database": self.DATABASE, "files": self.FILES})
        version = restore._point_version(
            shell, IDENTIFIER, self.DATABASE, convention.dump_filename(IDENTIFIER), "mariadb"
        )
        self.assertEqual(version, "11.8.2")
        for application, shared in (
            ("wordpress", ["private/wp-config.php"]),
            ("laravel", ["private/laravel.env", "private/storage", "private/cache"]),
        ):
            with self.subTest(application=application):
                selected = replace(
                    evidence(
                        application=application,
                        parts=("database", "files"),
                        point_data={**found, "size": size},
                    ),
                    point={**found, "size": size},
                    snapshot=self.DATABASE,
                    files_snapshot=self.FILES,
                    point_parts=("database", "files"),
                    point_version=version,
                )
                draft = restore.review(
                    selected,
                    PreparationInputs("", IDENTIFIER, point=self.POINT, scope="full"),
                )
                self.assertTrue(draft.eligible, draft.refusals)
                self.assertEqual(draft.document["shared"], shared)
                self.assertEqual(draft.document["application"], application)
                self.assertEqual(draft.document["snapshot"], self.DATABASE)
                self.assertEqual(draft.document["files_snapshot"], self.FILES)
                restore.body(draft.document, BodyContext("unit", BOOT, 0))


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
        self.assertEqual(draft.document["safety_tags"], {})
        restore.body(draft.document, BodyContext("unit", BOOT, 0))

    def test_a_files_restore_warns_that_files_and_database_differ(self) -> None:
        draft = restore.review(
            evidence(
                parts=("database", "files"),
                point_data=point(scope="full", parts=("database", "files")),
            ),
            PreparationInputs("", IDENTIFIER, point=POINT, scope="files"),
        )
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(consent_of(draft.effects), Consent.DESTRUCTIVE)
        self.assertEqual(draft.document["scope"], "files")
        self.assertEqual(draft.document["snapshot"], "")
        self.assertEqual(draft.document["files_snapshot"], FILES_SNAPSHOT)
        self.assertEqual(draft.document["safety_scope"], "files")
        self.assertEqual(list(cast(dict[str, list[str]], draft.document["safety_tags"])), ["files"])
        rows = cast(list[dict[str, str]], draft.document["details"])
        values = "\n".join(row["value"] for row in rows)
        self.assertIn("files and the database may come from different points", values)
        self.assertIn("Files only", values)
        self.assertIn("files-only safety backup", values)
        restore.body(draft.document, BodyContext("unit", BOOT, 0))

    def test_a_full_restore_binds_both_parts_and_a_full_safety_backup(self) -> None:
        draft = restore.review(
            evidence(
                parts=("database", "files"),
                point_data=point(scope="full", parts=("database", "files")),
            ),
            PreparationInputs("", IDENTIFIER, point=POINT, scope="full"),
        )
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(draft.document["scope"], "full")
        self.assertEqual(draft.document["snapshot"], SNAPSHOT)
        self.assertEqual(draft.document["files_snapshot"], FILES_SNAPSHOT)
        self.assertEqual(draft.document["safety_scope"], "full")
        self.assertEqual(
            set(cast(dict[str, list[str]], draft.document["safety_tags"])), {"database", "files"}
        )
        rows = cast(list[dict[str, str]], draft.document["details"])
        values = "\n".join(row["value"] for row in rows)
        self.assertIn("full site safety backup", values)
        self.assertIn("application files and its database", values)
        restore.body(draft.document, BodyContext("unit", BOOT, 0))

    def test_a_live_point_review_names_the_capture_window(self) -> None:
        draft = restore.review(
            evidence(parts=("database", "files"), point_data=point(scope="full")),
            PreparationInputs("", IDENTIFIER, point=POINT, scope="files"),
        )
        rows = cast(list[dict[str, str]], draft.document["details"])
        values = "\n".join(row["value"] for row in rows)
        self.assertIn("may differ by the capture window", values)

    def test_a_wordpress_restore_names_the_private_file_and_its_database(self) -> None:
        draft = restore.review(
            evidence(
                application="wordpress",
                parts=("database", "files"),
                point_data=point(scope="full", parts=("database", "files")),
            ),
            PreparationInputs("", IDENTIFIER, point=POINT, scope="full"),
        )
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(draft.document["shared"], ["private/wp-config.php"])
        self.assertEqual(
            draft.document["files"],
            [f"/var/www/{IDENTIFIER}/current", f"/var/www/{IDENTIFIER}/private/wp-config.php"],
        )
        rows = cast(list[dict[str, str]], draft.document["details"])
        values = "\n".join(row["value"] for row in rows)
        self.assertIn("WordPress", values)
        self.assertIn("private configuration is replaced", values)
        self.assertIn("database settings are kept", values)

    def test_a_laravel_restore_replaces_its_shared_state_as_a_whole(self) -> None:
        draft = restore.review(
            evidence(
                application="laravel",
                parts=("database", "files"),
                point_data=point(scope="full", parts=("database", "files")),
            ),
            PreparationInputs("", IDENTIFIER, point=POINT, scope="full"),
        )
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(
            draft.document["shared"],
            ["private/laravel.env", "private/storage", "private/cache"],
        )
        rows = cast(list[dict[str, str]], draft.document["details"])
        values = "\n".join(row["value"] for row in rows)
        self.assertIn("Laravel", values)
        self.assertIn(".env, storage and bootstrap cache are replaced as a whole", values)
        restore.body(draft.document, BodyContext("unit", BOOT, 0))

    def test_a_full_restore_of_a_point_without_a_database_leaves_it_alone(self) -> None:
        draft = restore.review(
            evidence(parts=("files",), point_data=point(scope="files", parts=("files",))),
            PreparationInputs("", IDENTIFIER, point=POINT, scope="full"),
        )
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(draft.document["snapshot"], "")
        self.assertEqual(draft.document["dump"], [])
        self.assertEqual(draft.document["safety_scope"], "files")
        rows = cast(list[dict[str, str]], draft.document["details"])
        values = "\n".join(row["value"] for row in rows)
        self.assertIn("the database stays as it is now", values)

    def test_a_database_restore_of_a_files_point_is_refused(self) -> None:
        draft = restore.review(
            evidence(parts=("files",), point_data=point(scope="files", parts=("files",))),
            PreparationInputs("", IDENTIFIER, point=POINT, scope="database"),
        )
        self.assertFalse(draft.eligible)
        self.assertIn("no complete database copy", " ".join(draft.refusals))

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

    def test_the_reviewed_database_snapshot_is_bound_by_its_own_id(self) -> None:
        draft = restore.review(evidence(), PreparationInputs("", IDENTIFIER, point=POINT))
        rows = [
            {
                "id": draft.document["snapshot"],
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
            self.assertTrue(
                restore_body.reviewed_point(
                    draft.document,
                    convention.repository(IDENTIFIER),
                    convention.server_key(IDENTIFIER),
                )
            )

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


class RestoreFilesTests(SimpleTestCase):
    """Private staging admission and the convention's file classification (#401)."""

    def stage(
        self, application: str = "plain"
    ) -> tuple[tempfile.TemporaryDirectory[str], pathlib.Path]:
        temporary = tempfile.TemporaryDirectory()
        base = pathlib.Path(temporary.name) / "var" / "www" / IDENTIFIER
        release = base / "releases" / "initial"
        (release / "public").mkdir(parents=True)
        (release / "public" / "index.php").write_text("<?php\n")
        if application != "plain":
            (base / "private").mkdir()
        if application == "laravel":
            (release / "artisan").write_text("<?php\n")
            (base / "private" / "laravel.env").write_text("APP_ENV=production\n")
            (base / "private" / "storage").mkdir()
            (base / "private" / "cache").mkdir()
            (release / ".env").symlink_to(f"/var/www/{IDENTIFIER}/private/laravel.env")
            (release / "storage").symlink_to(f"/var/www/{IDENTIFIER}/private/storage")
            (release / "bootstrap").mkdir()
            (release / "bootstrap" / "cache").symlink_to(f"/var/www/{IDENTIFIER}/private/cache")
        if application == "wordpress":
            (base / "private" / "wp-config.php").write_text("<?php\n")
        return temporary, base

    def test_a_staged_plain_release_is_admitted(self) -> None:
        temporary, base = self.stage()
        with temporary:
            admitted = restore_body.admitted(base.parent.parent.parent, IDENTIFIER, "plain")
            self.assertEqual(admitted["release"], base / "releases" / "initial")

    def test_a_staged_laravel_release_is_admitted_with_its_private_state(self) -> None:
        temporary, base = self.stage("laravel")
        with temporary:
            admitted = restore_body.admitted(base.parent.parent.parent, IDENTIFIER, "laravel")
            self.assertEqual(
                set(cast(dict[str, object], admitted["shared"])),
                {"private/laravel.env", "private/storage", "private/cache"},
            )

    def test_a_link_outside_the_convention_is_refused(self) -> None:
        temporary, base = self.stage()
        with temporary:
            link = base / "releases" / "initial" / "public" / "escape"
            link.symlink_to("/etc/passwd")
            with self.assertRaises(ValueError):
                restore_body.admitted(base.parent.parent.parent, IDENTIFIER, "plain")
            link.unlink()
            link.symlink_to("../../../../../etc/passwd")
            with self.assertRaises(ValueError):
                restore_body.admitted(base.parent.parent.parent, IDENTIFIER, "plain")

    def test_a_device_fifo_socket_setuid_or_setgid_file_is_refused(self) -> None:
        temporary, base = self.stage()
        with temporary:
            fifo = base / "releases" / "initial" / "public" / "pipe"
            os.mkfifo(fifo)
            with self.assertRaises(ValueError):
                restore_body.admitted(base.parent.parent.parent, IDENTIFIER, "plain")
            fifo.unlink()
            executable = base / "releases" / "initial" / "public" / "index.php"
            executable.chmod(0o4755)
            with self.assertRaises(ValueError):
                restore_body.admitted(base.parent.parent.parent, IDENTIFIER, "plain")
            executable.chmod(0o2755)
            with self.assertRaises(ValueError):
                restore_body.admitted(base.parent.parent.parent, IDENTIFIER, "plain")

    def test_a_laravel_release_is_classified_from_the_convention(self) -> None:
        temporary, base = self.stage("laravel")
        with temporary:
            release = base / "releases" / "initial"
            (release / "public" / "app.css").write_text("body{}")
            (release / "src").mkdir()
            (release / "src" / "app.php").write_text("<?php")
            owner = os.getuid()
            group = os.getgid()
            restore_body.classify_release(release, "laravel", owner, group, group)
            self.assertIn(stat.S_IMODE(release.stat().st_mode), (0o711,))
            self.assertIn((release / "public").stat().st_mode & 0o7777, (0o2750, 0o750))
            self.assertEqual(stat.S_IMODE((release / "public" / "index.php").stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE((release / "public" / "app.css").stat().st_mode), 0o640)
            self.assertEqual(stat.S_IMODE((release / "src" / "app.php").stat().st_mode), 0o600)

    def test_a_wordpress_release_is_group_readable_by_caddy_and_never_world_readable(self) -> None:
        temporary, base = self.stage("wordpress")
        with temporary:
            release = base / "releases" / "initial"
            (release / "public" / "wp-load.php").write_text("<?php")
            owner = os.getuid()
            group = os.getgid()
            restore_body.classify_release(release, "wordpress", owner, group, group)
            for path in (
                release,
                release / "public",
                release / "public" / "index.php",
                release / "public" / "wp-load.php",
            ):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode) & 0o006, 0)

    def test_wordpress_private_configuration_keeps_the_target_database(self) -> None:
        from wordpress import convention as wordpress

        target = wordpress.render_private_configuration(
            IDENTIFIER,
            tuple(f"target{salt:02d}" * 5 for salt in range(8)),
            (("TARGET_CONSTANT", "from-target"),),
        )
        point = wordpress.render_private_configuration(
            "other",
            tuple(f"point{salt:02d}-" * 5 for salt in range(8)),
            (("POINT_CONSTANT", "from-point"),),
        )
        merged = restore_body.merge_private_configuration(point, target, IDENTIFIER)
        self.assertEqual(wordpress.private_configuration_problem(merged, IDENTIFIER), "")
        self.assertIn("define( 'DB_NAME', 'salpha' );", merged)
        self.assertNotIn("sother", merged)
        self.assertIn("define( 'AUTH_KEY', 'point00-", merged)
        self.assertIn("define( 'POINT_CONSTANT', 'from-point' );", merged)
        self.assertNotIn("TARGET_CONSTANT", merged)
        self.assertIn("define( 'ABSPATH', '/var/www/alpha/current/public/' );", merged)
        with self.assertRaises(ValueError):
            restore_body.merge_private_configuration("<?php\nsystem('x');\n", target, IDENTIFIER)
        with self.assertRaises(ValueError):
            restore_body.merge_private_configuration(point, "not a configuration", IDENTIFIER)
        injected = point.replace("$table_prefix = ", "system('x');\n$table_prefix = ")
        with self.assertRaises(ValueError):
            restore_body.merge_private_configuration(injected, target, IDENTIFIER)

    def test_laravel_shared_state_is_replaced_as_a_whole(self) -> None:
        staged_temporary, staged_base = self.stage("laravel")
        target_temporary = tempfile.TemporaryDirectory()
        with staged_temporary, target_temporary:
            staged = restore_body.admitted(staged_base.parent.parent.parent, IDENTIFIER, "laravel")
            shared = cast(dict[str, pathlib.Path], staged["shared"])
            (shared["private/storage"] / "from-point.txt").write_text("in the point\n")
            site = pathlib.Path(target_temporary.name) / "var" / "www" / IDENTIFIER
            for name in ("laravel.env", "storage", "cache"):
                path = site / "private" / name
                if name == "laravel.env":
                    path.parent.mkdir(parents=True)
                    path.write_text("APP_ENV=after\n")
                else:
                    path.mkdir(parents=True)
            (site / "private" / "storage" / "later.txt").write_text("after the point\n")
            settings = SimpleNamespace(identifier=IDENTIFIER, directory=str(site))
            owner, group = os.getuid(), os.getgid()
            restore_body._replace_shared(shared, settings, "laravel", owner, group)
            self.assertFalse((site / "private" / "storage" / "later.txt").exists())
            self.assertEqual(
                (site / "private" / "storage" / "from-point.txt").read_text(), "in the point\n"
            )
            self.assertEqual((site / "private" / "laravel.env").read_text(), "APP_ENV=production\n")
            self.assertEqual(stat.S_IMODE((site / "private" / "storage").stat().st_mode), 0o700)
            self.assertEqual(
                stat.S_IMODE((site / "private" / "storage" / "from-point.txt").stat().st_mode),
                0o600,
            )

    def test_publishing_a_restored_release_runs_no_application_code(self) -> None:
        staged_temporary, staged_base = self.stage("laravel")
        with staged_temporary:
            staged = restore_body.admitted(staged_base.parent.parent.parent, IDENTIFIER, "laravel")
            staged_release = cast(pathlib.Path, staged["release"])
            private = staged_base / "private"
            for source, name in (
                (".env", "laravel.env"),
                ("storage", "storage"),
                ("bootstrap/cache", "cache"),
            ):
                link = staged_release / source
                link.unlink()
                link.symlink_to(private / name)
            settings = SimpleNamespace(identifier=IDENTIFIER, directory=str(staged_base))
            with (
                mock.patch("backups.bodies.restore.subprocess.run") as run,
                mock.patch("backups.bodies.restore.subprocess.Popen") as popen,
            ):
                release = restore_body.place(
                    staged,
                    settings,
                    "laravel",
                    "restore-0123456789abcdef-a1b2c3d4",
                    os.getuid(),
                    os.getgid(),
                    os.getgid(),
                )
            run.assert_not_called()
            popen.assert_not_called()
            self.assertEqual(
                os.readlink(staged_base / "current"),
                "releases/restore-0123456789abcdef-a1b2c3d4",
            )
            self.assertTrue((release / "artisan").is_file())


class RestoreReadinessTests(SimpleTestCase):
    def test_laravel_readiness_uses_deploys_up_path_and_refuses_a_redirect(self) -> None:
        settings = SimpleNamespace(identifier=IDENTIFIER, names=[f"{IDENTIFIER}.test"])
        with (
            mock.patch.object(restore_body, "readiness_request", return_value=200) as request,
            mock.patch.object(restore_body, "READY_SECONDS", 30),
        ):
            self.assertTrue(restore_body.site_ready(settings, "laravel"))
            request.assert_any_call(settings, "/index.php/up", "/up")
        with (
            mock.patch.object(restore_body, "readiness_request", return_value=302),
            mock.patch.object(restore_body, "READY_SECONDS", 0),
        ):
            self.assertFalse(restore_body.site_ready(settings, "laravel"))

    def test_wordpress_readiness_asks_for_the_home_and_login_pages(self) -> None:
        settings = SimpleNamespace(identifier=IDENTIFIER, names=[f"{IDENTIFIER}.test"])
        with mock.patch.object(restore_body, "readiness_request", return_value=200) as request:
            self.assertTrue(restore_body.site_ready(settings, "wordpress"))
        self.assertEqual(
            [call.args[1:] for call in request.call_args_list],
            [("/index.php", "/"), ("/wp-login.php", "/wp-login.php")],
        )


class RestoreApplyTests(ChangeTestCase):
    def restore_review(self, draft: ReviewDraft | None = None) -> ChangeReview:
        draft = draft or restore.review(evidence(), PreparationInputs("", IDENTIFIER, point=POINT))
        preparation = ChangePreparation.objects.create(
            server=self.server,
            kind_slug=restore.SLUG,
            requested_by=self.user,
            ssh_alias=self.server.ssh_alias,
            inputs={
                "version": 1,
                "identifier": IDENTIFIER,
                "point": POINT,
                **(
                    {"scope": draft.document["scope"]}
                    if draft.document.get("scope") != "database"
                    else {}
                ),
            },
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

    def test_site_consent_cannot_apply_a_files_restore(self) -> None:
        draft = restore.review(
            evidence(
                parts=("database", "files"),
                point_data=point(scope="full", parts=("database", "files")),
            ),
            PreparationInputs("", IDENTIFIER, point=POINT, scope="files"),
        )
        review = self.restore_review(draft)
        self.assertEqual(review.consent, Consent.DESTRUCTIVE)
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

    def test_files_only_and_full_site_choose_their_own_scope(self) -> None:
        server = self.store()
        record_points(
            server,
            (point(scope="full", parts=("database", "files")),),
            identifier="shop",
        )
        for scope in ("files", "full"):
            with self.subTest(scope=scope):
                ChangePreparation.objects.filter(server=server).delete()
                response = self.client.post(
                    f"/servers/{server.pk}/sites/shop/backups/restore/prepare/",
                    {"point": POINT, "scope": scope},
                )
                self.assertEqual(response.status_code, 302)
                preparation = ChangePreparation.objects.filter(server=server).latest("pk")
                self.assertEqual(preparation.kind_slug, restore.SLUG)
                self.assertEqual(preparation.inputs["scope"], scope)

    def test_a_forged_restore_scope_is_refused(self) -> None:
        server = self.store()
        response = self.client.post(
            f"/servers/{server.pk}/sites/shop/backups/restore/prepare/",
            {"point": POINT, "scope": "everything"},
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
            "This stopped after pausing the site to restore it. Nothing after it ran.",
        )
        self.assertContains(page, "Reopen site")
        self.assertNotContains(page, "This stopped after pausing the site for a full backup.")
        overview = self.client.get(f"/servers/{server.pk}/sites/shop/")
        self.assertContains(
            overview,
            "This stopped after pausing the site to restore it. Nothing after it ran.",
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
