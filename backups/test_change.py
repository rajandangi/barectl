"""Enable backups and Back up now: reviews, bodies, consent and the secret canary (#396)."""

import hashlib
import importlib.resources
import json
from datetime import timedelta
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast, override
from unittest import mock

from django.test import Client
from django.utils import timezone

from discovery import ssh
from discovery.recorded import Recorded, ReplayShell, Transcript

if TYPE_CHECKING:
    from django.test.client import _MonkeyPatchedWSGIResponse

from backups.observation import ObservedBackup
from bootstrap.standing import HostJudgment, Standing
from discovery.fakes import COLLECTED, record_attempt
from discovery.models import DiscoveryAttempt, ObservationOutcome
from discovery.snapshot import Observation, save_snapshot
from operations import confidential, engine
from operations.consent import Scope, consent_of
from operations.engine import BodyContext, ReviewDraft
from operations.fakes import ChangeTestCase
from operations.inputs import PreparationInputs
from operations.models import ChangePreparation, ChangeReview, ChangeRun, Consent
from runtimes.catalog import Architecture, load
from servers.models import Server
from sites.bodies.common import SITE_GATED

from . import change, check, convention, kit, observation
from .bodies import native as backup_native
from .models import BackupCheck

IDENTIFIER = "alpha"
BOOT = "8f14e45f-ea6f-4c1c-9b7b-2f0f4c1c9b7b"
CANARY = "barectl-canary-backup-passphrase-4a7e"
RESTIC = next(
    build for build in load().offered(Architecture.X86_64) if build.entry == convention.RESTIC_ENTRY
)


def detail_rows(document: dict[str, object]) -> dict[str, str]:
    rows = document.get("details")
    if not isinstance(rows, list):
        return {}
    return {
        str(row["label"]): str(row["value"])
        for row in rows
        if isinstance(row, dict) and "label" in row and "value" in row
    }


def site_record(**values: object) -> dict[str, object]:
    return {
        "identifier": IDENTIFIER,
        "names": ["alpha.test"],
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
    database: bool = True,
    enabled: bool = False,
    profile: str = "",
    repository: bool = False,
    key: bool = False,
    problems: tuple[str, ...] = (),
    engine_name: str = "mariadb",
    standing: Standing = Standing.TARGET_STACK,
    application: str = "plain",
    disk_available: int = 2 * 1024 * 1024 * 1024,
    current_sites: tuple[str, ...] = (IDENTIFIER,),
) -> change.BackupEvidence:
    backup = observation.ObservedBackup(
        IDENTIFIER,
        profile,
        repository,
        key,
        problems,
        database,
        "" if database else "This site has no site database.",
    )
    return change.BackupEvidence(
        architecture=Architecture.X86_64,
        standing=standing,
        engine=engine_name,
        site=site_record(application=application),
        database=database,
        database_problem="" if database else "This site has no site database.",
        backup=backup,
        problem="",
        boot_id=BOOT,
        uptime_centiseconds=100,
        restic_path=RESTIC.path,
        restic_version=RESTIC.version,
        disk_available=disk_available,
        current_sites=current_sites,
    )


class EnableReviewTests(ChangeTestCase):
    def test_enabling_is_shared_consent_and_carries_the_passphrase(self) -> None:
        draft = change.review_enable(evidence(), PreparationInputs("", IDENTIFIER))
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(draft.effects[0].scope, Scope.SHARED)
        self.assertTrue(draft.writes_secrets)
        self.assertIn("acknowledgement", draft.document)
        self.assertTrue(draft.document["kit_lines"])
        self.assertNotIn("passphrase", json.dumps(draft.document["details"]).lower())

    def test_a_site_without_a_database_can_still_be_enabled_for_full_copies(self) -> None:
        draft = change.review_enable(evidence(database=False), PreparationInputs("", IDENTIFIER))
        self.assertTrue(draft.eligible, draft.refusals)
        details = detail_rows(draft.document)
        self.assertIn("no site database", details["Database only"])

    def test_an_already_enabled_site_has_no_changes(self) -> None:
        draft = change.review_enable(
            evidence(
                enabled=True,
                profile=RESTIC.path,
                repository=True,
                key=True,
            ),
            PreparationInputs("", IDENTIFIER),
        )
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertTrue(draft.no_changes)

    def test_the_body_requires_a_staged_passphrase(self) -> None:
        draft = change.review_enable(evidence(), PreparationInputs("", IDENTIFIER))
        with self.assertRaises(ValueError):
            change.body_enable(draft.document, BodyContext("unit", BOOT, 0))
        body = change.body_enable(
            draft.document,
            BodyContext("unit", BOOT, 0, "/run/barectl/secrets/" + "a" * 32),
        )
        self.assertTrue(body.source)
        self.assertEqual(len(body.arguments), 1)


class BackupReviewTests(ChangeTestCase):
    def test_database_only_is_refused_without_a_site_database(self) -> None:
        draft = change.review_backup(evidence(database=False), PreparationInputs("", IDENTIFIER))
        self.assertFalse(draft.eligible)
        self.assertIn("no site database", " ".join(draft.refusals))

    def test_backup_needs_enabled_backups(self) -> None:
        draft = change.review_backup(evidence(), PreparationInputs("", IDENTIFIER))
        self.assertFalse(draft.eligible)
        self.assertIn("Enable backups", " ".join(draft.refusals))

    def test_a_database_capture_is_site_consent_and_carries_no_pause(self) -> None:
        draft = change.review_backup(
            evidence(
                enabled=True,
                profile=RESTIC.path,
                repository=True,
                key=True,
            ),
            PreparationInputs("", IDENTIFIER),
        )
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(draft.effects[0].scope, Scope.SITE)
        self.assertFalse(draft.effects[0].destroys_data)
        self.assertEqual(draft.document["filename"], "salpha.sql")
        body = change.body_backup(draft.document, BodyContext("unit", BOOT, 0))
        self.assertTrue(body.source)

    def test_a_forged_document_is_refused_by_the_native_body(self) -> None:
        enabled = evidence(enabled=True, profile=RESTIC.path, repository=True, key=True)
        setup = change.review_enable(enabled, PreparationInputs("", IDENTIFIER))
        forged_setup = dict(setup.document)
        forged_setup["repository"] = "/var/lib/barectl-backups/other/onsite"
        with self.assertRaises(ValueError):
            change.body_enable(
                forged_setup, BodyContext("unit", BOOT, 0, "/run/barectl/secrets/" + "a" * 32)
            )
        capture = change.review_backup(enabled, PreparationInputs("", IDENTIFIER))
        forged_capture = dict(capture.document)
        forged_capture["tags"] = ["barectl", "site:alpha"]
        with self.assertRaises(ValueError):
            change.body_backup(forged_capture, BodyContext("unit", BOOT, 0))

    def test_the_capture_tags_are_barectl_bounded(self) -> None:
        point = "0123456789abcdef"
        tags = convention.tags(IDENTIFIER, "database", origin="manual", live=True, point=point)
        self.assertIn(convention.MARKER, tags)
        self.assertIn("site:alpha", tags)
        self.assertIn("complete", tags)
        self.assertIn("point:" + point, tags)


class ExitCodeTests(ChangeTestCase):
    def test_restic_exit_codes_map_to_the_engine_classes(self) -> None:
        cases = {
            (0, True): ("succeeded", "", 0),
            (0, False): ("failed", "backup_verify", 3),
            (3, True): ("partial", "backup_partial", 2),
            (3, False): ("failed", "backup_verify", 3),
            (10, False): ("refused", "backup_repository", 1),
            (11, False): ("lock_busy", "backup_lock", 10),
            (12, False): ("refused", "backup_password", 1),
            (1, False): ("refused", "backup_dump", 1),
            (99, False): ("failed", "backup_unknown", 3),
            (1, True): ("partial", "backup_partial", 2),
        }
        for arguments, expected in cases.items():
            with self.subTest(arguments=arguments):
                self.assertEqual(backup_native.classify(*arguments), expected)


class ListingTests(ChangeTestCase):
    SNAPSHOTS = json.dumps(
        [
            {
                "id": "a" * 64,
                "short_id": "a" * 8,
                "time": "2026-10-27T11:00:00.000000000Z",
                "tags": [
                    "barectl",
                    "site:alpha",
                    "scope:database",
                    "part:database",
                    "origin:manual",
                    "capture:live",
                    "point:0123456789abcdef",
                    "complete",
                ],
            },
            {
                "id": "b" * 64,
                "short_id": "b" * 8,
                "time": "2026-10-27T12:00:00.000000000Z",
                "tags": ["manual"],
            },
        ]
    )

    def test_only_barectl_points_are_listed(self) -> None:
        parsed = check.parse_listing(self.SNAPSHOTS)
        self.assertIsNotNone(parsed)
        points = check.points(parsed or [])
        self.assertEqual(len(points), 1)
        self.assertEqual(points[0]["scope"], "database")
        self.assertEqual(points[0]["point"], "0123456789abcdef")
        self.assertTrue(points[0]["complete"])

    def test_a_non_listing_is_unreadable(self) -> None:
        self.assertIsNone(check.parse_listing("{not json"))
        self.assertIsNone(check.parse_listing('{"snapshots": []}'))

    def test_the_listing_never_locks_the_repository(self) -> None:
        self.assertIn("--no-lock", check.listing_command(IDENTIFIER))

    def test_the_kit_holds_no_secret(self) -> None:
        lines = kit.lines(
            server_name="Web",
            identifier=IDENTIFIER,
            restic_version=RESTIC.version,
        )
        text = "\n".join(lines)
        self.assertIn(convention.repository(IDENTIFIER), text)
        self.assertIn("restic", text)
        self.assertNotIn("RESTIC_PASSWORD=", text)


class ApplyConsentTests(ChangeTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        confidential.reset()
        self.addCleanup(confidential.reset)

    def review(self, *, consent: str = Consent.SHARED) -> ChangeReview:
        draft: ReviewDraft = change.review_enable(evidence(), PreparationInputs("", IDENTIFIER))
        preparation = ChangePreparation.objects.create(
            server=self.server,
            kind_slug=change.ENABLE_SLUG,
            requested_by=self.user,
            ssh_alias=self.server.ssh_alias,
            inputs={"version": 1, "identifier": IDENTIFIER},
            status="succeeded",
        )
        now = timezone.now()
        return ChangeReview.objects.create(
            preparation=preparation,
            kind_slug=draft.kind,
            intent=draft.intent,
            eligible=True,
            consent=consent,
            writes_secrets=True,
            affected_sites=[IDENTIFIER],
            effects=[
                {"scope": "shared", "text": "Enable backups.", "sites": [IDENTIFIER]},
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

    def test_a_shared_change_needs_the_shared_and_escrow_acknowledgements(self) -> None:
        review = self.review()
        self.sign_in_with("view_changes", "change_shared", "manage_secrets")
        for data in (
            {"secret": CANARY},
            {"affected_sites": "on", "secret": CANARY},
            {"acknowledged": "on", "secret": CANARY},
        ):
            with self.subTest(data=data):
                response = self.apply_review(review, data)
                self.assertEqual(response.status_code, 302)
                self.assertFalse(ChangeRun.objects.exists())

    def test_the_wrong_consent_permission_is_denied(self) -> None:
        review = self.review()
        self.sign_in_with("view_changes", "change_site", "manage_secrets")
        response = self.apply_review(
            review,
            {"affected_sites": "on", "acknowledged": "on", "secret": CANARY},
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ChangeRun.objects.exists())

    def test_a_csrf_token_is_required(self) -> None:
        review = self.review()
        self.sign_in_with("view_changes", "change_shared", "manage_secrets")
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        response = client.post(
            f"/changes/{review.preparation_id}/apply/",
            {"affected_sites": "on", "acknowledged": "on", "secret": CANARY},
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ChangeRun.objects.exists())

    def test_the_passphrase_leaves_no_trace(self) -> None:
        review = self.review()
        self.sign_in_with("view_changes", "change_shared", "manage_secrets")
        response = self.apply_review(
            review,
            {"affected_sites": "on", "acknowledged": "on", "secret": CANARY},
        )
        self.assertEqual(response.status_code, 302)
        run = ChangeRun.objects.get(review=review)
        self.assertNotIn(CANARY, run.secret_sealed)
        self.run_worker()
        run.refresh_from_db()
        sources = [
            "\n".join(self.remote.commands),
            "\n".join(self.systemd.submissions),
            "\n".join(self.systemd.journals),
            "\n".join(self.systemd.systemctl_outputs),
        ]
        for model in (ChangeReview, ChangeRun):
            sources.extend(
                " ".join(str(getattr(row, field.name)) for field in model._meta.fields)
                for row in model.objects.all()
            )
        sources.extend(
            page.content.decode()
            for page in (
                response,
                self.client.get(f"/changes/{review.preparation_id}/"),
                self.client.get(f"/runs/{run.pk}/"),
            )
        )
        for source in sources:
            self.assertNotIn(CANARY, source)
        self.assertIn(
            hashlib.sha256(CANARY.encode()).hexdigest(),
            self.systemd.secret_digests,
        )
        self.assertEqual(run.secret_sealed, "")


class PageTests(ChangeTestCase):
    def store(self, *, backups: tuple[ObservedBackup, ...] = ()) -> Server:
        server = self.server
        attempt = record_attempt(server, DiscoveryAttempt.Status.SUCCEEDED)
        collected = COLLECTED.__class__(
            **{
                field: getattr(COLLECTED, field)
                for field in COLLECTED.__dataclass_fields__
                if field not in ("backups", "standing")
            },
            backups=Observation(
                ObservationOutcome.OBSERVED, ("/var/lib/barectl-backups",), "", backups
            ),
            standing=HostJudgment(Standing.TARGET_STACK, (), (), ()),
        )
        save_snapshot(attempt, collected, timezone.now())
        return server

    def test_opening_backups_makes_no_ssh_connection(self) -> None:
        server = self.store(
            backups=(
                observation.ObservedBackup(
                    IDENTIFIER,
                    RESTIC.path,
                    True,
                    True,
                    (),
                    True,
                    "",
                    None,
                ),
            )
        )
        self.sign_in_with("view_server", "view_changes", "view_siteobservation")
        self.remote.commands.clear()
        response = self.client.get(f"/servers/{server.pk}/sites/{IDENTIFIER}/backups/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Backups")
        self.assertEqual(self.remote.commands, [])

    def test_a_removed_server_forgets_finished_checks(self) -> None:
        from servers.registration import remove_server

        server = self.store(
            backups=(ObservedBackup(IDENTIFIER, RESTIC.path, True, True, (), True, "", None),)
        )
        row = BackupCheck.objects.create(
            server=server,
            identifier=IDENTIFIER,
            ssh_alias=server.ssh_alias,
            status="succeeded",
            listing={"version": 1, "outcome": "observed", "points": []},
        )
        remove_server(server)
        self.assertFalse(BackupCheck.objects.filter(pk=row.pk).exists())

    def test_database_only_is_disabled_with_its_reason(self) -> None:
        server = self.store(
            backups=(
                ObservedBackup(
                    IDENTIFIER,
                    RESTIC.path,
                    True,
                    True,
                    (),
                    False,
                    "This site has no site database.",
                    None,
                ),
            )
        )
        self.sign_in_with("view_server", "view_changes", "view_siteobservation")
        response = self.client.get(f"/servers/{server.pk}/sites/{IDENTIFIER}/backups/")
        self.assertContains(response, "Database only is unavailable.")
        self.assertContains(response, "This site has no site database.")

    def test_a_backup_check_stores_a_typed_listing_with_its_time(self) -> None:
        server = self.store(
            backups=(
                observation.ObservedBackup(
                    IDENTIFIER,
                    RESTIC.path,
                    True,
                    True,
                    (),
                    True,
                    "",
                    None,
                ),
            )
        )
        self.sign_in_with(
            "view_server", "view_changes", "view_siteobservation", "view_evidence", "change_site"
        )
        value = json.dumps(
            {
                "version": 1,
                "sites": [
                    {
                        "identifier": IDENTIFIER,
                        "profile": RESTIC.path,
                        "repository": True,
                        "key": True,
                        "problems": [],
                        "database": True,
                        "database_problem": "",
                        "last": None,
                    }
                ],
            }
        )
        self.remote.answer_root(
            observation.read_command((IDENTIFIER,), "postgresql", Architecture.X86_64),
            __import__("discovery.ssh", fromlist=["CommandResult"]).CommandResult(0, value),
        )
        listing = json.dumps(
            [
                {
                    "id": "c" * 64,
                    "time": "2026-10-27T11:00:00Z",
                    "tags": [
                        "barectl",
                        "site:alpha",
                        "scope:database",
                        "origin:manual",
                        "capture:live",
                        "point:0123456789abcdef",
                        "complete",
                    ],
                }
            ]
        )
        self.remote.answer_root(
            check.listing_command(IDENTIFIER),
            __import__("discovery.ssh", fromlist=["CommandResult"]).CommandResult(0, listing),
        )
        response = self.client.post(f"/servers/{server.pk}/sites/{IDENTIFIER}/backups/check/")
        self.assertEqual(response.status_code, 302)
        self.run_worker()
        row = check.latest_check(server, IDENTIFIER)
        if row is None:
            self.fail("No check was recorded.")
        self.assertIsNotNone(row.checked_at)
        self.assertEqual(row.listing["outcome"], "observed")
        self.assertEqual(len(row.listing["points"]), 1)
        page = self.client.get(f"/servers/{server.pk}/sites/{IDENTIFIER}/backups/")
        self.assertContains(page, "Saved here")


class FullReviewTests(ChangeTestCase):
    def enabled(
        self,
        *,
        database: bool = True,
        engine_name: str = "mariadb",
        current_sites: tuple[str, ...] = (IDENTIFIER,),
        disk_available: int = 2 * 1024 * 1024 * 1024,
    ) -> change.BackupEvidence:
        return evidence(
            enabled=True,
            profile=RESTIC.path,
            repository=True,
            key=True,
            database=database,
            engine_name=engine_name,
            current_sites=current_sites,
            disk_available=disk_available,
        )

    def test_a_full_capture_is_site_consent_and_names_what_it_pauses(self) -> None:
        draft = change.review_full(self.enabled(), PreparationInputs("", IDENTIFIER))
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(draft.document["scope"], "full")
        self.assertEqual(draft.effects[0].scope, Scope.SITE)
        self.assertIn("database and files", str(draft.effects[0].text))
        details = detail_rows(draft.document)
        self.assertIn("Visitors see a maintenance page", details["Site is paused"])
        self.assertIn("object cache", details["Excluded"])
        files = draft.document.get("files")
        if not isinstance(files, list):
            self.fail("The review named no files.")
        self.assertEqual(files[0], f"/var/www/{IDENTIFIER}/current")
        tags = draft.document.get("tags")
        if not isinstance(tags, dict):
            self.fail("The review named no tags.")
        self.assertTrue(tags["database"])
        self.assertTrue(tags["files"])
        change.body_full(draft.document, BodyContext("unit", BOOT, 0))

    def test_other_sites_make_the_caddy_step_shared_consent(self) -> None:
        draft = change.review_full(
            self.enabled(current_sites=(IDENTIFIER, "beta")),
            PreparationInputs("", IDENTIFIER),
        )
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual([effect.scope for effect in draft.effects], [Scope.SITE, Scope.SHARED])
        self.assertEqual(consent_of(draft.effects), Consent.SHARED)
        self.assertEqual(draft.current_sites, (IDENTIFIER, "beta"))

    def test_a_site_without_a_database_copies_files_only(self) -> None:
        draft = change.review_full(
            self.enabled(database=False, engine_name=""),
            PreparationInputs("", IDENTIFIER),
        )
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(draft.document["scope"], "files")
        self.assertEqual(draft.document["dump"], [])
        tags = draft.document.get("tags")
        if not isinstance(tags, dict):
            self.fail("The review named no tags.")
        self.assertNotIn("database", tags)
        change.body_full(draft.document, BodyContext("unit", BOOT, 0))

    def test_a_wordpress_full_capture_copies_the_release_and_private_file(self) -> None:
        draft = change.review_full(
            evidence(
                enabled=True,
                profile=RESTIC.path,
                repository=True,
                key=True,
                application="wordpress",
            ),
            PreparationInputs("", IDENTIFIER),
        )
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(
            draft.document["files"],
            [f"/var/www/{IDENTIFIER}/current", f"/var/www/{IDENTIFIER}/private/wp-config.php"],
        )
        self.assertEqual(draft.document["application"], "wordpress")
        change.body_full(draft.document, BodyContext("unit", BOOT, 0))

    def test_a_laravel_full_capture_copies_the_release_and_shared_state(self) -> None:
        draft = change.review_full(
            evidence(
                enabled=True,
                profile=RESTIC.path,
                repository=True,
                key=True,
                application="laravel",
            ),
            PreparationInputs("", IDENTIFIER),
        )
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(
            draft.document["files"],
            [
                f"/var/www/{IDENTIFIER}/current",
                f"/var/www/{IDENTIFIER}/private/laravel.env",
                f"/var/www/{IDENTIFIER}/private/storage",
                f"/var/www/{IDENTIFIER}/private/cache",
            ],
        )
        self.assertEqual(draft.document["application"], "laravel")
        change.body_full(draft.document, BodyContext("unit", BOOT, 0))

    def test_recorded_full_listings_verify_each_site_kinds_capture(self) -> None:
        point = "e1fa817d57ef0663"
        command = change.point_snapshots_command(IDENTIFIER, point)
        shell = ReplayShell(
            Transcript(
                "backups",
                {},
                "26.04",
                "x86_64",
                "ssh-ed25519 SHA256:x",
                (
                    ("id -u", Recorded(ssh.CommandResult(0, "0\n"))),
                    (
                        command,
                        Recorded(
                            ssh.CommandResult(
                                0,
                                importlib.resources.files("backups.fixtures")
                                .joinpath("restic-full-snapshots.txt")
                                .read_text(encoding="utf-8"),
                            )
                        ),
                    ),
                ),
            )
        )
        for application in ("wordpress", "laravel"):
            with self.subTest(application=application):
                with mock.patch("backups.change.secrets.token_hex", return_value=point):
                    draft = change.review_full(
                        evidence(
                            enabled=True,
                            profile=RESTIC.path,
                            repository=True,
                            key=True,
                            application=application,
                        ),
                        PreparationInputs("", IDENTIFIER),
                    )
                review = cast(ChangeReview, SimpleNamespace(document=draft.document))
                self.assertTrue(change.verify_full(shell, review))

    def test_a_shortage_of_free_space_refuses_the_review(self) -> None:
        draft = change.review_full(
            self.enabled(disk_available=1024),
            PreparationInputs("", IDENTIFIER),
        )
        self.assertFalse(draft.eligible)
        self.assertIn("free space", " ".join(draft.refusals))

    def test_a_forged_full_capture_is_refused(self) -> None:
        draft = change.review_full(self.enabled(), PreparationInputs("", IDENTIFIER))
        for key, value in (
            ("caddy", "not the reviewed site"),
            ("gate", "not the reviewed gate"),
            ("repository", "/var/lib/barectl-backups/other/onsite"),
        ):
            with self.subTest(key=key):
                forged = dict(draft.document)
                forged[key] = value
                with self.assertRaises(ValueError):
                    change.body_full(forged, BodyContext("unit", BOOT, 0))


class FullPointTests(ChangeTestCase):
    def test_a_full_point_needs_both_complete_parts(self) -> None:
        point = "0123456789abcdef"
        full = convention.tags
        snapshots = [
            {
                "id": "a" * 64,
                "time": "2026-10-29T04:00:00Z",
                "tags": list(
                    full(
                        IDENTIFIER,
                        "full",
                        part="database",
                        origin="manual",
                        live=False,
                        point=point,
                    )
                ),
            },
            {
                "id": "b" * 64,
                "time": "2026-10-29T04:00:00Z",
                "tags": list(
                    full(
                        IDENTIFIER,
                        "full",
                        part="files",
                        origin="manual",
                        live=False,
                        point=point,
                    )
                ),
            },
        ]
        parsed = check.parse_listing(json.dumps(snapshots))
        points = check.points(parsed or [])
        self.assertEqual(len(points), 1)
        self.assertEqual(points[0]["scope"], "full")
        self.assertTrue(points[0]["complete"])

    def test_half_a_full_point_is_listed_but_never_restorable(self) -> None:
        point = "0123456789abcdef"
        snapshots = [
            {
                "id": "a" * 64,
                "time": "2026-10-29T04:00:00Z",
                "tags": list(
                    convention.tags(
                        IDENTIFIER,
                        "full",
                        part="database",
                        origin="manual",
                        live=False,
                        point=point,
                    )
                ),
            }
        ]
        parsed = check.parse_listing(json.dumps(snapshots))
        points = check.points(parsed or [])
        self.assertEqual(len(points), 1)
        self.assertFalse(points[0]["complete"])
        self.assertEqual(points[0]["missing"], ["files"])

    def test_a_complete_part_without_complete_tags_is_not_restorable(self) -> None:
        point = "0123456789abcdef"
        snapshots = [
            {
                "id": "a" * 64,
                "time": "2026-10-29T04:00:00Z",
                "tags": list(
                    convention.tags(
                        IDENTIFIER,
                        "full",
                        part="database",
                        origin="manual",
                        live=False,
                        point=point,
                        complete=False,
                    )
                ),
            },
            {
                "id": "b" * 64,
                "time": "2026-10-29T04:00:00Z",
                "tags": list(
                    convention.tags(
                        IDENTIFIER,
                        "full",
                        part="files",
                        origin="manual",
                        live=False,
                        point=point,
                        complete=False,
                    )
                ),
            },
        ]
        points = check.points(check.parse_listing(json.dumps(snapshots)) or [])
        self.assertEqual(len(points), 1)
        self.assertFalse(points[0]["complete"])
        self.assertEqual(points[0]["incomplete"], ["database", "files"])


class ReopenReviewTests(ChangeTestCase):
    def record(self, *, gated: bool = True) -> dict[str, object]:
        return site_record(
            state="partial" if gated else "complete",
            problem=SITE_GATED if gated else "",
            serving_form="maintenance" if gated else "plain",
        )

    def test_a_gated_site_is_reopened_by_one_reviewed_change(self) -> None:
        from . import reopen

        draft = reopen.review(
            reopen.ReopenEvidence(
                Standing.TARGET_STACK,
                self.record(),
                BOOT,
                100,
                (IDENTIFIER,),
            ),
            PreparationInputs("", IDENTIFIER),
        )
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(draft.effects[0].scope, Scope.SITE)
        details = detail_rows(draft.document)
        self.assertIn("maintenance page", details["Visitors"].lower())
        reopen.body(draft.document, BodyContext("unit", BOOT, 0))
        forged = dict(draft.document)
        forged["caddy"] = "not the reviewed site"
        with self.assertRaises(ValueError):
            reopen.body(forged, BodyContext("unit", BOOT, 0))

    def test_a_site_that_is_not_gated_has_nothing_to_reopen(self) -> None:
        from . import reopen

        draft = reopen.review(
            reopen.ReopenEvidence(Standing.TARGET_STACK, self.record(gated=False), BOOT, 100, ()),
            PreparationInputs("", IDENTIFIER),
        )
        self.assertFalse(draft.eligible)
        self.assertIn("not paused", " ".join(draft.refusals))


class FullApplyConsentTests(ChangeTestCase):
    def full_review(self) -> ChangeReview:
        draft = change.review_full(
            evidence(
                enabled=True,
                profile=RESTIC.path,
                repository=True,
                key=True,
                current_sites=(IDENTIFIER, "beta"),
                disk_available=2 * 1024 * 1024 * 1024,
            ),
            PreparationInputs("", IDENTIFIER),
        )
        preparation = ChangePreparation.objects.create(
            server=self.server,
            kind_slug=change.FULL_SLUG,
            requested_by=self.user,
            ssh_alias=self.server.ssh_alias,
            inputs={"version": 1, "identifier": IDENTIFIER},
            status="succeeded",
        )
        now = timezone.now()
        return ChangeReview.objects.create(
            preparation=preparation,
            kind_slug=draft.kind,
            intent=draft.intent,
            eligible=True,
            consent=Consent.SHARED,
            affected_sites=[IDENTIFIER, "beta"],
            effects=[
                {"scope": "shared", "text": "Reload Caddy.", "sites": [IDENTIFIER, "beta"]},
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

    def test_site_consent_cannot_apply_a_shared_full_capture(self) -> None:
        review = self.full_review()
        self.sign_in_with("view_changes", "change_site")
        response = self.client.post(
            f"/changes/{review.preparation_id}/apply/", {"affected_sites": "on"}
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ChangeRun.objects.exists())

    def test_a_full_capture_apply_needs_csrf(self) -> None:
        review = self.full_review()
        self.sign_in_with("view_changes", "change_shared")
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        response = client.post(f"/changes/{review.preparation_id}/apply/", {"affected_sites": "on"})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ChangeRun.objects.exists())

    def test_a_shared_full_capture_needs_the_affected_sites_tick(self) -> None:
        review = self.full_review()
        self.sign_in_with("view_changes", "change_shared")
        response = self.client.post(f"/changes/{review.preparation_id}/apply/", {})
        self.assertEqual(response.status_code, 302)
        self.assertFalse(ChangeRun.objects.exists())


class FullPageTests(ChangeTestCase):
    def store(self, *, gated: bool, last: observation.BackupResult) -> Server:
        from .testing import record_backups

        server = self.server
        record_backups(server, gated=gated, last=last)
        self.sign_in_with(
            "view_server", "view_changes", "view_siteobservation", "view_evidence", "change_site"
        )
        return server

    def test_full_site_is_offered_and_prepares_its_own_kind(self) -> None:
        from .testing import result

        server = self.store(gated=False, last=result())
        page = self.client.get(f"/servers/{server.pk}/sites/shop/backups/")
        self.assertContains(page, "Full site (pauses the site briefly)")
        response = self.client.post(
            f"/servers/{server.pk}/sites/shop/backups/back-up/prepare/", {"scope": "full"}
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(ChangePreparation.objects.get(server=server).kind_slug, change.FULL_SLUG)

    def test_a_gated_site_shows_one_sentence_and_one_reopen_action_without_ssh(self) -> None:
        from .testing import result

        server = self.store(
            gated=True,
            last=result(result_class="partial", scope="full", reason="backup_paused"),
        )
        self.remote.commands.clear()
        page = self.client.get(f"/servers/{server.pk}/sites/shop/backups/")
        self.assertContains(
            page, "This stopped after pausing the site for a full backup. Nothing after it ran."
        )
        self.assertContains(page, "Reopen site")
        self.assertEqual(self.remote.commands, [])
        overview = self.client.get(f"/servers/{server.pk}/sites/shop/")
        self.assertContains(
            overview,
            "This stopped after pausing the site for a full backup. Nothing after it ran.",
        )
        self.assertEqual(self.remote.commands, [])
        response = self.client.post(f"/servers/{server.pk}/sites/shop/backups/reopen/prepare/")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(ChangePreparation.objects.get(server=server).kind_slug, "reopen_site")

    def test_a_gate_from_another_change_does_not_offer_the_backup_action(self) -> None:
        from .testing import result

        server = self.store(gated=True, last=result(scope="full"))
        page = self.client.get(f"/servers/{server.pk}/sites/shop/backups/")
        self.assertNotContains(page, "Reopen site")
        self.assertNotContains(
            page, "This stopped after pausing the site for a full backup. Nothing after it ran."
        )

    def test_an_invalid_backup_scope_is_refused(self) -> None:
        from .testing import result

        server = self.store(gated=False, last=result())
        response = self.client.post(
            f"/servers/{server.pk}/sites/shop/backups/back-up/prepare/", {"scope": "other"}
        )
        self.assertEqual(response.status_code, 404)
        self.assertFalse(ChangePreparation.objects.exists())
