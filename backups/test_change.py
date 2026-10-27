"""Enable backups and Back up now: reviews, bodies, consent and the secret canary (#396)."""

import hashlib
import json
from datetime import timedelta
from typing import TYPE_CHECKING, override

from django.test import Client
from django.utils import timezone

if TYPE_CHECKING:
    from django.test.client import _MonkeyPatchedWSGIResponse

from backups.observation import ObservedBackup
from bootstrap.standing import HostJudgment, Standing
from discovery.fakes import COLLECTED, record_attempt
from discovery.models import DiscoveryAttempt, ObservationOutcome
from discovery.snapshot import Observation, save_snapshot
from operations import confidential, engine
from operations.consent import Scope
from operations.engine import BodyContext, ReviewDraft
from operations.fakes import ChangeTestCase
from operations.inputs import PreparationInputs
from operations.models import ChangePreparation, ChangeReview, ChangeRun, Consent
from runtimes.catalog import Architecture, load
from servers.models import Server

from . import change, check, convention, kit, observation
from .bodies import backup as backup_body
from .models import BackupCheck

IDENTIFIER = "alpha"
BOOT = "8f14e45f-ea6f-4c1c-9b7b-2f0f4c1c9b7b"
CANARY = "barectl-canary-backup-passphrase-4a7e"
RESTIC = next(
    build for build in load().offered(Architecture.X86_64) if build.entry == convention.RESTIC_ENTRY
)


def site_record(**values: object) -> dict[str, object]:
    return {
        "identifier": IDENTIFIER,
        "runtime": "php84",
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
        site=site_record(),
        database=database,
        database_problem="" if database else "This site has no site database.",
        backup=backup,
        problem="",
        boot_id=BOOT,
        uptime_centiseconds=100,
        restic_path=RESTIC.path,
        restic_version=RESTIC.version,
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

    def test_a_site_without_a_database_is_refused(self) -> None:
        draft = change.review_enable(evidence(database=False), PreparationInputs("", IDENTIFIER))
        self.assertFalse(draft.eligible)
        self.assertIn("no site database", " ".join(draft.refusals))

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
                self.assertEqual(backup_body.classify(*arguments), expected)


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
        self.sign_in_with("view_server", "view_changes", "view_siteobservation", "view_evidence")
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
