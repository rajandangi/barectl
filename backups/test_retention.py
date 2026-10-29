"""Retention and Keep: recorded restic output, consent, bodies and the Backups page (#404)."""

import base64
import gzip
import importlib.resources
import json
from datetime import timedelta
from typing import TYPE_CHECKING, cast

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
from runtimes.catalog import Architecture, load

from . import change, convention, observation, retention
from .bodies import retention as retention_body
from .models import BackupRetention
from .testing import point, record_backups, record_points

IDENTIFIER = "alpha"
BOOT = "8f14e45f-ea6f-4c1c-9b7b-2f0f4c1c9b7b"
POINT = "1111111111111111"
RESTIC = next(
    build for build in load().offered(Architecture.X86_64) if build.entry == convention.RESTIC_ENTRY
)


def fixture(name: str) -> str:
    return importlib.resources.files("backups.fixtures").joinpath(name).read_text(encoding="utf-8")


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


def base_evidence(
    *, enabled: bool = True, offsite: observation.OffsiteStorage | None = None
) -> change.BackupEvidence:
    backup = observation.ObservedBackup(
        IDENTIFIER,
        RESTIC.path if enabled else "",
        enabled,
        enabled,
        (),
        True,
        "",
        None,
        offsite,
    )
    return change.BackupEvidence(
        Architecture.X86_64,
        Standing.TARGET_STACK,
        "mariadb",
        site_record(),
        True,
        "",
        backup,
        "",
        BOOT,
        100,
        RESTIC.path,
        RESTIC.version,
        2 * 1024 * 1024 * 1024,
        (IDENTIFIER,),
        offsite,
    )


def survey(
    *,
    deleting: tuple[str, ...] = (POINT,),
    foreign: int = 1,
) -> retention.LocationSurvey:
    rows: list[dict[str, object]] = [
        {
            "location": "onsite",
            "scope": "database",
            "point": point_id,
            "time": "2026-09-01T03:00:00Z",
        }
        for point_id in deleting
    ]
    return retention.LocationSurvey(tuple(rows), foreign, "")


def retained_evidence(
    *, installed: bool = False, days: int = 0, clock: bool = True
) -> retention.RetentionEvidence:
    policy = retention.RetentionPolicy(
        installed=installed,
        days=days,
        offsite=False,
        texts=dict.fromkeys(retention.unit_key_paths(IDENTIFIER)),
    )
    return retention.RetentionEvidence(
        base_evidence(), policy, clock, survey(), retention.LocationSurvey()
    )


class RecordedRetentionTests(SimpleTestCase):
    def test_the_recorded_dry_run_lists_the_old_point_at_the_shell_seam(self) -> None:
        point_id = POINT
        snapshot_command = retention.onsite_command(IDENTIFIER, "snapshots", "--json", "--no-lock")
        forget_command = retention.onsite_command(
            IDENTIFIER, *retention.forget_argv(7, "database", "database", dry_run=True)
        )
        shell = ReplayShell(
            Transcript(
                "retention",
                {},
                "26.04",
                "x86_64",
                "ssh-ed25519 SHA256:x",
                (
                    ("id -u", Recorded(ssh.CommandResult(0, "0\n"))),
                    ("id -u", Recorded(ssh.CommandResult(0, "0\n"))),
                    (
                        snapshot_command,
                        Recorded(ssh.CommandResult(0, fixture("restic-retention-snapshots.txt"))),
                    ),
                    (
                        forget_command,
                        Recorded(ssh.CommandResult(0, fixture("restic-forget-dry-run.txt"))),
                    ),
                ),
            )
        )
        found = retention.survey(shell, IDENTIFIER, None, 7)
        self.assertEqual(found.problem, "")
        self.assertEqual([row["point"] for row in found.deletions], [point_id])
        self.assertEqual(found.foreign, 1)

    def test_the_recorded_clock_is_read_at_the_shell_seam(self) -> None:
        shell = ReplayShell(
            Transcript(
                "retention-clock",
                {},
                "26.04",
                "x86_64",
                "ssh-ed25519 SHA256:x",
                (
                    ("id -u", Recorded(ssh.CommandResult(0, "0\n"))),
                    (
                        retention.clock_command(),
                        Recorded(ssh.CommandResult(0, fixture("timedatectl-ntp-synchronized.txt"))),
                    ),
                ),
            )
        )
        self.assertTrue(retention.read_clock(shell))

    def test_the_recorded_forget_names_its_removed_point(self) -> None:
        removed = retention._forget_points(fixture("restic-forget.txt"))
        self.assertEqual(removed, {POINT})

    def test_the_recorded_prune_is_a_successful_text_result(self) -> None:
        self.assertIn("done", fixture("restic-prune.txt"))
        self.assertNotIn("config", fixture("restic-prune.txt"))


class RetentionReviewTests(SimpleTestCase):
    def test_a_policy_is_destructive_consent_and_lists_what_would_go_now(self) -> None:
        draft = retention.review_set(retained_evidence(), PreparationInputs("", IDENTIFIER, days=7))
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(consent_of(draft.effects), Consent.DESTRUCTIVE)
        self.assertEqual(draft.effects[0].scope, Scope.SITE)
        details = {
            str(row["label"]): str(row["value"])
            for row in cast("list[dict[str, object]]", draft.document["details"])
        }
        self.assertEqual(details["Keep backups for"], "1 week")
        self.assertIn("would be deleted now", details["Would be deleted now"])
        self.assertIn("permanent", details["Deletion is permanent"])
        self.assertIn("deletes nothing now", str(draft.document["note"]))
        deletions = cast("list[dict[str, object]]", draft.document["deletions"])
        self.assertEqual(deletions[0]["point"], POINT)

    def test_an_unsynchronized_clock_is_named_and_does_not_refuse_the_review(self) -> None:
        draft = retention.review_set(
            retained_evidence(clock=False), PreparationInputs("", IDENTIFIER, days=14)
        )
        self.assertTrue(draft.eligible, draft.refusals)
        details = {
            str(row["label"]): str(row["value"])
            for row in cast("list[dict[str, object]]", draft.document["details"])
        }
        self.assertIn("not synchronized", details["Server clock"])

    def test_the_same_policy_is_a_no_change_review(self) -> None:
        draft = retention.review_set(
            retained_evidence(installed=True, days=7), PreparationInputs("", IDENTIFIER, days=7)
        )
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertTrue(draft.no_changes)
        self.assertIn("already set", str(draft.document["note"]))

    def test_a_policy_needs_backups_enabled(self) -> None:
        evidence = retention.RetentionEvidence(
            base_evidence(enabled=False),
            retention.RetentionPolicy(),
            True,
            retention.LocationSurvey(),
            retention.LocationSurvey(),
        )
        draft = retention.review_set(evidence, PreparationInputs("", IDENTIFIER, days=7))
        self.assertFalse(draft.eligible)
        self.assertIn("Enable backups", " ".join(draft.refusals))

    def test_a_keep_review_is_site_consent_and_toggles_only_keep(self) -> None:
        evidence = retention.KeepEvidence(
            base_evidence(),
            {"point": POINT, "time": "2026-10-28T03:00:00Z", "scope": "database"},
            ("a" * 64,),
            False,
        )
        draft = retention.review_keep(evidence, PreparationInputs("", IDENTIFIER, point=POINT))
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual(consent_of(draft.effects), Consent.SITE)
        self.assertEqual(draft.document["action"], "add")
        self.assertEqual(draft.document["snapshots"], ["a" * 64])
        self.assertEqual(draft.document["kind"], "keep")

    def test_a_kept_point_offers_to_stop_keeping(self) -> None:
        evidence = retention.KeepEvidence(
            base_evidence(),
            {"point": POINT, "time": "2026-10-28T03:00:00Z", "scope": "database"},
            ("a" * 64,),
            True,
        )
        draft = retention.review_keep(evidence, PreparationInputs("", IDENTIFIER, point=POINT))
        self.assertEqual(draft.document["action"], "remove")


class RetentionBodyTests(SimpleTestCase):
    def test_a_forged_period_is_refused_by_the_body(self) -> None:
        draft = retention.review_set(retained_evidence(), PreparationInputs("", IDENTIFIER, days=7))
        forged = dict(draft.document)
        forged["days"] = 1
        with self.assertRaises(ValueError):
            retention.body_set(forged, BodyContext("unit", BOOT, 0))

    def test_a_forged_offsite_destination_is_refused_by_the_body(self) -> None:
        draft = retention.review_set(retained_evidence(), PreparationInputs("", IDENTIFIER, days=7))
        forged = dict(draft.document)
        forged["offsite"] = {
            "repository": "s3:https://elsewhere/bucket/prefix/alpha",
            "capture_env": convention.OFFSITE_CAPTURE,
            "prune_env": convention.OFFSITE_PRUNE,
            "storage": {
                "provider": "s3",
                "bucket": "bucket",
                "region": "us-east-1",
                "endpoint": "https://s3.us-east-1.amazonaws.com",
                "prefix": "prefix",
                "prune": "yes",
            },
        }
        with self.assertRaises(ValueError):
            retention.body_set(forged, BodyContext("unit", BOOT, 0))

    def test_a_reviewed_offsite_plan_is_accepted_by_the_body(self) -> None:
        storage = observation.OffsiteStorage(
            "s3",
            "barectl-backups",
            "us-east-1",
            "https://s3.us-east-1.amazonaws.com",
            "barectl/0123456789abcdef",
        )
        policy = retention.RetentionPolicy(
            texts=dict.fromkeys(retention.unit_key_paths(IDENTIFIER))
        )
        evidence = retention.RetentionEvidence(
            base_evidence(offsite=storage),
            policy,
            True,
            survey(),
            survey(),
        )
        draft = retention.review_set(evidence, PreparationInputs("", IDENTIFIER, days=7))
        self.assertTrue(draft.eligible, draft.refusals)
        body = retention.body_set(draft.document, BodyContext("unit", BOOT, 0))
        self.assertEqual(body.source, retention.RETENTION_BYTES)
        decoded = json.loads(gzip.decompress(base64.b64decode(body.arguments[0])))
        self.assertEqual(decoded["filename"], "salpha.sql")
        self.assertEqual(decoded["offsite"]["prune_env"], convention.OFFSITE_PRUNE)

    def test_a_keep_body_carries_only_the_reviewed_point(self) -> None:
        body = retention.body_keep(
            {
                "version": 1,
                "body_sha256": retention.KEEP_SHA256,
                "kind": "keep",
                "identifier": IDENTIFIER,
                "point": POINT,
                "action": "add",
                "snapshots": ["a" * 64],
                "repository": convention.repository(IDENTIFIER),
                "server_key": convention.server_key(IDENTIFIER),
            },
            BodyContext("unit", BOOT, 0),
        )
        self.assertEqual(body.source, retention.KEEP_BYTES)
        self.assertEqual(len(body.arguments), 1)
        decoded = json.loads(gzip.decompress(base64.b64decode(body.arguments[0])))
        self.assertEqual(decoded["point"], POINT)
        self.assertEqual(decoded["action"], "add")

    def test_the_keep_body_refuses_an_unknown_snapshot(self) -> None:
        document = {
            "version": 1,
            "body_sha256": retention.KEEP_SHA256,
            "kind": "keep",
            "identifier": IDENTIFIER,
            "point": POINT,
            "action": "add",
            "snapshots": ["not-a-snapshot"],
            "repository": convention.repository(IDENTIFIER),
            "server_key": convention.server_key(IDENTIFIER),
        }
        with self.assertRaises(ValueError):
            retention.body_keep(document, BodyContext("unit", BOOT, 0))

    def test_a_cleanup_result_line_carries_counts_and_no_location(self) -> None:
        value = retention_body._result(
            {"identifier": IDENTIFIER},
            "onsite",
            {"deleted": 1, "kept": 2, "skipped": 0, "failed": 0, "foreign": 3},
        )
        onsite = cast("dict[str, int]", value["onsite"])
        offsite = cast("dict[str, int]", value["offsite"])
        self.assertEqual(onsite["deleted"], 1)
        self.assertEqual(offsite["deleted"], 0)
        text = json.dumps(value)
        self.assertNotIn("/var/lib", text)
        self.assertNotIn("s3:", text)


class RetentionRequestTests(ChangeTestCase):
    def review(self, days: int = 7) -> ChangeReview:
        draft: ReviewDraft = retention.review_set(
            retained_evidence(), PreparationInputs("", IDENTIFIER, days=days)
        )
        preparation = ChangePreparation.objects.create(
            server=self.server,
            kind_slug=retention.SET_SLUG,
            requested_by=self.user,
            ssh_alias=self.server.ssh_alias,
            inputs={"version": 1, "identifier": IDENTIFIER, "days": days},
            status="succeeded",
        )
        now = timezone.now()
        return ChangeReview.objects.create(
            preparation=preparation,
            kind_slug=draft.kind,
            intent=draft.intent,
            eligible=True,
            consent=Consent.DESTRUCTIVE,
            writes_secrets=False,
            affected_sites=[IDENTIFIER],
            effects=[{"scope": "site", "text": "Delete old points.", "sites": [IDENTIFIER]}],
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

    def test_site_consent_cannot_apply_a_destructive_retention_policy(self) -> None:
        review = self.review()
        self.sign_in_with("view_changes", "change_site")
        response = self.apply_review(review, {"confirmation": IDENTIFIER})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ChangeRun.objects.exists())

    def test_a_retention_apply_needs_csrf(self) -> None:
        review = self.review()
        self.sign_in_with("view_changes", "change_destructive")
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        response = client.post(
            f"/changes/{review.preparation_id}/apply/",
            {"confirmation": IDENTIFIER},
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ChangeRun.objects.exists())

    def test_preparing_retention_needs_csrf(self) -> None:
        self.sign_in_with("view_server", "view_changes", "change_site")
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        response = client.post(
            f"/servers/{self.server.pk}/sites/{IDENTIFIER}/backups/retention/prepare/",
            {"days": "7"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ChangePreparation.objects.exists())

    def test_opening_backups_makes_no_ssh_connection_with_a_policy(self) -> None:
        record_backups(self.server, identifier=IDENTIFIER)
        record_points(self.server, (point(),), identifier=IDENTIFIER)
        BackupRetention.objects.create(
            server=self.server,
            identifier=IDENTIFIER,
            installed=True,
            days=14,
            checked_at=timezone.now(),
        )
        self.sign_in_with("view_server", "view_changes", "view_siteobservation")
        self.remote.commands.clear()
        response = self.client.get(f"/servers/{self.server.pk}/sites/{IDENTIFIER}/backups/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Keep backups for")
        self.assertContains(response, "2 weeks")
        self.assertContains(response, "Keep")
        self.assertEqual(self.remote.commands, [])

    def test_keep_is_offered_on_a_restorable_point(self) -> None:
        record_backups(self.server, identifier=IDENTIFIER)
        record_points(self.server, (point(),), identifier=IDENTIFIER)
        self.sign_in_with("view_server", "view_changes", "view_siteobservation", "change_site")
        response = self.client.get(f"/servers/{self.server.pk}/sites/{IDENTIFIER}/backups/")
        self.assertContains(response, "Keep")
