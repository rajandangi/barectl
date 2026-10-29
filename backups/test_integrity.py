"""The weekly integrity finding: recorded output, review units and the Backups page (#405)."""

import importlib.resources
import json
from datetime import UTC, datetime
from typing import cast

from django.test import Client, SimpleTestCase

from discovery import ssh
from discovery.models import ObservationOutcome, SiteState
from discovery.recorded import Recorded, ReplayShell, Transcript
from discovery.snapshot import ObservedSite
from operations.fakes import ChangeTestCase
from operations.inputs import PreparationInputs

from . import change, check, convention, integrity, observation, presentation
from .bodies import integrity as integrity_body
from .testing import integrity as finding
from .testing import point, record_backups, record_points, result

IDENTIFIER = "shop"
POINT = "1111111111111111"


def fixture(name: str) -> str:
    return importlib.resources.files("backups.fixtures").joinpath(name).read_text(encoding="utf-8")


def replay(text: str) -> ReplayShell:
    command = integrity.journal_command()
    return ReplayShell(
        Transcript(
            "integrity",
            {},
            "26.04",
            "x86_64",
            "ssh-ed25519 SHA256:x",
            (
                ("id -u", Recorded(ssh.CommandResult(0, "0\n"))),
                (command, Recorded(ssh.CommandResult(0, text))),
            ),
        )
    )


class RecordedIntegrityTests(SimpleTestCase):
    def test_a_recorded_read_data_check_is_a_successful_finding(self) -> None:
        self.assertIn("read 7/20 data packs", fixture("restic-check-read-data.txt"))
        self.assertIn("no errors were found", fixture("restic-check-read-data.txt"))
        findings = integrity.read_results(
            replay(fixture("integrity-result-succeeded.txt")), "alpha"
        )
        if findings is None:
            self.fail("The recorded result was not accepted.")
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0].verified)
        self.assertEqual(findings[0].point, POINT)
        self.assertEqual(findings[0].subset, "7/20")
        self.assertEqual(findings[0].size, 4096)

    def test_a_recorded_corrupted_pack_is_an_integrity_failure(self) -> None:
        self.assertIn("pack", fixture("restic-check-corrupt.txt"))
        self.assertIn("repository contains errors", fixture("restic-check-corrupt.txt"))
        findings = integrity.read_results(replay(fixture("integrity-result-corrupt.txt")), "alpha")
        if findings is None:
            self.fail("The recorded result was not accepted.")
        self.assertEqual(findings[0].result_class, "failed")
        self.assertEqual(findings[0].reason, "integrity_pack")
        self.assertFalse(findings[0].verified)

    def test_a_recorded_lock_skip_is_never_success_or_verified(self) -> None:
        findings = integrity.read_results(
            replay(fixture("integrity-result-lock-skip.txt")), "alpha"
        )
        if findings is None:
            self.fail("The recorded result was not accepted.")
        self.assertEqual(findings[0].result_class, "lock_busy")
        self.assertFalse(findings[0].verified)
        self.assertEqual(
            presentation.integrity_views(findings)[0].headline, "The last check was skipped."
        )

    def test_a_check_exit_code_maps_to_one_result_class(self) -> None:
        self.assertEqual(integrity_body._check_failure(10), ("refused", "backup_repository", 1))
        self.assertEqual(integrity_body._check_failure(11), ("lock_busy", "backup_lock", 10))
        self.assertEqual(integrity_body._check_failure(12), ("refused", "backup_password", 1))
        self.assertEqual(integrity_body._check_failure(1), ("failed", "integrity_pack", 3))


class RotationTests(SimpleTestCase):
    def test_the_read_data_subset_advances_per_run_and_wraps(self) -> None:
        self.assertEqual(integrity_body.rotate("3/20"), "4/20")
        self.assertEqual(integrity_body.rotate("20/20"), "1/20")
        self.assertRegex(integrity_body.rotate(None, now=0), r"\A([1-9]|1[0-9]|20)/20\Z")

    def test_a_weekly_start_covers_every_subset_over_twenty_weeks(self) -> None:
        week = 7 * 86400
        values = {integrity_body.default_subset(now=week * index) for index in range(20)}
        self.assertEqual(len(values), 20)


class IntegrityReviewTests(SimpleTestCase):
    def test_enable_reviews_the_two_weekly_units(self) -> None:
        from .test_change import evidence

        draft = change.review_enable(evidence(), PreparationInputs("", "alpha"))
        self.assertTrue(draft.eligible, draft.refusals)
        raw = draft.document.get("check")
        if not isinstance(raw, dict):
            self.fail("Enable backups reviewed no integrity check.")
        units = cast("dict[str, object]", raw["units"])
        self.assertEqual(set(units), set(integrity_body.UNIT_KEYS))
        onsite = str(units["check.timer"])
        self.assertIn("OnCalendar=Sun *-*-* 05:15:00 UTC", onsite)
        self.assertIn("Persistent=false", onsite)
        service = str(units["check.service"])
        self.assertIn("/etc/barectl/backups/integrity/alpha.sh check", service)
        self.assertIn(" check ", service)
        self.assertNotIn("PASSWORD", service)
        payload = cast("dict[str, object]", raw["payload"])
        self.assertEqual(payload["server_key"], convention.server_key("alpha"))

    def test_a_forged_integrity_setup_is_refused(self) -> None:
        from .test_change import evidence

        draft = change.review_enable(evidence(), PreparationInputs("", "alpha"))
        forged = json.loads(json.dumps(draft.document))
        forged["check"]["units"]["check.timer"] = "[Timer]\nOnCalendar=daily\n"
        with self.assertRaises(ValueError):
            integrity.validate_enable(forged)

    def test_a_forged_payload_is_refused_by_the_body(self) -> None:
        document = {
            "version": 1,
            "identifier": "alpha",
            "repository": "/var/lib/barectl-backups/beta/onsite",
            "server_key": convention.server_key("alpha"),
            "filename": convention.dump_filename("alpha"),
        }
        with self.assertRaises(ValueError):
            integrity_body.checked_document(document)

    def test_a_result_line_carries_counts_bytes_and_no_location(self) -> None:
        value = integrity_body._result(
            {"identifier": "alpha"},
            "onsite",
            "succeeded",
            point=POINT,
            checked=2,
            snapshots=1,
            size=4096,
            subset="7/20",
        )
        self.assertEqual(value["kind"], "integrity")
        self.assertEqual(value["point"], POINT)
        self.assertEqual(value["bytes"], 4096)
        self.assertEqual(value["subset"], "7/20")
        text = json.dumps(value)
        self.assertNotIn("/var/lib", text)
        self.assertNotIn("s3:", text)

    def test_the_staged_enable_body_compiles_with_the_check(self) -> None:
        compile(change.ENABLE_SOURCE, "enable-backups-body", "exec")


class VerifiedPresentationTests(SimpleTestCase):
    def listing(self) -> dict[str, object]:
        return {
            "version": 1,
            "outcome": "observed",
            "points": [point(point=POINT)],
        }

    def test_a_listing_alone_never_marks_a_point_verified(self) -> None:
        rows = presentation.points_view(self.listing())
        self.assertEqual(rows[0].status, "Saved here")
        self.assertEqual(rows[0].verified, "Not verified")

    def test_a_successful_check_without_a_read_back_never_verifies(self) -> None:
        rows = presentation.points_view(self.listing(), integrity=(finding(point=""),))
        self.assertEqual(rows[0].verified, "Not verified")

    def test_only_the_read_back_point_is_verified_and_with_its_time(self) -> None:
        rows = presentation.points_view(self.listing(), integrity=(finding(point=POINT),))
        self.assertEqual(rows[0].verified, "On this server, 30 Oct 2026, 05:15")

    def test_a_corrupted_pack_does_not_change_the_capture_result(self) -> None:
        backup = observation.ObservedBackup(
            IDENTIFIER,
            "/nix/store/rac858616ds2w2z3db69kp80vr9s8mkp-restic-0.18.1",
            True,
            True,
            (),
            True,
            "",
            result(),
            None,
            None,
            (finding(result_class="failed", reason="integrity_pack", point=""),),
        )
        last = presentation.last_view(backup)
        if last is None:
            self.fail("The capture result was not shown.")
        self.assertEqual(last.headline, "Database only saved.")
        views = presentation.integrity_views(backup.integrity)
        self.assertEqual(views[0].headline, "The last check found damaged data.")
        self.assertFalse(views[0].verified)
        self.assertTrue(views[1].headline.startswith("Not checked"))


class IntegrityObservationTests(SimpleTestCase):
    def test_a_discovery_answer_carries_its_integrity_finding(self) -> None:
        row = {
            "identifier": IDENTIFIER,
            "profile": "",
            "repository": False,
            "key": False,
            "problems": [],
            "database": False,
            "database_problem": "",
            "last": None,
            "integrity": {
                "onsite": {
                    "location": "onsite",
                    "class": "succeeded",
                    "reason": "",
                    "at": "2026-10-30T05:15:00+00:00",
                    "point": POINT,
                    "checked": 1,
                    "snapshots": 1,
                    "bytes": 4096,
                    "subset": "7/20",
                },
                "offsite": None,
            },
        }
        parsed = observation.observations({"version": 1, "sites": [row]}, (self.site(),))
        if parsed is None:
            self.fail("The answer was not accepted.")
        self.assertEqual(parsed[0].integrity[0].point, POINT)
        self.assertTrue(parsed[0].integrity[0].verified)

    @staticmethod
    def site() -> ObservedSite:
        return ObservedSite(
            IDENTIFIER,
            ("shop.test",),
            "php84",
            None,
            SiteState.MANAGED,
            ObservationOutcome.OBSERVED,
            file="/etc/caddy/sites/shop.caddy",
        )


class IntegrityRequestTests(ChangeTestCase):
    def test_opening_backups_makes_no_ssh_connection_and_shows_the_finding_apart(self) -> None:
        record_backups(
            self.server,
            identifier=IDENTIFIER,
            last=result(),
            integrity=(finding(point=POINT),),
        )
        record_points(self.server, (point(point=POINT),), identifier=IDENTIFIER)
        self.sign_in_with("view_server", "view_changes", "view_siteobservation")
        self.remote.commands.clear()
        response = self.client.get(f"/servers/{self.server.pk}/sites/{IDENTIFIER}/backups/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Integrity")
        self.assertContains(response, "The newest recovery point was read back.")
        self.assertContains(response, "Database only saved.")
        self.assertContains(response, "On this server, 30 Oct 2026, 05:15")
        self.assertEqual(self.remote.commands, [])

    def test_check_backups_needs_csrf(self) -> None:
        record_backups(self.server, identifier=IDENTIFIER, last=result())
        self.sign_in_with("view_server", "view_changes", "view_siteobservation")
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        response = client.post(f"/servers/{self.server.pk}/sites/{IDENTIFIER}/backups/check/")
        self.assertEqual(response.status_code, 403)
        self.assertFalse(check.active(self.server, IDENTIFIER))

    def test_passive_discovery_stores_the_typed_finding(self) -> None:
        now = datetime(2026, 10, 30, 5, 15, tzinfo=UTC)
        finding_row = finding(point=POINT, at=now.isoformat())
        record_backups(self.server, identifier=IDENTIFIER, integrity=(finding_row,))
        stored = integrity.stored(self.server, IDENTIFIER)
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0].location, "onsite")
        self.assertEqual(stored[0].point, POINT)
