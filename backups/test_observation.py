"""Backup evidence parsing, the section's wording and its stale label (#396)."""

from datetime import timedelta

from django.test import SimpleTestCase
from django.utils import timezone

from discovery.models import ObservationOutcome, SiteState
from discovery.snapshot import ObservedSite

from . import check, observation, presentation
from .models import BackupCheck

BOOT = "8f14e45f-ea6f-4c1c-9b7b-2f0f4c1c9b7b"
PROFILE = "/nix/store/rac858616ds2w2z3db69kp80vr9s8mkp-restic-0.18.1"


def site(identifier: str = "alpha") -> ObservedSite:
    return ObservedSite(
        identifier,
        (f"{identifier}.example.com",),
        "php84",
        None,
        SiteState.MANAGED,
        ObservationOutcome.OBSERVED,
        file=f"/etc/caddy/sites/{identifier}.caddy",
    )


def row(**values: object) -> dict[str, object]:
    return {
        "identifier": "alpha",
        "profile": PROFILE,
        "repository": True,
        "key": True,
        "problems": [],
        "database": True,
        "database_problem": "",
        "last": None,
        **values,
    }


class ObservationTests(SimpleTestCase):
    def test_an_enabled_site_needs_the_tool_both_files_and_no_problem(self) -> None:
        value = {"version": 1, "sites": [row()]}
        parsed = observation.observations(value, (site(),))
        if parsed is None:
            self.fail("The answer was not accepted.")
        self.assertTrue(parsed[0].enabled)
        self.assertEqual(parsed[0].restic_version, "0.18.1")

    def test_a_missing_key_is_not_enabled(self) -> None:
        value = {"version": 1, "sites": [row(key=False)]}
        parsed = observation.observations(value, (site(),))
        if parsed is None:
            self.fail("The answer was not accepted.")
        self.assertFalse(parsed[0].enabled)

    def test_the_newest_safe_result_is_carried(self) -> None:
        value = {
            "version": 1,
            "sites": [
                row(
                    last={
                        "class": "succeeded",
                        "reason": "",
                        "scope": "database",
                        "origin": "manual",
                        "at": "2026-10-27T11:00:00+00:00",
                        "point": "0123456789abcdef",
                        "snapshots": 1,
                        "bytes": 4096,
                    }
                )
            ],
        }
        parsed = observation.observations(value, (site(),))
        if parsed is None or parsed[0].last is None:
            self.fail("The result was not accepted.")
        self.assertEqual(parsed[0].last.result_class, "succeeded")
        self.assertEqual(parsed[0].last.size, 4096)

    def test_an_answer_for_another_site_is_refused(self) -> None:
        value = {"version": 1, "sites": [row(identifier="beta")]}
        self.assertFalse(observation.valid(value, ("alpha",)))


class PresentationTests(SimpleTestCase):
    def test_a_stale_listing_is_labelled(self) -> None:
        row = BackupCheck(
            identifier="alpha",
            listing={"version": 1, "outcome": "observed", "points": []},
            checked_at=timezone.now() - timedelta(hours=1),
        )
        self.assertTrue(check.stale(row))

    def test_points_hide_an_incomplete_point_from_restore(self) -> None:
        listing = {
            "version": 1,
            "outcome": "observed",
            "points": [
                {
                    "time": "2026-10-27T11:00:00Z",
                    "scope": "database",
                    "complete": False,
                    "live": True,
                    "keep": False,
                    "short": "aaaa",
                    "point": "0123456789abcdef",
                }
            ],
        }
        points = presentation.points_view(listing)
        self.assertEqual(points[0].status, "Incomplete")
        self.assertFalse(points[0].restorable)

    def test_a_failed_result_is_not_reported_as_saved(self) -> None:
        backup = observation.ObservedBackup(
            "alpha",
            PROFILE,
            True,
            True,
            (),
            True,
            "",
            observation.BackupResult(
                "refused",
                "backup_dump",
                "database",
                "manual",
                "2026-10-27T11:00:00+00:00",
                "",
                0,
                0,
            ),
        )
        view = presentation.last_view(backup)
        if view is None:
            self.fail("No wording.")
        self.assertEqual(view.headline, "The backup did not run.")
        self.assertIn("dump failed", view.detail)
