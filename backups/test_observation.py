"""Backup evidence parsing, the section's wording and its stale label (#396)."""

import json
from datetime import UTC, datetime, timedelta
from unittest import mock

from django.test import SimpleTestCase
from django.utils import timezone

from discovery.models import ObservationOutcome, SiteState
from discovery.snapshot import ObservedSite

from . import check, observation, presentation
from .bodies import observe as body
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


def _line(value: dict[str, object], usec: int = 1_762_000_000_000_000) -> str:
    return json.dumps(
        {
            "MESSAGE": "barectl-result " + json.dumps(value, separators=(",", ":")),
            "__REALTIME_TIMESTAMP": str(usec),
        }
    )


def _result(
    *,
    kind: str = "backup",
    identifier: str = "alpha",
    result_class: str = "succeeded",
    reason: str = "",
    at: str = "2026-10-27T11:00:00+00:00",
    point: str = "0123456789abcdef",
    **values: object,
) -> dict[str, object]:
    return {
        "kind": kind,
        "site": identifier,
        "class": result_class,
        "reason": reason,
        "at": at,
        "point": point,
        **values,
    }


class JournalTests(SimpleTestCase):
    def run_journal(self, *lines: str) -> body.Journal:
        with mock.patch.object(body, "bounded", return_value=(0, "\n".join(lines).encode())):
            return body.journal()

    def test_every_exit_class_and_run_kind_is_kept_as_a_run(self) -> None:
        reading = self.run_journal(
            _line(_result(result_class="succeeded", offsite="failed")),
            _line(
                _result(
                    kind="copy",
                    result_class="lock_busy",
                    reason="backup_lock",
                    at="",
                ),
                usec=1_761_999_999_000_000,
            ),
            _line(
                _result(
                    kind="integrity",
                    result_class="partial",
                    location="offsite",
                    checked=3,
                    snapshots=2,
                    subset="3/20",
                    bytes=8192,
                ),
                usec=1_761_999_998_000_000,
            ),
            _line(
                _result(
                    kind="cleanup",
                    result_class="failed",
                    location="onsite",
                    onsite={"deleted": 2, "kept": 1, "skipped": 3, "failed": 4},
                    offsite={"deleted": 0, "kept": 0, "skipped": 0, "failed": 0},
                ),
                usec=1_761_999_997_000_000,
            ),
        )
        (site,) = reading.runs
        self.assertEqual(
            [(run["kind"], run["class"]) for run in reading.runs["alpha"]],
            [
                ("capture", "succeeded"),
                ("copy", "lock_busy"),
                ("check", "partial"),
                ("cleanup", "failed"),
            ],
        )
        self.assertEqual(reading.runs["alpha"][0]["offsite"], "failed")
        onsite = reading.runs["alpha"][3]["onsite"]
        self.assertIsInstance(onsite, dict)
        self.assertEqual(onsite.get("failed") if isinstance(onsite, dict) else None, 4)
        self.assertNotIn("offsite_counts", reading.runs["alpha"][3])
        self.assertEqual(site, "alpha")

    def test_a_copy_without_its_own_time_takes_the_journal_time(self) -> None:
        reading = self.run_journal(_line(_result(kind="copy", at=""), usec=1_762_000_000_123_456))
        self.assertEqual(
            reading.runs["alpha"][0]["at"],
            datetime.fromtimestamp(1_762_000_000.123456, tz=UTC).replace(microsecond=0).isoformat(),
        )

    def test_an_interim_pause_line_is_not_a_second_run(self) -> None:
        reading = self.run_journal(
            _line(_result(result_class="partial", reason="backup_files")),
            _line(
                _result(result_class="partial", reason="backup_paused"),
                usec=1_761_999_999_000_000,
            ),
        )
        self.assertEqual(
            [(run["kind"], run["reason"]) for run in reading.runs["alpha"]],
            [("capture", "backup_files")],
        )

    def test_an_interrupted_run_keeps_its_pause_line(self) -> None:
        reading = self.run_journal(_line(_result(result_class="partial", reason="backup_paused")))
        self.assertEqual(reading.runs["alpha"][0]["reason"], "backup_paused")
        self.assertEqual(reading.newest["alpha"]["reason"], "backup_paused")


class ScheduleTests(SimpleTestCase):
    def run_schedules(
        self, timers: list[dict[str, object]], files: list[dict[str, object]]
    ) -> dict[str, list[dict[str, object]]]:
        def bounded(argv: list[str], *, limit: int = 0) -> tuple[int, bytes]:
            if "list-timers" in argv:
                return 0, json.dumps(timers).encode()
            return 0, json.dumps(files).encode()

        with mock.patch.object(body, "bounded", side_effect=bounded):
            return body.schedules(["alpha"])

    def test_on_off_and_missing_timers_come_from_systemd_only(self) -> None:
        now = int(datetime.now(tz=UTC).timestamp() * 1_000_000)
        found = self.run_schedules(
            [
                {
                    "unit": "barectl-site-alpha-backup.timer",
                    "next": now + 3_600_000_000,
                    "last": now - 60_000_000,
                },
                {
                    "unit": "barectl-site-alpha-check.timer",
                    "next": None,
                    "last": 0,
                },
            ],
            [
                {"unit_file": "barectl-site-alpha-backup.timer", "state": "enabled"},
                {"unit_file": "barectl-site-alpha-check.timer", "state": "disabled"},
                {"unit_file": "barectl-site-alpha-cleanup.timer", "state": "enabled"},
            ],
        )
        rows = {row["work"]: row for row in found["alpha"]}
        self.assertTrue(rows["backup"]["on"])
        self.assertEqual(rows["backup"]["next"], now + 3_600_000_000)
        self.assertFalse(rows["check"]["on"])
        self.assertEqual(rows["check"]["next"], 0)
        # A timer in the unit files but not in list-timers is off, not missing.
        self.assertFalse(rows["cleanup"]["on"])
        self.assertNotIn("copy", rows)


class ObservationsTests(SimpleTestCase):
    def site_row(self, **values: object) -> dict[str, object]:
        return row(**values)

    def test_runs_and_timers_are_carried_additively(self) -> None:
        value = {
            "version": 1,
            "sites": [
                self.site_row(
                    runs=[
                        {
                            "kind": "capture",
                            "class": "succeeded",
                            "reason": "",
                            "at": "2026-10-27T11:00:00+00:00",
                            "point": "0123456789abcdef",
                            "scope": "database",
                            "origin": "scheduled",
                            "snapshots": 1,
                            "bytes": 4096,
                            "offsite": "failed",
                        }
                    ],
                    timers=[
                        {
                            "work": "backup",
                            "location": "",
                            "on": True,
                            "next": 1_793_329_200_000_000,
                            "last": 1_793_000_000_000_000,
                        }
                    ],
                )
            ],
        }
        parsed = observation.observations(value, (site(),))
        if parsed is None:
            self.fail("The answer was not accepted.")
        self.assertEqual(parsed[0].runs[0].result_class, "succeeded")
        self.assertEqual(parsed[0].runs[0].offsite, "failed")
        self.assertEqual(parsed[0].timers[0].work, "backup")
        self.assertTrue(parsed[0].timers[0].on)

    def test_a_timer_that_fired_without_a_result_line_is_could_not_confirm(self) -> None:
        fired = datetime(2026, 10, 27, 11, 0, tzinfo=UTC)
        value = {
            "version": 1,
            "sites": [
                self.site_row(
                    runs=[],
                    timers=[
                        {
                            "work": "backup",
                            "location": "",
                            "on": True,
                            "next": int(fired.timestamp() * 1_000_000) + 86_400_000_000,
                            "last": int(fired.timestamp() * 1_000_000),
                        }
                    ],
                )
            ],
        }
        parsed = observation.observations(value, (site(),))
        if parsed is None:
            self.fail("The answer was not accepted.")
        (run,) = parsed[0].runs
        self.assertEqual(run.kind, "capture")
        self.assertEqual(run.result_class, "")
        self.assertEqual(run.time, fired)

    def test_a_cleanup_result_matches_its_timer_without_a_location_on_the_line(self) -> None:
        fired = datetime(2026, 10, 27, 11, 0, tzinfo=UTC)
        usec = int(fired.timestamp() * 1_000_000)
        value = {
            "version": 1,
            "sites": [
                self.site_row(
                    runs=[
                        {
                            "kind": "cleanup",
                            "class": "succeeded",
                            "reason": "",
                            "at": fired.isoformat(),
                            "onsite": {"deleted": 1, "kept": 2, "skipped": 0, "failed": 0},
                            "offsite": {"deleted": 0, "kept": 0, "skipped": 0, "failed": 0},
                        }
                    ],
                    timers=[
                        {
                            "work": "cleanup",
                            "location": "onsite",
                            "on": True,
                            "next": usec + 86_400_000_000,
                            "last": usec,
                        }
                    ],
                )
            ],
        }
        parsed = observation.observations(value, (site(),))
        if parsed is None:
            self.fail("The answer was not accepted.")
        self.assertEqual([run.kind for run in parsed[0].runs], ["cleanup"])

    def test_an_invalid_run_or_timer_is_refused(self) -> None:
        value = {
            "version": 1,
            "sites": [
                self.site_row(
                    runs=[
                        {
                            "kind": "capture",
                            "class": "succeeded",
                            "reason": "",
                            "at": "",
                            "point": "",
                            "scope": "",
                            "origin": "",
                            "snapshots": 0,
                            "bytes": 0,
                            "offsite": "",
                            "path": "/var/lib/barectl-backups/alpha",
                        }
                    ]
                )
            ],
        }
        self.assertFalse(observation.valid(value, ("alpha",)))
