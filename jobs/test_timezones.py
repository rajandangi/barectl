"""The viewer's zone and the local calendar-day boundaries (#291)."""

from datetime import UTC, datetime
from zoneinfo import ZoneInfo

from django.test import SimpleTestCase

from .timezones import DisplayZone, resolve_zone, start_of_local_day


class ViewerZoneTests(SimpleTestCase):
    def test_a_known_iana_zone_is_named_on_the_page(self) -> None:
        zone = resolve_zone("Europe/London")
        self.assertEqual(zone.label, "Europe/London")
        self.assertFalse(zone.labelled_utc)
        self.assertEqual(zone.info, ZoneInfo("Europe/London"))

    def test_a_missing_zone_falls_back_to_labelled_utc(self) -> None:
        for missing in (None, "", "   ", "Not/AZone", "../etc/passwd", "UTC/../UTC"):
            with self.subTest(value=missing):
                zone = resolve_zone(missing)
                self.assertEqual(zone.label, "UTC")
                self.assertTrue(zone.labelled_utc)
                self.assertEqual(zone.info, ZoneInfo("UTC"))

    def test_the_zone_is_validated_against_the_zone_database(self) -> None:
        zone = resolve_zone("Pacific/Auckland")
        self.assertIsInstance(zone, DisplayZone)
        self.assertEqual(zone.label, "Pacific/Auckland")


class LocalDayStartTests(SimpleTestCase):
    def test_today_starts_at_local_midnight(self) -> None:
        # 23:30 UTC is already the next day in Tokyo.
        now = datetime(2026, 11, 3, 23, 30, tzinfo=UTC)
        start = start_of_local_day(now, ZoneInfo("Asia/Tokyo"))
        self.assertEqual(start, datetime(2026, 11, 3, 15, 0, tzinfo=UTC))

    def test_past_seven_days_include_today_and_the_previous_six_local_days(self) -> None:
        now = datetime(2026, 11, 3, 12, 0, tzinfo=UTC)
        start = start_of_local_day(now, ZoneInfo("Europe/London"), days_back=6)
        self.assertEqual(start, datetime(2026, 10, 28, 0, 0, tzinfo=UTC))

    def test_past_thirty_days_include_today_and_the_previous_twenty_nine_local_days(self) -> None:
        now = datetime(2026, 11, 3, 12, 0, tzinfo=UTC)
        start = start_of_local_day(now, ZoneInfo("Europe/London"), days_back=29)
        # 5 October was still British Summer Time, so its local midnight is 23:00 UTC.
        self.assertEqual(start, datetime(2026, 10, 4, 23, 0, tzinfo=UTC))

    def test_a_daylight_saving_transition_uses_the_offset_at_local_midnight(self) -> None:
        # London moves to British Summer Time at 01:00 UTC on 29 March 2026. At noon the
        # offset is +01:00, but midnight that day was still GMT: 00:00 UTC.
        now = datetime(2026, 3, 29, 12, 0, tzinfo=UTC)
        start = start_of_local_day(now, ZoneInfo("Europe/London"))
        self.assertEqual(start, datetime(2026, 3, 29, 0, 0, tzinfo=UTC))
        week = start_of_local_day(now, ZoneInfo("Europe/London"), days_back=6)
        self.assertEqual(week, datetime(2026, 3, 23, 0, 0, tzinfo=UTC))

    def test_the_calendar_day_is_the_viewer_day_not_the_utc_day(self) -> None:
        # 02:00 UTC on 4 November is still 3 November in New York.
        now = datetime(2026, 11, 4, 2, 0, tzinfo=UTC)
        self.assertEqual(
            start_of_local_day(now, ZoneInfo("America/New_York")),
            datetime(2026, 11, 3, 5, 0, tzinfo=UTC),
        )
