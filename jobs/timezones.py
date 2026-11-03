"""The viewer's named time zone and local calendar-day boundaries (Phase E #291).

Server timestamps stay UTC. A zone changes only the display and where a range starts,
never what the server keeps or runs. A missing or unknown zone falls back to UTC and the
page says so (docs/server-jobs.md, issue #284 Time).
"""

from dataclasses import dataclass
from datetime import UTC, datetime, time, timedelta
from functools import lru_cache
from zoneinfo import ZoneInfo, available_timezones

UTC_ZONE = ZoneInfo("UTC")


@lru_cache(maxsize=1)
def _available_zones() -> frozenset[str]:
    # Reading the zone database is not free; the set is fixed for the process.
    return frozenset(available_timezones())


@dataclass(frozen=True)
class DisplayZone:
    """A validated zone, or UTC with ``labelled_utc`` telling the page to name the fallback."""

    name: str
    info: ZoneInfo
    labelled_utc: bool

    @property
    def label(self) -> str:
        return "UTC" if self.labelled_utc else self.name


def resolve_zone(name: str | None) -> DisplayZone:
    """The viewer's zone when the zone database knows it, otherwise labelled UTC."""
    candidate = (name or "").strip()
    if candidate and candidate in _available_zones():
        return DisplayZone(candidate, ZoneInfo(candidate), False)
    return DisplayZone("UTC", UTC_ZONE, True)


def start_of_local_day(now: datetime, zone: ZoneInfo, *, days_back: int = 0) -> datetime:
    """The UTC instant at which the viewer's local day began, ``days_back`` days ago."""
    local_day = now.astimezone(zone).date() - timedelta(days=days_back)
    local_midnight = datetime.combine(local_day, time.min, tzinfo=zone)
    return local_midnight.astimezone(UTC)
