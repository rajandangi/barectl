"""Recent results ranges, Site, Type of work and Result filters (Phase E #291).

The filters read the saved Jobs observation. They never contact the server, and their
options and counts are built only from rows the viewer may see. A row with no usable time
cannot be placed in a range, so it is left out and counted in a notice.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Final, Protocol
from zoneinfo import ZoneInfo

from operations import engine
from sites import names as site_names

from .timezones import start_of_local_day

TODAY: Final = "today"
SEVEN_DAYS: Final = "7d"
THIRTY_DAYS: Final = "30d"
DEFAULT_RANGE: Final = SEVEN_DAYS

# The label order the page shows: Today, Past 7 days (the default), Past 30 days.
RANGE_CHOICES: Final = (
    (TODAY, "Today", 0),
    (SEVEN_DAYS, "Past 7 days", 6),
    (THIRTY_DAYS, "Past 30 days", 29),
)
_RANGE_DAYS: Final = {value: days_back for value, _, days_back in RANGE_CHOICES}

# The issue's plain result words, matched to the engine's result classes.
RESULT_CHOICES: Final = (
    ("finished", "Finished", "succeeded"),
    ("partial", "Partly applied", "partial"),
    ("refused", "Refused", "refused"),
    ("failed", "Failed", "failed"),
    ("timed_out", "Timed out", "timed_out"),
    ("skipped", "Skipped", "lock_busy"),
    ("unconfirmed", "Could not confirm", ""),
)
_RESULT_KEYS: Final = {result_class: key for key, _, result_class in RESULT_CHOICES}
# Backup runs are Recent results too, so Type of work can narrow them (#286).
BACKUP_WORK_LABELS: Final = {
    "backup": "Backup",
    "backup_copy": "Offsite copy",
    "backup_check": "Backup check",
    "backup_cleanup": "Backup cleanup",
}


def _work_label(slug: str) -> str:
    kind = engine.kind_of(slug)
    return kind.label if kind is not None else BACKUP_WORK_LABELS.get(slug, slug)


class Filterable(Protocol):
    """The row facts a range or filter reads; no presentation type is imported here."""

    @property
    def when(self) -> datetime | None: ...

    @property
    def running(self) -> bool: ...

    @property
    def sites(self) -> tuple[str, ...]: ...

    @property
    def kind_slug(self) -> str: ...

    @property
    def result_class(self) -> str: ...


@dataclass(frozen=True)
class Selection:
    """The query-string selection, with only established values kept."""

    range: str = DEFAULT_RANGE
    site: str = ""
    work: str = ""
    result: str = ""

    @classmethod
    def parse(cls, query: Mapping[str, str]) -> Selection:
        selected_range = query.get("range", "").strip()
        if selected_range not in _RANGE_DAYS:
            selected_range = DEFAULT_RANGE
        site = query.get("site", "").strip()
        if site and not site_names.valid_identifier(site):
            site = ""
        work = query.get("work", "").strip()
        if work and engine.kind_of(work) is None and work not in BACKUP_WORK_LABELS:
            work = ""
        result = query.get("result", "").strip()
        if result and result not in {key for key, _, _ in RESULT_CHOICES}:
            result = ""
        return cls(selected_range, site, work, result)

    @property
    def active(self) -> bool:
        return self.range != DEFAULT_RANGE or bool(self.site or self.work or self.result)


@dataclass(frozen=True)
class RangeOption:
    value: str
    label: str
    selected: bool


@dataclass(frozen=True)
class Option:
    value: str
    label: str
    count: int
    selected: bool


@dataclass(frozen=True)
class Filters:
    """The controls and counts the page renders beside Recent results."""

    selection: Selection
    ranges: tuple[RangeOption, ...]
    sites: tuple[Option, ...]
    works: tuple[Option, ...]
    results: tuple[Option, ...]
    shown: int
    untimed: int


@dataclass(frozen=True)
class Filtered[RowT]:
    rows: tuple[RowT, ...]
    untimed: int
    filters: Filters


def filter_recent[RowT: Filterable](
    rows: Sequence[RowT],
    selection: Selection,
    *,
    now: datetime,
    zone: ZoneInfo,
) -> Filtered[RowT]:
    """The newest-first rows of Recent results that the selection keeps."""
    start = start_of_local_day(now, zone, days_back=_RANGE_DAYS[selection.range])
    timed = [row for row in rows if not row.running and row.when is not None]
    untimed = sum(1 for row in rows if not row.running and row.when is None)
    in_range = [row for row in timed if _when(row) >= start]
    kept = [row for row in in_range if _matches(row, selection)]
    kept.sort(key=_when, reverse=True)
    filters = Filters(
        selection=selection,
        ranges=tuple(
            RangeOption(value, label, value == selection.range) for value, label, _ in RANGE_CHOICES
        ),
        sites=_site_options(in_range, selection),
        works=_work_options(in_range, selection),
        results=_result_options(in_range, selection),
        shown=len(kept),
        untimed=untimed,
    )
    return Filtered(tuple(kept), untimed, filters)


def _when(row: Filterable) -> datetime:
    value = row.when
    if value is None:
        raise ValueError("an untimed row cannot be placed in a range")
    return value


def _matches(row: Filterable, selection: Selection) -> bool:
    if selection.site and selection.site not in row.sites:
        return False
    if selection.work and row.kind_slug != selection.work:
        return False
    if selection.result:
        return _RESULT_KEYS.get(row.result_class, "unconfirmed") == selection.result
    return True


def _site_options(rows: Sequence[Filterable], selection: Selection) -> tuple[Option, ...]:
    counts: dict[str, int] = {}
    for row in rows:
        for site in dict.fromkeys(row.sites):
            counts[site] = counts.get(site, 0) + 1
    return tuple(
        Option(site, site, count, site == selection.site) for site, count in sorted(counts.items())
    )


def _work_options(rows: Sequence[Filterable], selection: Selection) -> tuple[Option, ...]:
    counts: dict[str, int] = {}
    for row in rows:
        if row.kind_slug and (
            engine.kind_of(row.kind_slug) is not None or row.kind_slug in BACKUP_WORK_LABELS
        ):
            counts[row.kind_slug] = counts.get(row.kind_slug, 0) + 1
    options = [
        Option(slug, _work_label(slug), count, slug == selection.work)
        for slug, count in counts.items()
    ]
    options.sort(key=lambda option: option.label)
    return tuple(options)


def _result_options(rows: Sequence[Filterable], selection: Selection) -> tuple[Option, ...]:
    counts: dict[str, int] = {}
    for row in rows:
        key = _RESULT_KEYS.get(row.result_class, "unconfirmed")
        counts[key] = counts.get(key, 0) + 1
    return tuple(
        Option(key, label, counts.get(key, 0), key == selection.result)
        for key, label, _ in RESULT_CHOICES
    )
