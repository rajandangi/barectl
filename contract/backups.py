"""The backup section of the native contract (docs/backups.md, docs/recovery.md).

Every path, tag, filename and unit template below is read from the module that owns it.
:mod:`backups.convention` owns the onsite and offsite layout, the snapshot tags, the
schedule units and the runtime profile. :mod:`backups.kit` owns the recovery kit's fields,
which are read from its public signature so the manifest never parses the kit's prose.
"""

import inspect
from typing import Final

from backups import convention, kit

IDENTIFIER: Final = "zzzsite"
POINT: Final = "0123456789abcdef"
APPLICATION: Final = "wordpress"
BUCKET: Final = "example-bucket"
PREFIX: Final = "backup-prefix"
REGION: Final = "us-east-1"
ENDPOINT: Final = f"https://s3.{REGION}.amazonaws.com"
OFFSITE: Final[dict[str, str]] = {
    "provider": "s3",
    "bucket": BUCKET,
    "region": REGION,
    "endpoint": ENDPOINT,
    "prefix": PREFIX,
    "prune": "no",
}
SCHEDULE_AT: Final = "03:00"
UNIT_KINDS: Final = ("slice", "service", "timer")


def _identifier(value: str) -> str:
    """``value`` with the representative identifier, so the manifest names the shape."""
    return value.replace(IDENTIFIER, "<identifier>")


def _offsite(value: str) -> str:
    """``value`` with the representative repository fields named as placeholders."""
    return (
        _identifier(value)
        .replace(ENDPOINT, "<endpoint>")
        .replace(BUCKET, "<bucket>")
        .replace(PREFIX, "<prefix>")
        .replace(REGION, "<region>")
    )


def _tag(value: str) -> str:
    """One tag from :func:`backups.convention.tags` with its sample values templated."""
    for before, after in (
        (IDENTIFIER, "<identifier>"),
        (POINT, "<point>"),
        (APPLICATION, "<application>"),
        ("full", "<scope>"),
        ("database", "<part>"),
        ("manual", "<origin>"),
    ):
        value = value.replace(before, after)
    return value


def _tags(*, live: bool) -> list[str]:
    return [
        _tag(tag)
        for tag in convention.tags(
            IDENTIFIER,
            "full",
            part="database",
            origin="manual",
            live=live,
            point=POINT,
            application=APPLICATION,
        )
    ]


def _paths() -> dict[str, object]:
    return {
        "repository_root": convention.REPOSITORY_ROOT,
        "repository_lock_root": convention.REPOSITORY_LOCK_ROOT,
        "site": _identifier(convention.site_directory(IDENTIFIER)),
        "onsite": _identifier(convention.repository(IDENTIFIER)),
        "key_root": convention.KEY_ROOT,
        "server_key": _identifier(convention.server_key(IDENTIFIER)),
        "offsite": {
            "root": convention.OFFSITE_ROOT,
            "config": convention.OFFSITE_CONFIG,
            "capture": convention.OFFSITE_CAPTURE,
            "prune": convention.OFFSITE_PRUNE,
            "sources": convention.OFFSITE_SOURCES,
            "health": convention.OFFSITE_HEALTH,
            "repository": _offsite(convention.offsite_repository(OFFSITE, IDENTIFIER)),
            "health_repository": _offsite(convention.health_repository(OFFSITE)),
            "providers": list(convention.PROVIDERS),
            "provider_labels": dict(convention.PROVIDER_LABELS),
            "bucket_pattern": convention.BUCKET.pattern,
            "region_pattern": convention.REGION.pattern,
            "prefix_pattern": convention.PREFIX.pattern,
        },
    }


def _restic() -> dict[str, str]:
    return {
        "profile_root": convention.PROFILE_ROOT,
        "entry": convention.RESTIC_ENTRY,
        "profile": convention.RESTIC_PROFILE,
        "binary": convention.RESTIC_BIN,
        "cache": convention.CACHE_DIR,
    }


def _capture() -> dict[str, object]:
    return {
        "marker": convention.MARKER,
        "identifier_pattern": convention.SITE_IDENTIFIER.pattern,
        "tag_pattern": convention.TAG.pattern,
        "point_pattern": convention.POINT.pattern,
        "scopes": list(convention.SCOPES),
        "parts": list(convention.PARTS),
        "origins": list(convention.ORIGINS),
        "applications": list(convention.APPLICATIONS),
        "expected_parts": {
            scope: list(convention.expected_parts(scope)) for scope in convention.SCOPES
        },
        "tags": {"live": _tags(live=True), "paused": _tags(live=False)},
        "database_name": _identifier(convention.database_name(IDENTIFIER)),
        "dump_filename": _identifier(convention.dump_filename(IDENTIFIER)),
        "retention_days": list(convention.RETENTION_DAYS),
        "headroom_bytes": convention.HEADROOM_BYTES,
    }


def _schedule() -> dict[str, object]:
    def contents(kind: str) -> str:
        frequency = "daily" if kind == "timer" else ""
        return _identifier(convention.render_schedule(IDENTIFIER, kind, frequency, SCHEDULE_AT))

    return {
        "root": convention.SCHEDULE_ROOT,
        "script": _identifier(convention.schedule_script(IDENTIFIER)),
        "payload": _identifier(convention.schedule_payload(IDENTIFIER)),
        "units": {
            kind: {
                "file": _identifier(convention.schedule_unit_file(IDENTIFIER, kind)),
                "name": _identifier(convention.schedule_unit_name(IDENTIFIER, kind)),
                "contents": contents(kind),
            }
            for kind in UNIT_KINDS
        },
        "frequencies": list(convention.FREQUENCIES),
        "weekly_day": convention.WEEKLY_DAY,
        "time_pattern": convention.TIME.pattern,
        "calendar": {
            frequency: convention.schedule_calendar(frequency, SCHEDULE_AT)
            for frequency in convention.FREQUENCIES
        },
        "scopes": list(convention.SCHEDULE_SCOPES),
        "run_timeout": convention.SCHEDULE_RUN_TIMEOUT,
        "lock_wait_seconds": convention.SCHEDULE_LOCK_WAIT_SECONDS,
        "window_minutes": convention.SCHEDULE_WINDOW_MINUTES,
    }


def _recovery_kit() -> dict[str, object]:
    return {"fields": list(inspect.signature(kit.lines).parameters)}


def build() -> dict[str, object]:
    """The backup layout as one JSON-serializable mapping."""
    return {
        "paths": _paths(),
        "restic": _restic(),
        "capture": _capture(),
        "schedule": _schedule(),
        "recovery_kit": _recovery_kit(),
    }
