"""The backup convention: fixed paths, unit names, tags and result lines.

Phase D [#396](https://github.com/rajandangi/barectl/issues/396), ADR 0031 and ADR 0037.
This module is standard library only: the controller and the native bodies asserted from
the same source share it (docs/quality.md#python-typing-policy).
"""

import re
import shlex
from collections.abc import Sequence
from typing import Final

MARKER: Final = "barectl"
SITE_IDENTIFIER: Final = re.compile(r"[a-z][a-z0-9]{2,23}")
POINT: Final = re.compile(r"[0-9a-f]{16}")
TAG: Final = re.compile(r"[a-z0-9:_-]{1,48}")

PROFILE_ROOT: Final = "/nix/var/nix/profiles/barectl"
RESTIC_ENTRY: Final = "restic"
RESTIC_PROFILE: Final = f"{PROFILE_ROOT}/{RESTIC_ENTRY}"
RESTIC_BIN: Final = f"{RESTIC_PROFILE}/bin/restic"
REPOSITORY_ROOT: Final = "/var/lib/barectl-backups"
KEY_ROOT: Final = "/etc/barectl/backups"
CACHE_DIR: Final = "/var/cache/barectl/restic"
# Server-wide offsite storage: non-secret location fields and root-only credential files
# (docs/adr/0032-keep-secrets-in-private-native-files.md, Phase D #403).
OFFSITE_ROOT: Final = f"{KEY_ROOT}/offsite"
OFFSITE_CONFIG: Final = f"{OFFSITE_ROOT}/config"
OFFSITE_CAPTURE: Final = f"{OFFSITE_ROOT}/capture.env"
OFFSITE_PRUNE: Final = f"{OFFSITE_ROOT}/prune.env"
# The source site identifiers a connected offsite storage was opened with (#408). It holds
# no secret and never contains a repository path or snapshot listing.
OFFSITE_SOURCES: Final = f"{OFFSITE_ROOT}/sources"
OFFSITE_HEALTH: Final = "_health"
APPLICATIONS: Final = ("plain", "wordpress", "laravel")
REPOSITORY_LOCK_ROOT: Final = "/run/lock/barectl"
PROVIDERS: Final = ("s3", "r2")
PROVIDER_LABELS: Final = {"s3": "Amazon S3", "r2": "Cloudflare R2"}
# Every capture keeps this much of the repository filesystem free. The review states it.
HEADROOM_BYTES: Final = 1024 * 1024 * 1024

# A recovery point's scope is what it restores: its database, its files, or both. A full
# point without a site database has no database part, so it is a files-scope point.
SCOPES: Final = ("database", "files", "full")
PARTS: Final = ("database", "files")
ORIGINS: Final = ("manual", "scheduled", "safety")
POINT_TAG: Final = "point:"
# One policy per site: 1 week, 2 weeks, 3 weeks, 1 month or 6 months (#404).
RETENTION_DAYS: Final = (7, 14, 21, 30, 182)

RESULT_PREFIX: Final = "barectl-result "
# One schedule per site is a fixed timer in the site's own backup slice, separate from the
# automation slice (docs/adr/0036, docs/adr/0037, #402). The body is a fixed rendered file,
# never an engine run.
SCHEDULE_ROOT: Final = "/etc/barectl/backups/schedule"
SCHEDULE_SLICE: Final = "/etc/systemd/system/barectl-site-{identifier}-backup.slice"
SCHEDULE_SERVICE: Final = "/etc/systemd/system/barectl-site-{identifier}-backup.service"
SCHEDULE_TIMER: Final = "/etc/systemd/system/barectl-site-{identifier}-backup.timer"
SCHEDULE_RUN_TIMEOUT: Final = "2h"
SCHEDULE_LOCK_WAIT_SECONDS: Final = 30
# A window is the hour a schedule starts in; another site's window overlaps when it begins
# in that hour. The review refuses it and suggests the next free hour.
SCHEDULE_WINDOW_MINUTES: Final = 60
FREQUENCIES: Final = ("daily", "weekly")
SCHEDULE_SCOPES: Final = ("database", "files", "full")
WEEKLY_DAY: Final = "Mon"
TIME: Final = re.compile(r"([01][0-9]|2[0-3]):([0-5][0-9])\Z")


def schedule_script(identifier: str) -> str:
    if SITE_IDENTIFIER.fullmatch(identifier) is None:
        raise ValueError("Not a site identifier.")
    return f"{SCHEDULE_ROOT}/{identifier}.sh"


def schedule_payload(identifier: str) -> str:
    if SITE_IDENTIFIER.fullmatch(identifier) is None:
        raise ValueError("Not a site identifier.")
    return f"{SCHEDULE_ROOT}/{identifier}.json"


def schedule_unit_file(identifier: str, kind: str) -> str:
    if SITE_IDENTIFIER.fullmatch(identifier) is None:
        raise ValueError("Not a site identifier.")
    template = {
        "slice": SCHEDULE_SLICE,
        "service": SCHEDULE_SERVICE,
        "timer": SCHEDULE_TIMER,
    }.get(kind)
    if template is None:
        raise ValueError("Not a backup unit kind.")
    return template.format(identifier=identifier)


def schedule_unit_name(identifier: str, kind: str) -> str:
    return schedule_unit_file(identifier, kind).rsplit("/", 1)[-1]


def schedule_calendar(frequency: str, at: str) -> str:
    """The explicit UTC calendar expression for one reviewed schedule."""
    if frequency not in FREQUENCIES or TIME.fullmatch(at) is None:
        raise ValueError("Not a reviewed backup schedule.")
    day = f"{WEEKLY_DAY} " if frequency == "weekly" else ""
    return f"{day}*-*-* {at}:00 UTC"


def render_schedule_slice(identifier: str) -> str:
    if SITE_IDENTIFIER.fullmatch(identifier) is None:
        raise ValueError("Not a site identifier.")
    return f"[Unit]\nDescription=Barectl backups for {identifier}\n\n[Slice]\n"


def render_schedule_service(identifier: str) -> str:
    if SITE_IDENTIFIER.fullmatch(identifier) is None:
        raise ValueError("Not a site identifier.")
    return (
        "[Unit]\n"
        f"Description=Barectl backup capture for {identifier}\n"
        f"ConditionPathIsDirectory=/var/www/{identifier}\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"TimeoutStartSec={SCHEDULE_RUN_TIMEOUT}\n"
        "KillMode=control-group\n"
        f"Slice=barectl-site-{identifier}-backup.slice\n"
        f"ExecStart=/bin/sh {schedule_script(identifier)} {schedule_payload(identifier)}\n"
    )


def render_schedule_timer(identifier: str, frequency: str, at: str) -> str:
    calendar = schedule_calendar(frequency, at)
    return (
        "[Unit]\n"
        f"Description=Barectl backup schedule for {identifier}\n"
        "\n"
        "[Timer]\n"
        f"OnCalendar={calendar}\n"
        "AccuracySec=1s\n"
        "RandomizedDelaySec=0\n"
        "Persistent=false\n"
        "DeferReactivation=yes\n"
        f"Unit=barectl-site-{identifier}-backup.service\n"
        f"Slice=barectl-site-{identifier}-backup.slice\n"
        "\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )


def render_schedule(identifier: str, kind: str, frequency: str = "", at: str = "") -> str:
    if kind == "slice":
        return render_schedule_slice(identifier)
    if kind == "service":
        return render_schedule_service(identifier)
    if kind == "timer":
        return render_schedule_timer(identifier, frequency, at)
    raise ValueError("Not a backup unit kind.")


def site_directory(identifier: str) -> str:
    if SITE_IDENTIFIER.fullmatch(identifier) is None:
        raise ValueError("Not a site identifier.")
    return f"{REPOSITORY_ROOT}/{identifier}"


def repository(identifier: str) -> str:
    return f"{site_directory(identifier)}/onsite"


def server_key(identifier: str) -> str:
    if SITE_IDENTIFIER.fullmatch(identifier) is None:
        raise ValueError("Not a site identifier.")
    return f"{KEY_ROOT}/{identifier}.key"


def database_name(identifier: str) -> str:
    if SITE_IDENTIFIER.fullmatch(identifier) is None:
        raise ValueError("Not a site identifier.")
    return "s" + identifier


def dump_argv(identifier: str, engine: str) -> list[str]:
    """The dump client, run as the site's own Linux user over the local socket."""
    database = database_name(identifier)
    if engine == "mariadb":
        return [
            "/usr/sbin/runuser",
            "-u",
            "s" + identifier,
            "--",
            "/usr/bin/mariadb-dump",
            "--single-transaction",
            "--quick",
            "--no-tablespaces",
            "--routines",
            "--events",
            "--triggers",
            database,
        ]
    if engine == "postgresql":
        return [
            "/usr/sbin/runuser",
            "-u",
            "s" + identifier,
            "--",
            "/usr/bin/pg_dump",
            "--no-owner",
            "--no-privileges",
            database,
        ]
    raise ValueError("Unknown database engine.")


def dump_filename(identifier: str) -> str:
    return database_name(identifier) + ".sql"


def tags(
    identifier: str,
    scope: str,
    *,
    part: str | None = None,
    origin: str,
    live: bool,
    point: str,
    complete: bool = True,
    application: str = "",
) -> tuple[str, ...]:
    if scope not in SCOPES or origin not in ORIGINS or POINT.fullmatch(point) is None:
        raise ValueError("Not a reviewed capture.")
    if application and application not in APPLICATIONS:
        raise ValueError("Not a reviewed capture.")
    selected = scope if part is None else part
    if (
        selected not in PARTS
        or (scope == "full" and part is None)
        or (scope in ("database", "files") and part is not None and part != scope)
    ):
        raise ValueError("Not a reviewed capture.")
    values = (
        MARKER,
        f"site:{identifier}",
        f"scope:{scope}",
        f"part:{selected}",
        f"origin:{origin}",
        "capture:live" if live else "capture:paused",
        POINT_TAG + point,
        *((f"application:{application}",) if application else ()),
    )
    return (*values, "complete") if complete else values


def expected_parts(scope: str) -> tuple[str, ...]:
    """The parts a restorable point of this scope must carry."""
    if scope == "full":
        return ("database", "files")
    if scope == "files":
        return ("files",)
    return ("database",)


BUCKET: Final = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]")
REGION: Final = re.compile(r"[a-z0-9-]{2,32}")
ACCOUNT: Final = re.compile(r"[0-9a-f]{32}")
PREFIX: Final = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}(?:/[a-z0-9][a-z0-9._-]{0,63}){0,3}")


def endpoint(provider: str, region: str = "", account: str = "") -> str:
    """The one endpoint each supported template uses; there is no free-form endpoint."""
    if provider == "s3" and REGION.fullmatch(region):
        return f"https://s3.{region}.amazonaws.com"
    if provider == "r2" and ACCOUNT.fullmatch(account):
        return f"https://{account}.r2.cloudflarestorage.com"
    raise ValueError("Not a supported offsite storage template.")


def _expected_endpoint(config: dict[str, str]) -> str:
    provider = config.get("provider", "")
    url = config.get("endpoint", "")
    if provider == "s3":
        return endpoint(provider, config.get("region", ""))
    return endpoint(
        provider,
        config.get("region", ""),
        url.removeprefix("https://").split(".", 1)[0],
    )


def offsite_repository(config: dict[str, str], identifier: str) -> str:
    """One site's repository under the server's fixed bucket prefix."""
    if SITE_IDENTIFIER.fullmatch(identifier) is None:
        raise ValueError("Not a site identifier.")
    if (
        config.get("provider", "") not in PROVIDERS
        or BUCKET.fullmatch(config.get("bucket", "")) is None
        or PREFIX.fullmatch(config.get("prefix", "")) is None
        or (config.get("provider") == "r2" and config.get("region", "") != "auto")
        or (config.get("provider") == "s3" and REGION.fullmatch(config.get("region", "")) is None)
        or config.get("endpoint", "") != _expected_endpoint(config)
    ):
        raise ValueError("Not a supported offsite storage template.")
    return f"s3:{config['endpoint']}/{config['bucket']}/{config['prefix']}/{identifier}"


def offsite_restic_command(
    identifier: str,
    config: dict[str, str],
    *arguments: str,
    env_paths: Sequence[str] = (OFFSITE_CAPTURE,),
) -> str:
    """One offsite restic command, with the same credentials and options as a copy.

    The scenario helper and every product reader run this exact shell so the repository's
    path-style URL, region and root-only environment file cannot drift apart (#403, #404).
    """
    repository = offsite_repository(config, identifier)
    if not env_paths or not all(path.startswith(KEY_ROOT + "/") for path in env_paths):
        raise ValueError("Not a root-only offsite environment file.")
    if len(env_paths) == 1:
        load = f". {shlex.quote(env_paths[0])}"
    else:
        load = (
            f"if [ -f {shlex.quote(env_paths[0])} ]; then . {shlex.quote(env_paths[0])}; "
            f"else . {shlex.quote(env_paths[1])}; fi"
        )
    script = "; ".join(
        [
            "set -a",
            load,
            f"RESTIC_REPOSITORY={shlex.quote(repository)}",
            f"RESTIC_PASSWORD_FILE={shlex.quote(server_key(identifier))}",
            f"RESTIC_CACHE_DIR={shlex.quote(CACHE_DIR)}",
            f"AWS_DEFAULT_REGION={shlex.quote(config.get('region', ''))}",
            "set +a",
            shlex.join([RESTIC_BIN, "-o", "s3.bucket-lookup=path", *arguments]),
        ]
    )
    return "sh -c " + shlex.quote(script)


def health_repository(config: dict[str, str]) -> str:
    """A fixed repository the setup proves writable and readable without a site."""
    offsite_repository(config, "health")
    return f"s3:{config['endpoint']}/{config['bucket']}/{config['prefix']}/{OFFSITE_HEALTH}"


def read_config(text: str) -> dict[str, str]:
    """Parse the non-secret offsite config file, refusing any line outside the template."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        name, separator, value = line.partition("=")
        if (
            not separator
            or name in values
            or name
            not in {
                "provider",
                "bucket",
                "region",
                "endpoint",
                "prefix",
                "prune",
            }
        ):
            raise ValueError("The offsite storage setting is outside the supported template.")
        values[name] = value
    if set(values) != {"provider", "bucket", "region", "endpoint", "prefix", "prune"}:
        raise ValueError("The offsite storage setting is outside the supported template.")
    provider = values["provider"]
    if (
        provider not in PROVIDERS
        or BUCKET.fullmatch(values["bucket"]) is None
        or PREFIX.fullmatch(values["prefix"]) is None
        or values["prune"] not in ("yes", "no")
        or (provider == "r2" and values["region"] != "auto")
        or values["endpoint"] != _expected_endpoint(values)
    ):
        raise ValueError("The offsite storage setting is outside the supported template.")
    return values


def render_config(config: dict[str, str]) -> str:
    return "".join(
        f"{name}={config[name]}\n"
        for name in ("provider", "bucket", "region", "endpoint", "prefix", "prune")
    )
