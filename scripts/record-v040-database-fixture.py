# ruff: noqa: INP001
"""Record dashboard/upgrade_fixtures/v0.4.0.sqlite from the v0.4.0 tag.

The recorder is the only supported way to regenerate the fixture. It checks out the tag in
a detached temporary worktree, migrates that tree's own database, seeds one representative
row of every area the upgrade proof covers, and copies the database into the repository.

Run it with the development environment available:

    uv run --env-file .env python scripts/record-v040-database-fixture.py

The tag's pinned Django and django-tasks-db releases match this checkout, so the recorder
runs the tag's migrations with this environment's Python instead of creating a second
virtual environment. The limits are recorded in dashboard/upgrade_fixtures/README.md.
"""

import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

REFERENCE = "v0.4.0"
GIT = shutil.which("git") or "git"
SEED = """\
from datetime import UTC, datetime, timedelta

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group

from discovery.models import DiscoveryAttempt, DiscoverySnapshot, SettingObservation
from operations.models import (
    ChangePreparation,
    ChangeReview,
    ChangeRun,
    Consent,
    RemoteOperation,
    Result,
    Verification,
)
from servers.models import ConnectionDefinition, Server

now = datetime(2026, 10, 20, 9, 30, tzinfo=UTC)

operator = get_user_model().objects.create_user(
    username="operator",
    email="operator@example.com",
    password="fixture-password",
    first_name="Fixture",
    last_name="Operator",
    is_staff=True,
)
operator.groups.add(Group.objects.get(name="Administrator"))

server = Server.objects.create(
    name="Web",
    ssh_alias="web.example.com",
    connection_mode="agent",
    address="203.0.113.10",
    username="deploy",
    port=2222,
    credential_reference="SHA256:fixture",
    connection_revision=1,
    registration_revision=1,
)
ConnectionDefinition.objects.create(
    server=server,
    revision=1,
    mode="agent",
    alias="web.example.com",
    address="203.0.113.10",
    username="deploy",
    port=2222,
    credential_reference="SHA256:fixture",
)
attempt = DiscoveryAttempt.objects.create(
    server=server,
    ssh_alias="web.example.com",
    status=RemoteOperation.Status.SUCCEEDED,
    requested_by=operator,
    authority="discovery.add_discoveryattempt",
    started_at=now,
    finished_at=now,
)
snapshot = DiscoverySnapshot.objects.create(
    server=server,
    attempt=attempt,
    collected_at=now,
    os_status="observed",
    os_source="/etc/os-release",
    os_pretty_name="Ubuntu 26.04.1 LTS",
    os_name="Ubuntu",
    os_id="ubuntu",
    os_version_id="26.04",
    arch_status="observed",
    arch_value="x86_64",
    arch_source="uname -m",
    cpu_status="observed",
    cpu_count=2,
    cpu_source="nproc",
    memory_status="observed",
    memory_bytes=4_000_000_000,
    memory_source="/proc/meminfo",
    filesystem_status="observed",
    filesystem_size_bytes=50_000_000_000,
    filesystem_avail_bytes=40_000_000_000,
    filesystem_source="df -B1 --output=size,avail,target /",
    sites_status="observed",
    sites_source="/etc/caddy/sites",
    releases_status="observed",
    settings_status="observed",
    cache_status="absent",
    automation_status="absent",
    workers_status="absent",
    backups_status="absent",
    offsite_status="absent",
    jobs_status="absent",
    host_standing="target_stack",
)
SettingObservation.objects.create(
    snapshot=snapshot,
    identifier="shop",
    application="laravel",
    name="APP_NAME",
    digest="a" * 64,
    value="Fixture Shop",
)

preparation = ChangePreparation.objects.create(
    server=server,
    ssh_alias=server.ssh_alias,
    status=RemoteOperation.Status.SUCCEEDED,
    requested_by=operator,
    kind_slug="install_database_engine",
    inputs={"version": 1},
    started_at=now,
    finished_at=now,
)
review = ChangeReview.objects.create(
    preparation=preparation,
    kind_slug="install_database_engine",
    intent="Install MariaDB",
    eligible=False,
    consent=Consent.SHARED,
    ssh_alias=server.ssh_alias,
    collected_at=now,
    admission_expires_at=now + timedelta(minutes=15),
    document={"version": 1, "engine": "mariadb"},
)
ChangeRun.objects.create(
    server=server,
    ssh_alias=server.ssh_alias,
    review=review,
    requested_by=operator,
    requested_by_name=operator.username,
    server_name=server.name,
    unit_name="barectl-apply-" + "a" * 32 + ".service",
    status=RemoteOperation.Status.SUCCEEDED,
    execution=Result.SUCCEEDED,
    verification=Verification.PASSED,
    started_at=now,
    finished_at=now,
    acknowledged_at=now,
)

print(
    "seeded "
    f"{get_user_model().objects.count()} users, "
    f"{Group.objects.count()} groups, "
    f"{Server.objects.count()} servers, "
    f"{DiscoverySnapshot.objects.count()} snapshots, "
    f"{SettingObservation.objects.count()} settings, "
    f"{ChangePreparation.objects.count()} preparations, "
    f"{ChangeReview.objects.count()} reviews, "
    f"{ChangeRun.objects.count()} runs"
)
"""


def run(command: list[str], *, cwd: Path, env: dict[str, str]) -> None:
    print("+", " ".join(command), f"(in {cwd})")  # noqa: T201 - the recorder's report
    subprocess.run(  # noqa: S603 - fixed argv built here
        command, cwd=cwd, env=env, check=True
    )


def copy_database(source: Path, destination: Path) -> None:
    """Copy ``source`` with SQLite's backup API after folding its WAL into the database."""
    with sqlite3.connect(source) as original, sqlite3.connect(destination) as copy:
        original.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        original.backup(copy)


def environment_from(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip("'\"")
    return values


@contextmanager
def worktree(repository: Path, directory: Path) -> Iterator[Path]:
    tree = directory / "v0.4.0"
    subprocess.run(  # noqa: S603 - fixed argv built here
        [GIT, "worktree", "add", "--detach", str(tree), REFERENCE],
        cwd=repository,
        check=True,
    )
    try:
        yield tree
    finally:
        subprocess.run(  # noqa: S603 - fixed argv built here
            [GIT, "worktree", "remove", "--force", str(tree)],
            cwd=repository,
            check=False,
        )


def main() -> int:
    repository = Path(__file__).resolve().parent.parent
    fixture = repository / "dashboard" / "upgrade_fixtures" / "v0.4.0.sqlite"
    environment = os.environ | environment_from(repository / ".env")
    with tempfile.TemporaryDirectory(prefix="barectl-v040-") as temporary:
        directory = Path(temporary)
        with worktree(repository, directory) as tree:
            run([sys.executable, "manage.py", "migrate", "--noinput"], cwd=tree, env=environment)
            seed = directory / "seed.py"
            seed.write_text(SEED, encoding="utf-8")
            run(
                [
                    sys.executable,
                    "manage.py",
                    "shell",
                    "-c",
                    f"exec(compile(open({str(seed)!r}).read(), {str(seed)!r}, 'exec'))",
                ],
                cwd=tree,
                env=environment,
            )
            fixture.parent.mkdir(parents=True, exist_ok=True)
            copy_database(tree / "db.sqlite3", fixture)
            for suffix in ("-wal", "-shm"):
                fixture.with_name(fixture.name + suffix).unlink(missing_ok=True)
    with sqlite3.connect(fixture) as database:
        migrations = database.execute(
            "SELECT app, name FROM django_migrations ORDER BY app, name"
        ).fetchall()
        print(f"wrote {fixture} with {len(migrations)} recorded migrations")  # noqa: T201
        for app, name in migrations:
            print(f'        ("{app}", "{name}"),')  # noqa: T201 - update V040_MIGRATIONS
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
