"""Upgrading an existing Barectl installation in place.

The command and its operator guide are docs/upgrade.md. This module holds the checks,
the backup, and the migration so each can be tested without a controller. Barectl keeps
no server-side upgrade marker: the database and the server stay ordinary local state.
"""

import shutil
import sqlite3
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from django.conf import settings
from django.core.management import call_command
from django.db import OperationalError, connection
from django.db.migrations.executor import MigrationExecutor
from django.tasks import TaskResultStatus
from django_tasks_db.models import DBTaskResult

from discovery.services import request_discovery
from operations.models import RemoteOperation
from servers.models import Server

from .settings_views import barectl_version

BASELINE_VERSION = "0.4.0"

PRE_BASELINE_REFUSAL = (
    "This database predates Barectl 0.4.0 and cannot be upgraded in place; start a new "
    "installation and register your servers again."
)
NEWER_SCHEMA_REFUSAL = (
    "This database was migrated by a newer Barectl release; install that release instead "
    "of running this command."
)
ACTIVE_OPERATION_REFUSAL = (
    "A change preparation or change run is still queued or running; wait for it to finish, "
    "then run this command again."
)
ACTIVE_TASK_REFUSAL = (
    "The discovery worker still has queued or running tasks; stop it and wait for its "
    "tasks to finish, then run this command again."
)
WORKER_REFUSAL = "The discovery worker is still running; stop it, then run this command again."
MIGRATION_FAILED = (
    "The migration failed, so the original database was put back untouched. Backup: {backup}"
)

# A v0.4.0 database recorded all of V040_MIGRATIONS. Detection uses these five sentinels,
# one from each area added late in v0.4.0, so a database that lacks any of them predates
# the release even when later releases squash or replace the rest of the baseline.
V040_SENTINELS: frozenset[tuple[str, str]] = frozenset(
    {
        ("operations", "0007_change_run_window_outcome"),
        ("discovery", "0021_discoverysnapshot_jobs_source_and_more"),
        ("backups", "0008_typed_jobs_runs_and_timers"),
        ("security", "0003_securityobservation_ssh_accounts_readable_and_more"),
        ("servers", "0002_server_certificate_email"),
    }
)

# The migrations a v0.4.0 database recorded. The checked-in fixture and
# dashboard/test_upgrade.py keep this list equal to the tag's schema, so a migration that
# drops or renames a represented record fails the fast gate.
V040_MIGRATIONS: frozenset[tuple[str, str]] = frozenset(
    {
        ("auth", "0001_initial"),
        ("auth", "0002_alter_permission_name_max_length"),
        ("auth", "0003_alter_user_email_max_length"),
        ("auth", "0004_alter_user_username_opts"),
        ("auth", "0005_alter_user_last_login_null"),
        ("auth", "0006_require_contenttypes_0002"),
        ("auth", "0007_alter_validators_add_error_messages"),
        ("auth", "0008_alter_user_username_max_length"),
        ("auth", "0009_alter_user_last_name_max_length"),
        ("auth", "0010_alter_group_name_max_length"),
        ("auth", "0011_update_proxy_permissions"),
        ("auth", "0012_alter_user_first_name_max_length"),
        ("automation", "0001_initial"),
        ("automation", "0002_workerobservation"),
        ("backups", "0001_initial"),
        ("backups", "0002_backupobservation_copy_backupobservation_offsite_and_more"),
        ("backups", "0003_backup_retention"),
        ("backups", "0003_backup_schedule"),
        ("backups", "0004_merge_0003_backup_retention_0003_backup_schedule"),
        ("backups", "0005_backupintegrity"),
        ("backups", "0006_backupexport"),
        ("backups", "0007_backupobservation_runs_backupobservation_timers"),
        ("backups", "0008_typed_jobs_runs_and_timers"),
        ("cache", "0001_initial"),
        ("contenttypes", "0001_initial"),
        ("contenttypes", "0002_remove_content_type_name"),
        ("discovery", "0001_initial"),
        ("discovery", "0002_discoverysnapshot_releases_source_and_more"),
        ("discovery", "0003_siteobservation_certificate_error_and_more"),
        ("discovery", "0004_siteobservation_readiness"),
        ("discovery", "0005_siteobservation_application"),
        ("discovery", "0006_site_settings"),
        ("discovery", "0007_siteobservation_pool"),
        ("discovery", "0008_catalog_tool_profiles"),
        ("discovery", "0009_discoverysnapshot_certificate_email_and_more"),
        ("discovery", "0010_alter_componentobservation_component"),
        ("discovery", "0010_discoverysnapshot_automation_source_and_more"),
        ("discovery", "0011_merge_automation_and_component_choices"),
        ("discovery", "0011_siteobservation_log_rotation"),
        ("discovery", "0012_merge_log_rotation_and_automation"),
        ("discovery", "0013_discoverysnapshot_cache_source_and_more"),
        ("discovery", "0014_siteobservation_client"),
        ("discovery", "0016_discoverysnapshot_workers"),
        ("discovery", "0017_merge_workers_and_cache"),
        ("discovery", "0018_discoverysnapshot_backups"),
        ("discovery", "0019_discoverysnapshot_offsite_and_more"),
        ("discovery", "0020_runtimeobservation_installed_at"),
        ("discovery", "0021_discoverysnapshot_jobs_source_and_more"),
        ("django_tasks_database", "0001_initial"),
        ("django_tasks_database", "0002_alter_dbtaskresult_options"),
        ("django_tasks_database", "0003_dbtaskresult_enqueued_at_dbtaskresult_finished_at"),
        ("django_tasks_database", "0004_dbtaskresult_started_at"),
        ("django_tasks_database", "0005_alter_dbtaskresult_priority_and_more"),
        ("django_tasks_database", "0006_alter_dbtaskresult_args_kwargs_and_more"),
        ("django_tasks_database", "0007_add_separate_results_fields"),
        ("django_tasks_database", "0008_separate_results_field"),
        ("django_tasks_database", "0009_remove_results_field"),
        ("django_tasks_database", "0010_alter_dbtaskresult_status"),
        ("django_tasks_database", "0011_rename_complete_status"),
        ("django_tasks_database", "0012_add_separate_exception_fields"),
        ("django_tasks_database", "0013_separate_exception_fields"),
        ("django_tasks_database", "0014_remove_dbtaskresult_exception_data"),
        ("django_tasks_database", "0015_correctly_order_run_after"),
        (
            "django_tasks_database",
            "0016_remove_dbtaskresult_django_task_new_ordering_idx_and_more",
        ),
        ("django_tasks_database", "0017_dbtaskresult_metadata"),
        ("django_tasks_database", "0018_rename_succeeded_status"),
        (
            "django_tasks_database",
            "0019_rename_django_task_new_ordering_idx_tasks_db_new_ordering_idx_and_more",
        ),
        ("django_tasks_database", "0020_update_db_task_result_ordering"),
        ("django_tasks_database", "0021_conditional_partial_index_ordering"),
        ("jobs", "0001_initial"),
        ("logs", "0001_initial"),
        ("logs", "0002_journal_sources"),
        ("operations", "0001_initial"),
        ("operations", "0002_confidential_input_channel"),
        ("operations", "0003_alter_changereview_options_and_more"),
        ("operations", "0004_view_evidence_permission"),
        ("operations", "0005_remove_remoteoperation_remote_operation_kind_known_and_more"),
        ("operations", "0006_backup_check_kind"),
        ("operations", "0007_change_run_window_outcome"),
        ("security", "0001_initial"),
        ("security", "0002_securityobservation_package_blacklist_and_more"),
        ("security", "0003_securityobservation_ssh_accounts_readable_and_more"),
        ("servers", "0001_initial"),
        ("servers", "0002_server_certificate_email"),
        ("sessions", "0001_initial"),
        ("sites", "0001_initial"),
    }
)


class UpgradeRefused(Exception):
    """The upgrade did not start, or failed and was put back. The message is the sentence."""


@dataclass(frozen=True)
class SchemaState:
    applied: frozenset[tuple[str, str]]
    known: frozenset[tuple[str, str]]

    @property
    def baseline_applied(self) -> bool:
        return self.applied >= V040_SENTINELS

    @property
    def pending(self) -> frozenset[tuple[str, str]]:
        return self.known - self.applied

    @property
    def unknown(self) -> frozenset[tuple[str, str]]:
        return self.applied - self.known

    def describe(self) -> str:
        if not self.applied:
            return "no recorded migrations"
        if self.unknown:
            return "newer than this release"
        if not self.baseline_applied:
            return f"older than {BASELINE_VERSION}"
        count = len(self.pending)
        if not count:
            return "up to date"
        noun = "migration" if count == 1 else "migrations"
        return f"{BASELINE_VERSION} with {count} {noun} pending"


@dataclass(frozen=True)
class UpgradeOutcome:
    installed_version: str
    schema: SchemaState
    backup: Path | None
    queued: tuple[Server, ...]
    unreadable: tuple[tuple[Server, str], ...]


@dataclass(frozen=True)
class UpgradeEnvironment:
    installed_version: Callable[[], str]
    schema_state: Callable[[], SchemaState]
    active_operations: Callable[[], list[RemoteOperation]]
    active_tasks: Callable[[], int]
    process_commands: Callable[[], list[str]]
    create_backup: Callable[[], Path]
    run_migrations: Callable[[], None]
    restore_backup: Callable[[Path], None]
    servers: Callable[[], list[Server]]
    request_discovery: Callable[[Server], object]


def schema_state() -> SchemaState:
    return SchemaState(_applied_migrations(), _known_migrations())


def database_path() -> Path:
    return Path(str(connection.settings_dict["NAME"]))


def environment_path() -> Path:
    return Path(settings.BASE_DIR) / ".env"


def backup_root() -> Path:
    return Path(settings.BASE_DIR) / "upgrade-backups"


def active_operations() -> list[RemoteOperation]:
    return list(RemoteOperation.objects.filter(status__in=RemoteOperation.ACTIVE).order_by("pk"))


def active_task_count() -> int:
    return DBTaskResult.objects.filter(
        status__in=(TaskResultStatus.READY, TaskResultStatus.RUNNING)
    ).count()


def process_commands() -> list[str]:
    """The controller's process list, or an empty list when ``ps`` is unavailable."""
    try:
        completed = subprocess.run(
            ["/bin/ps", "-A", "-o", "command"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return []
    if completed.returncode != 0:
        return []
    return completed.stdout.splitlines()


def all_servers() -> list[Server]:
    return list(Server.objects.order_by("name"))


def create_database_backup(
    *,
    database: Path | None = None,
    env_file: Path | None = None,
    root: Path | None = None,
    now: datetime | None = None,
) -> Path:
    """Write a timestamped directory holding a consistent copy of the database and .env."""
    source = database if database is not None else database_path()
    environment = env_file if env_file is not None else environment_path()
    parent = root if root is not None else backup_root()
    stamp = (now if now is not None else datetime.now(UTC)).strftime("%Y%m%dT%H%M%SZ")
    destination = parent / stamp
    suffix = 2
    while destination.exists():
        destination = parent / f"{stamp}-{suffix}"
        suffix += 1
    destination.mkdir(parents=True)
    _copy_database(source, destination / source.name)
    if environment.exists():
        shutil.copy2(environment, destination / environment.name)
    return destination


def restore_database_backup(backup: Path, *, database: Path | None = None) -> None:
    """Put the backed-up database back and remove SQLite's sidecar files."""
    target = database if database is not None else database_path()
    saved = next(iter(sorted(backup.glob("*.sqlite3"))), None)
    if saved is None:
        raise FileNotFoundError(f"The backup at {backup} holds no SQLite database.")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(saved, target)
    for suffix in ("-wal", "-shm"):
        sidecar = target.with_name(target.name + suffix)
        sidecar.unlink(missing_ok=True)


def run_migrations() -> None:
    call_command("migrate", interactive=False, verbosity=1)


def backup_this_installation() -> Path:
    return create_database_backup()


def restore_this_installation(backup: Path) -> None:
    connection.close()
    restore_database_backup(backup)


def default_environment() -> UpgradeEnvironment:
    return UpgradeEnvironment(
        installed_version=barectl_version,
        schema_state=schema_state,
        active_operations=active_operations,
        active_tasks=active_task_count,
        process_commands=process_commands,
        create_backup=backup_this_installation,
        run_migrations=run_migrations,
        restore_backup=restore_this_installation,
        servers=all_servers,
        request_discovery=request_discovery,
    )


def perform_upgrade(
    *, check_only: bool = False, environment: UpgradeEnvironment | None = None
) -> UpgradeOutcome:
    """Check, back up, migrate, and queue verification for every saved server."""
    resolved = environment if environment is not None else default_environment()
    version = resolved.installed_version()
    state = resolved.schema_state()
    if not state.baseline_applied:
        raise UpgradeRefused(PRE_BASELINE_REFUSAL)
    if state.unknown:
        raise UpgradeRefused(NEWER_SCHEMA_REFUSAL)
    if check_only or not state.pending:
        return UpgradeOutcome(version, state, None, (), ())
    refusal = _refusal(resolved)
    if refusal is not None:
        raise UpgradeRefused(refusal)
    backup = resolved.create_backup()
    try:
        resolved.run_migrations()
    except Exception as error:
        resolved.restore_backup(backup)
        raise UpgradeRefused(MIGRATION_FAILED.format(backup=backup)) from error
    queued, unreadable = _queue_verifications(resolved)
    return UpgradeOutcome(version, state, backup, tuple(queued), tuple(unreadable))


def _refusal(environment: UpgradeEnvironment) -> str | None:
    if environment.active_operations():
        return ACTIVE_OPERATION_REFUSAL
    if environment.active_tasks():
        return ACTIVE_TASK_REFUSAL
    if any("manage.py db_worker" in command for command in environment.process_commands()):
        return WORKER_REFUSAL
    return None


def _queue_verifications(
    environment: UpgradeEnvironment,
) -> tuple[list[Server], list[tuple[Server, str]]]:
    queued: list[Server] = []
    unreadable: list[tuple[Server, str]] = []
    for server in environment.servers():
        try:
            environment.request_discovery(server)
        except Exception as error:
            # One unreadable server must not stop the others' verification.
            unreadable.append((server, type(error).__name__))
        else:
            queued.append(server)
    return queued, unreadable


def _applied_migrations() -> frozenset[tuple[str, str]]:
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT app, name FROM django_migrations")
            rows = cursor.fetchall()
    except OperationalError:
        return frozenset()
    return frozenset((str(app), str(name)) for app, name in rows)


def _known_migrations() -> frozenset[tuple[str, str]]:
    executor = MigrationExecutor(connection)
    return frozenset(executor.loader.graph.nodes)


def _copy_database(source: Path, destination: Path) -> None:
    uri = f"{source.resolve().as_uri()}?mode=ro"
    with (
        sqlite3.connect(uri, uri=True) as original,
        sqlite3.connect(destination) as copy,
    ):
        original.backup(copy)
