"""Backups lifecycle: enable, capture, restore and reconstruct from native evidence.

docs/quality.md#native-layer. This is the first shared Phase D scenario; later slices extend
it with retention and disaster recovery. Each check is an operator-visible outcome on a real
Ubuntu 26.04 host.
"""

import json
import shlex
from typing import cast

from django.test import tag

from backups.observation import ObservedBackup
from backups.schedule import ObservedBackupSchedule
from discovery.snapshot import CollectedSnapshot
from discovery.ssh import RemoteShell
from operations.inputs import PreparationInputs
from operations.models import ChangeReview
from runtimes.catalog import Architecture

from . import mirror
from .change_testing import apply_change, submit_change
from .scenario_testing import SCENARIO_TAG, ScenarioTestCase

IDENTIFIER = "bkalpha"
DOMAIN = "bkalpha.example.com"
PASSPHRASE = "correct-horse-battery-staple-backup"  # noqa: S105 - native test value
MARIADB_SOCKET = "/run/mysqld/mysqld.sock"
MYSQL = "mariadb --no-defaults --protocol=socket --socket=" + MARIADB_SOCKET + " --user=root -N -B"


def write(test: ScenarioTestCase, shell: RemoteShell, path: str, content: str) -> None:
    result = shell.run(f"install -D -m 0644 /dev/stdin {shlex.quote(path)}", stdin=content.encode())
    test.assertEqual(result.exit_status, 0, result.stdout)


class BackupCase(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = "bk"

    def router(self, shell: RemoteShell) -> None:
        write(self, shell, "/etc/apt/sources.list.d/barectl-fixture.sources", mirror.apt_sources())
        write(
            self,
            shell,
            "/etc/apt/apt.conf.d/99barectl-fixture",
            'Acquire::By-Hash "no";\nAcquire::Languages "none";\n',
        )
        self.assertEqual(shell.run("rm -f /etc/apt/sources.list.d/ubuntu.sources").exit_status, 0)
        update = shell.run("apt-get update 2>&1")
        self.assertEqual(update.exit_status, 0, update.stdout)

    def prepare_site(self) -> ChangeReview:
        from databases import engine as database_engine
        from databases import site as database_site
        from sites import change as sites_change

        with self.shell() as shell:
            self.router(shell)
            apply_change(self, database_engine.INSTALL, PreparationInputs("mariadb"), timeout=150)
        self.native("systemctl restart php-fpm@php84.service php-fpm@php85.service")
        apply_change(
            self,
            sites_change.CREATE_SITE,
            PreparationInputs("php84", IDENTIFIER, (DOMAIN,)),
            timeout=120,
        )
        review = apply_change(
            self,
            database_site.ADD_SITE_DATABASE,
            PreparationInputs("", IDENTIFIER),
            timeout=120,
        )
        self.native(
            f"{MYSQL} -e "  # noqa: S608 - checked fixture statement in a disposable database
            + shlex.quote(
                "CREATE TABLE recovery_check (id INT PRIMARY KEY, note VARCHAR(40)); "
                "INSERT INTO recovery_check VALUES (7, 'before-the-backup')"
            )
            + " s"
            + IDENTIFIER
        )
        return review

    def enable(self) -> ChangeReview:
        from backups import change

        return apply_change(
            self,
            change.ENABLE,
            PreparationInputs("", IDENTIFIER),
            timeout=150,
            secret=PASSPHRASE.encode(),
        )

    def capture(self) -> ChangeReview:
        from backups import change

        return apply_change(
            self, change.BACK_UP_NOW, PreparationInputs("", IDENTIFIER), timeout=150
        )

    def capture_full(self) -> ChangeReview:
        from backups import change

        return apply_change(
            self, change.BACK_UP_FULL, PreparationInputs("", IDENTIFIER), timeout=150
        )

    def restore_database(self, point: str) -> ChangeReview:
        from backups import restore

        return apply_change(
            self,
            restore.RESTORE,
            PreparationInputs("", IDENTIFIER, point=point),
            timeout=180,
        )

    def set_schedule(self, at: str, *, scope: str = "database") -> ChangeReview:
        from backups import schedule

        return apply_change(
            self,
            schedule.SET_BACKUP_SCHEDULE,
            PreparationInputs(
                "",
                IDENTIFIER,
                schedule_state="on",
                backup_schedule=True,
                frequency="daily",
                at=at,
                scope=scope,
            ),
            timeout=120,
        )

    def disable_schedule(self) -> ChangeReview:
        from backups import schedule

        return apply_change(
            self,
            schedule.SET_BACKUP_SCHEDULE,
            PreparationInputs(
                "",
                IDENTIFIER,
                schedule_state="off",
                backup_schedule=True,
            ),
            timeout=120,
        )

    def schedule_row(self) -> ObservedBackupSchedule:
        from backups import schedule

        with self.shell() as shell:
            rows = schedule.read(shell, (IDENTIFIER,))
        if rows is None:
            self.fail("The backup schedule could not be read.")
        return rows[0]

    def next_schedule_time(self) -> str:
        from datetime import UTC, datetime, timedelta

        moment = datetime.now(UTC) + timedelta(minutes=2)
        return moment.strftime("%H:%M")

    def site_status(self, path: str = "/") -> int:
        return int(
            self.native(
                "curl --silent --show-error --max-time 20 --resolve "
                f"{DOMAIN}:80:127.0.0.1 -o /dev/null -w '%{{http_code}}' "
                f"http://{DOMAIN}{path}"
            ).strip()
        )

    def large_file(self) -> None:
        path = f"/var/www/{IDENTIFIER}/current/public/large.bin"
        self.native(f"head -c 268435456 /dev/urandom > {path}")
        self.native(f"chown s{IDENTIFIER}:s{IDENTIFIER} {path}")

    def wait_stage(self, unit: str, stage: str, timeout: float = 30) -> None:
        import time

        end = time.monotonic() + timeout
        while time.monotonic() < end:
            found = self.native(
                f"journalctl -u {unit} --no-pager -o cat --grep '^barectl-stage {stage}$' "
                "| head -n 1"
            ).strip()
            if found:
                return
            time.sleep(0.1)
        self.fail(f"The run never reached {stage}: " + self.native(f"journalctl -u {unit} -n 40"))

    def observe(self) -> CollectedSnapshot:
        from discovery.observations import collect

        with self.shell() as shell:
            return collect(shell)

    def backup_row(self, collected: CollectedSnapshot) -> ObservedBackup:
        return next(row for row in collected.backups.value if row.identifier == IDENTIFIER)


@tag(SCENARIO_TAG)
class BackupLifecycle(BackupCase):
    def test_enables_captures_and_reconstructs_from_native_evidence(self) -> None:
        from backups import check, convention, observation
        from discovery.root_read import run_root

        self.prepare_site()
        enabled = self.enable()
        with self.shell() as shell:
            row = observation.read(
                shell,
                (IDENTIFIER,),
                "mariadb",
                Architecture.X86_64,
            )
            if row is None:
                self.fail("The backup evidence could not be read.")
            observed = cast(list[dict[str, object]], row["sites"])[0]
            self.assertTrue(observed["repository"])
            self.assertTrue(observed["key"])
            self.assertTrue(observed["database"])
            # Plain restic opens the repository with only the recovery passphrase.
            staged = "/run/barectl/secrets/passphrase-check"
            staged_result = shell.run(
                f"install -d -m 700 /run/barectl/secrets && install -m 600 /dev/stdin {staged}",
                stdin=PASSPHRASE.encode(),
            )
            self.assertEqual(staged_result.exit_status, 0)
            listing = run_root(
                shell,
                "sh -c "
                + shlex.quote(
                    f"RESTIC_REPOSITORY={convention.repository(IDENTIFIER)} "
                    f"RESTIC_PASSWORD_FILE={staged} "
                    f"RESTIC_CACHE_DIR={convention.CACHE_DIR} "
                    f"{convention.RESTIC_BIN} snapshots --json --no-lock"
                ),
            )
            shell.run(f"rm -f {staged}")
            self.assertEqual(listing.exit_status, 0, listing.stdout)
            self.assertEqual(json.loads(listing.stdout or "[]"), [])
        # One reviewed schedule installs a fixed UTC timer. It fires a live capture with no
        # controller connected, and a fresh controller reads the same schedule back.
        at = self.next_schedule_time()
        self.set_schedule(at)
        installed = self.schedule_row()
        self.assertTrue(installed.installed)
        self.assertTrue(installed.timer_active)
        self.assertTrue(installed.timer_enabled)
        self.assertGreater(installed.next_elapse_us, 0)
        import time

        end = time.monotonic() + 180
        scheduled: list[dict[str, object]] = []
        while time.monotonic() < end and not scheduled:
            scheduled = [point for point in self.points() if point.get("origin") == "scheduled"]
            if not scheduled:
                time.sleep(2)
        self.assertTrue(scheduled, "The real backup timer never fired a scheduled capture.")
        self.assertTrue(scheduled[0]["live"])
        self.assertTrue(scheduled[0]["complete"])
        collected = self.observe()
        backup = self.backup_row(collected)
        if backup.last is None:
            self.fail("No scheduled result was reconstructed.")
        self.assertEqual(backup.last.origin, "scheduled")
        self.assertIn(backup.last.result_class, ("succeeded", "partial"))
        from operations.models import ChangeReview as Review
        from operations.models import ChangeRun

        ChangeRun.objects.all().delete()
        Review.objects.all().delete()
        reconstructed = self.schedule_row()
        self.assertTrue(reconstructed.installed)
        self.assertEqual(reconstructed.frequency, "daily")
        self.assertEqual(reconstructed.at, at)
        self.assertGreater(reconstructed.next_elapse_us, 0)
        self.disable_schedule()
        self.assertFalse(self.schedule_row().installed)
        self.capture()
        self.assertEqual(self.site_status("/"), 200)
        self.assertNotIn("respond 503", self.native(f"cat /etc/caddy/sites/{IDENTIFIER}.caddy"))
        collected = self.observe()
        backup = self.backup_row(collected)
        self.assertTrue(backup.enabled)
        if backup.last is None:
            self.fail("No backup result was reconstructed.")
        self.assertIn(backup.last.result_class, ("succeeded", "partial"))
        self.assertEqual(backup.last.scope, "database")
        with self.shell() as shell:
            listing = run_root(shell, check.listing_command(IDENTIFIER))
        parsed = check.parse_listing(listing.stdout)
        self.assertIsNotNone(parsed, listing.stdout)
        points = check.points(parsed or [])
        self.assertEqual(len(points), 1)
        self.assertTrue(points[0]["complete"])
        database_point = points[0]["point"]
        # A fresh controller keeps no local change history and still sees the same state.
        from operations.models import ChangeReview as Review
        from operations.models import ChangeRun

        ChangeRun.objects.all().delete()
        Review.objects.all().delete()
        again = self.observe()
        backup = self.backup_row(again)
        self.assertTrue(backup.enabled)
        self.assertEqual(backup.last.point if backup.last else "", points[0]["point"])
        # The kernel exposes the result line without the passphrase.
        journal = self.native("journalctl --no-pager -o cat --grep '^barectl-result ' | tail -n 20")
        self.assertIn('"kind":"backup"', journal)
        self.assertNotIn(PASSPHRASE, journal)
        self.assertNotIn(PASSPHRASE, enabled.document.get("kit_lines", []))
        # A failing dump creates no recovery point and says so.
        before = self.points()
        self.native("mv /usr/bin/mariadb-dump /usr/bin/mariadb-dump.barectl-test")
        try:
            from backups import change

            apply_change(
                self,
                change.BACK_UP_NOW,
                PreparationInputs("", IDENTIFIER),
                timeout=60,
                expected="refused",
                reason="backup_dump",
            )
        finally:
            self.native("mv /usr/bin/mariadb-dump.barectl-test /usr/bin/mariadb-dump")
        self.assertEqual(self.points(), before)
        # A full capture writes both parts under one point and reopens the site only after
        # both are verified present.
        self.capture_full()
        full = [point for point in self.points() if point["scope"] == "full"]
        self.assertEqual(len(full), 1)
        self.assertTrue(full[0]["complete"])
        self.assertEqual(full[0]["parts"], ["database", "files"])
        self.assertEqual(self.site_status("/"), 200)
        collected = self.observe()
        backup = self.backup_row(collected)
        if backup.last is None:
            self.fail("No full backup result was reconstructed.")
        self.assertEqual(backup.last.scope, "full")
        self.assertEqual(backup.last.result_class, "succeeded")
        with self.shell() as shell:
            environment = (
                f"RESTIC_REPOSITORY={convention.repository(IDENTIFIER)} "
                f"RESTIC_PASSWORD_FILE={convention.server_key(IDENTIFIER)} "
                f"RESTIC_CACHE_DIR={convention.CACHE_DIR} {convention.RESTIC_BIN}"
            )
            listing = run_root(
                shell,
                f"{environment} snapshots --json --no-lock --tag point:{backup.last.point}",
            )
            rows = json.loads(listing.stdout or "[]")
            files_id = next(
                row["id"]
                for row in rows
                if isinstance(row.get("tags"), list) and "part:files" in row["tags"]
            )
            files = run_root(shell, f"{environment} ls --json --no-lock {files_id}")
            self.assertIn(f"/var/www/{IDENTIFIER}/releases/initial", files.stdout)
            self.assertNotIn("respond 503", self.native(f"cat /etc/caddy/sites/{IDENTIFIER}.caddy"))
        # A capture killed while it copies files stays gated, and one reviewed action reopens it.
        from backups import reopen

        self.large_file()
        submitted = submit_change(self, change.BACK_UP_FULL, PreparationInputs("", IDENTIFIER))
        self.wait_stage(submitted.unit, "backup-files")
        self.native(f"systemctl kill --signal=KILL {submitted.unit}")
        self.assertEqual(self.site_status("/"), 503)
        self.assertIn("respond 503", self.native(f"cat /etc/caddy/sites/{IDENTIFIER}.caddy"))
        apply_change(self, reopen.REOPEN_SITE, PreparationInputs("", IDENTIFIER), timeout=60)
        self.assertEqual(self.site_status("/"), 200)
        # A database-only restore replaces the point's data, takes a safety copy first and
        # leaves the site serving. The import runs as the site principal, not a superuser.
        self.native(
            f"{MYSQL} -e "  # noqa: S608 - checked fixture statement in a disposable database
            + shlex.quote(
                "UPDATE recovery_check SET note='after-the-point' WHERE id=7; "
                "CREATE TABLE after_the_point (id INT PRIMARY KEY)"
            )
            + " s"
            + IDENTIFIER
        )
        before_restore = len(self.points())
        self.restore_database(str(database_point))
        self.assertEqual(self.site_status("/"), 200)
        self.assertEqual(
            self.native(
                f"{MYSQL} -N -B -e "  # noqa: S608 - checked fixture query in a disposable database
                + shlex.quote("SELECT note FROM recovery_check WHERE id=7")
                + " s"
                + IDENTIFIER
            ).strip(),
            "before-the-backup",
        )
        query = (
            f"SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='s{IDENTIFIER}' "  # noqa: S608
            "AND TABLE_NAME='after_the_point'"
        )
        self.assertEqual(
            self.native(f"{MYSQL} -N -B -e " + shlex.quote(query)).strip(),
            "0",
        )
        after_restore = self.points()
        safety = [row for row in after_restore if row["origin"] == "safety"]
        self.assertEqual(len(safety), 1)
        self.assertEqual(safety[0]["scope"], "database")
        self.assertEqual(len(after_restore), before_restore + 1)
        journal = self.native("journalctl --no-pager -o cat --grep '^barectl-result ' | tail -n 20")
        self.assertIn('"kind":"restore"', journal)
        self.assertIn("restore_done", journal)
        self.assertNotIn(PASSPHRASE, journal)

    def points(self) -> list[dict[str, object]]:
        from backups import check
        from discovery.root_read import run_root

        with self.shell() as shell:
            listing = run_root(shell, check.listing_command(IDENTIFIER))
        return check.points(check.parse_listing(listing.stdout) or [])


@tag(SCENARIO_TAG)
@tag("breadth")
class RebootedFullBackup(BackupCase):
    breadth = True

    def test_a_reboot_during_a_full_capture_keeps_the_gate(self) -> None:
        from backups import change, reopen

        self.prepare_site()
        self.enable()
        self.large_file()
        submitted = submit_change(
            self,
            change.BACK_UP_FULL,
            PreparationInputs("", IDENTIFIER),
        )
        self.wait_stage(submitted.unit, "backup-files")
        self.stop_for(20)
        self.assertEqual(self.site_status("/"), 503)
        site_file = self.native(f"cat /etc/caddy/sites/{IDENTIFIER}.caddy")
        self.assertIn("respond 503", site_file)
        apply_change(
            self,
            reopen.REOPEN_SITE,
            PreparationInputs("", IDENTIFIER),
            timeout=60,
        )
        self.assertEqual(self.site_status("/"), 200)
