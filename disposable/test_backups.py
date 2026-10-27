"""Backups lifecycle: enable, take a database-only point, and reconstruct it (#396).

docs/quality.md#native-layer. This is the first shared Phase D scenario; later slices extend
it with full captures, restore, retention and disaster recovery. Each check is an
operator-visible outcome on a real Ubuntu 26.04 host.
"""

import json
import shlex
from typing import cast

from django.test import tag

from backups.observation import ObservedBackup
from discovery.snapshot import CollectedSnapshot
from discovery.ssh import RemoteShell
from operations.inputs import PreparationInputs
from operations.models import ChangeReview
from runtimes.catalog import Architecture

from . import mirror
from .change_testing import apply_change
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
        self.capture()
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

    def points(self) -> list[dict[str, object]]:
        from backups import check
        from discovery.root_read import run_root

        with self.shell() as shell:
            listing = run_root(shell, check.listing_command(IDENTIFIER))
        return check.points(check.parse_listing(listing.stdout) or [])
