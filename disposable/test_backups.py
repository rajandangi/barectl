"""Backups lifecycle: enable, capture, restore and reconstruct from native evidence.

docs/quality.md#native-layer. This is the first shared Phase D scenario; later slices extend
it with retention and disaster recovery. Each check is an operator-visible outcome on a real
Ubuntu 26.04 host.
"""

import json
import shlex
import tempfile
from pathlib import Path
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
    identifier = IDENTIFIER
    domain = DOMAIN
    layer = "L1"
    exclusive = True
    prefix = "bk"
    S3_HOST = "s3.us-east-1.amazonaws.com"
    S3_DUALSTACK_HOST = "s3.dualstack.us-east-1.amazonaws.com"
    S3_BUCKET = "barectl-test"
    S3_REGION = "us-east-1"

    def start_s3(self) -> None:
        """A local S3-compatible server on the lane, signed by the fixture CA.

        It runs in its own container on the lane network, not on the server: a listener on
        the server's 443 would make host standing Not manageable, and the endpoint template
        has no port. The server resolves the container's network alias and trusts the
        fixture CA.
        """
        from . import mirror
        from .docker import docker, quietly

        certificate, key = mirror.mirror_certificate([self.S3_HOST, self.S3_DUALSTACK_HOST])
        fixture = Path(__file__).resolve().parent / "native_mirror" / "s3.py"
        root = tempfile.TemporaryDirectory()
        self.s3_root = Path(root.name)
        self.addCleanup(root.cleanup)
        server = self._server_container()
        network = docker(
            "inspect", "-f", "{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}", server
        ).strip()
        image = docker("inspect", "-f", "{{.Config.Image}}", server).strip()
        self.s3_container = f"{server}-s3"
        self.addCleanup(quietly, "rm", "-f", self.s3_container)
        docker(
            "run", "-d", "--name", self.s3_container, "--pull=never",
            "--network", network, "--network-alias", self.S3_HOST,
            "--network-alias", self.S3_DUALSTACK_HOST,
            "-v", f"{fixture}:/s3fixture.py:ro",
            "-v", f"{certificate}:/tls/cert.pem:ro",
            "-v", f"{key}:/tls/key.pem:ro",
            "-v", f"{self.s3_root}:/srv/s3",
            "--entrypoint", "python3", image,
            "/s3fixture.py", "--root", "/srv/s3", "--address", "0.0.0.0:443",
            "--certificate", "/tls/cert.pem", "--key", "/tls/key.pem",
        )  # fmt: skip
        self._wait_for_s3()

    def _server_container(self) -> str:
        import os

        return os.environ["BARECTL_SSH_TEST_CONTAINER"]

    def _wait_for_s3(self) -> None:
        with self.shell() as shell:
            result = shell.run(
                "timeout 30 sh -c 'until curl --silent --show-error "
                "--cacert /usr/local/share/ca-certificates/barectl-fixture-ca.crt "
                f"https://{self.S3_HOST}/ -o /dev/null; do sleep 0.2; done'"
            )
        if result.exit_status:
            from .docker import docker

            self.fail(
                "The local S3 server did not answer: "
                + result.stdout
                + docker("logs", self.s3_container)
            )

    def s3_files(self) -> list[str]:
        return sorted(
            path.relative_to(self.s3_root).as_posix()
            for path in self.s3_root.rglob("*")
            if path.is_file()
            and not path.relative_to(self.s3_root).as_posix().startswith(".uploads/")
        )

    def offsite_files(self) -> list[str]:
        return [line for line in self.s3_files() if line.startswith(f"{self.S3_BUCKET}/")]

    def offsite_setup(self) -> ChangeReview:
        from backups import offsite

        secret = json.dumps(
            {
                "values": {
                    "access_key": "barectl-test-access",
                    "secret_key": "barectl-test-secret",
                    "passphrase": PASSPHRASE,
                }
            }
        ).encode()
        inputs = PreparationInputs(provider="s3", bucket=self.S3_BUCKET, region=self.S3_REGION)
        return apply_change(
            self,
            offsite.SET_UP,
            inputs,
            timeout=60,
            secret=secret,
        )

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
            PreparationInputs("php84", self.identifier, (self.domain,)),
            timeout=120,
        )
        review = apply_change(
            self,
            database_site.ADD_SITE_DATABASE,
            PreparationInputs("", self.identifier),
            timeout=120,
        )
        self.native(
            f"{MYSQL} -e "  # noqa: S608 - checked fixture statement in a disposable database
            + shlex.quote(
                "CREATE TABLE recovery_check (id INT PRIMARY KEY, note VARCHAR(40)); "
                "INSERT INTO recovery_check VALUES (7, 'before-the-backup')"
            )
            + " s"
            + self.identifier
        )
        return review

    def enable(self) -> ChangeReview:
        from backups import change

        return apply_change(
            self,
            change.ENABLE,
            PreparationInputs("", self.identifier),
            timeout=150,
            secret=PASSPHRASE.encode(),
        )

    def capture(self) -> ChangeReview:
        from backups import change

        return apply_change(
            self, change.BACK_UP_NOW, PreparationInputs("", self.identifier), timeout=150
        )

    def capture_full(self) -> ChangeReview:
        from backups import change

        return apply_change(
            self, change.BACK_UP_FULL, PreparationInputs("", self.identifier), timeout=150
        )

    def restore_database(self, point: str) -> ChangeReview:
        from backups import restore

        return apply_change(
            self,
            restore.RESTORE,
            PreparationInputs("", self.identifier, point=point),
            timeout=180,
        )

    def restore_files(self, point: str) -> ChangeReview:
        from backups import restore

        return apply_change(
            self,
            restore.RESTORE,
            PreparationInputs("", self.identifier, point=point, scope="files"),
            timeout=180,
        )

    def restore_full(self, point: str) -> ChangeReview:
        from backups import restore

        return apply_change(
            self,
            restore.RESTORE,
            PreparationInputs("", self.identifier, point=point, scope="full"),
            timeout=180,
        )

    def write_file(self, path: str, content: str) -> None:
        with self.shell() as shell:
            write(self, shell, path, content)

    def release_owns_its_files(self, release: str) -> None:
        """A restored release, and every entry in it, belongs to the site user (Phase D #401).

        The plain-PHP assertion proves the release form Create and Deploy produce. The
        WordPress form has fast-layer evidence and the recorded automation state; it is not
        a second site in this item because the shared scenario must stay within 180 s.
        """
        account = "s" + self.identifier
        root = f"/var/www/{self.identifier}/releases/{release}"
        self.assertEqual(self.native(f"find {root} -not -user {account} -print"), "")
        self.assertEqual(self.native(f"find {root} -perm -0004 -print"), "")

    def set_schedule(self, at: str, *, scope: str = "database") -> ChangeReview:
        from backups import schedule

        return apply_change(
            self,
            schedule.SET_BACKUP_SCHEDULE,
            PreparationInputs(
                "",
                self.identifier,
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
                self.identifier,
                schedule_state="off",
                backup_schedule=True,
            ),
            timeout=120,
        )

    def schedule_row(self) -> ObservedBackupSchedule:
        from backups import schedule

        with self.shell() as shell:
            rows = schedule.read(shell, (self.identifier,))
        if rows is None:
            self.fail("The backup schedule could not be read.")
        return rows[0]

    def next_schedule_time(self) -> str:
        from datetime import UTC, datetime, timedelta

        now = datetime.now(UTC)
        moment = now + timedelta(minutes=2 if now.second >= 50 else 1)
        return moment.strftime("%H:%M")

    def site_status(self, path: str = "/") -> int:
        return int(
            self.native(
                "curl --silent --show-error --max-time 20 --resolve "
                f"{self.domain}:80:127.0.0.1 -o /dev/null -w '%{{http_code}}' "
                f"http://{self.domain}{path}"
            ).strip()
        )

    def https_status(self, path: str = "/") -> int:
        """The site's HTTPS answer through Caddy, including any redirect it would send."""
        return int(
            self.native(
                "curl --silent --show-error --max-time 20 --insecure --resolve "
                f"{self.domain}:443:127.0.0.1 -o /dev/null -w '%{{http_code}}' "
                f"https://{self.domain}{path}"
            ).strip()
        )

    def large_file(self) -> None:
        path = f"/var/www/{self.identifier}/current/public/large.bin"
        self.native(f"head -c 268435456 /dev/urandom > {path}")
        self.native(f"chown s{self.identifier}:s{self.identifier} {path}")

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
        return next(row for row in collected.backups.value if row.identifier == self.identifier)

    def points(self) -> list[dict[str, object]]:
        from backups import check
        from discovery.root_read import run_root

        with self.shell() as shell:
            listing = run_root(shell, check.listing_command(self.identifier))
        return check.points(check.parse_listing(listing.stdout) or [])

    def offsite_points(self) -> list[dict[str, object]]:
        from backups import check, convention
        from discovery.root_read import run_root

        repository = (
            f"s3:https://{self.S3_HOST}/{self.S3_BUCKET}/{self.offsite_prefix()}/{self.identifier}"
        )
        with self.shell() as shell:
            listing = run_root(
                shell,
                "sh -c "
                + shlex.quote(
                    "set -a; . /etc/barectl/backups/offsite/capture.env; set +a; "
                    f"RESTIC_REPOSITORY={repository} "
                    f"RESTIC_PASSWORD_FILE={convention.server_key(self.identifier)} "
                    f"RESTIC_CACHE_DIR={convention.CACHE_DIR} "
                    f"AWS_DEFAULT_REGION={self.S3_REGION} "
                    f"{convention.RESTIC_BIN} -o s3.bucket-lookup=path snapshots --json --no-lock"
                ),
            )
        return check.points(check.parse_listing(listing.stdout) or [])

    def offsite_prefix(self) -> str:
        from backups import convention

        text = self.native(f"cat {convention.OFFSITE_CONFIG}")
        for line in text.splitlines():
            name, _, value = line.partition("=")
            if name == "prefix":
                return value
        raise AssertionError("The offsite config has no prefix.")


@tag(SCENARIO_TAG)
class BackupLifecycle(BackupCase):
    def test_enables_captures_and_reconstructs_from_native_evidence(self) -> None:
        from backups import check, convention, observation
        from discovery.root_read import run_root

        self.prepare_site()
        enabled = self.enable()
        # Offsite storage is checked against a local S3-compatible server, never the internet.
        self.start_s3()
        self.offsite_setup()
        self.assertEqual(
            self.native("stat -c '%u %a' /etc/barectl/backups/offsite/capture.env").strip(),
            "0 600",
        )
        self.assertNotIn(
            "barectl-test-secret",
            self.native("journalctl --no-pager -o cat --grep '^barectl-' | tail -n 40"),
        )
        with self.shell() as shell:
            row = observation.read(
                shell,
                (self.identifier,),
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
                    f"RESTIC_REPOSITORY={convention.repository(self.identifier)} "
                    f"RESTIC_PASSWORD_FILE={staged} "
                    f"RESTIC_CACHE_DIR={convention.CACHE_DIR} "
                    f"AWS_DEFAULT_REGION={self.S3_REGION} "
                    f"{convention.RESTIC_BIN} -o s3.bucket-lookup=path snapshots --json --no-lock"
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

        end = time.monotonic() + 80
        scheduled: list[dict[str, object]] = []
        while time.monotonic() < end and not scheduled:
            scheduled = [
                point
                for point in self.points()
                if point.get("origin") == "scheduled" and point.get("complete")
            ]
            if not scheduled:
                time.sleep(2)
        self.assertTrue(
            scheduled, "The real backup timer never fired a complete scheduled capture."
        )
        self.assertTrue(scheduled[0]["live"])
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
        self.assertNotIn(
            "respond 503", self.native(f"cat /etc/caddy/sites/{self.identifier}.caddy")
        )
        collected = self.observe()
        backup = self.backup_row(collected)
        self.assertTrue(backup.enabled)
        if backup.last is None:
            self.fail("No backup result was reconstructed.")
        self.assertIn(backup.last.result_class, ("succeeded", "partial"))
        self.assertEqual(backup.last.scope, "database")
        self.assertEqual(backup.last.offsite, "copied")
        offsite_points = self.offsite_points()
        self.assertEqual(len(offsite_points), 1)
        self.assertTrue(offsite_points[0]["complete"])
        self.assertEqual(offsite_points[0]["point"], backup.last.point)
        # A capture whose offsite copy fails keeps the onsite point and says so. The local S3
        # server rejects this marker credential, so the failure is immediate and offline.
        self.native(
            "mv /etc/barectl/backups/offsite/capture.env /root/capture.env.saved && "
            "printf 'AWS_ACCESS_KEY_ID=denied\nAWS_SECRET_ACCESS_KEY=denied\n' "
            "> /etc/barectl/backups/offsite/capture.env && "
            "chown root:root /etc/barectl/backups/offsite/capture.env && "
            "chmod 600 /etc/barectl/backups/offsite/capture.env"
        )
        try:
            self.capture()
        finally:
            self.native("mv /root/capture.env.saved /etc/barectl/backups/offsite/capture.env")
        failed = self.backup_row(self.observe()).last
        if failed is None:
            self.fail("No failed offsite result was reconstructed.")
        self.assertEqual(failed.result_class, "succeeded")
        self.assertEqual(failed.offsite, "failed")
        self.assertIn(failed.point, {str(point["point"]) for point in self.points()})
        # Copy offsite again repairs a failed copy without a new capture.
        from backups import offsite

        apply_change(
            self,
            offsite.COPY,
            PreparationInputs("", self.identifier, point=failed.point),
            timeout=120,
        )
        self.assertTrue(any(str(point["point"]) == failed.point for point in self.offsite_points()))
        # Removing offsite storage leaves every copy in the bucket.
        before_files = self.offsite_files()
        apply_change(
            self,
            offsite.REMOVE,
            PreparationInputs(),
            timeout=60,
            secret=json.dumps({"values": {"bucket": self.S3_BUCKET}}).encode(),
        )
        self.assertEqual(
            self.native("test ! -e /etc/barectl/backups/offsite/config; echo $?").strip(), "0"
        )
        self.assertEqual(self.offsite_files(), before_files)
        with self.shell() as shell:
            listing = run_root(shell, check.listing_command(self.identifier))
        parsed = check.parse_listing(listing.stdout)
        self.assertIsNotNone(parsed, listing.stdout)
        points = check.points(parsed or [])
        self.assertGreaterEqual(len(points), 1)
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
                PreparationInputs("", self.identifier),
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
        full_point = str(full[0]["point"])
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
                f"RESTIC_REPOSITORY={convention.repository(self.identifier)} "
                f"RESTIC_PASSWORD_FILE={convention.server_key(self.identifier)} "
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
            self.assertIn(f"/var/www/{self.identifier}/releases/initial", files.stdout)
            self.assertNotIn(
                "respond 503", self.native(f"cat /etc/caddy/sites/{self.identifier}.caddy")
            )
        # A capture killed while it copies files stays gated, and one reviewed action reopens it.
        from backups import reopen

        self.large_file()
        submitted = submit_change(self, change.BACK_UP_FULL, PreparationInputs("", self.identifier))
        self.wait_stage(submitted.unit, "backup-files")
        self.native(f"systemctl kill --signal=KILL {submitted.unit}")
        self.assertEqual(self.site_status("/"), 503)
        self.assertIn("respond 503", self.native(f"cat /etc/caddy/sites/{self.identifier}.caddy"))
        apply_change(self, reopen.REOPEN_SITE, PreparationInputs("", self.identifier), timeout=60)
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
            + self.identifier
        )
        before_restore = len(self.points())
        self.restore_database(str(database_point))
        self.assertEqual(self.site_status("/"), 200)
        self.assertEqual(
            self.native(
                f"{MYSQL} -N -B -e "  # noqa: S608 - checked fixture query in a disposable database
                + shlex.quote("SELECT note FROM recovery_check WHERE id=7")
                + " s"
                + self.identifier
            ).strip(),
            "before-the-backup",
        )
        query = (
            "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='s"  # noqa: S608
            f"{self.identifier}' AND TABLE_NAME='after_the_point'"
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
        # A files-only restore brings back the point's files as a new release owned by the
        # site user, keeps the release it replaced and takes a files-only safety backup first.
        replaced = self.native(f"readlink /var/www/{self.identifier}/current").strip()
        self.write_file(
            f"/var/www/{self.identifier}/current/public/hello.txt", "changed after the full point\n"
        )
        self.restore_files(full_point)
        self.assertEqual(self.site_status("/"), 200)
        self.assertIn(
            "Welcome to your PHP site.",
            self.native(f"cat /var/www/{self.identifier}/current/public/hello.txt"),
        )
        restored_release = self.native(f"readlink /var/www/{self.identifier}/current").strip()
        self.assertNotEqual(restored_release, replaced)
        self.assertEqual(
            self.native(f"test -d /var/www/{self.identifier}/{replaced}; echo $?"), "0"
        )
        self.release_owns_its_files(restored_release.removeprefix("releases/"))
        self.assertEqual(
            self.native(
                f"stat -c '%G %a' /var/www/{self.identifier}/current/public/hello.txt"
            ).strip(),
            "caddy 640",
        )
        files_safety = [row for row in self.points() if row["origin"] == "safety"]
        self.assertEqual(len(files_safety), 2)
        self.assertIn("files", {row["scope"] for row in files_safety})
        # A full-site restore brings back the same point's files and database together.
        self.write_file(f"/var/www/{self.identifier}/current/public/hello.txt", "changed again\n")
        self.native(
            f"{MYSQL} -e "  # noqa: S608 - checked fixture statement in a disposable database
            + shlex.quote(
                "UPDATE recovery_check SET note='changed-after-the-full-point' WHERE id=7"
            )
            + " s"
            + self.identifier
        )
        before_full = len(self.points())
        self.restore_full(full_point)
        self.assertEqual(self.site_status("/"), 200)
        self.assertIn(
            "Welcome to your PHP site.",
            self.native(f"cat /var/www/{self.identifier}/current/public/hello.txt"),
        )
        self.assertEqual(
            self.native(
                f"{MYSQL} -N -B -e "  # noqa: S608 - checked fixture query in a disposable database
                + shlex.quote("SELECT note FROM recovery_check WHERE id=7")
                + " s"
                + self.identifier
            ).strip(),
            "before-the-backup",
        )
        full_restored = self.native(f"readlink /var/www/{self.identifier}/current").strip()
        self.assertNotEqual(full_restored, restored_release)
        self.assertEqual(
            self.native(f"test -d /var/www/{self.identifier}/{restored_release}; echo $?"), "0"
        )
        self.release_owns_its_files(full_restored.removeprefix("releases/"))
        after_full = self.points()
        self.assertEqual(len(after_full), before_full + 1)
        full_safety = [row for row in after_full if row["origin"] == "safety"]
        self.assertEqual(len(full_safety), 3)
        self.assertTrue(any(row["scope"] == "full" for row in full_safety))


@tag(SCENARIO_TAG)
class Retention(BackupCase):
    """Retention and Keep on a real server: backdated points, read-back and independent sides."""

    def offsite_config(self) -> dict[str, str]:
        from backups import convention

        return convention.read_config(self.native(f"cat {convention.OFFSITE_CONFIG}"))

    def restic_repository(self, offsite: bool = False) -> str:
        from backups import convention

        if not offsite:
            return convention.repository(self.identifier)
        return convention.offsite_repository(self.offsite_config(), self.identifier)

    def restic_shell(self, *arguments: str, offsite: bool = False) -> str:
        from backups import convention

        if offsite:
            return convention.offsite_restic_command(
                self.identifier,
                self.offsite_config(),
                *arguments,
                env_paths=(convention.OFFSITE_PRUNE, convention.OFFSITE_CAPTURE),
            )
        return (
            f"RESTIC_REPOSITORY={self.restic_repository()} "
            f"RESTIC_PASSWORD_FILE={convention.server_key(self.identifier)} "
            f"RESTIC_CACHE_DIR={convention.CACHE_DIR} "
            + shlex.join([convention.RESTIC_BIN, *arguments])
        )

    def create_point(
        self,
        point: str,
        when: str,
        *,
        scope: str = "database",
        part: str = "database",
        keep: bool = False,
        filename: str = "",
        offsite: bool = False,
    ) -> None:
        from backups import convention

        tags = [
            "barectl",
            f"site:{self.identifier}",
            f"scope:{scope}",
            f"part:{part}",
            "origin:manual",
            "capture:live",
            f"point:{point}",
            "complete",
        ]
        if keep:
            tags.append("keep")
        tag_arguments = [item for tag in tags for item in ("--tag", tag)]
        if part == "database":
            name = filename or convention.dump_filename(self.identifier)
            command = "printf 'fixture dump' | " + self.restic_shell(
                "backup",
                "--stdin",
                "--stdin-filename",
                name,
                "--time",
                when,
                *tag_arguments,
                offsite=offsite,
            )
        else:
            command = self.restic_shell(
                "backup", "--time", when, *tag_arguments, "/etc/hostname", offsite=offsite
            )
        self.native(command)

    def snapshot_rows(self, offsite: bool = False) -> list[dict[str, object]]:
        import json as json_module

        text = self.native(self.restic_shell("snapshots", "--json", "--no-lock", offsite=offsite))
        start = text.index("[")
        return [row for row in json_module.loads(text[start:]) if isinstance(row, dict)]

    def retained_points(self, offsite: bool = False) -> set[str]:
        found: set[str] = set()
        for row in self.snapshot_rows(offsite):
            tags = row.get("tags")
            if not isinstance(tags, list):
                continue
            for value in tags:
                if isinstance(value, str) and value.startswith("point:"):
                    found.add(value[6:])
        return found

    def snapshot_ids(self, point: str, offsite: bool = False) -> list[str]:
        found = []
        for row in self.snapshot_rows(offsite):
            tags = row.get("tags")
            if (
                isinstance(tags, list)
                and f"point:{point}" in tags
                and isinstance(row.get("id"), str)
            ):
                found.append(str(row["id"]))
        return found

    def foreign_present(self) -> bool:
        return "hand-made" in self.native(self.restic_shell("snapshots", "--json", "--no-lock"))

    def unsynchronize_clock(self) -> None:
        self.native("systemctl stop systemd-timesyncd 2>/dev/null || true")
        self.native("timedatectl set-ntp false 2>/dev/null || true")
        if self.native("timedatectl show --property=NTPSynchronized --value").strip() == "no":
            return
        saved = "/usr/bin/timedatectl.barectl-saved"
        self.native(f"mv /usr/bin/timedatectl {saved}")
        with self.shell() as shell:
            write(self, shell, "/usr/bin/timedatectl", "#!/bin/sh\nprintf 'no\\n'\n")
        self.native("chmod 0755 /usr/bin/timedatectl")
        self.addCleanup(
            self.native,
            f"if [ -e {saved} ]; then mv {saved} /usr/bin/timedatectl; fi",
        )

    def cleanup_result(self, location: str = "onsite") -> dict[str, object]:
        import json as json_module

        unit = f"barectl-site-{self.identifier}-" + (
            "cleanup.service" if location == "onsite" else "cleanupoffsite.service"
        )
        self.native(f"systemctl start {unit} || true")
        text = self.native(
            f"journalctl -u {unit} --no-pager -o cat --grep '^barectl-result ' -n 1"
        ).strip()
        self.native(f"systemctl reset-failed {unit} 2>/dev/null || true")
        return dict(json_module.loads(text.removeprefix("barectl-result ")))

    def test_retention_keeps_the_newest_point_and_never_touches_foreign_snapshots(self) -> None:
        from backups import retention

        self.prepare_site()
        self.start_s3()
        self.enable()
        self.offsite_setup()

        old = "aaaaaaaaaaaaaaaa"
        kept = "bbbbbbbbbbbbbbbb"
        old_full = "cccccccccccccccc"
        new_full = "eeeeeeeeeeeeeeee"
        corrupt = "dddddddddddddddd"
        self.create_point(old, "2026-08-01 03:00:00")
        self.create_point(kept, "2026-08-02 03:00:00", keep=True)
        self.create_point(old_full, "2026-08-03 03:00:00", scope="full", part="database")
        self.create_point(old_full, "2026-08-03 03:00:00", scope="full", part="files")
        self.create_point(new_full, "2026-10-28 03:00:00", scope="full", part="database")
        self.create_point(new_full, "2026-10-28 03:00:00", scope="full", part="files")
        self.create_point(corrupt, "2026-10-29 03:00:00", filename="wrong.sql")
        from backups import offsite

        for copied in (old, kept):
            apply_change(
                self,
                offsite.COPY,
                PreparationInputs("", self.identifier, point=copied),
                timeout=120,
            )
        self.native(self.restic_shell("backup", "--tag", "hand-made", "/etc/hostname"))
        before = self.retained_points()
        offsite_before = self.retained_points(offsite=True)

        review = apply_change(
            self,
            retention.SET,
            PreparationInputs("", self.identifier, days=7),
            timeout=180,
        )
        self.assertIn(old, {str(row["point"]) for row in review.document["deletions"]})
        self.assertEqual(self.retained_points(), before, "Applying retention deleted a point.")
        self.assertEqual(self.retained_points(offsite=True), offsite_before)

        refused = self.cleanup_result()
        self.assertIn(refused["class"], ("partial", "failed"))
        self.assertIn(corrupt, self.retained_points(), "A failed read-back did not keep the group.")
        self.assertIn(old, self.retained_points())

        ids = self.snapshot_ids(corrupt)
        self.assertTrue(ids)
        self.native(self.restic_shell("forget", *ids))
        newest = "ffffffffffffffff"
        self.create_point(newest, "2026-10-29 04:00:00")
        apply_change(
            self,
            offsite.COPY,
            PreparationInputs("", self.identifier, point=newest),
            timeout=120,
        )

        result = self.cleanup_result()
        self.assertEqual(result["class"], "succeeded")
        self.assertIn("onsite", result)
        self.assertNotIn(old, self.retained_points())
        self.assertNotIn(old_full, self.retained_points())
        self.assertIn(new_full, self.retained_points())
        self.assertIn(newest, self.retained_points())
        self.assertIn(kept, self.retained_points())
        self.assertTrue(self.foreign_present())
        self.assertIn(old, self.retained_points(offsite=True), "Onsite cleanup changed offsite.")

        offsite_result = self.cleanup_result("offsite")
        self.assertEqual(offsite_result["class"], "succeeded")
        self.assertNotIn(old, self.retained_points(offsite=True))
        self.assertIn(kept, self.retained_points(offsite=True))
        self.assertIn(newest, self.retained_points(offsite=True))

        self.unsynchronize_clock()
        skipped = self.cleanup_result()
        self.assertEqual(skipped["class"], "refused")
        self.assertEqual(skipped["reason"], "cleanup_clock")


@tag(SCENARIO_TAG)
class Integrity(BackupCase):
    """The weekly check on a real server: read-back, rotation, damage and a held lock."""

    def restic_shell(self, *arguments: str, offsite: bool = False) -> str:
        from backups import convention

        repository = (
            convention.repository(IDENTIFIER)
            if not offsite
            else f"s3:https://{self.S3_HOST}/{self.S3_BUCKET}/{self.offsite_prefix()}/{IDENTIFIER}"
        )
        source = ". /etc/barectl/backups/offsite/capture.env; " if offsite else ""
        return (
            f"{source}RESTIC_REPOSITORY={repository} "
            f"RESTIC_PASSWORD_FILE={convention.server_key(IDENTIFIER)} "
            f"RESTIC_CACHE_DIR={convention.CACHE_DIR} "
            + shlex.join([convention.RESTIC_BIN, *arguments])
        )

    def point_ids(self) -> set[str]:
        text = self.native(self.restic_shell("snapshots", "--json", "--no-lock"))
        rows = json.loads(text[text.index("[") :])
        found: set[str] = set()
        for row in rows if isinstance(rows, list) else []:
            tags = row.get("tags") if isinstance(row, dict) else None
            if isinstance(tags, list):
                found.update(
                    str(tag)[6:]
                    for tag in tags
                    if isinstance(tag, str) and tag.startswith("point:")
                )
        return found

    def integrity_result(self, location: str = "onsite") -> dict[str, object]:
        unit = f"barectl-site-{IDENTIFIER}-" + (
            "check.service" if location == "onsite" else "checkoffsite.service"
        )
        self.native(f"systemctl start {unit}")
        text = self.native(
            f"journalctl -u {unit} --no-pager -o cat --grep '^barectl-result ' -n 1"
        ).strip()
        return dict(json.loads(text.removeprefix("barectl-result ")))

    def last_integrity_subsets(self, location: str = "onsite") -> list[str]:
        unit = f"barectl-site-{IDENTIFIER}-" + (
            "check.service" if location == "onsite" else "checkoffsite.service"
        )
        text = self.native(
            f"journalctl -u {unit} --no-pager -o cat --grep '^barectl-result ' -n 20"
        )
        subsets = []
        for line in reversed(text.splitlines()):
            if line.startswith("barectl-result "):
                row = json.loads(line.removeprefix("barectl-result "))
                if isinstance(row, dict) and row.get("kind") == "integrity":
                    subsets.append(str(row.get("subset", "")))
        return subsets

    def test_the_weekly_check_reads_the_newest_point_and_reports_a_corrupted_pack(self) -> None:
        self.prepare_site()
        self.start_s3()
        self.enable()
        self.offsite_setup()
        capture = self.capture()
        point = str(capture.document["point"])

        self.assertFalse(self.last_integrity_subsets(), "A check ran before the first run.")
        onsite = self.integrity_result()
        self.assertEqual(onsite["class"], "succeeded", onsite)
        self.assertEqual(onsite["location"], "onsite")
        self.assertEqual(onsite["point"], point)
        self.assertRegex(str(onsite["subset"]), r"\A([1-9]|1[0-9]|20)/20\Z")
        again = self.integrity_result()
        self.assertEqual(again["class"], "succeeded", again)
        self.assertNotEqual(again["subset"], onsite["subset"], "The subset did not advance.")
        self.assertEqual(again["point"], point)

        offsite = self.integrity_result("offsite")
        self.assertEqual(offsite["class"], "succeeded", offsite)
        self.assertEqual(offsite["location"], "offsite")
        self.assertEqual(offsite["point"], point)

        packs = self.native(
            f"find /var/lib/barectl-backups/{IDENTIFIER}/onsite/data -type f -name '*.p'"
        ).split()
        self.assertTrue(packs, "The repository holds no packs.")
        pack = packs[0]
        self.native(f"cp -p {pack} {pack}.bak")
        self.native(f"printf damaged >> {pack}")
        damaged = self.integrity_result()
        self.assertEqual(damaged["class"], "failed", damaged)
        self.assertEqual(damaged["reason"], "integrity_pack")
        self.assertEqual(damaged["point"], "")
        self.assertIn(point, self.point_ids(), "An integrity failure removed a recovery point.")

        capture = self.capture()
        self.assertTrue(capture.document["point"])
        self.assertIn(point, self.point_ids(), "A capture after damage removed a recovery point.")

        self.native(f"mv {pack}.bak {pack}")
        repaired = self.integrity_result()
        self.assertEqual(repaired["class"], "succeeded", repaired)
        self.assertEqual(repaired["point"], point)

        lock = f"/run/lock/barectl/backup-{IDENTIFIER}.lock"
        self.native(f"install -m 0600 /dev/null {lock}")
        self.native(f"flock -x {lock} -c 'sleep 3' >/dev/null 2>&1 &")
        self.native("sleep 1")
        skipped = self.integrity_result()
        self.assertEqual(skipped["class"], "lock_busy", skipped)
        self.assertEqual(skipped["reason"], "backup_lock")
        self.assertNotEqual(skipped["class"], "succeeded")
        self.native("sleep 4")


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
            PreparationInputs("", self.identifier),
        )
        self.wait_stage(submitted.unit, "backup-files")
        self.stop_for(20)
        self.assertEqual(self.site_status("/"), 503)
        site_file = self.native(f"cat /etc/caddy/sites/{self.identifier}.caddy")
        self.assertIn("respond 503", site_file)
        apply_change(
            self,
            reopen.REOPEN_SITE,
            PreparationInputs("", self.identifier),
            timeout=60,
        )
        self.assertEqual(self.site_status("/"), 200)


@tag(SCENARIO_TAG)
class WordPressFullRestore(BackupCase):
    """A WordPress site's paused full point comes back as files and database (#406).

    The L5 layer carries MariaDB, the runtimes and the ACME fixture; this item creates the
    WordPress site on it, captures one paused full point, mutates the uploads, the private
    configuration and the database, restores with the safety backup and proves the data,
    ownership, permissions and both HTTPS readiness answers.
    """

    layer = "L5"
    identifier = "bkwp"
    domain = "bkwp.example.com"
    prefix = "bkwp"
    ADMIN = "barectladmin"
    ADMIN_PASSWORD = "Barectl-Restore-406"  # noqa: S105 - native test value
    TITLE = "Barectl restore fixture"
    UPLOAD = "wp-content/uploads/barectl.txt"

    def create_site(self) -> None:
        from wordpress import create

        apply_change(
            self,
            create.CREATE_WORDPRESS,
            PreparationInputs(
                "php84",
                self.identifier,
                (self.domain,),
                https=True,
                title=self.TITLE,
                admin_username=self.ADMIN,
                admin_email="admin@example.com",
            ),
            timeout=180,
            secret=self.ADMIN_PASSWORD.encode(),
        )
        self.assertIn(
            f"s{self.identifier}",
            self.native(f"cat /var/www/{self.identifier}/private/wp-config.php"),
        )

    def upload(self, name: str, content: str) -> None:
        site = f"s{self.identifier}"
        self.native(
            f"install -d -o {site} -g caddy -m 2750 "
            f"/var/www/{self.identifier}/current/public/wp-content/uploads"
        )
        self.native(
            f"install -o {site} -g caddy -m 640 /dev/stdin "
            f"/var/www/{self.identifier}/current/public/{name}"
            " <<'EOF'\n" + content + "EOF"
        )

    def option(self) -> str:
        query = "SELECT option_value FROM wp_options WHERE option_name='blogname'"
        return self.native(f"{MYSQL} -e {shlex.quote(query)} s{self.identifier}").strip()

    def test_a_wordpress_site_restores_files_database_and_readiness(self) -> None:
        self.create_site()
        self.upload(self.UPLOAD, "before-the-point\n")
        self.enable()
        self.capture_full()
        points = [row for row in self.points() if row["scope"] == "full"]
        self.assertEqual(len(points), 1)
        self.assertTrue(points[0]["complete"])
        point = str(points[0]["point"])
        serving = self.native(f"readlink /var/www/{self.identifier}/current").strip()
        title = self.option()
        private_digest = self.native(
            f"sha256sum /var/www/{self.identifier}/private/wp-config.php | cut -d' ' -f1"
        ).strip()
        # Mutation after the point: uploads, a new file, an extra constant and the database.
        self.native(
            f"install -o s{self.identifier} -g caddy -m 640 /dev/stdin "
            f"/var/www/{self.identifier}/current/public/{self.UPLOAD} "
            "<<'EOF'\nchanged-after-the-point\nEOF"
        )
        self.upload("wp-content/uploads/later.txt", "not-in-the-point\n")
        self.native(
            f"printf \"define( 'BARECTL_RESTORE_LATER', 'after' );\\n\" "
            f">>/var/www/{self.identifier}/private/wp-config.php"
        )
        statement = shlex.quote(
            "UPDATE wp_options SET option_value='changed' WHERE option_name='blogname'"
        )
        self.native(f"{MYSQL} -e {statement} s{self.identifier}")
        before = len(self.points())
        self.restore_full(point)
        # The files, the private configuration and the database all come from the point.
        self.assertEqual(
            self.native(f"cat /var/www/{self.identifier}/current/public/{self.UPLOAD}"),
            "before-the-point\n",
        )
        self.assertEqual(
            self.native(
                f"test -e /var/www/{self.identifier}/current/public/wp-content/uploads/later.txt; "
                "echo $?"
            ),
            "1",
        )
        self.assertEqual(
            self.native(
                f"sha256sum /var/www/{self.identifier}/private/wp-config.php | cut -d' ' -f1"
            ).strip(),
            private_digest,
        )
        self.assertEqual(self.option(), title)
        # The target's own database settings survive the private configuration's replacement.
        private = self.native(f"cat /var/www/{self.identifier}/private/wp-config.php")
        self.assertIn(f"define( 'DB_NAME', 's{self.identifier}' );", private)
        self.assertIn(f"define( 'DB_USER', 's{self.identifier}' );", private)
        self.assertNotIn("BARECTL_RESTORE_LATER", private)
        # Both answers the readiness check requires are 200 through Caddy over HTTPS.
        self.assertEqual(self.https_status("/"), 200)
        self.assertEqual(self.https_status("/wp-login.php"), 200)
        # A new site-owned release replaced the serving one, and the old one stayed retained.
        restored = self.native(f"readlink /var/www/{self.identifier}/current").strip()
        self.assertNotEqual(restored, serving)
        self.assertTrue(restored.startswith("releases/restore-"))
        self.assertEqual(self.native(f"test -d /var/www/{self.identifier}/{serving}; echo $?"), "0")
        self.release_owns_its_files(restored.removeprefix("releases/"))
        self.assertEqual(
            self.native(
                f"stat -c '%U %G %a' /var/www/{self.identifier}/private/wp-config.php"
            ).strip(),
            f"s{self.identifier} s{self.identifier} 600",
        )
        self.assertEqual(
            self.native(
                f"stat -c '%U %G %a' /var/www/{self.identifier}/current/public/{self.UPLOAD}"
            ).strip(),
            f"s{self.identifier} caddy 640",
        )
        after = self.points()
        self.assertEqual(len(after), before + 1)
        safety = [row for row in after if row["origin"] == "safety"]
        self.assertEqual(len(safety), 1)
        self.assertEqual(safety[0]["scope"], "full")
        # -- Deploy with pending migrations offers Back up first (#407) ----------------
        from backups import change as backup_change
        from backups import check as backup_check
        from backups import observation as backup_observation
        from discovery.root_read import run_root
        from laravel import change as laravel_change
        from sites import remove as site_remove

        migration = "2026_10_31_000000_create_before_deploy_table"
        with self.shell() as shell:
            write(
                self,
                shell,
                f"/var/www/{self.identifier}/current/database/migrations/{migration}.php",
                "<?php\n",
            )
            shell.run(
                f"chown s{self.identifier}:s{self.identifier} "
                f"/var/www/{self.identifier}/current/database/migrations/{migration}.php"
            )
        deploy_inputs = PreparationInputs("", self.identifier)
        with self.shell() as shell:
            draft = laravel_change.DEPLOY_SITE.review(
                laravel_change.DEPLOY_SITE.inspect(shell, deploy_inputs), deploy_inputs
            )
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertIn(migration, cast(list[str], draft.document["pending_migrations"]))
        self.assertTrue(draft.document["back_up_first"])
        self.assertIn("Back up first", str(draft.document["acknowledgement"]))
        # Back up first is the ordinary paused full capture with one recorded input.
        apply_change(
            self,
            backup_change.BACK_UP_FULL,
            PreparationInputs("", self.identifier, from_deploy=True),
            timeout=180,
        )
        with self.shell() as shell:
            after_backup = laravel_change.DEPLOY_SITE.review(
                laravel_change.DEPLOY_SITE.inspect(shell, deploy_inputs), deploy_inputs
            )
        full_point = next(
            row for row in self.points() if row.get("scope") == "full" and row.get("complete")
        )
        acknowledgement = str(after_backup.document["acknowledgement"])
        self.assertIn(str(full_point["point"])[:8], acknowledgement)
        self.assertNotIn("has no automatic backup", acknowledgement)

        # -- Remove site keeps the repository and lists it as removed (#407) ----------
        with self.shell() as shell:
            before_remove = backup_observation.removed(shell, ())
        apply_change(
            self,
            site_remove.REMOVE,
            PreparationInputs("", self.identifier, primary=self.domain),
            timeout=180,
        )
        repository = f"/var/lib/barectl-backups/{self.identifier}/onsite"
        self.assertEqual(self.native(f"test -d {repository}; echo $?").strip(), "0")
        self.assertEqual(
            self.native(f"test -f /etc/barectl/backups/{self.identifier}.key; echo $?").strip(),
            "0",
        )
        self.assertEqual(
            self.native(
                f"systemctl list-unit-files 'barectl-site-{self.identifier}-*' --no-legend | wc -l"
            ).strip(),
            "0",
        )
        with self.shell() as shell:
            names = backup_observation.removed(shell, ())
            listing = run_root(shell, backup_check.listing_command(self.identifier))
        self.assertEqual(before_remove, ())
        self.assertEqual(names, (self.identifier,))
        kept = backup_check.points(backup_check.parse_listing(listing.stdout) or [])
        self.assertIn(str(full_point["point"]), {str(row["point"]) for row in kept})


@tag(SCENARIO_TAG)
class LaravelFullRestore(BackupCase):
    """A Laravel site's paused full point replaces its shared state as a whole (#406).

    The L5 layer carries a deployed Laravel fixture with ``vendor/`` and the worker
    prerequisites. The item captures one paused full point, mutates the private ``.env``,
    the shared storage directory, the release and the database, restores with the safety
    backup, and proves ``/up`` answers 200 through Caddy with no redirect, the shared state
    came back whole, and the restored release counts toward Deploy's current plus five.
    """

    layer = "L5"
    identifier = "sqwalpha"
    domain = "site.fixture.test"
    prefix = "bklv"

    def env_digest(self) -> str:
        return self.native(
            f"sha256sum /var/www/{self.identifier}/private/laravel.env | cut -d' ' -f1"
        ).strip()

    def add_old_releases(self, count: int) -> list[str]:
        """Release directories older than the restore, as a Deploy's retained history."""
        names = [f"{index + 1:040x}-{'a' * 16}" for index in range(count)]
        account = f"s{self.identifier}"
        for index, name in enumerate(names, 1):
            release = f"/var/www/{self.identifier}/releases/{name}"
            self.native(f"install -d -o {account} -g {account} -m 711 {release}")
            self.native(f"install -o {account} -g {account} -m 600 /dev/null {release}/artisan")
            self.native(f"touch -d '2020-01-{index:02d} 00:00:00' {release}")
        return names

    def test_a_laravel_site_restores_shared_state_readiness_and_retention(self) -> None:
        from laravel import change as laravel_change
        from laravel import observation as laravel_observation

        self.enable()
        self.capture_full()
        points = [row for row in self.points() if row["scope"] == "full"]
        self.assertEqual(len(points), 1)
        self.assertTrue(points[0]["complete"])
        point = str(points[0]["point"])
        serving = self.native(f"readlink /var/www/{self.identifier}/current").strip()
        environment = self.env_digest()
        storage = f"/var/www/{self.identifier}/private/storage"
        self.native(
            f"install -o s{self.identifier} -g s{self.identifier} -m 600 /dev/stdin "
            f"{storage}/barectl-later.txt <<'EOF'\nnot-in-the-point\nEOF"
        )
        self.native(
            f"printf 'BARECTL_RESTORE_LATER=after\\n' >>"
            f"/var/www/{self.identifier}/private/laravel.env"
        )
        self.native(
            f"{MYSQL} -e "
            + shlex.quote("CREATE TABLE restore_later (id INT PRIMARY KEY)")
            + f" s{self.identifier}"
        )
        old = self.add_old_releases(5)
        before = len(self.points())
        self.restore_full(point)
        # The full point answers /up through Caddy over HTTPS with no redirect.
        self.assertEqual(self.https_status("/up"), 200)
        self.assertEqual(
            self.native(
                "curl --silent --show-error --max-time 20 --insecure --resolve "
                f"{self.domain}:443:127.0.0.1 -o /dev/null -w '%{{redirect_url}}' "
                f"https://{self.domain}/up"
            ),
            "",
        )
        # Shared state is replaced as a whole: the later file and the env edit are gone.
        self.assertEqual(self.env_digest(), environment)
        self.assertEqual(
            self.native(f"test -e {storage}/barectl-later.txt; echo $?"),
            "1",
        )
        query = (
            "SELECT COUNT(*) FROM information_schema.TABLES "
            "WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='restore_later'"
        )
        self.assertEqual(
            self.native(f"{MYSQL} -N -B -e {shlex.quote(query)}").strip(),
            "0",
        )
        # Shared state and the release keep the convention's classification.
        self.assertEqual(
            self.native(
                f"stat -c '%U %G %a' /var/www/{self.identifier}/private/laravel.env"
            ).strip(),
            f"s{self.identifier} s{self.identifier} 600",
        )
        self.assertEqual(
            self.native(f"stat -c '%U %G %a' /var/www/{self.identifier}/private/storage").strip(),
            f"s{self.identifier} s{self.identifier} 700",
        )
        restored = self.native(f"readlink /var/www/{self.identifier}/current").strip()
        self.assertNotEqual(restored, serving)
        self.assertTrue(restored.startswith("releases/restore-"))
        self.assertEqual(self.native(f"test -d /var/www/{self.identifier}/{serving}; echo $?"), "0")
        self.release_owns_its_files(restored.removeprefix("releases/"))
        # The restored release counts toward Deploy's current plus five, and the release it
        # replaced stays retained; only the oldest historical release is now prunable.
        with self.shell() as shell:
            value = laravel_observation.read(shell)
        if value is None:
            self.fail("Laravel observation did not answer after the restore.")
        row = laravel_observation.site(value, self.identifier)
        if row is None:
            self.fail("The restored Laravel site was not observed.")
        self.assertIn(
            restored.removeprefix("releases/"),
            [str(release["name"]) for release in laravel_change.releases_of(row)],
        )
        pruned = laravel_change.prune_names(row)
        self.assertNotIn(restored.removeprefix("releases/"), pruned)
        self.assertNotIn(serving.removeprefix("releases/"), pruned)
        self.assertEqual(pruned, [old[0]])
        after = self.points()
        self.assertEqual(len(after), before + 1)
        safety = [row for row in after if row["origin"] == "safety"]
        self.assertEqual(len(safety), 1)
        self.assertEqual(safety[0]["scope"], "full")
