"""Applying a reviewed WordPress installation on a real, disposable Ubuntu server
(docs/wordpress.md#applying-an-installation).

Tagged ``ssh`` and skipped unless the disposable server is configured, as
``bootstrap/test_apply_remote.py`` describes. The administrator prepares the site, HTTPS
lineage, MariaDB binding, PHP baseline and authenticated WP-CLI by hand (see
``test_install_remote``); Barectl then reviews and applies through the dashboard request, the
worker, its SSH connection, actual systemd, curl, tar, WP-CLI, MariaDB, PHP-FPM, Nginx and
WordPress, and the official artifacts over the real network. At most one administrator command
is inserted between two named fragments of the production body to fault a boundary. Ground
truth is read as root through ``docker exec``, independently of Barectl.
"""

import re
import subprocess
import time
from unittest import mock

from django.db.models import F

from bootstrap import native as bootstrap_native
from bootstrap.models import ApplyRun, ConfigurationPlan, Execution, Verification
from discovery import ssh
from discovery.fakes import run_worker
from discovery.native_testing import setting
from operations import native as operations_native
from operations.models import RemoteOperation

from . import core_native, install_apply, install_native, setup_native
from .install_apply_remote_testing import (
    BASE,
    NEW_BOOT,
    REPLACE_CERTIFICATE,
    RESTORE_PHP,
    SECRET_WORDS,
    SITE_FILE,
    USER,
    InstallApplyTestCase,
)
from .install_remote_testing import (
    DATABASE,
    IDENTIFIER,
    LINEAGE,
    PRIVATE,
    PUBLIC,
)
from .models import InstallRunResult, PlanWordpressInstall, RunWordpressInstall

Status = RemoteOperation.Status
Exit = install_native.Exit


# A boot ID no real boot of the disposable server has.
class InstallApplyAcceptanceTests(InstallApplyTestCase):
    def test_a_reviewed_installation_is_applied_and_verified(self) -> None:
        plan = self.eligible()
        before_units = self.units()
        run = self.apply_install(plan)
        journal = self.journal(run.unit_name)
        self.assertEqual(
            (run.status, run.execution, run.verification, run.exit_status),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED, 0),
            f"{run.failure}\n{journal[-3000:]}",
        )
        self.assertEqual(before_units, [])
        self.assertEqual(self.units(), [run.unit_name])
        self.assertEqual(InstallRunResult.objects.get(run=run).problems, "")
        self.assertEqual(RunWordpressInstall.objects.get(run=run).identifier, IDENTIFIER)
        self.assertEqual(self.tables(), "12")
        # HTTPS: home, login, and the denial routes.
        self.assertEqual(self.curl("/"), "200")
        self.assertEqual(self.curl("/wp-login.php"), "200")
        for denied in ("/wp-config.php", "/wp-content/uploads/x.php", "/.hidden"):
            self.assertEqual(self.curl(denied), "403", denied)
        self.assertEqual(self.curl("/", host="shop.test", scheme="http"), "301")
        self.assertEqual(self.curl("/.well-known/acme-challenge/x", scheme="http"), "404")
        self.assertEqual(self.curl("/", host="shop.test"), "301")
        # The site directory holds exactly its two directories again.
        self.assertEqual(self.administer(f"ls -A {BASE}").split(), ["private", "public"])
        self.assertEqual(self.administer(f"ls -A {PUBLIC}").split().count("index.html"), 0)
        self.assertIn("barectl-wordpress: HTTPS verified", journal)
        self.assertIn("barectl-wordpress: gate verified", journal)
        for word in SECRET_WORDS:
            self.assertNotIn(word, journal)

    def test_the_published_files_have_the_native_ownership_and_modes(self) -> None:
        run = self.apply_install(self.eligible())
        self.assertEqual(run.execution, Execution.SUCCEEDED, run.failure)
        self.assertEqual(
            self.administer(f"stat -c '%U:%G %a' {PUBLIC}/wp-config.php {PRIVATE}/wp-config.php")
            .strip()
            .splitlines(),
            [f"{USER}:www-data 640", f"{USER}:{USER} 600"],
        )
        # Every release file is the site user's, files 0644 and directories 0755 (WordPress
        # itself may have created further content since, with its own ownership).
        for listing in (
            f"find {PUBLIC} -mindepth 1 ! -user {USER} ! -name uploads -print -quit",
            f"find {PUBLIC} -type f ! -name wp-config.php ! -perm 0644 -print -quit",
            f"find {PUBLIC} -mindepth 1 -type d ! -perm 0755 -print -quit",
            f"find {PUBLIC} -type l -print -quit",
            f"find {PUBLIC} -type f -links +1 -print -quit",
        ):
            self.assertEqual(self.administer(listing).strip(), "", listing)
        self.assertEqual(
            self.administer(f"stat -c '%U:%G %a' {PUBLIC} {BASE} {BASE}/private").splitlines(),
            [f"{USER}:www-data 750", "root:root 755", f"{USER}:{USER} 700"],
        )
        # The preimages the run kept are root-only and exact.
        plan_row = RunWordpressInstall.objects.get(run=run)
        backup = f"/var/backups/nginx/{IDENTIFIER}.conf.{run.unit_name.split('-')[2][:32]}"
        self.assertEqual(
            self.administer(f"sha256sum {backup}").split()[0], plan_row.preimage_sha256
        )
        self.assertEqual(self.administer(f"stat -c '%U:%G %a' {backup}").strip(), "root:root 600")
        placeholder = (
            f"/var/backups/nginx/{IDENTIFIER}.index.html.{run.unit_name.split('-')[2][:32]}"
        )
        self.assertEqual(
            self.administer(f"sha256sum {placeholder}").split()[0], plan_row.placeholder_sha256
        )
        self.assertEqual(self.administer(f"stat -c %a {SITE_FILE}").strip(), "644")

    def test_the_unit_ran_under_the_reviewed_native_limits(self) -> None:
        run = self.apply_install(self.eligible())
        self.assertEqual(run.execution, Execution.SUCCEEDED, run.failure)
        shown = self.administer(
            f"systemctl show -p LimitFSIZE -p MemoryMax -p MemorySwapMax -p RuntimeMaxUSec "
            f"{run.unit_name}"
        )
        values = dict(line.split("=", 1) for line in shown.splitlines())
        self.assertEqual(values["LimitFSIZE"], str(core_native.MAX_FILE_BYTES))
        self.assertEqual(values["MemoryMax"], str(core_native.MEMORY_MAX_BYTES))
        self.assertEqual(values["MemorySwapMax"], "0")
        self.assertEqual(values["RuntimeMaxUSec"], "30min")

    def test_a_polluted_cache_is_never_used(self) -> None:
        # The cache WP-CLI would consult holds an archive of the right name with other bytes.
        pollute = (
            's /usr/bin/mkdir -p "$stg/home/cache/core" && '
            'printf polluted >"$stg/home/cache/core/wordpress-7.1.3-en_US.tar.gz" && '
            'chown -R "$u:$u" "$stg/home/cache"'
        )
        run = self.fault("stage", pollute)
        self.assertEqual(
            (run.status, run.execution, run.verification),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED),
            run.failure,
        )
        self.assertEqual(self.curl("/wp-login.php"), "200")

    def test_an_oversized_file_is_stopped_by_the_native_file_limit(self) -> None:
        big = (
            '( dd if=/dev/zero of="$base/.big$q" bs=1M count=100 >/dev/null 2>&1; '
            'echo "barectl-test: dd=$?" ); rm -f -- "$base/.big$q"'
        )
        run = self.fault("stage", big)
        self.assertEqual(run.execution, Execution.SUCCEEDED, run.failure)
        # SIGXFSZ ends dd with 128 + 25.
        self.assertIn("barectl-test: dd=153", self.journal(run.unit_name))

    def test_memory_above_the_native_limit_stops_the_whole_unit(self) -> None:
        grow = (
            "python3 -c 'x = bytearray(900 * 1024 * 1024); "
            'x[::4096] = b"x" * len(x[::4096])\' >/dev/null 2>&1; '
            'echo "barectl-test: python=$?"'
        )
        before = self.ground()
        run = self.fault("stage", grow)
        # The cgroup's memory limit killed the process, and systemd stops the whole unit.
        self.assertEqual(self.unit(run.unit_name)["Result"], "oom-kill")
        self.assertEqual(
            (run.status, run.verification), (Status.FAILED, Verification.NOT_APPLICABLE)
        )
        self.assertNotIn("barectl-test: python=0", self.journal(run.unit_name))
        # systemd ended the unit with SIGTERM first, so the run's own cleanup ran.
        self.assert_untouched_by(before, run)


class InstallRefusalTests(InstallApplyTestCase):
    """Refusals before any change leave the server exactly as it was."""

    def refuses(self, after: str, step: str, status: int) -> ApplyRun:
        before = self.ground()
        run = self.fault(after, step)
        self.assert_run(run, Execution.ARTIFACT_REFUSED, status)
        self.assertEqual(run.verification, Verification.NOT_APPLICABLE)
        self.assert_untouched_by(before, run)
        self.assertEqual(self.administer_home_residue(), "", "the run's staging was cleaned")
        return run

    def test_wrong_bytes_are_refused_before_anything_downloaded_is_used(self) -> None:
        run = self.refuses("download", 'printf x >>"$ar"', Exit.ARCHIVE)
        self.assertIn("not the reviewed bytes", run.failure)
        self.assertIn("no downloaded code ran", run.failure)

    def test_a_polluted_download_directory_is_refused_before_any_use(self) -> None:
        run = self.refuses("stage", 'printf x >"$stg/dl/wp_poison.tar.gz"', Exit.ARCHIVE)
        self.assertIn("no downloaded code ran", run.failure)

    def test_a_blocked_download_is_refused(self) -> None:
        run = self.refuses("stage", 'chmod 500 "$stg/dl"', Exit.DOWNLOAD)
        self.assertIn("could not download", run.failure)

    def test_dangerous_or_excess_entries_are_refused_by_the_admission(self) -> None:
        # A reviewed entry limit below the real archive's: the native admission refuses it.
        with mock.patch.object(core_native, "MAX_ENTRIES", 100):
            plan = self.eligible()
            before = self.ground()
            run = self.apply_install(plan)
        self.assert_run(run, Execution.ARTIFACT_REFUSED, Exit.ENTRIES)
        self.assertIn("refuses", run.failure)
        self.assert_untouched_by(before, run)

    def test_an_extraction_that_fails_is_refused(self) -> None:
        self.refuses("archive", 'chmod 500 "$stg/tree"', Exit.EXTRACT)

    def test_a_tree_that_fails_core_checksums_is_refused_before_publication(self) -> None:
        run = self.refuses("extract", "printf '\\n' >>\"$stg/tree/wp-login.php\"", Exit.CHECKSUMS)
        self.assertIn("checksum verification", run.failure)

    def test_a_missing_native_tool_is_refused_before_the_review_is_rechecked(self) -> None:
        self.addCleanup(
            self.administer, "mv /usr/bin/openssl.away /usr/bin/openssl 2>/dev/null; true"
        )
        plan = self.eligible()
        self.administer("mv /usr/bin/openssl /usr/bin/openssl.away")
        before = self.ground()
        run = self.apply_install(plan)
        self.administer("mv /usr/bin/openssl.away /usr/bin/openssl")
        self.assert_run(run, Execution.ARTIFACT_REFUSED, Exit.TOOLS)
        self.assertIn("lacks a native tool", run.failure)
        self.assert_untouched_by(before, run)

    def changed(self, change: str, undo: str = "true") -> ApplyRun:
        plan = self.eligible()
        self.addCleanup(self.administer, undo)
        self.administer(change)
        before = self.ground()
        run = self.apply_install(plan)
        self.assertEqual((run.status, run.execution), (Status.FAILED, Execution.DRIFT), run.failure)
        self.assertIn("changed after review", run.failure)
        self.assertEqual(self.ground(), before)
        self.assertEqual(self.units(), [run.unit_name])
        return run

    def test_a_new_application_file_after_review_is_drift(self) -> None:
        self.changed(f"touch {PUBLIC}/surprise.txt")

    def test_a_new_application_table_after_review_is_drift(self) -> None:
        self.changed(f"mariadb --no-defaults -e 'CREATE TABLE {DATABASE}.t (i INT)'")

    def test_a_changed_site_file_after_review_is_drift(self) -> None:
        self.changed(f"printf '# changed\\n' >>{SITE_FILE}; nginx -t -q")

    def test_a_changed_certificate_lineage_after_review_is_drift(self) -> None:
        self.changed(REPLACE_CERTIFICATE)

    def test_a_changed_tool_after_review_is_drift(self) -> None:
        self.changed(f"chmod 755 {setup_native.PHAR}", f"chmod 644 {setup_native.PHAR}")


class InstallFenceTests(InstallApplyTestCase):
    """The shared lock, boot and deadline fences, checked under the lock before any change."""

    def refused_install(self, plan: ConfigurationPlan, execution: Execution) -> ApplyRun:
        before = self.ground()
        run = self.apply_install(plan)
        self.assertEqual((run.status, run.execution), (Status.FAILED, execution), run.failure)
        self.assertEqual(self.ground(), before)
        return run

    def test_a_changed_boot_and_an_expired_deadline_refuse(self) -> None:
        plan = self.eligible()
        ConfigurationPlan.objects.filter(pk=plan.pk).update(
            boot_id="00000000-0000-4000-8000-000000000000"
        )
        self.refused_install(plan, Execution.BOOT_CHANGED)
        again = self.eligible()
        ConfigurationPlan.objects.filter(pk=again.pk).update(
            uptime_centiseconds=F("uptime_centiseconds") - 100000,
            admission_deadline_centiseconds=F("admission_deadline_centiseconds") - 100000,
        )
        self.refused_install(again, Execution.EXPIRED)

    def test_a_lock_held_by_another_controllers_run_refuses_at_once(self) -> None:
        plan = self.eligible()
        holder = self.submit(
            lambda unit, boot, deadline: "; ".join(
                [*bootstrap_native.admission(unit, boot, deadline), "sleep 120"]
            ),
            alias="disposable-second",
        )
        started = time.monotonic()
        run = self.refused_install(plan, Execution.LOCK_CONFLICT)
        self.assertLess(time.monotonic() - started, 60)
        self.assertIn("Prepare a new", run.failure)
        self.assertEqual(self.inspect(holder).execution, Execution.RUNNING)

    def test_another_runs_surviving_processes_refuse(self) -> None:
        plan = self.eligible()
        child = "setsid sh -c 'exec 9>&- </dev/null >/dev/null 2>&1; exec sleep 300' & wait"
        name = self.submit(
            lambda unit, boot, deadline: "; ".join(
                [*bootstrap_native.admission(unit, boot, deadline), child]
            )
        )
        time.sleep(1)
        self.administer(f"systemctl kill --kill-whom=main --signal=SIGKILL {name}")
        time.sleep(1)
        self.refused_install(plan, Execution.OTHER_RUN_ACTIVE)
        self.administer(f"systemctl kill --signal=SIGKILL {name}")
        self.wait_terminal(name, timeout=30)

    def test_a_scheduled_renewal_with_processes_refuses(self) -> None:
        plan = self.eligible()
        self.renewal()
        self.refused_install(plan, Execution.RENEWAL_ACTIVE)


class InstallGateTests(InstallApplyTestCase):
    """The provisioning gate is verified before any application file or table exists."""

    def test_the_gate_serves_503_throughout_and_nothing_is_public_before_it(self) -> None:
        samples = (
            "for i in 1 2 3 4 5 6; do "
            "curl -sk --max-time 5 --resolve www.shop.test:443:127.0.0.1 -o /dev/null "
            "-w 'barectl-test: / %{http_code}\\n' https://www.shop.test/; sleep 0.5; done"
        )
        run = self.fault("gate", samples, "true")
        self.assertEqual(run.execution, Execution.SUCCEEDED, run.failure)
        journal = self.journal(run.unit_name)
        codes = re.findall(r"barectl-test: / (\d+)", journal)
        self.assertEqual(codes, ["503"] * 6, journal[-1500:])

    def test_a_gate_that_cannot_be_staged_leaves_the_site_file_alone(self) -> None:
        plan = self.eligible()
        before = self.site_sha()
        with self.injected(plan, "checksums", ': >"$sn"'):
            run = self.apply_install(plan)
        self.assert_run(run, Execution.GATE_REFUSED, Exit.GATE)
        self.assertEqual(self.site_sha(), before)
        self.assertEqual(self.administer(f"ls -A {PUBLIC}").strip(), "index.html")
        self.assertEqual(self.tables(), "0")

    def test_a_gate_that_is_not_served_as_reviewed_restores_the_site_file(self) -> None:
        plan = self.eligible()
        before = self.site_sha()
        with self.injected(plan, "checksums", REPLACE_CERTIFICATE):
            run = self.apply_install(plan)
        self.assert_run(run, Execution.GATE_REFUSED, Exit.GATE_NOT_SERVING)
        self.assertEqual(self.site_sha(), before)
        self.assertEqual(self.administer(f"ls -A {PUBLIC}").strip(), "index.html")
        self.assertEqual(self.tables(), "0")
        self.assertIn("restored the previous site file", run.failure)

    def test_a_gate_that_cannot_be_proven_restored_is_reported_as_such(self) -> None:
        plan = self.eligible()
        broken = "/etc/nginx/conf.d/zz-barectl-broken.conf"
        self.addCleanup(self.administer, f"rm -f {broken}; nginx -t -q && systemctl reload nginx")
        with self.injected(plan, "checksums", f"printf 'not_a_directive;\\n' >{broken}"):
            run = self.apply_install(plan)
        self.assert_run(run, Execution.PARTIAL, Exit.GATE_NOT_RESTORED)
        self.assertIn("could not be proven restored", run.failure)
        # The previous bytes are back on disk; nothing application-related exists.
        self.assertEqual(self.site_sha(), PlanWordpressInstall.objects.get().preimage_sha256)
        self.assertEqual(self.administer(f"ls -A {PUBLIC}").strip(), "index.html")


class InstallPartialTests(InstallApplyTestCase):
    """Each publication, schema and serving boundary: files, tables and secrets stay."""

    def partial(self, after: str, step: str, status: int, undo: str = "true") -> ApplyRun:
        run = self.fault(after, step, undo)
        self.assert_run(run, Execution.PARTIAL, status)
        self.assertEqual(run.verification, Verification.NOT_APPLICABLE)
        self.assertIn("removes nothing automatically", run.failure)
        self.assertIn("never replays core installation", run.failure)
        self.assertEqual(self.administer_home_residue(), "", "the run's staging was cleaned")
        self.assertEqual(self.units().count(run.unit_name), 1)
        return run

    def test_a_foreign_release_file_is_never_overwritten(self) -> None:
        run = self.partial("gate", f"printf foreign >{PUBLIC}/index.php", Exit.PUBLISH)
        self.assertEqual(self.administer(f"cat {PUBLIC}/index.php"), "foreign")
        self.assertEqual(self.administer(f"stat -c '%U' {PUBLIC}/index.php").strip(), "root")
        self.assertEqual(self.administer(f"ls -A {PUBLIC}").split(), ["index.html", "index.php"])
        self.assert_gated()
        self.assertEqual(self.tables(), "0")
        self.assertIn("release files", run.failure)

    def test_an_existing_directory_is_never_replaced_or_given_to_the_site_user(self) -> None:
        run = self.partial("gate", 'mkdir -m 0700 "$pub/wp-content"', Exit.PUBLISH)
        self.assertEqual(
            self.administer(f"stat -c '%U:%G %a' {PUBLIC}/wp-content").strip(), "root:root 700"
        )
        self.assertEqual(self.administer(f"ls -A {PUBLIC}/wp-content").strip(), "")
        self.assertIn("release files", run.failure)

    def test_a_changed_placeholder_is_never_replaced(self) -> None:
        self.partial("publish", 'printf changed >>"$pub/index.html"', Exit.PLACEHOLDER)
        self.assertTrue(
            self.administer(f"cat {PUBLIC}/index.html").endswith("changed"),
            "the changed placeholder is kept",
        )
        self.assertEqual(self.administer(f"stat -c '%U' {PUBLIC}/wp-includes").strip(), USER)
        self.assert_gated()

    def test_a_foreign_loader_is_never_overwritten(self) -> None:
        self.partial("placeholder", 'printf foreign >"$pub/wp-config.php"', Exit.LOADER)
        self.assertEqual(self.administer(f"cat {PUBLIC}/wp-config.php"), "foreign")
        self.assertEqual(self.administer(f"ls {PRIVATE}").strip(), "")
        self.assertEqual(self.tables(), "0")
        self.assert_gated()

    def test_a_foreign_private_configuration_is_never_overwritten(self) -> None:
        self.partial("loader", 'printf foreign >"$prv/wp-config.php"', Exit.CONFIGURATION)
        self.assertEqual(self.administer(f"cat {PRIVATE}/wp-config.php"), "foreign")
        self.assertEqual(self.tables(), "0")
        self.assert_gated()

    def test_a_failed_core_installation_keeps_every_file_and_the_gate(self) -> None:
        grant = f"{DATABASE}.* FROM '{USER}'@'localhost'"
        revoke = f'mariadb --no-defaults -e "REVOKE ALL PRIVILEGES ON {grant}"'
        run = self.partial("configuration", revoke, Exit.INSTALL)
        self.assertIn("provisioning gate", run.failure)
        self.assertEqual(self.tables(), "0")
        configuration = self.administer(f"stat -c '%U:%G %a' {PRIVATE}/wp-config.php").strip()
        self.assertEqual(configuration, f"{USER}:{USER} 600")
        self.assertEqual(self.administer(f"ls {PUBLIC}/wp-includes | head -1").strip() != "", True)
        self.assert_gated()
        # The review refuses a second attempt instead of replaying the installation.
        again = self.review()
        self.assertFalse(again.eligible)
        self.assertIn("WordPress", self.texts(again))

    def test_a_damaged_schema_is_reported_and_never_repaired(self) -> None:
        table = f"{DATABASE}.wp_commentmeta"
        damage = f"mariadb --no-defaults -e 'ALTER TABLE {table} DROP COLUMN meta_value'"
        run = self.partial("install", damage, Exit.SCHEMA)
        self.assertEqual(self.tables(), "12")
        self.assertIn("complete WordPress core schema", run.failure)
        self.assert_gated()
        columns = self.administer(
            'mariadb --no-defaults -N -B -e "SELECT COUNT(*) FROM information_schema.COLUMNS '  # noqa: S608 - the test's own fixed names
            f"WHERE TABLE_SCHEMA='{DATABASE}' AND TABLE_NAME='wp_commentmeta'\""
        ).strip()
        self.assertEqual(columns, "3", "the damaged table was not repaired")

    def test_a_changed_release_file_fails_integrity_while_gated(self) -> None:
        run = self.partial("schema", "printf '\\n' >>\"$pub/wp-login.php\"", Exit.INTEGRITY)
        self.assertIn("checksum verification", run.failure)
        self.assert_gated()
        self.assertEqual(self.tables(), "12")

    def test_a_pool_that_does_not_answer_fails_the_private_access_check(self) -> None:
        stop = f"systemctl stop php{self.php}-fpm"
        run = self.partial("integrity", stop, Exit.ACCESS, RESTORE_PHP.format(php=self.php))
        self.assertIn("site user", run.failure)
        self.assertEqual(self.curl("/"), "503")

    def test_ready_routing_that_cannot_be_staged_keeps_the_gate(self) -> None:
        run = self.partial("access", ': >"$sn"', Exit.READY)
        self.assertIn("not served", run.failure)
        self.assert_gated()
        self.assertEqual(self.tables(), "12")


class InstallServingFailureTests(InstallApplyTestCase):
    """After the ready routing: restore the exact gate only while its bytes are this run's."""

    BREAK = 'chmod 000 "$pub/index.php" "$pub/wp-login.php"'

    def test_a_serving_failure_restores_and_verifies_the_exact_gate(self) -> None:
        plan = self.eligible()
        row = PlanWordpressInstall.objects.get(plan=plan)
        with self.injected(plan, "ready", self.BREAK):
            run = self.apply_install(plan)
        self.assert_run(run, Execution.NOT_SERVING, Exit.NOT_SERVING)
        self.assertEqual(self.site_sha(), row.gate_sha256)
        self.assert_gated()
        self.assertEqual(self.tables(), "12")
        self.assertIn("verified that application paths answer 503", run.failure)
        self.assertEqual(run.verification, Verification.NOT_APPLICABLE)
        self.assertEqual(self.administer(f"stat -c %a {PUBLIC}/index.php").strip(), "0")

    def test_a_gate_that_cannot_be_restored_reports_the_uncertain_exposure(self) -> None:
        plan = self.eligible()
        away = f"{LINEAGE}/fullchain.pem.away"
        self.addCleanup(self.administer, f"mv {away} {LINEAGE}/fullchain.pem 2>/dev/null; true")
        with self.injected(plan, "ready", f"{self.BREAK}; mv {LINEAGE}/fullchain.pem {away}"):
            run = self.apply_install(plan)
        self.assert_run(run, Execution.EXPOSURE_UNCERTAIN, Exit.EXPOSED)
        self.assertIn("could not prove", run.failure)
        self.assertIn("/etc/nginx/sites-available/shop.conf", run.failure)
        self.assertEqual(self.tables(), "12")

    def test_changed_ready_bytes_are_never_overwritten_by_the_restoration(self) -> None:
        plan = self.eligible()
        edited = f"printf '# an administrator edit\\n' >>{SITE_FILE}"
        with self.injected(plan, "ready", f"{self.BREAK}; {edited}"):
            run = self.apply_install(plan)
        self.assert_run(run, Execution.EXPOSURE_UNCERTAIN, Exit.EXPOSED)
        self.assertIn("# an administrator edit", self.administer(f"cat {SITE_FILE}"))
        self.assertNotEqual(self.site_sha(), PlanWordpressInstall.objects.get().gate_sha256)


class InstallTerminationTests(InstallApplyTestCase):
    def test_the_runtime_limit_stops_the_run_and_cleans_its_staging(self) -> None:
        plan = self.eligible()
        with (
            mock.patch.object(operations_native, "RUNTIME_MAX", "20s"),
            self.injected(plan, "stage", "sleep 120"),
        ):
            run = self.apply_install(plan)
        self.assertEqual((run.status, run.execution), (Status.FAILED, Execution.TIMED_OUT))
        self.assertEqual(self.administer_home_residue(), "")
        self.assertEqual(self.administer(f"ls -A {PUBLIC}").strip(), "index.html")
        self.assertTrue(self.lock_is_free())

    def test_a_killed_run_leaves_only_a_removable_staging_directory(self) -> None:
        plan = self.eligible()
        kill = 'systemctl kill --signal=SIGKILL "barectl-apply-$q.service"; sleep 30'
        with self.injected(plan, "stage", kill):
            run = self.apply_install(plan)
        self.assertEqual((run.status, run.execution), (Status.FAILED, Execution.KILLED))
        residue = self.administer_home_residue()
        self.assertRegex(residue, r"^\.wp-[0-9a-f]{32}$")
        # The next review names the residue and refuses until an administrator removes it.
        again = self.review()
        self.assertFalse(again.eligible)
        self.assertIn(residue, self.texts(again))
        self.assertIn("ordinary administration", self.texts(again))
        self.administer(f"rm -rf {BASE}/{residue}")
        self.assertTrue(self.review().eligible)


class InstallControllerLossTests(InstallApplyTestCase):
    def test_a_lost_acknowledgement_is_reconciled_without_a_second_dispatch(self) -> None:
        plan = self.eligible()
        request = self.request(plan)
        with self.losing(
            lambda command: command.startswith("sudo -n /usr/bin/systemd-run"), after=True
        ):
            run_worker()
        request.refresh_from_db()
        self.assertEqual(request.status, Status.RECONCILING, request.failure)
        self.wait_terminal(request.unit_name, timeout=300)
        run = self.check(request)
        self.assertEqual(
            (run.status, run.execution, run.verification),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED),
            run.failure,
        )
        self.assertEqual(self.units(), [run.unit_name], "the unit was submitted exactly once")
        self.assertEqual(self.tables(), "12")
        self.assertEqual(InstallRunResult.objects.get(run=run).problems, "")

    def test_the_run_continues_when_the_connection_is_lost_while_watching(self) -> None:
        plan = self.eligible()
        request = self.request(plan)
        with self.losing(
            lambda command: command.startswith(
                "cat /proc/sys/kernel/random/boot_id; systemctl show"
            ),
            after=False,
        ):
            run_worker()
        request.refresh_from_db()
        self.assertEqual(request.status, Status.RECONCILING, request.failure)
        self.wait_terminal(request.unit_name, timeout=300)
        run = self.check(request)
        self.assertEqual((run.status, run.execution), (Status.SUCCEEDED, Execution.SUCCEEDED))
        self.assertEqual(run.verification, Verification.PASSED)
        self.assertEqual(len(self.units()), 1)

    def test_a_submission_that_never_reached_the_server_is_never_replayed(self) -> None:
        plan = self.eligible()
        before = self.ground()
        request = self.request(plan)
        with self.losing(
            lambda command: command.startswith("sudo -n /usr/bin/systemd-run"), after=False
        ):
            run_worker()
        request.refresh_from_db()
        self.assertEqual(request.status, Status.RECONCILING, request.failure)
        self.assertEqual(self.units(), [])
        run = self.check(request)
        self.assertEqual((run.status, run.execution), (Status.RECONCILING, Execution.NOT_FOUND))
        self.assertEqual(self.units(), [], "checking never submits")
        self.assertEqual(self.ground(), before)

    def restart(self) -> None:
        """Restart the container's systemd, then give it a new boot ID, as a reboot would."""
        container = setting("CONTAINER")
        subprocess.run(  # noqa: S603 - the tests' own container
            ["docker", "restart", container],  # noqa: S607
            check=True,
            capture_output=True,
            timeout=120,
        )
        self.addCleanup(self.administer, "umount /proc/sys/kernel/random/boot_id 2>/dev/null; true")
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            state = subprocess.run(  # noqa: S603 - the tests' own container
                ["docker", "exec", container, "systemctl", "is-system-running"],  # noqa: S607
                capture_output=True,
                text=True,
                check=False,
            ).stdout.strip()
            if state in {"running", "degraded"}:
                break
            time.sleep(1)
        self.administer(
            f"printf '%s\\n' {NEW_BOOT} >/run/barectl-test-boot-id; "
            "mount --bind /run/barectl-test-boot-id /proc/sys/kernel/random/boot_id"
        )

    def test_a_restart_loses_the_evidence_and_the_old_payload_refuses_its_boot(self) -> None:
        plan = self.eligible()
        request = self.request(plan)
        with self.losing(
            lambda command: command.startswith("sudo -n /usr/bin/systemd-run"), after=True
        ):
            run_worker()
        self.wait_terminal(request.unit_name, timeout=300)
        request.refresh_from_db()
        self.assertEqual(request.status, Status.RECONCILING)
        self.restart()
        self.assertEqual(self.units(), [])
        checked = self.check(request)
        self.assertEqual(checked.status, Status.RECONCILING)
        self.assertIn("The server restarted", checked.failure)
        # Nothing resumes or replays; an acknowledgement closes it as outcome unknown.
        self.client.post(f"/applies/{checked.pk}/acknowledge/", {"understood": "on"})
        run_worker()
        checked.refresh_from_db()
        self.assertEqual(
            (checked.status, checked.execution), (Status.FAILED, Execution.OUTCOME_UNKNOWN)
        )
        before = self.ground()
        # The payload held in transit arrives after the restart and refuses its boot.
        script = install_apply.payload(checked, plan)
        argv = bootstrap_native.submission(
            checked.unit_name, script, limits=install_native.limits()
        )
        with ssh.connect_alias("disposable") as shell:
            result = shell.run(bootstrap_native.privileged(argv, root=False))
        self.assertEqual(result.exit_status, 0)
        shown = self.wait_terminal(checked.unit_name, timeout=60)
        self.assertEqual(shown["ExecMainStatus"], str(bootstrap_native.Exit.BOOT_CHANGED))
        self.assertEqual(self.ground(), before)
        # The application the unit installed before the restart is still there and a new
        # review refuses to install into it.
        self.assertEqual(self.tables(), "12")
        again = self.review()
        self.assertFalse(again.eligible)
