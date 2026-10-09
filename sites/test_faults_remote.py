"""A site run's fault boundaries on a real, disposable server (docs/sites.md).

Each test applies a reviewed site plan through the dashboard, the worker and actual systemd,
with at most one administrator command inserted between two named fragments of the
production payload (``sites.native.site_steps``), or with a fault at the transport. Another
site the administrator created by hand, with private data, must be unchanged and keep
serving, and the run is never submitted twice.
"""

import re
import shlex
import subprocess
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import timedelta
from typing import override
from unittest import mock

from django.contrib.auth.models import Permission

from bootstrap import apply as bootstrap_apply
from bootstrap import native as bootstrap_native
from bootstrap.apply_remote_testing import is_inspection, is_submission
from bootstrap.models import ApplyRun, Execution, Verification
from discovery.fakes import run_worker
from discovery.models import DiscoveryAttempt
from discovery.native_testing import setting
from operations.models import RemoteOperation
from servers.models import Server

from . import native
from .convention import render_placeholder
from .test_apply_remote import SiteApplyTestCase
from .test_review_remote import create_site, remove_site

Status = RemoteOperation.Status
Exit = native.Exit
SENTINEL = "operator data that no site run may touch\n"
BLOG_PAGE = "the blog's own page\n"
NEW_BOOT = "0badb007-0000-4000-8000-000000000147"


class FaultTestCase(SiteApplyTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.administer(create_site("blog", ("blog.test",), self.php))
        self.administer(
            f"printf %s {shlex.quote(SENTINEL)} >/var/www/blog/private/data && "
            "chown sblog:sblog /var/www/blog/private/data && chmod 600 /var/www/blog/private/data"
            f" && printf %s {shlex.quote(BLOG_PAGE)} >/var/www/blog/public/index.html && "
            "chown sblog:www-data /var/www/blog/public/index.html && "
            "chmod 640 /var/www/blog/public/index.html"
        )

    @contextmanager
    def injected(self, after: str, step: str) -> Iterator[None]:
        """The production payload with ``step`` run after its fragment ``after``."""
        real = native.site_steps

        def payload(unit: str, boot: str, deadline: int, change: native.SiteChange) -> str:
            steps = real(unit, boot, deadline, change)
            names = [item.name for item in steps]
            steps.insert(names.index(after) + 1, native.Step("injected", step))
            return "; ".join(item.text for item in steps)

        with mock.patch.object(native, "site_payload", payload):
            yield

    def fault(self, after: str, step: str, undo: str = "true") -> ApplyRun:
        plan = self.site_plan()
        self.addCleanup(self.administer, undo)
        with self.injected(after, step):
            return self.apply_site(plan)

    def assert_boundary(
        self, run: ApplyRun, execution: Execution, status: int, *, stages: int = 0
    ) -> None:
        self.assertEqual(
            (run.status, run.execution, run.exit_status, run.verification),
            (Status.FAILED, execution, status, Verification.NOT_APPLICABLE),
            run.failure,
        )
        self.assertEqual(ApplyRun.objects.count(), 1)
        self.assertEqual(self.units(), [run.unit_name])
        self.assertEqual(self.stages(), stages)
        self.assert_others_intact()

    def stages(self) -> int:
        """How many staged files a run left beside the site's destinations."""
        found = self.administer(
            "find /var/www/shop /etc/nginx/sites-available /etc/nginx/sites-available.real "
            f"/etc/nginx/sites-enabled /etc/php/{self.php}/fpm/pool.d -maxdepth 2 -name '.*' "
            "2>/dev/null; true"
        )
        return sum(1 for line in found.splitlines() if re.search(r"/\.[^/]+\.[0-9a-f]{32}$", line))

    def nginx_workers(self) -> set[str]:
        return set(self.administer("pgrep -P $(cat /run/nginx.pid)").split())

    def fpm_workers(self) -> set[str]:
        # The packaged pool's workers, which no request here starts or ends.
        return set(
            self.administer(
                f"pgrep -P $(systemctl show -p MainPID --value php{self.php}-fpm) -f 'pool www$'"
            ).split()
        )

    def assert_not_reloaded(self, before: set[str], after: set[str]) -> None:
        # A reload starts new workers; those an earlier reload retired may still be exiting.
        self.assertTrue(after)
        self.assertLessEqual(after, before)

    def assert_others_intact(self) -> None:
        self.assertEqual(self.administer("cat /var/www/blog/private/data"), SENTINEL)
        self.assertEqual(self.get("blog.test"), BLOG_PAGE)
        self.assertIn("Welcome to nginx", self.get("other.test"))

    def wait_for(self, check: str) -> None:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.administer(f"{check} && echo yes || true").strip() == "yes":
                return
            time.sleep(0.5)
        raise AssertionError(f"{check} did not hold.")

    def present(self) -> set[str]:
        """Which of the site's resources exist, as root sees them."""
        checks = {
            "user": "getent passwd sshop",
            "boundary": "test -d /var/www/shop",
            "public": "test -d /var/www/shop/public",
            "private": "test -d /var/www/shop/private",
            "placeholder": "test -f /var/www/shop/public/index.html",
            "probe": "ls /var/www/shop/public | grep -q '^probe-'",
            "pool": f"test -f /etc/php/{self.php}/fpm/pool.d/shop.conf",
            "socket": "test -S /run/php/sshop.sock",
            "source": "test -f /etc/nginx/sites-available/shop.conf",
            "link": "test -L /etc/nginx/sites-enabled/shop.conf",
        }
        found = self.administer(
            "; ".join(f"{check} >/dev/null 2>&1 && echo {name}" for name, check in checks.items())
            + "; true"
        )
        return set(found.split())


class DriftTests(FaultTestCase):
    def test_changes_after_review_refuse_under_the_lock_without_changes(self) -> None:
        cases = {
            "a writable site directory": (
                "chmod 0775 /etc/nginx/sites-available",
                "chmod 0755 /etc/nginx/sites-available",
            ),
            "a new configuration file": (
                "touch /etc/nginx/conf.d/extra.conf",
                "rm -f /etc/nginx/conf.d/extra.conf",
            ),
            "a changed allocation policy": (
                "echo '# changed' >>/etc/login.defs",
                "sed -i '$d' /etc/login.defs",
            ),
            "an account taking the site user's name": (
                "useradd --no-create-home sshop",
                "userdel sshop",
            ),
            "another site's name": (
                (
                    "sed -i 's/server_name blog.test;/server_name blog.test www.shop.test;/' "
                    "/etc/nginx/sites-available/blog.conf"
                ),
                "sed -i 's/ www.shop.test;/;/' /etc/nginx/sites-available/blog.conf",
            ),
        }
        for case, (change, undo) in cases.items():
            with self.subTest(case=case):
                plan = self.site_plan()
                self.administer(change)
                try:
                    run = self.apply_site(plan)
                finally:
                    self.administer(undo)
                self.assertEqual((run.execution, run.exit_status), (Execution.DRIFT, 15))
                self.assertEqual(run.status, Status.FAILED)
                self.assertEqual(self.present(), set())
                self.assert_others_intact()
                self.clear_units()
                ApplyRun.objects.all().delete()


class AccountBoundaryTests(FaultTestCase):
    def test_a_held_account_lock_refuses_before_changes(self) -> None:
        plan = self.site_plan()
        # A live process holds the account databases' lock, as another tool would.
        self.addCleanup(self.administer, "pkill -f '^sleep 301$'; rm -f /etc/passwd.lock")
        self.administer("echo $$ >/etc/passwd.lock; exec sleep 301", detach=True)
        self.wait_for("test -s /etc/passwd.lock")
        run = self.apply_site(plan)
        self.assert_boundary(run, Execution.ACCOUNT_BUSY, Exit.ACCOUNT_BUSY)
        self.assertEqual(self.present(), set())
        self.assertIn("useradd could not change the account databases", run.failure)
        # A refusal before changes queues no discovery.
        self.assertFalse(DiscoveryAttempt.objects.exists())

    def test_a_scheduled_renewal_with_processes_refuses_before_changes(self) -> None:
        plan = self.site_plan()
        self.renewal(survivor=True)
        run = self.apply_site(plan)
        self.assert_boundary(run, Execution.RENEWAL_ACTIVE, bootstrap_native.Exit.RENEWAL_ACTIVE)
        self.assertEqual(self.present(), set())
        self.assertIn("renewal service still had processes", run.failure)

    def test_an_account_unlike_the_review_stops_before_any_file(self) -> None:
        wrapper = (
            '#!/bin/sh\n/run/barectl-useradd.real "$@" || exit $?\n'
            'for last; do :; done; usermod -aG www-data "$last"\n'
        )
        run = self.fault(
            "revalidation",
            "cp /usr/sbin/useradd /run/barectl-useradd.real && "
            f"printf %s {shlex.quote(wrapper)} >/run/barectl-useradd && "
            "chmod 755 /run/barectl-useradd && mount --bind /run/barectl-useradd /usr/sbin/useradd",
            "umount /usr/sbin/useradd 2>/dev/null; rm -f /run/barectl-useradd*",
        )
        self.assert_boundary(run, Execution.PARTIAL, Exit.ACCOUNT_MISMATCH)
        self.assertEqual(self.present(), {"user"})
        self.assertIn("userdel sshop only if nothing uses it", run.failure)
        # Discovery follows any run that may have changed the server.
        self.assertTrue(DiscoveryAttempt.objects.exists())
        # A fresh review refuses the partial site; after ordinary administration it is
        # eligible again.
        self.administer("gpasswd -d sshop www-data >/dev/null")
        plan = self.site_plan()
        self.assertIn("Finish", plan.intent)
        self.administer("userdel sshop")
        self.assertTrue(self.site_plan().eligible)

    def test_useradd_failing_after_changing_the_databases_is_partial(self) -> None:
        wrapper = '#!/bin/sh\n/run/barectl-useradd.real "$@"\nexit 1\n'
        run = self.fault(
            "revalidation",
            "cp /usr/sbin/useradd /run/barectl-useradd.real && "
            f"printf %s {shlex.quote(wrapper)} >/run/barectl-useradd && "
            "chmod 755 /run/barectl-useradd && mount --bind /run/barectl-useradd /usr/sbin/useradd",
            "umount /usr/sbin/useradd 2>/dev/null; rm -f /run/barectl-useradd*",
        )
        self.assert_boundary(run, Execution.PARTIAL, Exit.ACCOUNT)
        self.assertEqual(self.present(), {"user"})
        self.assertIn("may or may not exist", run.failure)


class FilesystemBoundaryTests(FaultTestCase):
    def test_a_read_only_web_root_stops_at_the_directories(self) -> None:
        run = self.fault(
            "account",
            "mount --bind /var/www /var/www && mount -o remount,bind,ro /var/www",
            "umount /var/www 2>/dev/null; true",
        )
        self.assert_boundary(run, Execution.PARTIAL, Exit.DIRECTORIES)
        self.assertEqual(self.present(), {"user"})

    def test_a_full_document_root_stops_at_the_content(self) -> None:
        run = self.fault(
            "directories",
            "mount -t tmpfs -o size=4k,nr_inodes=1,mode=0750,uid=0,gid=33 tmpfs "
            "/var/www/shop/public",
            "umount /var/www/shop/public 2>/dev/null; true",
        )
        self.assert_boundary(run, Execution.PARTIAL, Exit.CONTENT)
        self.assertEqual(self.present(), {"user", "boundary", "public", "private"})

    def test_a_full_pool_directory_stops_before_any_reload(self) -> None:
        pool = f"/etc/php/{self.php}/fpm/pool.d"
        run = self.fault(
            "document root",
            f"mount -t tmpfs -o size=4k,nr_inodes=1,mode=0755 tmpfs {pool}",
            f"umount {pool} 2>/dev/null; true",
        )
        self.assert_boundary(run, Execution.PARTIAL, Exit.POOL)
        self.assertEqual(self.present(), {"user", "boundary", "public", "private", "placeholder"})

    def test_a_full_site_directory_leaves_the_pool_active(self) -> None:
        available = "/etc/nginx/sites-available"
        run = self.fault(
            "pool reload",
            f"mount -t tmpfs -o size=4k,nr_inodes=1,mode=0755 tmpfs {available}",
            f"umount {available} 2>/dev/null; true",
        )
        self.assert_boundary(run, Execution.PARTIAL, Exit.SITE_FILE)
        self.assertEqual(
            self.present(),
            {"user", "boundary", "public", "private", "placeholder", "pool", "socket"},
        )


class ValidationBoundaryTests(FaultTestCase):
    def wrapped(self, binary: str, failures: int) -> tuple[str, str]:
        """Replace ``binary`` so that its first ``failures`` syntax checks fail."""
        counter = "/run/barectl-check-count"
        wrapper = (
            "#!/bin/sh\n"
            'if [ "$1" = -t ]; then\n'
            f"  c=$(cat {counter} 2>/dev/null || echo 0); echo $((c + 1)) >{counter}\n"
            f'  if [ "$c" -lt {failures} ]; then echo "barectl test: invalid" >&2; exit 1; fi\n'
            "fi\n"
            f'exec /run/barectl-check.real "$@"\n'
        )
        inject = (
            f"cp {binary} /run/barectl-check.real && "
            f"printf %s {shlex.quote(wrapper)} >/run/barectl-check && chmod 755 /run/barectl-check "
            f"&& mount --bind /run/barectl-check {binary}"
        )
        undo = f"umount {binary} 2>/dev/null; rm -f /run/barectl-check* {counter}"
        return inject, undo

    def test_a_rejected_pool_is_withdrawn_before_any_reload(self) -> None:
        workers = (self.nginx_workers(), self.fpm_workers())
        run = self.fault("revalidation", *self.wrapped(f"/usr/sbin/php-fpm{self.php}", 1))
        self.assert_boundary(run, Execution.PARTIAL, Exit.POOL_WITHDRAWN)
        self.assert_not_reloaded(workers[0], self.nginx_workers())
        self.assert_not_reloaded(workers[1], self.fpm_workers())
        self.assertEqual(self.present(), {"user", "boundary", "public", "private", "placeholder"})

    def test_a_pool_that_cannot_be_withdrawn_is_reported_and_not_reloaded(self) -> None:
        fpm = self.administer(f"systemctl show -p MainPID --value php{self.php}-fpm").strip()
        workers = (self.nginx_workers(), self.fpm_workers())
        run = self.fault("revalidation", *self.wrapped(f"/usr/sbin/php-fpm{self.php}", 99))
        self.assert_boundary(run, Execution.PARTIAL, Exit.POOL_INVALID)
        self.assert_not_reloaded(workers[0], self.nginx_workers())
        self.assert_not_reloaded(workers[1], self.fpm_workers())
        # The unchanged pool was withdrawn; the configuration stayed invalid.
        self.assertEqual(self.present(), {"user", "boundary", "public", "private", "placeholder"})
        self.assertEqual(
            self.administer(f"systemctl show -p MainPID --value php{self.php}-fpm").strip(), fpm
        )

    def test_a_rejected_site_link_is_withdrawn_before_any_reload(self) -> None:
        workers = self.nginx_workers()
        run = self.fault("revalidation", *self.wrapped("/usr/sbin/nginx", 1))
        self.assert_boundary(run, Execution.PARTIAL, Exit.LINK_WITHDRAWN)
        self.assert_not_reloaded(workers, self.nginx_workers())
        present = self.present()
        self.assertIn("source", present)
        self.assertNotIn("link", present)

    def test_a_link_that_cannot_be_withdrawn_is_reported_and_not_reloaded(self) -> None:
        workers = self.nginx_workers()
        run = self.fault("revalidation", *self.wrapped("/usr/sbin/nginx", 99))
        self.assert_boundary(run, Execution.PARTIAL, Exit.NGINX_INVALID)
        self.assert_not_reloaded(workers, self.nginx_workers())
        present = self.present()
        self.assertIn("source", present)
        self.assertNotIn("link", present)
        self.assertIn("rm /etc/nginx/sites-enabled/shop.conf", run.failure)


class ReloadBoundaryTests(FaultTestCase):
    def drop_in(self, unit: str, command: str) -> tuple[str, str]:
        directory = f"/run/systemd/system/{unit}.d"
        inject = (
            f"mkdir -p {directory} && printf '[Service]\\nExecReload=\\nExecReload={command}\\n' "
            f">{directory}/barectl-test.conf && systemctl daemon-reload"
        )
        return inject, f"rm -rf {directory}; systemctl daemon-reload"

    def test_a_failed_pool_reload_is_reported(self) -> None:
        run = self.fault(
            "pool validation", *self.drop_in(f"php{self.php}-fpm.service", "/bin/false")
        )
        self.assert_boundary(run, Execution.PARTIAL, Exit.FPM_RELOAD)

    def test_a_pool_that_never_listens_is_reported(self) -> None:
        run = self.fault(
            "pool validation", *self.drop_in(f"php{self.php}-fpm.service", "/bin/true")
        )
        self.assert_boundary(run, Execution.PARTIAL, Exit.SOCKET)
        self.assertNotIn("socket", self.present())

    def test_a_failed_nginx_reload_is_reported(self) -> None:
        run = self.fault("site validation", *self.drop_in("nginx.service", "/bin/false"))
        self.assert_boundary(run, Execution.PARTIAL, Exit.NGINX_RELOAD)
        self.assertLessEqual({"source", "link", "pool", "socket"}, self.present())


class ServingBoundaryTests(FaultTestCase):
    def test_a_site_that_does_not_serve_removes_its_probe(self) -> None:
        run = self.fault("site reload", "chmod 0700 /var/www/shop/public")
        self.assert_boundary(run, Execution.PARTIAL, Exit.NOT_SERVING)
        self.assertNotIn("probe", self.present())

    def test_a_probe_that_cannot_be_removed_is_incomplete_verification(self) -> None:
        public = "/var/www/shop/public"
        run = self.fault(
            "site reload",
            f"mount --bind {public} {public} && mount -o remount,bind,ro {public}",
            f"umount {public} 2>/dev/null; true",
        )
        self.assert_boundary(run, Execution.PARTIAL, Exit.PROBE_LEFT)
        self.assertIn("probe", self.present())
        self.assertIn("verification is incomplete", run.failure)
        # The site itself serves; only its probe is left.
        self.assertEqual(self.get("shop.test"), render_placeholder("shop"))

    def test_cleanup_preserves_a_replaced_application_inode_and_restore_collisions(self) -> None:
        real = native.site_payload
        for collision in (False, True):
            with self.subTest(collision=collision):
                plan = self.site_plan()

                def attacked(
                    unit: str,
                    boot: str,
                    deadline: int,
                    change: native.SiteChange,
                    restore_collision: bool = collision,
                ) -> str:
                    payload = real(unit, boot, deadline, change)
                    probe = change.probe.path
                    capture = '/usr/bin/mv --no-copy --no-clobber -T -- "$sp" "$q"'
                    self.assertIn(capture, payload)
                    swap = (
                        "attacked=$(runuser -u sshop -- /bin/sh -c "
                        '\'[ "$(id -u)" = "$3" ] || exit 92; '
                        'mv -- "$1" "$2" && printf "application preserved" >"$1" '
                        '&& printf "swapped %s" "$3"\' sh '
                        f'{probe} /var/www/shop/public/saved-probe.php "$u") '
                        '&& [ "$attacked" = "swapped $u" ] && '
                        f"stat -c '%d:%i' -- {probe} >/var/www/shop/replaced-inode && "
                    )
                    payload = payload.replace(capture, swap + capture)
                    if restore_collision:
                        restore = '/usr/bin/mv --no-copy --no-clobber -T -- "$q" "$sp"'
                        self.assertIn(restore, payload)
                        payload = payload.replace(
                            restore,
                            f"printf 'new application entry' >{probe}; " + restore,
                        )
                    return payload

                with mock.patch.object(native, "site_payload", attacked):
                    run = self.apply_site(plan)
                self.assert_boundary(run, Execution.PARTIAL, Exit.PROBE_LEFT)
                suffix = run.unit_name.removeprefix(bootstrap_native.UNIT_PREFIX).removesuffix(
                    ".service"
                )
                probe = f"/var/www/shop/public/probe-{plan.site.probe_token}.php"
                anchor = f"/var/www/shop/.probe-{plan.site.probe_token}.php.{suffix}.anchor"
                quarantine = anchor.removesuffix(".anchor") + ".quarantine"
                restored = quarantine if collision else probe
                self.assertEqual(self.administer(f"cat {restored}"), "application preserved")
                self.assertEqual(
                    self.administer(f"stat -c '%d:%i' -- {restored}"),
                    self.administer("cat /var/www/shop/replaced-inode"),
                )
                self.assertEqual(
                    self.administer(f"stat -c '%d:%i' -- {anchor}"),
                    self.administer("stat -c '%d:%i' /var/www/shop/public/saved-probe.php"),
                )
                if collision:
                    self.assertEqual(self.administer(f"cat {probe}"), "new application entry")
                else:
                    self.assertEqual(
                        self.administer(f"test ! -e {quarantine} && echo absent"), "absent\n"
                    )
                self.administer(remove_site("shop", self.php))
                self.clear_units()
                ApplyRun.objects.all().delete()

    def test_cleanup_preserves_a_new_application_entry_after_capture(self) -> None:
        plan = self.site_plan()
        real = native.site_payload

        def attacked(unit: str, boot: str, deadline: int, change: native.SiteChange) -> str:
            payload = real(unit, boot, deadline, change)
            capture = '/usr/bin/mv --no-copy --no-clobber -T -- "$sp" "$q"'
            self.assertIn(capture, payload)
            return payload.replace(
                capture,
                capture + f" && printf 'new application entry' >{change.probe.path}",
            )

        with mock.patch.object(native, "site_payload", attacked):
            run = self.apply_site(plan)
        self.assert_boundary(run, Execution.PARTIAL, Exit.PROBE_LEFT)
        self.assertEqual(
            self.administer(f"cat /var/www/shop/public/probe-{plan.site.probe_token}.php"),
            "new application entry",
        )
        self.assertEqual(
            self.administer("find /var/www/shop -name '*.anchor' -o -name '*.quarantine'"), ""
        )

    def test_cleanup_refuses_copy_and_delete_across_filesystems(self) -> None:
        public = "/var/www/shop/public"
        other = "/run/barectl-site-public"
        self.addCleanup(self.administer, f"umount {public} 2>/dev/null; rm -r -- {other}; true")
        run = self.fault(
            "site reload",
            f"mkdir {other} && cp -a {public}/. {other}/ && "
            f"chown sshop:www-data {other} && chmod 0750 {other} && "
            f"mount --bind {other} {public} && "
            f'[ "$(stat -c %d {public})" != "$(stat -c %d /var/www/shop)" ]',
        )
        self.assert_boundary(run, Execution.PARTIAL, Exit.PROBE_LEFT)
        self.assertIn("probe", self.present())
        self.assertNotEqual(
            self.administer(f"stat -c %d {public}"),
            self.administer("stat -c %d /var/www/shop"),
        )
        self.assertEqual(self.administer("find /var/www/shop -maxdepth 1 -name '*.quarantine'"), "")
        self.assertNotEqual(self.administer("find /var/www/shop -maxdepth 1 -name '*.anchor'"), "")


class PublicationRaceTests(FaultTestCase):
    """Changes an administrator makes after revalidation, just before a publication."""

    def test_a_writable_pool_directory_is_refused_before_staging(self) -> None:
        pool = f"/etc/php/{self.php}/fpm/pool.d"
        workers = self.fpm_workers()
        run = self.fault("document root", f"chmod 0777 {pool}", f"chmod 0755 {pool}")
        self.assert_boundary(run, Execution.PARTIAL, Exit.POOL)
        self.assertNotIn("pool", self.present())
        self.assert_not_reloaded(workers, self.fpm_workers())

    def test_a_site_directory_replaced_by_a_link_is_refused_before_staging(self) -> None:
        available = "/etc/nginx/sites-available"
        run = self.fault(
            "pool reload",
            f"mv {available} {available}.real && ln -s {available}.real {available}",
            f"test -L {available} && rm {available} && mv {available}.real {available}; true",
        )
        self.assert_boundary(run, Execution.PARTIAL, Exit.SITE_FILE)
        self.assertEqual(self.administer(f"ls -A {available}.real"), "blog.conf\ndefault\n")

    def test_a_pool_file_that_appeared_is_kept_and_not_replaced(self) -> None:
        pool = f"/etc/php/{self.php}/fpm/pool.d/shop.conf"
        run = self.fault("document root", f"printf 'external\\n' >{pool}")
        self.assert_boundary(run, Execution.PARTIAL, Exit.POOL, stages=1)
        self.assertEqual(self.administer(f"cat {pool}"), "external\n")

    def test_a_site_file_that_appeared_is_kept_and_not_replaced(self) -> None:
        source = "/etc/nginx/sites-available/shop.conf"
        run = self.fault("pool reload", f"printf 'external\\n' >{source}")
        self.assert_boundary(run, Execution.PARTIAL, Exit.SITE_FILE, stages=1)
        self.assertEqual(self.administer(f"cat {source}"), "external\n")

    def test_a_link_that_appeared_is_kept_and_not_replaced(self) -> None:
        link = "/etc/nginx/sites-enabled/shop.conf"
        workers = self.nginx_workers()
        run = self.fault("site file", f"ln -s /etc/nginx/sites-available/default {link}")
        self.assert_boundary(run, Execution.PARTIAL, Exit.SITE_LINK)
        self.assertEqual(
            self.administer(f"readlink {link}"), "/etc/nginx/sites-available/default\n"
        )
        self.assert_not_reloaded(workers, self.nginx_workers())

    def test_a_probe_left_by_a_later_failure_is_reported(self) -> None:
        public = "/var/www/shop/public"
        run = self.fault(
            "probe",
            f"mount --bind {public} {public} && mount -o remount,bind,ro {public}",
            f"umount {public} 2>/dev/null; true",
        )
        self.assert_boundary(run, Execution.PARTIAL, Exit.PROBE_LEFT)
        self.assertIn("probe", self.present())


class ExecutionFaultTests(FaultTestCase):
    def test_a_lost_acknowledgement_is_checked_without_resubmitting(self) -> None:
        plan = self.site_plan()
        with self.losing(is_submission, after=True):
            run = self.apply_site(plan)
        self.assertEqual(run.status, Status.RECONCILING)
        self.wait_terminal(run.unit_name)
        run = self.check(run)
        self.assertEqual(
            (run.status, run.execution, run.verification),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED),
            run.failure,
        )
        self.assertEqual(self.units(), [run.unit_name])
        self.assert_others_intact()

    def test_a_worker_lost_while_watching_is_reconciled(self) -> None:
        plan = self.site_plan()
        with self.losing(is_inspection, after=False):
            run = self.apply_site(plan)
        self.assertEqual(run.status, Status.RECONCILING)
        self.wait_terminal(run.unit_name)
        run = self.check(run)
        self.assertEqual(run.status, Status.SUCCEEDED, run.failure)
        self.assertEqual(self.units(), [run.unit_name])

    def test_a_repeated_request_converges_on_one_run(self) -> None:
        plan = self.site_plan()
        first = self.request(plan)
        second = self.request(plan)
        self.assertEqual(first.pk, second.pk)
        run_worker()
        first.refresh_from_db()
        self.assertEqual(first.status, Status.SUCCEEDED, first.failure)
        self.client.post(f"/plans/{plan.pk}/apply/")
        run_worker()
        self.assertEqual(ApplyRun.objects.count(), 1)
        self.assertEqual(self.units(), [first.unit_name])

    def test_a_killed_wrapper_is_terminated_with_the_account_left(self) -> None:
        run = self.fault("account", "kill -9 $$")
        self.assertEqual((run.status, run.execution), (Status.FAILED, Execution.KILLED))
        self.assertEqual(self.present(), {"user"})
        self.assert_others_intact()

    def test_a_killed_wrapper_leaves_what_it_published(self) -> None:
        base = {"user", "boundary", "public", "private", "placeholder"}
        cases = {
            "placeholder": base,
            "site link": base | {"probe", "pool", "socket", "source", "link"},
            "pool reload": base | {"probe", "pool", "socket"},
        }
        for after, expected in cases.items():
            with self.subTest(after=after):
                run = self.fault(after, "kill -9 $$")
                self.assertEqual((run.status, run.execution), (Status.FAILED, Execution.KILLED))
                self.assertEqual(self.present(), expected)
                self.assertEqual(self.stages(), 0)
                self.assert_others_intact()
                self.clear_units()
                ApplyRun.objects.all().delete()
                self.administer(remove_site("shop", self.php))

    def test_a_wrapper_killed_after_the_reload_is_checked_as_killed(self) -> None:
        plan = self.site_plan()
        with self.injected("site reload", "kill -9 $$"), self.losing(is_inspection, after=False):
            run = self.apply_site(plan)
        self.assertEqual(run.status, Status.RECONCILING)
        self.wait_terminal(run.unit_name)
        run = self.check(run)
        self.assertEqual((run.status, run.execution), (Status.FAILED, Execution.KILLED))
        self.assertIn("probe", self.present())
        self.assertEqual(self.get("shop.test"), render_placeholder("shop"))
        self.assert_others_intact()

    def test_the_runtime_limit_after_the_reload_leaves_the_probe(self) -> None:
        with mock.patch.object(bootstrap_native, "RUNTIME_MAX", "5s"):
            run = self.fault("site reload", "sleep 60")
        if run.status == Status.RECONCILING:
            self.wait_terminal(run.unit_name)
            run = self.check(run)
        self.assertEqual((run.status, run.execution), (Status.FAILED, Execution.TIMED_OUT))
        self.assertIn("probe", self.present())
        self.assertEqual(self.stages(), 0)
        self.assert_others_intact()

    def test_a_child_outliving_its_wrapper_keeps_the_lock_until_it_ends(self) -> None:
        with mock.patch.object(bootstrap_apply, "WATCH_LIMIT", timedelta(seconds=6)):
            run = self.fault(
                "account",
                "sleep 600 </dev/null >/dev/null 2>&1 & kill -9 $$",
                "pkill -f '^sleep 600$'; true",
            )
        self.assertEqual(run.status, Status.RECONCILING)
        self.assertFalse(self.lock_is_free())
        self.administer("pkill -f '^sleep 600$'; true")
        self.wait_terminal(run.unit_name)
        run = self.check(run)
        self.assertEqual((run.status, run.execution), (Status.FAILED, Execution.KILLED))
        self.assertTrue(self.lock_is_free())
        self.assertEqual(self.present(), {"user"})
        self.assertEqual(self.stages(), 0)
        self.assert_others_intact()

    def test_the_runtime_limit_stops_the_run(self) -> None:
        with mock.patch.object(bootstrap_native, "RUNTIME_MAX", "5s"):
            run = self.fault("directories", "sleep 60")
        if run.status == Status.RECONCILING:
            self.wait_terminal(run.unit_name)
            run = self.check(run)
        self.assertEqual((run.status, run.execution), (Status.FAILED, Execution.TIMED_OUT))
        self.assertEqual(self.present(), {"user", "boundary", "public", "private"})
        self.assert_others_intact()


class CleanupTests(FaultTestCase):
    def test_a_cleanup_never_clears_a_running_site_unit(self) -> None:
        for codename in (
            "view_configurationplan",
            "prepare_configurationplan",
            "clear_native_results",
        ):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        finished = self.submit(lambda unit, boot, deadline: "exit 0")
        self.wait_terminal(finished)
        with mock.patch.object(bootstrap_apply, "WATCH_LIMIT", timedelta(seconds=6)):
            run = self.fault(
                "account",
                "sleep 600 </dev/null >/dev/null 2>&1 & kill -9 $$",
                "pkill -f '^sleep 600$'; true",
            )
        self.assertEqual(run.status, Status.RECONCILING)
        # The reconciling run holds its registration's active slot; another registration of
        # the same server prepares and applies the cleanup.
        first, self.server = (
            self.server,
            Server.objects.create(name="Disposable again", ssh_alias="disposable-second"),
        )
        cleanup = self.plan("clear_results")
        self.assertEqual(list(cleanup.native_units.values_list("unit_name", flat=True)), [finished])
        refused = self.apply(cleanup)
        # The child still holds the lock it inherited, and its control group has processes.
        self.assertIn(refused.execution, {Execution.LOCK_CONFLICT, Execution.OTHER_RUN_ACTIVE})
        self.server = first
        self.assertIn(run.unit_name, self.units())
        self.assertEqual(self.unit(run.unit_name)["SubState"], "running")
        self.administer("pkill -f '^sleep 600$'; true")
        self.wait_terminal(run.unit_name)
        run = self.check(run)
        self.assertEqual((run.status, run.execution), (Status.FAILED, Execution.KILLED))
        self.assert_others_intact()


class RestartTests(FaultTestCase):
    def restart(self) -> None:
        """Restart the container, then give it a new boot ID, as a reboot would."""
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

    def test_a_restart_mid_run_leaves_a_partial_site_and_an_unknown_outcome(self) -> None:
        with mock.patch.object(bootstrap_apply, "WATCH_LIMIT", timedelta(seconds=6)):
            run = self.fault("account", "sleep 600")
        self.assertEqual(run.status, Status.RECONCILING)
        self.restart()
        self.assertEqual(self.units(), [])
        run = self.check(run)
        self.assertEqual(run.status, Status.RECONCILING)
        self.assertIn("The server restarted", run.failure)
        self.client.post(f"/applies/{run.pk}/acknowledge/", {"understood": "on"})
        run_worker()
        run.refresh_from_db()
        self.assertEqual(
            (run.status, run.execution),
            (Status.FAILED, Execution.OUTCOME_UNKNOWN),
            run.closure_blocked,
        )
        # docs/sites.md#recovering-a-partial-site: the failed run itself is never replayed.
        self.assertEqual(self.present(), {"user"})
        self.assertEqual(self.stages(), 0)
        self.assert_others_intact()
        self.assertEqual(self.get("blog.test"), BLOG_PAGE)


class FinishTests(FaultTestCase):
    def test_interrupted_boundaries_finish_without_replacing_existing_resources(self) -> None:
        for after in ("account", "directories", "pool reload", "site file"):
            with self.subTest(after=after):
                interrupted = self.fault(after, "kill -9 $$")
                self.assertEqual(interrupted.execution, Execution.KILLED, interrupted.failure)
                account = self.administer("getent passwd sshop; getent group sshop")
                before = self.administer(
                    "find /var/www/shop -maxdepth 1 -printf '%p %i %m %U %G\\n' 2>/dev/null; "
                    f"stat -c '%n %i %a %u %g' /etc/php/{self.php}/fpm/pool.d/shop.conf "
                    "/etc/nginx/sites-available/shop.conf 2>/dev/null; true"
                ).splitlines()
                plan = self.site_plan()
                self.assertIn("Finish", plan.intent)
                self.assertEqual(plan.site_account.command, "")
                finished = self.apply_site(plan)
                self.assertEqual(
                    (finished.execution, finished.exit_status, finished.verification),
                    (Execution.SUCCEEDED, 0, Verification.PASSED),
                    finished.failure,
                )
                self.assertEqual(
                    self.administer("getent passwd sshop; getent group sshop"), account
                )
                after_state = self.administer(
                    "find /var/www/shop -maxdepth 1 -printf '%p %i %m %U %G\\n'; "
                    f"stat -c '%n %i %a %u %g' /etc/php/{self.php}/fpm/pool.d/shop.conf "
                    "/etc/nginx/sites-available/shop.conf"
                ).splitlines()
                self.assertLessEqual(set(before), set(after_state))
                if after != "directories":
                    self.assertEqual(self.get("shop.test"), render_placeholder("shop"))
                self.assertTrue(self.site_plan().no_changes)
                self.assert_others_intact()
                self.administer(remove_site("shop", self.php))
                self.clear_units()

    def test_site_user_cannot_write_the_content_stage_before_publication(self) -> None:
        plan = self.site_plan()
        real = native.site_payload

        def attacked(unit: str, boot: str, deadline: int, change: native.SiteChange) -> str:
            payload = real(unit, boot, deadline, change)
            attempt = (
                'cat >"$s" && denied=$(runuser -u sshop -- /bin/sh -c '
                '\'[ "$(id -u)" = "$2" ] || exit 92; '
                'if printf compromised >>"$1"; then exit 93; '
                'else printf "denied %s" "$2"; fi\' sh "$s" "$u") '
                '&& [ "$denied" = "denied $u" ] && sync -- "$s"'
            )
            fragment = 'cat >"$s" && sync -- "$s"'
            self.assertIn(fragment, payload)
            return payload.replace(fragment, attempt)

        with mock.patch.object(native, "site_payload", attacked):
            run = self.apply_site(plan)
        self.assertEqual(
            (run.execution, run.verification), (Execution.SUCCEEDED, Verification.PASSED)
        )
        self.assertEqual(self.get("shop.test"), render_placeholder("shop"))
        self.assertEqual(self.stages(), 0)
        self.assertEqual(
            self.administer("find /var/www/shop -name '*.anchor' -o -name '*.quarantine'"), ""
        )
        self.assert_others_intact()

    def test_finish_accepts_a_locked_star_password_and_refuses_socket_metadata_drift(self) -> None:
        interrupted = self.fault("site file", "kill -9 $$")
        self.assertEqual(interrupted.execution, Execution.KILLED)
        self.administer("usermod --password '*' sshop")
        plan = self.site_plan()
        self.administer("chmod 0640 /run/php/sshop.sock")
        refused = self.apply_site(plan)
        self.assertEqual((refused.execution, refused.exit_status), (Execution.DRIFT, Exit.DRIFT))
        self.assertNotIn("link", self.present())
        self.administer("chmod 0600 /run/php/sshop.sock")
        finished = self.apply_site(self.site_plan())
        self.assertEqual(
            (finished.execution, finished.verification),
            (Execution.SUCCEEDED, Verification.PASSED),
            finished.failure,
        )
        self.assertEqual(self.administer("getent shadow sshop | cut -d: -f2 | cut -c1"), "*\n")
        self.assert_others_intact()

    def test_finishing_a_php_application_never_adds_a_placeholder(self) -> None:
        self.fault("site file", "kill -9 $$")
        self.administer(
            "rm /var/www/shop/public/index.html; "
            "printf '%s' '<?php echo \"application response\";' >/var/www/shop/public/index.php; "
            "chown sshop:www-data /var/www/shop/public/index.php; "
            "chmod 0640 /var/www/shop/public/index.php"
        )
        plan = self.site_plan()
        self.assertFalse(plan.site_files.filter(role="placeholder").exists())
        run = self.apply_site(plan)
        self.assertEqual(
            (run.execution, run.verification),
            (Execution.SUCCEEDED, Verification.PASSED),
            run.failure,
        )
        self.assertEqual(self.get("shop.test"), "application response")
        self.assertEqual(self.administer("test -e /var/www/shop/public/index.html; echo $?"), "1\n")
        self.assert_others_intact()

    def test_finish_preserves_application_content_and_refuses_account_drift(self) -> None:
        interrupted = self.fault("site file", "kill -9 $$")
        self.assertEqual(interrupted.execution, Execution.KILLED)
        self.administer("printf '%s\\n' 'application page' >/var/www/shop/public/index.html")
        plan = self.site_plan()
        inode = self.administer("stat -c %i /var/www/shop/public/index.html")
        self.administer("usermod --shell /bin/sh sshop")
        refused = self.apply_site(plan)
        self.assertEqual((refused.execution, refused.exit_status), (Execution.DRIFT, Exit.DRIFT))
        self.assertNotIn("link", self.present())
        self.administer("usermod --shell /usr/sbin/nologin sshop")
        run = self.apply_site(self.site_plan())
        self.assertEqual(
            (run.execution, run.verification), (Execution.SUCCEEDED, Verification.PASSED)
        )
        self.assertEqual(self.get("shop.test"), "application page\n")
        self.assertEqual(self.administer("stat -c %i /var/www/shop/public/index.html"), inode)
        self.assertTrue(self.site_plan().no_changes)
        self.assert_others_intact()
