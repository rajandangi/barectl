"""Applying reviewed challenge routes on a real, disposable server (docs/tls.md).

Tagged ``ssh`` and skipped unless the disposable server is configured, as
``bootstrap/test_apply_remote.py`` describes. The administrator creates the site ``shop``
by the convention; every run goes through the dashboard request, the worker, Barectl's SSH
connection and actual systemd and Nginx, with at most one administrator command inserted
between two named fragments of the production payload. Ground truth is read as root through
``docker exec``. The site ``blog``, with private data, must be unchanged and keep serving.
"""

import shlex
from collections.abc import Iterator
from contextlib import contextmanager
from typing import override
from unittest import mock

from django.contrib.auth.models import Permission

from bootstrap.models import ApplyRun, ConfigurationPlan, Execution, PlanPreparation, Verification
from bootstrap.test_apply_remote import _is_inspection
from discovery.fakes import current, run_worker
from discovery.services import request_discovery
from discovery.test_remote import setting
from operations.models import RemoteOperation
from sites import native as site_native
from sites.convention import Stage, render_placeholder, render_site
from sites.test_faults_remote import FaultTestCase
from sites.test_review_remote import create_site

from . import native
from .models import ChallengeRunResult, RunChallenge

Status = RemoteOperation.Status
Exit = native.Exit
NAMES = ("shop.test", "www.shop.test")
WEBROOT = "/var/lib/letsencrypt/shop"
SOURCE = "/etc/nginx/sites-available/shop.conf"
TOKEN_FILE = f"{WEBROOT}/.well-known/acme-challenge/external-token"


class ChallengeTestCase(FaultTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        for codename in ("view_tlsplan", "prepare_tlsplan", "apply_tlsplan"):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.administer(create_site("shop", NAMES, self.php))
        self.administer(
            f"printf %s {shlex.quote(render_placeholder('shop'))} >/var/www/shop/public/index.html"
        )
        self.ipv6 = "[::]:80" in self.administer("ss -Hltn sport = :80")

    def challenge_plan(self) -> ConfigurationPlan:
        self.client.post(
            f"/servers/{self.server.pk}/tls/challenge/prepare/", {"identifier": "shop"}
        )
        run_worker()
        preparation = PlanPreparation.objects.latest("queued_at", "pk")
        self.assertEqual(preparation.status, Status.SUCCEEDED, preparation.failure)
        plan = ConfigurationPlan.objects.get(preparation=preparation)
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        return plan

    @contextmanager
    def route_injected(self, after: str, step: str) -> Iterator[None]:
        real = native.challenge_steps

        def payload(unit: str, boot: str, deadline: int, change: native.ChallengeChange) -> str:
            steps = real(unit, boot, deadline, change)
            names = [item.name for item in steps]
            steps.insert(names.index(after) + 1, site_native.Step("injected", step))
            return "; ".join(item.text for item in steps)

        with mock.patch.object(native, "challenge_payload", payload):
            yield

    def route_fault(self, after: str, step: str, undo: str = "true") -> ApplyRun:
        plan = self.challenge_plan()
        self.addCleanup(self.administer, undo)
        with self.route_injected(after, step):
            return self.apply_site(plan)

    def status(self, host: str, path: str, address: str = "127.0.0.1") -> str:
        """The status and body of an HTTP GET on the server."""
        client = native.status_client(self.php)
        return self.administer(
            f"{client}; s {shlex.quote(address)} {shlex.quote(host)} {shlex.quote(path)}; true"
        )

    def source(self) -> str:
        return self.administer(f"cat {SOURCE}")

    def http(self) -> str:
        return render_site("shop", NAMES, ipv6=self.ipv6)

    def challenge(self) -> str:
        return render_site("shop", NAMES, ipv6=self.ipv6, stage=Stage.CHALLENGE)

    def backups(self) -> list[str]:
        return self.administer("ls -1 /var/backups/nginx 2>/dev/null; true").split()

    def assert_stopped(self, run: ApplyRun, execution: Execution, status: int | None) -> None:
        self.assertEqual(
            (run.status, run.execution, run.exit_status, run.verification),
            (Status.FAILED, execution, status, Verification.NOT_APPLICABLE),
            run.failure,
        )
        self.assertEqual(ApplyRun.objects.count(), 1)
        self.assertEqual(self.units(), [run.unit_name])
        stages = self.administer("ls -A /etc/nginx/sites-available | grep '^\\.' ; true")
        self.assertEqual(stages, "")
        self.assertIn("Site shop is ready.", self.get("shop.test"))
        self.assert_others_intact()


class ChallengeAcceptanceTests(ChallengeTestCase):
    def test_a_reviewed_route_serves_challenges_and_keeps_http(self) -> None:
        before = self.source()
        run = self.apply_site(self.challenge_plan())
        self.assertEqual(
            (run.status, run.execution, run.verification, run.exit_status),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED, 0),
            run.failure,
        )
        self.assertEqual(ChallengeRunResult.objects.get(run=run).problems, "")
        self.assertEqual(before, self.http())
        self.assertEqual(self.source(), self.challenge())
        backup = RunChallenge.objects.get(run=run).backup_path
        self.assertEqual(self.administer(f"cat {backup}"), before)
        self.assertEqual(
            self.administer(
                f"stat -c '%n %U %G %a' {backup} /var/backups/nginx {WEBROOT} "
                f"/var/lib/letsencrypt {SOURCE}; ls -A {WEBROOT}"
            ),
            f"{backup} root root 600\n/var/backups/nginx root root 700\n"
            f"{WEBROOT} root www-data 750\n/var/lib/letsencrypt root root 755\n"
            f"{SOURCE} root root 644\n",
        )
        self.assertIn("Site shop is ready.", self.get("shop.test"))
        self.assert_others_intact()
        # A challenge file Certbot's webroot plugin writes is served as a file for each name
        # and family; PHP there is never run, and nothing is listed.
        self.administer(
            f"mkdir -p {WEBROOT}/.well-known/acme-challenge && "
            f"printf 'token-body' >{TOKEN_FILE} && "
            f"printf '<?php echo 6 * 7;' >{WEBROOT}/.well-known/acme-challenge/x.php && "
            f"chmod 755 {WEBROOT}/.well-known {WEBROOT}/.well-known/acme-challenge && "
            f"chmod 644 {TOKEN_FILE} {WEBROOT}/.well-known/acme-challenge/x.php"
        )
        addresses = ("127.0.0.1", "[::1]") if self.ipv6 else ("127.0.0.1",)
        for address in addresses:
            for name in NAMES:
                with self.subTest(address=address, name=name):
                    path = "/.well-known/acme-challenge/external-token"
                    self.assertEqual(self.status(name, path, address), "200 token-body")
                    php = self.status(name, "/.well-known/acme-challenge/x.php", address)
                    self.assertNotIn("42", php)
                    listing = self.status(name, "/.well-known/acme-challenge/", address)
                    self.assertTrue(listing.startswith("404 "), listing)
        # Another name never reaches the webroot.
        other = self.status("other.test", "/.well-known/acme-challenge/external-token")
        self.assertNotIn("token-body", other)
        # A fresh review has no changes, the site stays satisfied, and discovery finds the
        # site complete with its webroot.
        plan = self.challenge_plan()
        self.assertTrue(plan.no_changes)
        self.assertTrue(self.site_plan(names=" ".join(NAMES)).no_changes)
        self.addCleanup(self.administer, f"gpasswd -d {setting('USER')} shadow >/dev/null")
        self.administer(f"usermod -aG shadow {setting('USER')}")
        request_discovery(self.server)
        run_worker()
        (site,) = (s for s in current(self.server).collected.sites.value if s.identifier == "shop")
        self.assertTrue(site.complete, [r for r in site.resources if not r.conforms])
        self.assertIn("challenge_webroot", [r.resource.value for r in site.resources])

    def test_a_lost_acknowledgement_is_checked_without_resubmitting(self) -> None:
        plan = self.challenge_plan()
        with self.losing(_is_inspection, after=False):
            run = self.apply_site(plan)
        self.assertEqual(run.status, Status.RECONCILING)
        self.wait_terminal(run.unit_name)
        run = self.check(run)
        self.assertEqual((run.status, run.verification), (Status.SUCCEEDED, Verification.PASSED))
        self.assertEqual(self.units(), [run.unit_name])
        self.assertEqual(self.source(), self.challenge())


class ChallengeFaultTests(ChallengeTestCase):
    def wrapped(self, failures: int) -> tuple[str, str]:
        """nginx whose first ``failures`` syntax checks fail."""
        counter = "/run/barectl-check-count"
        wrapper = (
            "#!/bin/sh\n"
            'if [ "$1" = -t ]; then\n'
            f"  c=$(cat {counter} 2>/dev/null || echo 0); echo $((c + 1)) >{counter}\n"
            f'  if [ "$c" -lt {failures} ]; then exit 1; fi\n'
            "fi\n"
            'exec /run/barectl-check.real "$@"\n'
        )
        inject = (
            "cp /usr/sbin/nginx /run/barectl-check.real && "
            f"printf %s {shlex.quote(wrapper)} >/run/barectl-check && chmod 755 /run/barectl-check "
            "&& mount --bind /run/barectl-check /usr/sbin/nginx"
        )
        return inject, f"umount /usr/sbin/nginx 2>/dev/null; rm -f /run/barectl-check* {counter}"

    def test_a_site_file_changed_after_review_refuses_without_changes(self) -> None:
        plan = self.challenge_plan()
        self.administer(f"printf '# administrator\\n' >>{SOURCE}")
        run = self.apply_site(plan)
        self.assert_stopped(run, Execution.DRIFT, Exit.DRIFT)
        self.assertEqual(self.administer(f"test -e {WEBROOT} && echo yes; true"), "")
        self.assertEqual(self.backups(), [])

    def test_backup_failure_stops_before_the_site_file(self) -> None:
        run = self.route_fault(
            "revalidation",
            "mount -t tmpfs -o ro,mode=755 tmpfs /var/backups",
            "umount /var/backups 2>/dev/null; true",
        )
        self.assert_stopped(run, Execution.PARTIAL, Exit.DIRECTORIES)
        self.assertEqual(self.source(), self.http())

    def test_a_site_file_changed_before_replacement_is_kept(self) -> None:
        run = self.route_fault("directories", f"printf '# administrator\\n' >>{SOURCE}")
        self.assert_stopped(run, Execution.PARTIAL, Exit.REPLACEMENT)
        self.assertEqual(self.source(), self.http() + "# administrator\n")
        self.assertEqual(len(self.backups()), 1)

    def test_a_refused_candidate_is_restored_and_nothing_reloads(self) -> None:
        workers = self.nginx_workers()
        run = self.route_fault("directories", *self.wrapped(1))
        self.assert_stopped(run, Execution.PARTIAL, Exit.RESTORED)
        self.assertEqual(self.source(), self.http())
        self.assert_not_reloaded(workers, self.nginx_workers())

    def test_a_configuration_still_refused_after_restoring_is_reported(self) -> None:
        workers = self.nginx_workers()
        run = self.route_fault("directories", *self.wrapped(99))
        self.assertEqual((run.execution, run.exit_status), (Execution.PARTIAL, Exit.NOT_RESTORED))
        self.assertIn("Restore the preimage with cp", run.failure)
        self.assertEqual(self.source(), self.http())
        self.assert_not_reloaded(workers, self.nginx_workers())

    def test_a_failed_reload_is_reported(self) -> None:
        directory = "/run/systemd/system/nginx.service.d"
        run = self.route_fault(
            "validation",
            f"mkdir -p {directory} && printf '[Service]\\nExecReload=\\nExecReload=/bin/false\\n' "
            f">{directory}/barectl-test.conf && systemctl daemon-reload",
            f"rm -rf {directory}; systemctl daemon-reload",
        )
        self.assert_stopped(run, Execution.PARTIAL, Exit.NGINX_RELOAD)
        self.assertEqual(self.source(), self.challenge())

    def test_a_route_that_does_not_serve_removes_its_probe(self) -> None:
        run = self.route_fault("reload", f"chmod 0700 {WEBROOT}", f"chmod 0750 {WEBROOT}")
        self.assert_stopped(run, Execution.PARTIAL, Exit.NOT_SERVING)
        self.assertEqual(self.administer(f"ls -A {WEBROOT}"), "")

    def test_a_probe_that_cannot_be_removed_is_reported(self) -> None:
        challenges = f"{WEBROOT}/.well-known/acme-challenge"
        run = self.route_fault(
            "probe",
            f"mount --bind {challenges} {challenges} && mount -o remount,bind,ro {challenges}",
            f"umount {challenges} 2>/dev/null; true",
        )
        self.assert_stopped(run, Execution.PARTIAL, Exit.PROBE_LEFT)
        self.assertIn("barectl-", self.administer(f"ls {challenges}"))

    def test_a_killed_run_leaves_what_it_replaced(self) -> None:
        workers = self.nginx_workers()
        run = self.route_fault("replacement", "kill -9 $$")
        self.assertEqual((run.status, run.execution), (Status.FAILED, Execution.KILLED))
        self.assertEqual(self.source(), self.challenge())
        self.assertEqual(len(self.backups()), 1)
        self.assert_not_reloaded(workers, self.nginx_workers())
        self.assert_others_intact()
