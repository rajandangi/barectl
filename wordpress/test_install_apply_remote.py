"""Applying a reviewed WordPress installation on a real, disposable Ubuntu server
(docs/wordpress.md#applying-an-installation).

Tagged ``ssh`` and skipped unless the disposable server is configured, as
``bootstrap/test_apply_remote.py`` describes. The administrator prepares the site, HTTPS
lineage, MariaDB binding, PHP baseline and authenticated WP-CLI by hand (see
``test_install_remote``); Barectl reviews and applies through the dashboard request, the
worker, its SSH connection, actual systemd, curl, tar, WP-CLI and WordPress, and the official
artifacts over the real network. Ground truth is read as root through ``docker exec``.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from unittest import mock

from bootstrap.models import ApplyRun, ConfigurationPlan, Execution, Verification
from discovery.fakes import run_worker
from operations.models import RemoteOperation

from . import install_native
from .models import InstallRunResult, RunWordpressInstall
from .test_install_remote import (
    IDENTIFIER,
    PRIVATE,
    PUBLIC,
    InstallationServerCase,
)

Status = RemoteOperation.Status
SECRET_WORDS = ("password", "salt", "AUTH_KEY", "admin_password")


class InstallApplyTestCase(InstallationServerCase):
    def eligible(self) -> ConfigurationPlan:
        plan = self.review()
        self.assertTrue(plan.eligible, self.texts(plan))
        return plan

    def apply_install(self, plan: ConfigurationPlan) -> ApplyRun:
        run = self.request(plan)
        run_worker()
        run.refresh_from_db()
        return run

    @contextmanager
    def injected(self, after: str, step: str) -> Iterator[None]:
        """Insert one administrator command between two named fragments of the production
        body, as the run's staged body carries it."""
        real = install_native.body_steps

        def steps(row: object, evidence: object, release: str) -> list[install_native.Step]:
            built = real(row, evidence, release)  # type: ignore[arg-type]
            names = [item.name for item in built]
            built.insert(names.index(after) + 1, install_native.Step("injected", step))
            return built

        with mock.patch.object(install_native, "body_steps", steps):
            yield

    def curl(self, path: str, *, host: str = "www.shop.test") -> str:
        return self.administer(
            f"curl -sk --max-time 20 --resolve {host}:443:127.0.0.1 "
            f"-o /dev/null -w '%{{http_code}}' https://{host}{path}; true"
        ).strip()


class InstallApplyAcceptanceTests(InstallApplyTestCase):
    def test_a_reviewed_installation_is_applied_and_verified(self) -> None:
        plan = self.eligible()
        run = self.apply_install(plan)
        journal = self.journal(run.unit_name)
        self.assertEqual(
            (run.status, run.execution, run.verification, run.exit_status),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED, 0),
            f"{run.failure}\n{journal[-3000:]}",
        )
        self.assertEqual(InstallRunResult.objects.get(run=run).problems, "")
        self.assertEqual(RunWordpressInstall.objects.get(run=run).identifier, IDENTIFIER)
        self.assertEqual(self.tables(), "12")
        self.assertEqual(self.curl("/wp-login.php"), "200")
        self.assertEqual(self.curl("/wp-config.php"), "403")
        self.assertEqual(
            self.administer(f"ls -A /var/www/{IDENTIFIER}").split(), ["private", "public"]
        )
        self.assertIn("barectl-wordpress: HTTPS verified", journal)
        for word in SECRET_WORDS:
            self.assertNotIn(word, journal.replace("barectl-wordpress", ""))
        self.assertEqual(
            self.administer(f"stat -c '%U:%G %a' {PUBLIC}/wp-config.php {PRIVATE}/wp-config.php")
            .strip()
            .splitlines(),
            [f"s{IDENTIFIER}:www-data 640", f"s{IDENTIFIER}:s{IDENTIFIER} 600"],
        )
