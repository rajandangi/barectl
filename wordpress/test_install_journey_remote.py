"""A WordPress installation in Chromium against a disposable server
(docs/wordpress.md#applying-an-installation).

Tagged ``ssh`` and ``native-browser``; the hosting journeys' ACME and DNS fixtures are not
needed, but their browser base is: the production build, the worker in the test process and the
server reached only through the controller's SSH connection. The administrator prepares the
site, HTTPS lineage, MariaDB binding, PHP baseline and authenticated WP-CLI by hand. The operator
then reviews and applies the installation from the site's page with the keyboard; the controller
loses the answer to the submission, the unit finishes on the server, Check outcome records it as
verified, the documented terminal step sets a password, and the application answers over HTTPS.
Ground truth is read with ``docker exec``.
"""

import re
import shlex
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import override
from unittest import mock

from django.contrib.auth.models import Permission
from playwright.sync_api import expect

from bootstrap.models import Action, ApplyRun, Execution, Verification
from bootstrap.test_apply_remote import _is_submission, _LosingShell
from dashboard.hosting_testing import HostingJourneyTestCase
from discovery import ssh
from discovery.ssh import RemoteShell
from operations.models import RemoteOperation
from servers.ssh_config import ConnectionTarget

from . import install
from .models import InstallRunResult
from .test_install_remote import FORM, IDENTIFIER, cleanups, prepare

Status = RemoteOperation.Status
NAME = "www.shop.test"
PASSWORD = "Barectl-Journey-Passw0rd-3tQ8mZ"  # noqa: S105 - the test's own throwaway value


class InstallJourneyTests(HostingJourneyTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        for codename in ("view_wordpressplan", "prepare_wordpressplan", "install_wordpress"):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        for cleanup in cleanups(self.php):
            self.addCleanup(self.administer, cleanup)
        prepare(self.administer, self.php)

    @contextmanager
    def losing(self, lose: Callable[[str], bool], *, after: bool) -> Iterator[None]:
        """Lose the answer to the first command ``lose`` matches on the controller's connections."""
        real = ssh.connect

        @contextmanager
        def connect(target: ConnectionTarget) -> Iterator[RemoteShell]:
            with real(target) as shell:
                yield _LosingShell(shell, lose, after=after)

        with mock.patch.object(ssh, "connect", connect):
            yield

    def https(self, path: str, *, host: str = NAME) -> str:
        return self.administer(
            f"curl -sk --max-time 20 --resolve {host}:443:127.0.0.1 -o /dev/null "
            f"-w '%{{http_code}} %{{redirect_url}}' https://{host}{path}; true"
        ).strip()

    def test_review_apply_lose_the_controller_check_set_a_password_and_use_https(self) -> None:
        page = self.page
        server = self.register()
        page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/{IDENTIFIER}/wordpress/")
        section = page.locator("#site-wordpress-install")
        expect(section.get_by_role("heading", name="Install WordPress", level=2)).to_be_visible()
        table = section.get_by_role("table", name="Prerequisites as last observed")
        expect(table).to_contain_text("Convention site")
        # The form takes the four bounded values, with the keyboard.
        section.get_by_label("Canonical HTTPS name").fill(FORM["wordpress-canonical_name"])
        section.get_by_label("Site title").fill(FORM["wordpress-title"])
        section.get_by_label("Administrator login").fill(FORM["wordpress-admin_login"])
        section.get_by_label("Administrator email").fill(FORM["wordpress-admin_email"])
        button = section.get_by_role("button", name="Prepare WordPress installation review")
        self.submit(button, "/install/prepare/")
        expect(section).to_contain_text("Ready for review", timeout=60_000)
        expect(section).to_contain_text(f"https://{NAME}/")
        self.assertEqual(
            self.administer(f"ls -A /var/www/{IDENTIFIER}/public").strip(), "index.html"
        )
        section.get_by_role("link", name=re.compile("Open this plan")).click()
        expect(page.locator("#apply-confirmation")).to_contain_text(
            re.compile(
                r"Apply plan \d+, WordPress installation review, revision \d+, to Production"
            )
        )
        self.assert_no_overflow()

        # The controller loses the answer to the submission; the unit runs on regardless.
        apply = page.get_by_role("button", name=re.compile(r"^Apply plan \d+$"))
        apply.focus()
        page.keyboard.press("Enter")
        expect(page.get_by_role("heading", name="Apply queued", level=2)).to_be_visible()
        with self.losing(_is_submission, after=True):
            self.drain_worker()
        run = ApplyRun.objects.latest("pk")
        self.assertEqual(run.status, Status.RECONCILING, run.failure)
        page.reload()
        expect(page.locator("#apply-status")).to_contain_text("Outcome not established")
        expect(page.get_by_role("button", name="Check outcome")).to_be_visible()
        self.wait_for_unit(run.unit_name)
        check = page.get_by_role("button", name="Check outcome")
        check.focus()
        with page.expect_navigation():
            page.keyboard.press("Enter")
        self.drain_worker()
        expect(page.get_by_role("heading", name="Applied and verified", level=2)).to_be_visible(
            timeout=120_000
        )
        run.refresh_from_db()
        self.assertEqual(
            (run.status, run.execution, run.verification),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED),
            run.failure,
        )
        self.assertEqual(InstallRunResult.objects.get(run=run).problems, "")
        self.assertEqual(
            self.administer("systemctl list-units --all --plain --no-legend 'barectl-apply-*'")
            .strip()
            .count("barectl-apply-"),
            1,
            "the unit was submitted exactly once",
        )

        # Completion: the required password step, correctly targeted, and the application.
        completion = page.locator("#run-completion")
        expect(completion).to_contain_text("Administrator password setup required")
        expect(completion).to_contain_text("not a live health check")
        step = install.password_command(IDENTIFIER, self.php, NAME, "owner")
        expect(completion.locator("#run-completion-command")).to_contain_text(step)
        expect(completion.get_by_role("link", name="Home page")).to_have_attribute(
            "href", f"https://{NAME}/"
        )
        expect(completion.get_by_role("link", name="WordPress dashboard")).to_have_attribute(
            "href", f"https://{NAME}/wp-admin/"
        )
        for claim in ("password was delivered", "email was sent", "ready to log in"):
            expect(page.locator("main")).not_to_contain_text(claim)
        audit = page.locator("#apply-audit")
        expect(audit).to_contain_text("Publish the provisioning gate")
        expect(audit).to_contain_text("Verified")
        self.assert_no_overflow()

        # The operator performs the step in a terminal on the server; the login then works.
        refused = self.login("guess-guess-guess")
        self.assertEqual(refused.split()[:1], ["200"], refused)
        output = self.administer(
            f"printf '%s\\n' {shlex.quote(PASSWORD)} | {step} 2>&1; echo status=$?"
        )
        self.assertIn("Success: Updated user", output)
        self.assertEqual(self.login(PASSWORD), f"302 https://{NAME}/wp-admin/")
        self.assertEqual(self.https("/"), "200")
        self.assertEqual(self.https("/wp-login.php"), "200")
        self.assertEqual(self.https("/wp-config.php"), "403")
        self.assertEqual(self.https("/sample-page/").split()[0], "200")
        self.assertEqual(self.https("/?s=anything").split()[0], "200")
        self.assertEqual(self.https("/", host="shop.test").split()[0], "301")
        self.assertEqual(
            self.administer(f"ls -A /var/www/{IDENTIFIER}").split(), ["private", "public"]
        )

        # The site's page now reports the application from native evidence, and the plan is
        # spent: the review offers no second installation.
        page.goto(f"{self.live_server_url}/servers/{server.pk}/sites/{IDENTIFIER}/wordpress/")
        expect(page.locator("#site-wordpress-install")).to_contain_text("Latest installation run")
        self.assertEqual(ApplyRun.objects.filter(action=Action.WORDPRESS_INSTALL).count(), 1)
        self.assert_no_overflow()
        self.assertEqual(self.console_errors, [])

    def wait_for_unit(self, unit: str) -> None:
        for _ in range(180):
            shown = self.administer(f"systemctl show -p ActiveState -p SubState {unit}")
            if "ActiveState=active" in shown and "SubState=exited" in shown:
                return
            if "ActiveState=failed" in shown:
                raise AssertionError(shown)
            time.sleep(1)
        raise AssertionError(f"{unit} did not finish.")

    def login(self, password: str) -> str:
        jar = "/tmp/barectl-journey-jar"  # noqa: S108 - a file in the disposable server
        self.addCleanup(self.administer, f"rm -f {jar}")
        return self.administer(
            f"curl -sk --max-time 30 --resolve {NAME}:443:127.0.0.1 -c {jar} -b {jar} "
            "-o /dev/null -w '%{http_code} %{redirect_url}' "
            '-H "Cookie: wordpress_test_cookie=WP%20Cookie%20check" '
            f"--data-urlencode log=owner --data-urlencode pwd={shlex.quote(password)} "
            "--data-urlencode wp-submit=Log+In --data-urlencode testcookie=1 "
            f"https://{NAME}/wp-login.php; true"
        ).strip()
