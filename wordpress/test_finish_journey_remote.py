"""Finishing a partial WordPress installation in Chromium against a disposable server
(docs/wordpress.md#finishing-a-partial-installation).

Tagged ``ssh`` and ``native-browser``; the hosting journeys' ACME and DNS fixtures are not
needed, but their browser base is: the production build, the worker in the test process and the
server reached only through the controller's SSH connection. The administrator prepares the
site, HTTPS lineage, MariaDB binding, PHP baseline and authenticated WP-CLI by hand. Barectl
installs through the dashboard's request and a real unit, stopped after a named fragment of its
body. The operator then reviews and finishes the installation from the site's page with the
keyboard, the documented terminal step sets a password and the application answers over HTTPS;
an edited release file is refused in the same page and nothing on the server changes. Ground
truth is read with ``docker exec``.
"""

import re
import shlex
from typing import override

from django.contrib.auth.models import Permission
from django.test import tag
from playwright.sync_api import Locator, expect

from bootstrap.models import Action, ApplyRun, Execution, Verification
from dashboard.browser_testing import DevelopmentAssets
from dashboard.hosting_testing import HostingJourneyTestCase
from discovery.fakes import run_worker
from discovery.services import request_discovery
from operations.models import RemoteOperation
from servers.models import Server

from . import install
from .finish_remote_testing import interrupt_installation
from .install_remote_testing import IDENTIFIER, NAME, PASSWORD, PUBLIC, cleanups, prepare
from .models import InstallRunResult, PlanWordpressFinish

Status = RemoteOperation.Status


class FinishJourneyTests(HostingJourneyTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        for codename in (
            "view_wordpressplan",
            "prepare_wordpressplan",
            "install_wordpress",
            "view_siteapplicationobservation",
        ):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        for cleanup in cleanups(self.php):
            self.addCleanup(self.administer, cleanup)
        prepare(self.administer, self.php)
        self.client.force_login(self.user)

    def https(self, path: str, *, host: str = NAME) -> str:
        return self.administer(
            f"curl -sk --max-time 20 --resolve {host}:443:127.0.0.1 -o /dev/null "
            f"-w '%{{http_code}} %{{redirect_url}}' https://{host}{path}; true"
        ).strip()

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

    def password_hash(self) -> str:
        query = f"SELECT user_pass FROM s{IDENTIFIER}.wp_users"  # noqa: S608 - fixed name
        return self.administer(f"mariadb --no-defaults -N -B -e {shlex.quote(query)} | sha256sum")

    def files(self) -> str:
        return self.administer(
            f"cd {PUBLIC} && find . -type f -exec sha256sum {{}} + | sort | sha256sum"
        )

    def stranded(self, after: str) -> int:
        """Register the server in the browser, install through the dashboard's request and stop
        the unit after the named fragment, then refresh what the site's page observes."""
        server = self.register()
        run = interrupt_installation(self.client, server, after)
        self.assertEqual((run.status, run.exit_status), (Status.FAILED, 77), run.failure)
        request_discovery(server)
        run_worker()
        return server.pk

    def open_finish(self, server_pk: int) -> Locator:
        page = self.page
        page.goto(f"{self.live_server_url}/servers/{server_pk}/sites/{IDENTIFIER}/wordpress/")
        section = page.locator("#site-wordpress-finish")
        expect(
            section.get_by_role("heading", name="Finish a partial WordPress installation", level=2)
        ).to_be_visible()
        return section

    def test_finish_an_interrupted_installation_set_a_password_and_use_https(self) -> None:
        server_pk = self.stranded("configuration")
        page = self.page
        # The passive evidence is read by the SSH user, who is not root: it reports the gate and
        # what it cannot read, never an installation.
        page.goto(f"{self.live_server_url}/servers/{server_pk}/sites/{IDENTIFIER}/wordpress/")
        application = page.get_by_role("region", name="WordPress application")
        expect(application).to_contain_text("WordPress behind the provisioning gate")
        section = self.open_finish(server_pk)
        expect(section).to_contain_text("It needs no record of the earlier run")
        expect(section).to_contain_text("No Finish review for this site yet")
        self.assert_no_overflow()
        before_files = self.files()
        # The optional fields take the keyboard like any form.
        section.get_by_label("Site title").fill("Shop & Sons")
        section.get_by_label("Administrator login").fill("owner")
        section.get_by_label("Administrator email").fill("owner@example.com")
        button = section.get_by_role("button", name="Prepare Finish review")
        self.submit(button, "/finish/prepare/")
        expect(section).to_contain_text("Ready for review", timeout=60_000)
        expect(section).to_contain_text(f"https://{NAME}/")
        expect(section).to_contain_text("Keeps the existing supported")
        expect(section).to_contain_text("Administrator password setup required")
        self.assertEqual(self.files(), before_files)
        section.get_by_role("link", name=re.compile("Open this plan")).click()
        expect(page.locator("#apply-confirmation")).to_contain_text(
            re.compile(
                r"Apply plan \d+, WordPress installation Finish, revision \d+, to Production"
            )
        )
        self.assert_no_overflow()

        apply = page.get_by_role("button", name=re.compile(r"^Apply plan \d+$"))
        apply.focus()
        page.keyboard.press("Enter")
        expect(page.get_by_role("heading", name="Apply queued", level=2)).to_be_visible()
        self.drain_worker()
        run = ApplyRun.objects.filter(action=Action.WORDPRESS_FINISH).get()
        self.assertEqual(
            (run.status, run.execution, run.verification),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED),
            run.failure,
        )
        expect(page.get_by_role("heading", name="Applied and verified", level=2)).to_be_visible(
            timeout=120_000
        )
        self.assertEqual(InstallRunResult.objects.get(run=run).problems, "")
        listed = self.administer("systemctl list-units --all --plain --no-legend 'barectl-apply-*'")
        self.assertEqual(listed.count(run.unit_name), 1, "the Finish was submitted exactly once")

        completion = page.locator("#run-completion")
        expect(completion).to_contain_text("Administrator password setup required")
        expect(completion).to_contain_text("not a live health check")
        step = install.password_command(IDENTIFIER, self.php, NAME, "owner")
        expect(completion.locator("#run-completion-command")).to_contain_text(step)
        expect(completion.get_by_role("link", name="WordPress dashboard")).to_have_attribute(
            "href", f"https://{NAME}/wp-admin/"
        )
        audit = page.locator("#apply-audit")
        expect(audit).to_contain_text("Verify that the provisioning gate")
        expect(audit).to_contain_text("Keep /var/www/shop/private/wp-config.php")
        expect(audit).to_contain_text("Verified")
        self.assert_no_overflow()

        refused = self.login("guess-guess-guess")
        self.assertEqual(refused.split()[:1], ["200"], refused)
        output = self.administer(
            f"printf '%s\\n' {shlex.quote(PASSWORD)} | {step} 2>&1; echo status=$?"
        )
        self.assertIn("Success: Updated user", output)
        self.assertEqual(self.login(PASSWORD), f"302 https://{NAME}/wp-admin/")
        self.assertEqual(self.https("/"), "200")
        self.assertEqual(self.https("/wp-config.php"), "403")
        self.assertEqual(self.https("/", host="shop.test").split()[0], "301")
        self.assertEqual(
            self.administer(f"ls -A /var/www/{IDENTIFIER}").split(), ["private", "public"]
        )
        page.goto(f"{self.live_server_url}/servers/{server_pk}/sites/{IDENTIFIER}/wordpress/")
        expect(page.locator("#site-wordpress-finish")).to_contain_text("Latest Finish run")
        self.assertEqual(self.console_errors, [])

    def test_an_installed_site_gets_the_ready_routing_and_no_password_step(self) -> None:
        server_pk = self.stranded("access")
        page = self.page
        section = self.open_finish(server_pk)
        button = section.get_by_role("button", name="Prepare Finish review")
        self.submit(button, "/finish/prepare/")
        expect(section).to_contain_text("Ready for review", timeout=60_000)
        expect(section).to_contain_text("Core installation is not run")
        expect(section).not_to_contain_text("Administrator password setup required")
        users = self.password_hash()
        section.get_by_role("link", name=re.compile("Open this plan")).click()
        apply = page.get_by_role("button", name=re.compile(r"^Apply plan \d+$"))
        apply.focus()
        page.keyboard.press("Enter")
        expect(page.get_by_role("heading", name="Apply queued", level=2)).to_be_visible()
        self.drain_worker()
        run = ApplyRun.objects.filter(action=Action.WORDPRESS_FINISH).get()
        self.assertEqual(
            (run.status, run.verification), (Status.SUCCEEDED, Verification.PASSED), run.failure
        )
        expect(page.get_by_role("heading", name="Applied and verified", level=2)).to_be_visible(
            timeout=120_000
        )
        completion = page.locator("#run-completion")
        expect(completion).not_to_contain_text("Administrator password setup required")
        expect(completion.get_by_role("link", name="Home page")).to_have_attribute(
            "href", f"https://{NAME}/"
        )
        self.assertEqual(self.password_hash(), users, "the administrator's account was not touched")
        self.assertEqual(self.https("/"), "200")
        self.assertEqual(PlanWordpressFinish.objects.get().runs_install, False)
        self.assertEqual(self.console_errors, [])

    def test_foreign_content_is_refused_in_the_page_and_changes_nothing(self) -> None:
        server_pk = self.stranded("publish")
        self.administer(f"printf x >{PUBLIC}/robots.txt")
        before = self.files()
        request_discovery(Server.objects.get(pk=server_pk))
        run_worker()
        page = self.page
        section = self.open_finish(server_pk)
        section.get_by_label("Site title").fill("Shop & Sons")
        section.get_by_label("Administrator login").fill("owner")
        section.get_by_label("Administrator email").fill("owner@example.com")
        button = section.get_by_role("button", name="Prepare Finish review")
        self.submit(button, "/finish/prepare/")
        expect(section).to_contain_text("robots.txt", timeout=60_000)
        expect(section).to_contain_text("never adopts, overwrites or deletes")
        self.assertEqual(PlanWordpressFinish.objects.count(), 0)
        section.get_by_role("link", name=re.compile("Open this plan")).click()
        expect(page.get_by_text("robots.txt").first).to_be_visible()
        expect(page.get_by_role("button", name=re.compile(r"^Apply plan"))).to_have_count(0)
        self.assertFalse(ApplyRun.objects.filter(action=Action.WORDPRESS_FINISH).exists())
        self.assertEqual(self.files(), before)
        self.assert_no_overflow()
        self.assertEqual(self.console_errors, [])

    def test_an_edited_release_file_is_refused_by_the_run_before_it_changes_anything(
        self,
    ) -> None:
        server_pk = self.stranded("publish")
        self.administer(f"printf '// edited\\n' >>{PUBLIC}/wp-admin/admin.php")
        edited = self.files()
        request_discovery(Server.objects.get(pk=server_pk))
        run_worker()
        page = self.page
        section = self.open_finish(server_pk)
        section.get_by_label("Site title").fill("Shop & Sons")
        section.get_by_label("Administrator login").fill("owner")
        section.get_by_label("Administrator email").fill("owner@example.com")
        self.submit(section.get_by_role("button", name="Prepare Finish review"), "/finish/prepare/")
        expect(section).to_contain_text("Ready for review", timeout=60_000)
        expect(section).to_contain_text("compares every existing entry")
        section.get_by_role("link", name=re.compile("Open this plan")).click()
        apply = page.get_by_role("button", name=re.compile(r"^Apply plan \d+$"))
        apply.focus()
        page.keyboard.press("Enter")
        expect(page.get_by_role("heading", name="Apply queued", level=2)).to_be_visible()
        self.drain_worker()
        run = ApplyRun.objects.filter(action=Action.WORDPRESS_FINISH).get()
        self.assertEqual(
            (run.status, run.execution, run.verification),
            (Status.FAILED, Execution.EDITED_FILES, Verification.NOT_APPLICABLE),
            run.failure,
        )
        page.reload()
        expect(page.locator("#apply-status")).to_contain_text("differ from the pinned archive")
        expect(page.locator("#apply-status")).to_contain_text("stopped before making any")
        self.assertEqual(self.files(), edited)
        self.assertEqual(
            self.administer(f"ls -A /var/www/{IDENTIFIER}").split(), ["private", "public"]
        )
        self.assert_no_overflow()


@tag("ssh", "native-browser")
class DevelopmentFinishJourneyTests(DevelopmentAssets, FinishJourneyTests):
    """The journey again with the Vite development server's modules, styles and fonts."""
