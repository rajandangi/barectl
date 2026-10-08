"""Site pages and polls while a later connection check is queued, running or failed.

docs/dashboard-workflows.md#site-pages
"""

from collections.abc import Callable
from typing import TYPE_CHECKING, override
from unittest import mock

from bootstrap.models import PlanPreparation
from discovery.fakes import record_attempt
from discovery.models import SiteObservation
from discovery.services import request_discovery
from operations.models import RemoteOperation
from servers.models import Server
from servers.site_access import STALE_SITE
from servers.testing import HTMX_FRAGMENT
from tls.fakes import NAMES, TlsTestCase, record_step
from tls.models import CertificateInstallation

if TYPE_CHECKING:
    from django.test.client import _MonkeyPatchedWSGIResponse

PERMISSIONS = (
    "view_server",
    "view_siteobservation",
    "view_tlsplan",
    "prepare_tlsplan",
    "apply_tlsplan",
    "issue_certificate",
    "view_databaseplan",
    "prepare_databaseplan",
    "view_configurationplan",
    "prepare_configurationplan",
)
Status = RemoteOperation.Status
SECTIONS = ("overview", "database", "https", "wordpress", "activity", "advanced")
CHECKING = "A new connection check is running; these observations may be out of date."
CHECK_FAILED = "The latest connection check failed, so these observations may be out of date."
REFRESH = "Refresh observations before changing this site."


def announced(response: _MonkeyPatchedWSGIResponse) -> str:
    """What the response's live-region partial announces."""
    content = response.content.decode()
    start = content.find("<hx-partial")
    return content[start : content.index("</hx-partial>", start)] if start >= 0 else ""


class StaleSitePageTests(TlsTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        request_discovery(self.server)
        self.run_worker()
        SiteObservation.objects.create(
            snapshot=self.server.snapshots.get(),
            identifier="shop",
            server_names="\n".join(NAMES),
            php_version="8.3",
            state="managed",
            outcome="observed",
        )
        self.site.answer(self.remote)
        self.sign_in_with(*PERMISSIONS)

    def url(self, path: str, identifier: str = "shop") -> str:
        return f"/servers/{self.server.pk}/sites/{identifier}/{path}"

    def queued(self) -> None:
        request_discovery(self.server)

    def running(self) -> None:
        record_attempt(request_discovery(self.server), Status.RUNNING)

    def failed(self) -> None:
        record_attempt(
            request_discovery(self.server), Status.FAILED, failure="The host did not answer."
        )

    def checks(self) -> tuple[tuple[str, Callable[[], None], str], ...]:
        """Each later check state, applied in order, with the notice it shows."""
        return (
            ("queued", self.queued, CHECKING),
            ("running", self.running, CHECKING),
            ("failed", self.failed, CHECK_FAILED),
        )

    def polls(self, identifier: str = "shop") -> tuple[str, ...]:
        return (
            self.url("database/plans/?shown=x", identifier),
            self.url("https/readiness/?shown=x", identifier),
            self.url("https/installation/?shown=x", identifier),
            self.url("wordpress/runtime/?shown=x", identifier),
        )

    def posts(self) -> tuple[tuple[str, dict[str, str]], ...]:
        revision = str(self.server.snapshots.latest("pk").pk)
        return (
            (self.url("database/prepare/"), {"action": "database_mariadb"}),
            (self.url("https/readiness/prepare/"), {}),
            (
                self.url("https/install/"),
                {"installation-email": "ops@example.com", "installation-snapshot": revision},
            ),
            (self.url("wordpress/runtime/prepare/"), {}),
        )

    def test_every_site_page_shows_the_last_snapshot_with_the_stale_notice(self) -> None:
        for name, apply, notice in self.checks():
            apply()
            for section in SECTIONS:
                with self.subTest(check=name, section=section):
                    response = self.client.get(self.url(f"{section}/"))
                    self.assertContains(response, 'aria-label="Site sections"')
                    self.assertContains(response, "shop.example.com, www.shop.example.com")
                    self.assertNotContains(response, "This site cannot be confirmed")
                    if section != "activity":
                        self.assertContains(response, notice)
                        self.assertContains(response, "Collected <time")

    def test_every_site_poll_renders_the_last_site(self) -> None:
        for name, apply, _ in self.checks():
            apply()
            for poll in self.polls():
                with self.subTest(check=name, poll=poll):
                    response = self.client.get(poll, headers=HTMX_FRAGMENT)
                    self.assertEqual(response.status_code, 200)
                    self.assertNotContains(response, "Not Found")

    def test_change_forms_are_explained_rather_than_offered(self) -> None:
        for name, apply, _ in self.checks():
            apply()
            with self.subTest(check=name):
                database = self.client.get(self.url("database/"))
                https = self.client.get(self.url("https/"))
                self.assertNotContains(database, "Prepare MariaDB database plan")
                self.assertNotContains(https, 'name="installation-email"')
                self.assertNotContains(
                    self.client.get(self.url("wordpress/")), "Prepare WordPress PHP runtime plan"
                )
                self.assertNotContains(https, "Check readiness</button>")
                # Enable HTTPS keeps no busy slot of its own, so it always explains.
                self.assertContains(https, REFRESH)
                if name == "failed":
                    # Nothing else is active, so the stale observation is the reason.
                    self.assertContains(database, REFRESH)
                    self.assertContains(https, REFRESH, count=2)
                else:
                    # The connection check holds the server's operation slot, as before.
                    self.assertContains(database, "A database plan can be prepared after")
                    self.assertContains(https, "A readiness review can be prepared after")

    def test_change_posts_are_refused_while_the_observation_is_stale(self) -> None:
        for name, apply, _ in self.checks():
            apply()
            for url, data in self.posts():
                with self.subTest(check=name, url=url):
                    response = self.client.post(url, data, headers=HTMX_FRAGMENT)
                    self.assertContains(response, REFRESH, status_code=409)
                    self.assertIn(STALE_SITE, announced(response))
                    page = self.client.post(url, data)
                    self.assertEqual(page.status_code, 302)
        self.assertFalse(PlanPreparation.objects.exists())
        self.assertFalse(CertificateInstallation.objects.exists())

    def test_a_busy_refusal_is_announced(self) -> None:
        for url, data in self.posts()[:2]:
            module = "databases" if "/database/" in url else "tls"
            queue = (
                "request_binding_preparation"
                if module == "databases"
                else "request_readiness_preparation"
            )
            with self.subTest(url=url), mock.patch(f"{module}.views.{queue}", return_value=None):
                response = self.client.post(url, data, headers=HTMX_FRAGMENT)
                self.assertIn(
                    "Barectl is running another remote operation for this server.",
                    announced(response),
                )

    def test_polled_cards_carry_the_notice_and_drop_it_with_the_check(self) -> None:
        self.queued()
        for poll in self.polls():
            with self.subTest(poll=poll):
                self.assertContains(self.client.get(poll, headers=HTMX_FRAGMENT), CHECKING)
        self.run_worker()
        SiteObservation.objects.create(
            snapshot=self.server.snapshots.latest("pk"),
            identifier="shop",
            server_names="\n".join(NAMES),
            php_version="8.3",
            state="managed",
            outcome="observed",
        )
        for poll in self.polls():
            with self.subTest(poll=poll, check="verified"):
                response = self.client.get(poll, headers=HTMX_FRAGMENT)
                self.assertNotContains(response, CHECKING)
                self.assertNotContains(response, 'hx-trigger="every 2s"')
                self.assertNotContains(response, REFRESH)
        self.failed()
        for poll in self.polls():
            with self.subTest(poll=poll, check="failed"):
                self.assertContains(
                    self.client.get(poll, headers=HTMX_FRAGMENT), f"<strong>{CHECK_FAILED}</strong>"
                )

    def test_a_fresh_observation_offers_the_changes_again(self) -> None:
        self.failed()
        request_discovery(self.server)
        self.run_worker()
        SiteObservation.objects.create(
            snapshot=self.server.snapshots.latest("pk"),
            identifier="shop",
            server_names="\n".join(NAMES),
            php_version="8.3",
            state="managed",
            outcome="observed",
        )
        https = self.client.get(self.url("https/"))
        self.assertNotContains(https, REFRESH)
        self.assertContains(https, 'name="installation-email"')
        self.assertContains(self.client.get(self.url("database/")), "Prepare MariaDB database plan")

    def test_a_site_absent_from_the_last_complete_collection_is_still_not_found(self) -> None:
        for name, apply, notice in self.checks():
            apply()
            with self.subTest(check=name):
                response = self.client.get(self.url("overview/", "absent1"))
                self.assertContains(response, "Site not found in the latest observation")
                self.assertContains(response, notice)
                self.assertNotContains(response, 'aria-label="Site sections"')
                for poll in self.polls("absent1"):
                    self.assertEqual(self.client.get(poll, headers=HTMX_FRAGMENT).status_code, 404)

    def test_without_a_snapshot_the_site_is_unknown(self) -> None:
        other = Server.objects.create(name="Other", ssh_alias="stage.example.net")
        for name, status in (("none", None), ("queued", Status.QUEUED), ("failed", Status.FAILED)):
            if status is not None:
                record_attempt(request_discovery(other), status)
            with self.subTest(check=name):
                response = self.client.get(f"/servers/{other.pk}/sites/shop/overview/")
                self.assertContains(response, "This site cannot be confirmed")
                self.assertNotContains(response, 'aria-label="Site sections"')
                for poll in self.polls():
                    self.assertEqual(
                        self.client.get(
                            poll.replace(f"/servers/{self.server.pk}/", f"/servers/{other.pk}/"),
                            headers=HTMX_FRAGMENT,
                        ).status_code,
                        404,
                    )

    def test_installation_progress_keeps_polling_while_discovery_runs_between_stages(
        self,
    ) -> None:
        installation = CertificateInstallation.objects.create(
            server=self.server,
            requested_by=self.user,
            identifier="shop",
            names="\n".join(NAMES),
            discovery_revision=self.server.snapshots.latest("pk").pk,
            email="ops@example.com",
            authority="https://acme.example/directory",
            ssh_alias=self.server.ssh_alias,
        )
        record_step(installation, 0)
        for name, apply in (("queued", self.queued), ("running", self.running)):
            apply()
            with self.subTest(check=name):
                poll = self.client.get(
                    self.url("https/installation/?shown=x"), headers=HTMX_FRAGMENT
                )
                self.assertContains(poll, 'id="site-installation"')
                self.assertContains(poll, 'hx-trigger="every 2s"')
                # The stage's run finished; the installation waits for this check to continue.
                self.assertContains(poll, "<strong>Route preparation</strong>: Current")
                self.assertContains(poll, "Apply run<span")
                self.assertContains(poll, "<strong>Renewal setup</strong>: Not started")
                self.assertNotContains(poll, REFRESH)
        installation.refresh_from_db()
        self.assertEqual(installation.status, CertificateInstallation.Status.ACTIVE)
