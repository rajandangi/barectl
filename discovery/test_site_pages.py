"""Site observations through the request, worker and page, with their view permission.

docs/ssh-connections.md#site-observations
"""

import re

from django.utils.html import escape

from operations.models import RemoteOperation
from servers.models import Server
from servers.testing import HTMX_FRAGMENT
from tls.installation import PERMISSIONS as INSTALL

from . import ssh
from .fakes import AVAILABLE_DIR, PHP_DIR, SITE_DIR, DiscoveryTestCase, add_site, current
from .models import SiteObservation
from .presentation import SITES_NOTE

VIEW = ("view_server", "add_server", "add_discoveryattempt")
SITES = "view_siteobservation"
# Text only the Sites section shows, its facts included; the site files and pools cards
# are gone.
SITE_ONLY = (
    "sites-heading",
    "supported site convention",
    "/var/www/alpha",
    "Site user",
)


class SitePageTests(DiscoveryTestCase):
    def discover_as(self, *codenames: str) -> Server:
        self.grant(*codenames)
        server = self.register()
        self.run_worker()
        return server

    def add_broken_site(self) -> None:
        """beta: an enabled Nginx file whose account, pool and socket do not exist."""
        add_site(self.remote, "beta", ("beta.test",))
        del self.remote.files[f"{PHP_DIR}/8.3/fpm/pool.d/beta.conf"]
        self.remote.directories[f"{PHP_DIR}/8.3/fpm/pool.d"].remove("beta.conf")
        self.remote.sockets.discard("/run/php/sbeta.sock")
        self.remote.results["getent passwd sbeta"] = ssh.CommandResult(2, "")

    def test_sites_are_shown_with_keyboard_details_and_without_actions(self) -> None:
        add_site(self.remote)
        self.add_broken_site()
        server = self.discover_as(*VIEW, SITES)
        page = self.client.get(f"/servers/{server.pk}/advanced/").content.decode()
        start = page.index('aria-labelledby="sites-heading"')
        section = page[start : page.index("</section>", start)]
        # One card per site, led by its domains, with the native identifier kept.
        self.assertEqual(section.count('class="barectl-site"'), 2)
        self.assertEqual(section.count("<details"), 2)
        self.assertEqual(section.count("<summary>"), 2)
        self.assertIn("alpha.test, www.alpha.test", section)
        self.assertIn(
            f'<a href="/servers/{server.pk}/sites/alpha/overview/">alpha.test, www.alpha.test</a>',
            section,
        )
        self.assertIn("<code>alpha</code>", section)
        self.assertIn("<code>beta</code>", section)
        self.assertIn("beta.test", section)
        self.assertIn("Matches the supported site convention", section)
        self.assertIn("Partly applied", section)
        # PHP version, database evidence and HTTPS evidence sit beside the domains.
        self.assertIn("<dt>PHP version</dt>", section)
        self.assertIn("<dt>Database</dt>", section)
        self.assertIn("<dt>HTTPS</dt>", section)
        self.assertIn(escape(SITES_NOTE), section)
        self.assertIn("UID 1001, GID 1001, home /var/www/alpha, shell /usr/sbin/nologin", section)
        for text in SITE_ONLY[1:]:
            self.assertIn(text, section)
        # Observing a site never offers to change it.
        self.assertNotIn("<form", section)
        self.assertNotIn("<button", section)

    def test_site_detail_is_scoped_to_the_server_and_current_observation(self) -> None:
        add_site(self.remote)
        server = self.discover_as(*VIEW, SITES)
        detail = self.client.get(f"/servers/{server.pk}/sites/alpha/overview/")
        self.assertContains(detail, "alpha.test, www.alpha.test")
        self.assertContains(detail, "<code>alpha</code>")
        self.assertContains(detail, "Observed site")
        self.assertContains(detail, 'aria-label="Site sections"')
        self.assertContains(detail, 'aria-current="page">Overview</a>')
        self.assertContains(detail, "PHP version")
        # The same identifier on another registration cannot share this observation.
        other = self.register(name="Other", alias="stage.example.net")
        elsewhere = self.client.get(f"/servers/{other.pk}/sites/alpha/overview/")
        self.assertContains(elsewhere, "This site cannot be confirmed")
        self.assertNotContains(elsewhere, "alpha.test")

    def test_site_sections_link_to_the_existing_workflows_with_permission(self) -> None:
        add_site(self.remote)
        self.grant(*VIEW, SITES, "view_databaseplan", "view_tlsplan")
        server = self.register()
        self.run_worker()
        for section, title in (
            ("database", "Database"),
            ("https", "HTTPS"),
            ("activity", "Activity"),
            ("advanced", "Advanced"),
        ):
            with self.subTest(section=section):
                response = self.client.get(f"/servers/{server.pk}/sites/alpha/{section}/")
                self.assertContains(response, f'aria-current="page">{title}</a>')
        database = self.client.get(f"/servers/{server.pk}/sites/alpha/database/")
        self.assertContains(database, "Site database plans")
        self.assertContains(
            database, f"/servers/{server.pk}/setup/?from=alpha&amp;origin=database#driver-plans"
        )
        https = self.client.get(f"/servers/{server.pk}/sites/alpha/https/")
        self.assertContains(https, "HTTPS readiness")
        self.assertContains(https, "#tls-plans")
        self.assertContains(
            self.client.get(f"/servers/{server.pk}/sites/alpha/activity/"),
            f"/servers/{server.pk}/activity/",
        )

    def test_history_restores_of_site_sections_are_local_full_pages_behind_sign_in(
        self,
    ) -> None:
        add_site(self.remote)
        server = self.discover_as(*VIEW, SITES, "view_databaseplan", "view_tlsplan")
        connections = len(self.remote.targets)
        operations = RemoteOperation.objects.count()
        restore = {"HX-Request": "true", "HX-History-Restore-Request": "true"}
        sections = (
            ("overview", "Overview"),
            ("database", "Database"),
            ("https", "HTTPS"),
            ("activity", "Activity"),
            ("advanced", "Advanced"),
        )
        for section, title in sections:
            with self.subTest(section=section):
                response = self.client.get(
                    f"/servers/{server.pk}/sites/alpha/{section}/", headers=restore
                )
                self.assertContains(response, "<html")
                self.assertContains(response, 'aria-label="Site sections"')
                self.assertContains(response, f'aria-current="page">{title}</a>')
                self.assertContains(response, "alpha.test, www.alpha.test")
        # Navigation reads the cached observation; it neither connects nor queues work.
        self.assertEqual(len(self.remote.targets), connections)
        self.assertEqual(RemoteOperation.objects.count(), operations)
        # A signed-out history restore is sent to sign-in and shows nothing of the site.
        self.client.logout()
        for section, _ in sections:
            with self.subTest(signed_out=section):
                path = f"/servers/{server.pk}/sites/alpha/{section}/"
                response = self.client.get(path, headers=restore)
                self.assertEqual(response.status_code, 204)
                self.assertEqual(response.headers["HX-Redirect"], f"/accounts/login/?next={path}")
                self.assertEqual(response.content, b"")

    def test_site_pages_offer_no_deployment_editing_or_deletion_controls(self) -> None:
        add_site(self.remote)
        server = self.discover_as(
            *VIEW,
            SITES,
            "view_databaseplan",
            "prepare_databaseplan",
            "view_tlsplan",
            "prepare_tlsplan",
            "apply_tlsplan",
            "issue_certificate",
        )
        unimplemented = re.compile(r"\b(deploy|edit|delete|remove|rename|upload)\b", re.IGNORECASE)
        for section in ("overview", "database", "https", "activity", "advanced"):
            with self.subTest(section=section):
                page = self.client.get(f"/servers/{server.pk}/sites/alpha/{section}/")
                main = page.content.decode().split("<main", 1)[1]
                controls = re.findall(r"<(?:button|a)\b[^>]*>(.*?)</(?:button|a)>", main, re.DOTALL)
                labels = [" ".join(re.sub(r"<[^>]+>", " ", label).split()) for label in controls]
                self.assertTrue(labels)
                self.assertEqual([label for label in labels if unimplemented.search(label)], [])

    def test_a_nonconforming_site_s_controls_say_their_preparation_decides(self) -> None:
        add_site(self.remote)
        self.add_broken_site()
        self.grant(*VIEW, SITES, "view_databaseplan", "view_tlsplan")
        server = self.register()
        self.run_worker()
        database = f"/servers/{server.pk}/sites/beta/database/"
        https = f"/servers/{server.pk}/sites/beta/https/"
        # Without the control, the note has nothing to explain.
        for url in (database, https):
            with self.subTest(url=url):
                self.assertNotContains(self.client.get(url), "supported site convention.")
        self.grant("prepare_databaseplan", *(name.split(".")[1] for name in INSTALL))
        for url, control in (
            (database, "Preparing a database plan reads the server again and decides"),
            (https, "Enable HTTPS reads the server again before each step and decides"),
        ):
            with self.subTest(url=url):
                page = self.client.get(url)
                self.assertContains(page, "<strong>Does not match the supported site convention.")
                self.assertContains(page, control)
                self.assertContains(page, "it may refuse")
                self.assertContains(page, f'href="/servers/{server.pk}/sites/beta/overview/"')
                matching = self.client.get(url.replace("/beta/", "/alpha/"))
                self.assertNotContains(matching, "supported site convention.")
                self.assertNotContains(matching, "it may refuse")
        self.assertContains(self.client.get(database), "Prepare MariaDB database plan")
        self.assertContains(self.client.get(https), ">Enable HTTPS</button>")

    def test_unread_evidence_is_not_called_a_mismatch(self) -> None:
        add_site(self.remote)
        self.remote.unsearchable.add("/var/www/alpha")
        self.grant(*VIEW, SITES, "view_databaseplan", "prepare_databaseplan")
        server = self.register()
        self.run_worker()
        page = self.client.get(f"/servers/{server.pk}/sites/alpha/database/")
        self.assertContains(page, "Not confirmed against the supported site convention.")
        self.assertContains(page, "Some of this site's evidence could not be read")
        self.assertNotContains(page, "Does not match the supported site convention.")

    def test_a_site_absent_from_the_latest_complete_collection_is_not_found(self) -> None:
        add_site(self.remote)
        server = self.discover_as(*VIEW, SITES)
        response = self.client.get(f"/servers/{server.pk}/sites/absent1/overview/")
        self.assertContains(response, "Site not found in the latest observation")
        self.assertContains(response, "Return to Sites")
        self.assertContains(response, f"/servers/{server.pk}/sites/absent1/activity/")
        self.assertNotContains(response, 'aria-label="Site sections"')

    def test_site_detail_is_unknown_without_a_complete_observation(self) -> None:
        self.grant(*VIEW, SITES)
        self.client.force_login(self.user)
        server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        response = self.client.get(f"/servers/{server.pk}/sites/alpha/overview/")
        self.assertContains(response, "This site cannot be confirmed")
        self.assertNotContains(response, "Site not found in the latest observation")

    def test_site_detail_requires_the_observation_permission_and_rejects_bad_names(self) -> None:
        add_site(self.remote)
        server = self.discover_as(*VIEW)
        self.assertEqual(
            self.client.get(f"/servers/{server.pk}/sites/alpha/overview/").status_code, 403
        )
        self.grant(SITES)
        self.assertEqual(
            self.client.get(f"/servers/{server.pk}/sites/alpha/overview/").status_code, 200
        )
        self.assertEqual(
            self.client.get(f"/servers/{server.pk}/sites/Bad!/overview/").status_code, 404
        )
        self.assertEqual(self.client.get("/servers/999/sites/alpha/overview/").status_code, 404)

    def test_an_account_without_the_permission_cannot_read_site_observations(self) -> None:
        add_site(self.remote)
        self.add_broken_site()
        server = self.discover_as(*VIEW)
        self.assertTrue(current(server).collected.sites.value)
        page = self.client.get(f"/servers/{server.pk}/advanced/")
        fragment = self.client.get(
            f"/servers/{server.pk}/discovery/?section=advanced", headers=HTMX_FRAGMENT
        )
        activity = self.client.get("/activity/")
        for response in (page, fragment, activity):
            self.assertEqual(response.status_code, 200)
            for text in (*SITE_ONLY, "sbeta"):
                self.assertNotContains(response, text)
        # The rest of the snapshot is still shown to the account.
        self.assertContains(page, 'aria-labelledby="web-stack-heading"')

    def test_the_polling_fragment_carries_sites_for_permitted_accounts(self) -> None:
        add_site(self.remote)
        server = self.discover_as(*VIEW, SITES)
        fragment = self.client.get(
            f"/servers/{server.pk}/discovery/?section=advanced", headers=HTMX_FRAGMENT
        )
        self.assertContains(fragment, 'aria-labelledby="sites-heading"')
        self.assertContains(fragment, "Matches the supported site convention")

    def test_before_discovery_the_section_says_nothing_was_observed(self) -> None:
        self.grant(*VIEW, SITES)
        self.client.force_login(self.user)
        server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        self.assertContains(
            self.client.get(f"/servers/{server.pk}/advanced/"), "No site observations yet."
        )

    def test_refreshes_follow_external_edits_and_removal(self) -> None:
        add_site(self.remote)
        server = self.discover_as(*VIEW, SITES)
        self.assertEqual(current(server).collected.sites.value[0].state, "managed")

        # The administrator stops the pool; its socket goes away.
        self.remote.sockets.clear()
        self.client.post(f"/servers/{server.pk}/verify/")
        self.run_worker()
        (site,) = current(server).collected.sites.value
        self.assertEqual(site.state, "partly_applied")
        self.assertEqual(SiteObservation.objects.count(), 1)

        # Then removes the site's Nginx and pool configuration.
        del self.remote.links[f"{SITE_DIR}/alpha.conf"]
        del self.remote.files[f"{AVAILABLE_DIR}/alpha.conf"]
        self.remote.directories[SITE_DIR].remove("alpha.conf")
        self.remote.directories[AVAILABLE_DIR].remove("alpha.conf")
        pool = f"{PHP_DIR}/8.3/fpm/pool.d/alpha.conf"
        del self.remote.files[pool]
        self.remote.directories[f"{PHP_DIR}/8.3/fpm/pool.d"].remove("alpha.conf")
        self.client.post(f"/servers/{server.pk}/verify/")
        self.run_worker()
        self.assertEqual(current(server).collected.sites.value, ())
        self.assertFalse(SiteObservation.objects.exists())
        page = self.client.get(f"/servers/{server.pk}/advanced/")
        self.assertNotContains(page, "alpha.test")
        self.assertNotContains(page, f"/servers/{server.pk}/sites/alpha/overview/")
        # The removed site's page is absent, not a resurrected site with change controls.
        removed = self.client.get(f"/servers/{server.pk}/sites/alpha/overview/")
        self.assertContains(removed, "Site not found in the latest observation")
        self.assertNotContains(removed, 'class="usa-form')
