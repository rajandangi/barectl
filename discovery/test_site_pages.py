"""Site observations through the request, worker and page, with their view permission.

docs/ssh-connections.md#site-observations
"""

from django.db import IntegrityError, transaction
from django.utils.html import escape

from servers.models import Server
from servers.testing import HTMX_FRAGMENT

from . import ssh
from .fakes import AVAILABLE_DIR, PHP_DIR, SITE_DIR, DiscoveryTestCase, add_site, current
from .models import SiteObservation, SiteResourceObservation
from .presentation import SITES_NOTE

VIEW = ("view_server", "add_server", "add_discoveryattempt")
SITES = "view_siteobservation"
# Text only the Sites section shows; the site files and pools sections show names and
# sockets of their own.
SITE_ONLY = ("sites-heading", "supported site convention", "/var/www/alpha", "getent passwd")


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
        page = self.client.get(f"/servers/{server.pk}/").content.decode()
        start = page.index('aria-labelledby="sites-heading"')
        section = page[start : page.index("</section>", start)]
        self.assertEqual(section.count("<details"), 2)
        self.assertEqual(section.count("<summary>"), 2)
        self.assertInHTML(
            "<summary><code>alpha</code>: Matches the supported site convention</summary>",
            section,
        )
        self.assertIn("<code>beta</code>: Does not match the supported site convention", section)
        self.assertIn(escape(SITES_NOTE), section)
        self.assertIn("The account database has no user sbeta.", section)
        self.assertIn("Observed, as the convention requires", section)
        self.assertIn("UID 1001, GID 1001, home /var/www/alpha, shell /usr/sbin/nologin", section)
        # Observing a site never offers to change it.
        self.assertNotIn("<form", section)
        self.assertNotIn("<button", section)

    def test_an_account_without_the_permission_cannot_read_site_observations(self) -> None:
        add_site(self.remote)
        self.add_broken_site()
        server = self.discover_as(*VIEW)
        self.assertTrue(current(server).collected.sites.value)
        page = self.client.get(f"/servers/{server.pk}/")
        fragment = self.client.get(f"/servers/{server.pk}/discovery/", headers=HTMX_FRAGMENT)
        activity = self.client.get("/activity/")
        for response in (page, fragment, activity):
            self.assertEqual(response.status_code, 200)
            for text in (*SITE_ONLY, "sbeta"):
                self.assertNotContains(response, text)
        # The rest of the snapshot is still shown to the account.
        self.assertContains(page, 'aria-labelledby="nginx-site-files-heading"')

    def test_the_polling_fragment_carries_sites_for_permitted_accounts(self) -> None:
        add_site(self.remote)
        server = self.discover_as(*VIEW, SITES)
        fragment = self.client.get(f"/servers/{server.pk}/discovery/", headers=HTMX_FRAGMENT)
        self.assertContains(fragment, 'aria-labelledby="sites-heading"')
        self.assertContains(fragment, "Matches the supported site convention")

    def test_before_discovery_the_section_says_nothing_was_observed(self) -> None:
        self.grant(*VIEW, SITES)
        self.client.force_login(self.user)
        server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        self.assertContains(self.client.get(f"/servers/{server.pk}/"), "No site observations yet.")

    def test_refreshes_follow_external_edits_and_removal(self) -> None:
        add_site(self.remote)
        server = self.discover_as(*VIEW, SITES)
        self.assertTrue(current(server).collected.sites.value[0].complete)

        # The administrator stops the pool; its socket goes away.
        self.remote.sockets.clear()
        self.client.post(f"/servers/{server.pk}/verify/")
        self.run_worker()
        (site,) = current(server).collected.sites.value
        self.assertFalse(site.complete)
        self.assertEqual(SiteObservation.objects.count(), 1)
        self.assertEqual(SiteResourceObservation.objects.count(), len(site.resources))

        # Then removes the site's Nginx configuration.
        del self.remote.links[f"{SITE_DIR}/alpha.conf"]
        del self.remote.files[f"{AVAILABLE_DIR}/alpha.conf"]
        self.remote.directories[SITE_DIR].remove("alpha.conf")
        self.remote.directories[AVAILABLE_DIR].remove("alpha.conf")
        self.client.post(f"/servers/{server.pk}/verify/")
        self.run_worker()
        self.assertEqual(current(server).collected.sites.value, ())
        self.assertFalse(SiteObservation.objects.exists())
        self.assertNotContains(self.client.get(f"/servers/{server.pk}/"), "<code>alpha</code>:")

    def test_the_database_refuses_a_conforming_resource_that_was_not_observed(self) -> None:
        add_site(self.remote)
        self.discover_as(*VIEW)
        resource = SiteResourceObservation.objects.first()
        if resource is None:
            self.fail("The site's resources were stored.")
        resource.status = "absent"
        with self.assertRaises(IntegrityError), transaction.atomic():
            resource.save(update_fields=["status"])
