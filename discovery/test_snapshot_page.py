"""How the server page renders a stored snapshot, for each kind of observation.

Snapshots are built by value and saved with ``save_snapshot``, so these tests depend only
on what a snapshot holds, not on how discovery collected it.
"""

from dataclasses import replace

from servers.models import Server
from servers.tests import ControllerConfigTestCase

from .models import DiscoveryAttempt, ObservationOutcome
from .snapshot import CollectedSnapshot, Observation, OsRelease, save_snapshot
from .test_snapshot import COLLECTED, COLLECTED_AT

OBSERVED = ObservationOutcome.OBSERVED


class SnapshotPageTests(ControllerConfigTestCase):
    def show(self, collected: CollectedSnapshot) -> str:
        """Save ``collected`` as a server's snapshot and return its rendered page."""
        server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        attempt = DiscoveryAttempt.objects.create(
            server=server,
            ssh_alias=server.ssh_alias,
            status=DiscoveryAttempt.Status.SUCCEEDED,
            finished_at=COLLECTED_AT,
        )
        save_snapshot(attempt, collected, COLLECTED_AT)
        self.grant_view()
        self.client.force_login(self.user)
        return self.client.get(f"/servers/{server.pk}/").content.decode()

    @staticmethod
    def section(page: str, heading: str) -> str:
        """The rendered section labelled by the heading with id ``heading``."""
        start = page.index(f'aria-labelledby="{heading}"')
        return page[start : page.index("</section>", start)]

    def assert_alert(self, html: str, label: str, warning: str) -> None:
        self.assertInHTML(
            f'<p class="usa-alert__text"><strong>{label}:</strong> {warning}</p>', html
        )

    def test_observed_values_and_their_sources_are_shown(self) -> None:
        page = self.show(COLLECTED)
        os = self.section(page, "os-heading")
        self.assertIn("Ubuntu 24.04.3 LTS", os)
        self.assertIn("from <code>/etc/os-release</code>", os)
        # A field the os-release file does not set is reported as such.
        self.assertIn("Not reported", os)
        capacity = self.section(page, "capacity-heading")
        self.assertIn("x86_64", capacity)
        self.assertIn("(4121137152 bytes)", capacity)
        self.assertIn("total (53689778176 bytes), 0\xa0bytes available (0 bytes)", capacity)
        self.assertIn(
            "Read with <code>uname -m</code>, <code>nproc</code>, <code>/proc/meminfo</code>, "
            "<code>df -B1 --output=size,avail,target /</code>.",
            capacity,
        )
        web_stack = self.section(page, "web-stack-heading")
        self.assertIn("postgresql 16+257build1.1<br>postgresql-16 16.15-0", web_stack)
        self.assertIn(
            "postgresql.service active (exited), enabled<br>postgresql@16-main.service",
            web_stack,
        )
        # Each distinct command once, splitting sources of several commands.
        self.assertIn(
            "Read with <code>dpkg-query</code>, <code>ls -1b /etc/postgresql</code>, "
            "<code>systemctl show postgresql.service</code>.",
            web_stack,
        )
        sites = self.section(page, "nginx-site-files-heading")
        self.assertIn("Listens on 443 ssl<br>[::]:443 ssl", sites)
        self.assertIn("Server names example.com<br>www.example.com", sites)
        self.assertIn("Read from <code>/etc/nginx/sites-enabled/example.com</code>", sites)
        pools = self.section(page, "php-fpm-pools-heading")
        self.assertInHTML("<dt><code>www</code> (PHP 8.3)</dt>", pools)
        self.assertIn("Listens on /run/php/php8.3-fpm.sock", pools)

    def test_an_observation_that_is_not_observed_is_an_alert_with_its_outcome(self) -> None:
        page = self.show(COLLECTED)
        capacity = self.section(page, "capacity-heading")
        # The value is replaced by the outcome, and the warning explains it.
        self.assertInHTML("<dd>Unsupported</dd>", capacity)
        self.assert_alert(capacity, "Unsupported", "nproc did not report the CPU count.")
        web_stack = self.section(page, "web-stack-heading")
        self.assertIn("Packages: Absent", web_stack)
        self.assertIn("Service units: Absent", web_stack)
        self.assertEqual(web_stack.count("<strong>Absent:</strong>"), 2)
        sites = self.section(page, "nginx-site-files-heading")
        self.assert_alert(sites, "Inaccessible", "The SSH user cannot read it.")

    def test_a_warning_on_an_observed_observation_is_a_note(self) -> None:
        page = self.show(COLLECTED)
        pools = self.section(page, "php-fpm-pools-heading")
        self.assertInHTML(
            '<p class="barectl-note">Pools in skipped files are not shown.</p>', pools
        )
        self.assertNotIn("usa-alert", pools)
        self.assertNotIn("<strong>Observed:</strong>", page)

    def test_an_empty_observed_collection_shows_only_its_note(self) -> None:
        empty = Observation(
            OBSERVED,
            "/etc/nginx/sites-enabled",
            "No site configuration files are listed in /etc/nginx/sites-enabled.",
            (),
        )
        page = self.show(replace(COLLECTED, nginx_site_files=empty))
        sites = self.section(page, "nginx-site-files-heading")
        self.assertNotIn('class="barectl-facts"', sites)
        self.assertInHTML(
            '<p class="barectl-note">No site configuration files are listed in '
            "/etc/nginx/sites-enabled.</p>",
            sites,
        )
        self.assertNotIn("usa-alert", sites)

    def test_the_os_name_stands_in_for_a_missing_pretty_name(self) -> None:
        release = OsRelease("", "Debian GNU/Linux", "debian", "")
        page = self.show(
            replace(COLLECTED, os=Observation(OBSERVED, "/usr/lib/os-release", "", release))
        )
        os = self.section(page, "os-heading")
        self.assertInHTML("<dd>Debian GNU/Linux</dd>", os)
        self.assertInHTML("<dd>debian</dd>", os)
        self.assertInHTML("<dd>Not reported</dd>", os)

    def test_capacity_that_was_not_observed_is_never_shown_as_zero(self) -> None:
        unsupported = ObservationOutcome.UNSUPPORTED
        page = self.show(
            replace(
                COLLECTED,
                architecture=Observation(unsupported, "uname -m", "No architecture.", None),
                memory_bytes=Observation(unsupported, "/proc/meminfo", "No memory.", None),
                filesystem=Observation(
                    ObservationOutcome.INACCESSIBLE,
                    "df -B1 --output=size,avail,target /",
                    "No filesystem.",
                    None,
                ),
            )
        )
        capacity = self.section(page, "capacity-heading")
        # The architecture, CPUs and memory are unsupported, and the filesystem inaccessible.
        self.assertInHTML("<dd>Unsupported</dd>", capacity, count=3)
        self.assertInHTML("<dd>Inaccessible</dd>", capacity, count=1)
        self.assertNotIn("<dd>0</dd>", capacity)
        self.assertNotIn("bytes", capacity)
        self.assertEqual(capacity.count("usa-alert--warning"), 4)

    def test_a_source_of_several_reads_names_each(self) -> None:
        pools = replace(
            COLLECTED.php_fpm_pools,
            source="/etc/php/8.1/fpm/pool.d\n/etc/php/8.3/fpm/php-fpm.conf",
        )
        page = self.show(replace(COLLECTED, php_fpm_pools=pools))
        self.assertIn(
            "from <code>/etc/php/8.1/fpm/pool.d</code>, <code>/etc/php/8.3/fpm/php-fpm.conf</code>",
            self.section(page, "php-fpm-pools-heading"),
        )
