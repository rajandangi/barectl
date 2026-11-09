"""How the server page renders a stored snapshot, for each kind of observation.

Snapshots are built by value and saved with ``save_snapshot``, so these tests depend only
on what a snapshot holds, not on how discovery collected it.
"""

from dataclasses import replace

from bootstrap.standing import HostJudgment, Standing
from servers.models import Server
from servers.testing import ControllerConfigTestCase

from .fakes import COLLECTED, COLLECTED_AT
from .models import DiscoveryAttempt, ObservationOutcome
from .snapshot import CollectedSnapshot, Observation, OsRelease, save_snapshot

OBSERVED = ObservationOutcome.OBSERVED


class SnapshotPageTests(ControllerConfigTestCase):
    def show(self, collected: CollectedSnapshot, section: str = "advanced") -> str:
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
        suffix = "" if section == "overview" else f"{section}/"
        return self.client.get(f"/servers/{server.pk}/{suffix}").content.decode()

    @staticmethod
    def section(page: str, heading: str) -> str:
        """The rendered section labelled by the heading with id ``heading``."""
        start = page.index(f'aria-labelledby="{heading}"')
        return page[start : page.index("</section>", start)]

    def assert_warning(self, html: str, label: str, warning: str) -> None:
        self.assertIn(label, html)
        self.assertIn(warning, html)

    def test_observed_values_appear_once_without_source_commands(self) -> None:
        page = self.show(COLLECTED)
        os = self.section(page, "server-details-heading")
        self.assertIn("Ubuntu 26.04.1 LTS", os)
        self.assertNotIn("<code>/etc/os-release</code>", os)
        self.assertEqual(os.count("Ubuntu 26.04.1 LTS"), 1)
        self.assertNotIn("Distribution ID", os)
        capacity = self.section(page, "server-details-heading")
        self.assertIn("x86_64", capacity)
        self.assertIn("3.8\xa0GB", capacity)
        self.assertIn("0\xa0bytes available of 50.0\xa0GB", capacity)
        self.assertNotIn("4121137152", capacity)
        self.assertNotIn("53689778176", capacity)
        for source in ("uname -m", "nproc", "/proc/meminfo", "df -B1 --output=size,avail,target /"):
            self.assertNotIn(f"<code>{source}</code>", capacity)
        web_stack = self.section(page, "advanced-system-heading")
        self.assertNotIn("Nginx", web_stack)
        self.assertIn("postgresql 18+290ubuntu1<br>postgresql-18 18.6-0", web_stack)
        self.assertIn(
            "postgresql.service active (exited), enabled<br>postgresql@18-main.service not found",
            web_stack,
        )
        for source in ("dpkg-query", "ls -1b /etc/postgresql", "systemctl show postgresql.service"):
            self.assertNotIn(f"<code>{source}</code>", web_stack)

    def test_not_manageable_advanced_keeps_evidence_and_hides_change_links(self) -> None:
        standing = HostJudgment(
            Standing.NOT_MANAGEABLE,
            ("Another web stack is installed: Apache.",),
            (),
            (("Nix", "absent"), ("Catalog realisation", "absent")),
            evidence=(
                ("Architecture", "amd64"),
                ("APT series", "3.2"),
                ("Nix installation", "absent"),
            ),
        )
        page = self.show(replace(COLLECTED, standing=standing))
        self.assertIn("Barectl cannot manage this server", page)
        self.assertIn("Another web stack is installed: Apache.", page)
        self.assertInHTML('<tr><th scope="row">Nix installation</th><td>absent</td></tr>', page)
        self.assertIn("Root filesystem", page)
        self.assertIn("Installed packages", page)
        checks = self.section(page, "advanced-host-heading")
        self.assertInHTML('<tr><th scope="row">APT version</th><td>3.2</td></tr>', checks)
        self.assertNotIn("Architecture", checks)
        self.assertNotIn("Reviewed hosting Setup", page)
        self.assertNotIn("Reviewed site creation", page)

    def test_unreadable_observations_keep_their_outcome_and_explanation(self) -> None:
        unreadable_package = replace(
            COLLECTED.components[1],
            package=Observation(
                ObservationOutcome.UNSUPPORTED,
                ("dpkg-query",),
                "Packages could not be read.",
                (),
            ),
        )
        page = self.show(
            replace(COLLECTED, components=(COLLECTED.components[0], unreadable_package))
        )
        capacity = self.section(page, "server-details-heading")
        self.assertInHTML("<span>Unsupported</span>", capacity)
        self.assert_warning(capacity, "Unsupported", "nproc did not report the CPU count.")
        web_stack = self.section(page, "advanced-system-heading")
        self.assertNotIn("<strong>Absent:</strong>", web_stack)
        self.assertNotIn("usa-alert--warning", web_stack)
        self.assertIn("Nginx", web_stack)
        self.assertIn("Packages could not be read.", web_stack)
        self.assertNotIn("No distribution web-stack packages or services were found.", web_stack)

    def test_the_os_name_stands_in_for_a_missing_pretty_name(self) -> None:
        release = OsRelease("", "Debian GNU/Linux", "debian", "")
        page = self.show(
            replace(COLLECTED, os=Observation(OBSERVED, ("/usr/lib/os-release",), "", release))
        )
        os = self.section(page, "server-details-heading")
        self.assertInHTML("<td>Debian GNU/Linux</td>", os)
        self.assertNotIn("Distribution ID", os)
        self.assertNotIn('<th scope="row">Version</th>', os)

    def test_capacity_that_was_not_observed_is_never_shown_as_zero(self) -> None:
        unsupported = ObservationOutcome.UNSUPPORTED
        page = self.show(
            replace(
                COLLECTED,
                architecture=Observation(unsupported, ("uname -m",), "No architecture.", None),
                memory_bytes=Observation(unsupported, ("/proc/meminfo",), "No memory.", None),
                filesystem=Observation(
                    ObservationOutcome.INACCESSIBLE,
                    ("df -B1 --output=size,avail,target /",),
                    "No filesystem.",
                    None,
                ),
            )
        )
        capacity = self.section(page, "server-details-heading")
        # The architecture, CPUs and memory are unsupported, and the filesystem inaccessible.
        self.assertInHTML("<span>Unsupported</span>", capacity, count=3)
        self.assertInHTML("<span>Inaccessible</span>", capacity, count=1)
        self.assertNotIn("<span>0</span>", capacity)
        self.assertNotIn("bytes", capacity)
        self.assertNotIn("usa-alert--warning", capacity)
        for warning in (
            "No architecture.",
            "No memory.",
            "No filesystem.",
            "nproc did not report the CPU count.",
        ):
            self.assertIn(warning, capacity)
