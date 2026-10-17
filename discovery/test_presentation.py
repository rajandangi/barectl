"""How a snapshot's observations are named and worded for the operator, without HTML."""

from dataclasses import replace

from django.test import SimpleTestCase

from .fakes import COLLECTED
from .models import ObservationOutcome, SiteState
from .presentation import Fact, present, present_sites
from .snapshot import Observation, OsRelease, ServiceUnit

OBSERVED = ObservationOutcome.OBSERVED
UNSUPPORTED = ObservationOutcome.UNSUPPORTED
INACCESSIBLE = ObservationOutcome.INACCESSIBLE


class PresentationTests(SimpleTestCase):
    def test_each_observation_and_entry_is_named_once_in_display_order(self) -> None:
        self.assertEqual(
            [shown.label for shown in present(COLLECTED).observations],
            [
                "Operating system",
                "Architecture",
                "CPUs",
                "Memory",
                "Root filesystem",
                "PostgreSQL packages",
                "PostgreSQL service units",
                "Nginx packages",
                "Nginx service units",
            ],
        )

    def test_warnings_are_the_uninspected_observations_with_their_labels(self) -> None:
        self.assertEqual(
            [(shown.label, shown.outcome, shown.warning) for shown in present(COLLECTED).warnings],
            [("CPUs", UNSUPPORTED, "nproc did not report the CPU count.")],
        )

    def test_observed_values_are_worded_for_the_page(self) -> None:
        presented = present(COLLECTED)
        self.assertEqual(
            presented.os_facts,
            (
                Fact("Operating system", "Ubuntu 26.04.1 LTS"),
                Fact("Distribution ID", "ubuntu"),
                Fact("Version", "Not reported"),
            ),
        )
        self.assertEqual(
            [shown.lines for shown in presented.capacity],
            [
                ("x86_64",),
                ("Unsupported",),
                ("3.8\xa0GB (4121137152 bytes)",),
                ("50.0\xa0GB total (53689778176 bytes), 0\xa0bytes available (0 bytes)",),
            ],
        )
        postgresql, nginx = presented.components
        self.assertEqual(
            postgresql.package.lines, ("postgresql 18+290ubuntu1", "postgresql-18 18.6-0")
        )
        self.assertEqual(nginx.package.lines, ("Packages: Absent",))
        self.assertEqual(nginx.service.lines, ("Service units: Absent",))

    def test_packages_outside_the_profile_are_shown_and_flagged(self) -> None:
        deviation = "postgresql-17 17.2 is installed but does not follow the profile."
        outside = replace(COLLECTED.components[0], managed=False, deviations=(deviation,))
        (shown,) = present(replace(COLLECTED, components=(outside,))).components
        self.assertFalse(shown.managed)
        self.assertEqual(shown.deviations, (deviation,))
        self.assertIn(deviation, shown.package.lines)

    def test_a_unit_systemd_did_not_find_is_worded_as_not_found(self) -> None:
        (postgresql, _) = present(COLLECTED).components
        self.assertEqual(
            postgresql.service.lines,
            (
                "postgresql.service active (exited), enabled",
                "postgresql@18-main.service not found",
            ),
        )

    def test_units_of_a_partial_service_observation_are_kept_beside_its_outcome(self) -> None:
        component = COLLECTED.components[0]
        unit = ServiceUnit("postgresql.service", "loaded", "inactive", "dead", "")
        partial = replace(
            component,
            service=Observation(UNSUPPORTED, ("systemctl show",), "Unit format.", (unit,)),
        )
        (shown,) = present(replace(COLLECTED, components=(partial,))).components
        self.assertEqual(shown.service.lines, ("postgresql.service inactive (dead)",))
        self.assertFalse(shown.service.observed)

    def test_the_os_name_stands_in_for_a_missing_pretty_name(self) -> None:
        release = OsRelease("", "Debian GNU/Linux", "debian", "12")
        os = Observation(OBSERVED, ("/usr/lib/os-release",), "", release)
        presented = present(replace(COLLECTED, os=os))
        self.assertEqual(presented.os.lines, ("Debian GNU/Linux",))
        self.assertEqual(presented.os_facts[0], Fact("Operating system", "Debian GNU/Linux"))

    def test_an_os_that_was_not_observed_has_no_facts(self) -> None:
        os = Observation(INACCESSIBLE, ("/etc/os-release",), "Cannot read it.", None)
        presented = present(replace(COLLECTED, os=os))
        self.assertEqual(presented.os_facts, ())
        self.assertEqual(presented.os.lines, ("Inaccessible",))

    def test_sources_are_listed_once_each_in_order(self) -> None:
        presented = present(COLLECTED)
        self.assertEqual(
            presented.capacity_sources,
            ["uname -m", "nproc", "/proc/meminfo", "df -B1 --output=size,avail,target /"],
        )
        self.assertEqual(
            presented.component_sources,
            ["dpkg-query", "ls -1b /etc/postgresql", "systemctl show postgresql.service"],
        )


class SitePresentationTests(SimpleTestCase):
    def test_site_observations_are_never_among_the_snapshot_warnings(self) -> None:
        labels = [shown.label for shown in present(COLLECTED).observations]
        self.assertFalse([label for label in labels if "Site" in label or "socket" in label])

    def test_each_site_is_summarized_by_its_one_state(self) -> None:
        alpha, beta = present_sites(COLLECTED.sites).sites
        self.assertEqual((alpha.state, alpha.verdict), (SiteState.MANAGED, "Managed"))
        self.assertEqual(alpha.summary, "Matches the supported site convention.")
        self.assertEqual(beta.state, SiteState.NOT_FOLLOWING)
        self.assertEqual(beta.verdict, "Not following the convention")
        self.assertIn("Caddy route", beta.summary)
        self.assertIn(
            "not a check that the site serves requests", present_sites(COLLECTED.sites).note
        )

    def test_a_site_names_its_file_and_account(self) -> None:
        alpha, beta = present_sites(COLLECTED.sites).sites
        self.assertIn(Fact("File", "/etc/caddy/sites/beta.caddy"), beta.facts)
        self.assertIn(
            Fact("Site user", "UID 1001, GID 1001, home /var/www/alpha, shell /usr/sbin/nologin"),
            alpha.facts,
        )
