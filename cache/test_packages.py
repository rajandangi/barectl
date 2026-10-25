"""The reviewed APT simulation's package, version and download size.

The Valkey install reuses the exact transaction parser of the database engine kind, so
this proves the one extension the cache foundation adds: APT's own size summary.
"""

from django.test import SimpleTestCase

from databases.packages import parse_simulation, parse_sizes, size_command

FRESH_INSTALL = """\
Inst valkey-server (9.0.3-0ubuntu2 Ubuntu:26.04/resolute [amd64])
Conf valkey-server (9.0.3-0ubuntu2 Ubuntu:26.04/resolute [amd64])
Inst valkey-tools (9.0.3-0ubuntu2 Ubuntu:26.04/resolute [amd64])
Conf valkey-tools (9.0.3-0ubuntu2 Ubuntu:26.04/resolute [amd64])
Need to get 2,758 kB of archives.
After this operation, 8.5 MB of additional disk space will be used.
0 upgraded, 2 newly installed, 0 to remove and 3 not upgraded.
"""


class SimulationSizeTests(SimpleTestCase):
    def test_the_review_keeps_the_download_and_disk_sizes_apt_reports(self) -> None:
        simulation = parse_simulation(FRESH_INSTALL)
        self.assertEqual(simulation.problems, ())
        self.assertEqual(
            [transition.package for transition in simulation.transitions],
            [
                "valkey-server",
                "valkey-server",
                "valkey-tools",
                "valkey-tools",
            ],
        )
        self.assertEqual(simulation.download_bytes, 2_758_000)
        self.assertEqual(simulation.installed_bytes, 8_500_000)

    def test_an_amount_with_a_cached_part_reports_the_download_that_is_needed(self) -> None:
        simulation = parse_simulation(FRESH_INSTALL.replace("2,758 kB", "0 B/2,758 kB"))
        self.assertEqual(simulation.problems, ())
        self.assertEqual(simulation.download_bytes, 0)

    def test_an_unreadable_size_line_is_a_refusal_not_an_estimate(self) -> None:
        simulation = parse_simulation(FRESH_INSTALL.replace("2,758 kB", "an unknown amount"))
        self.assertIn("size", " ".join(simulation.problems).lower())

    def test_a_simulation_without_size_lines_keeps_no_size(self) -> None:
        simulation = parse_simulation(
            "Inst valkey-server (9.0.3-0ubuntu2 Ubuntu:26.04/resolute [amd64])\n"
            "Conf valkey-server (9.0.3-0ubuntu2 Ubuntu:26.04/resolute [amd64])\n"
            "0 upgraded, 1 newly installed, 0 to remove and 3 not upgraded.\n"
        )
        self.assertEqual(simulation.problems, ())
        self.assertIsNone(simulation.download_bytes)
        self.assertIsNone(simulation.installed_bytes)

    def test_the_2604_planning_read_reports_the_transaction_size(self) -> None:
        # apt 3.2's --print-uris output, recorded on the 26.04 lane.
        text = (
            "The following NEW packages will be installed:\n"
            "  libatomic1 libjemalloc2 valkey-server valkey-tools\n"
            "0 upgraded, 4 newly installed, 0 to remove and 10 not upgraded.\n"
            "Need to get 1634 kB of archives.\n"
            "After this operation, 8604 kB of additional disk space will be used.\n"
            "'http://archive.ubuntu.com/ubuntu/pool/main/v/valkey/"
            "valkey-server_9.0.4-0ubuntu0.2_arm64.deb' "
            "valkey-server_9.0.4-0ubuntu0.2_arm64.deb 52916 "
            "MD5Sum:c04138cc13657aadc4f3055c2590375f\n"
        )
        self.assertEqual(parse_sizes(text), (1_634_000, 8_604_000, ()))

    def test_a_planning_read_without_a_size_line_is_refused(self) -> None:
        download, installed, problems = parse_sizes("0 upgraded, 0 newly installed.\n")
        self.assertIsNone(download)
        self.assertIsNone(installed)
        self.assertTrue(problems)

    def test_the_size_read_plans_without_simulating_or_fetching(self) -> None:
        command = size_command(("valkey-server",))
        self.assertIn("--print-uris", command)
        self.assertNotIn("--simulate", command)
        self.assertIn("install valkey-server", command)
