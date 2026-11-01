"""The reviewed upgrade transaction of ADR 0024."""

from django.test import SimpleTestCase

from databases.packages import (
    UpgradeAction,
    parse_simulation,
    ubuntu_origin,
    upgrade_actions_of,
    upgrade_command,
    upgrade_guard,
)

UPGRADE = """\
Inst tzdata [2026a-3ubuntu1] (2026c-0ubuntu0.26.04.1 Ubuntu:26.04/resolute-security [all])
Conf tzdata (2026c-0ubuntu0.26.04.1 Ubuntu:26.04/resolute-security [all])
Inst libssl3t64 [3.5.5-1ubuntu3] (3.5.5-1ubuntu3.7 Ubuntu:26.04/resolute-security [amd64])
Conf libssl3t64 (3.5.5-1ubuntu3.7 Ubuntu:26.04/resolute-security [amd64])
Inst openssl (3.5.5-1ubuntu3.7 Ubuntu:26.04/resolute-security [amd64])
Conf openssl (3.5.5-1ubuntu3.7 Ubuntu:26.04/resolute-security [amd64])
2 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.
"""


class UpgradeTransactionTests(SimpleTestCase):
    def test_the_review_names_each_upgrade_and_its_new_dependency(self) -> None:
        simulation = parse_simulation(UPGRADE)
        self.assertEqual(simulation.problems, ())
        actions = upgrade_actions_of(simulation.transitions, "amd64")
        self.assertEqual(
            [action.normalized() for action in actions],
            [
                (
                    "U tzdata 2026a-3ubuntu1 all 2026c-0ubuntu0.26.04.1 all "
                    "tzdata_2026c-0ubuntu0.26.04.1_all.deb"
                ),
                "C tzdata 2026c-0ubuntu0.26.04.1 all",
                (
                    "U libssl3t64 3.5.5-1ubuntu3 amd64 3.5.5-1ubuntu3.7 amd64 "
                    "libssl3t64_3.5.5-1ubuntu3.7_amd64.deb"
                ),
                "C libssl3t64 3.5.5-1ubuntu3.7 amd64",
                "U openssl - - 3.5.5-1ubuntu3.7 amd64 openssl_3.5.5-1ubuntu3.7_amd64.deb",
                "C openssl 3.5.5-1ubuntu3.7 amd64",
            ],
        )

    def test_an_upgrade_from_any_other_archive_refuses(self) -> None:
        simulation = parse_simulation(UPGRADE.replace("Ubuntu:26.04/resolute-security", "now", 1))
        with self.assertRaisesMessage(ValueError, "not the Ubuntu 26.04 archive"):
            upgrade_actions_of(simulation.transitions, "amd64")

    def test_a_removal_refuses(self) -> None:
        simulation = parse_simulation(UPGRADE + "Remv old-package [1.0]\n")
        with self.assertRaisesMessage(ValueError, "remove old-package"):
            upgrade_actions_of(simulation.transitions, "amd64")

    def test_an_origin_is_one_of_the_authenticated_release_suites(self) -> None:
        self.assertTrue(ubuntu_origin("Ubuntu:26.04/resolute"))
        self.assertTrue(ubuntu_origin("Ubuntu:26.04/resolute-security"))
        self.assertTrue(ubuntu_origin("resolute-updates/main"))
        self.assertFalse(ubuntu_origin("Ubuntu:25.10/resolute"))
        self.assertFalse(ubuntu_origin("resolute-backports/main"))
        self.assertFalse(ubuntu_origin("now"))
        self.assertFalse(ubuntu_origin("Example:resolute/main"))

    def test_the_guard_is_the_fixed_upgrade_grammar(self) -> None:
        guard = upgrade_guard(
            (
                UpgradeAction(True, "tzdata", "2026a-3ubuntu1", "2026c-0ubuntu0.26.04.1", "all"),
                UpgradeAction(False, "tzdata", "-", "2026c-0ubuntu0.26.04.1", "all"),
            )
        )
        self.assertIn("barectl_package_guard", guard)
        self.assertIn(
            "'U tzdata 2026a-3ubuntu1 all 2026c-0ubuntu0.26.04.1 all "
            "tzdata_2026c-0ubuntu0.26.04.1_all.deb'",
            guard,
        )
        self.assertIn("direction", guard)

    def test_the_simulation_requests_only_an_upgrade_at_the_candidate(self) -> None:
        command = upgrade_command((("tzdata", "2026c-0ubuntu0.26.04.1"),))
        self.assertIn("--only-upgrade", command)
        self.assertIn("--simulate", command)
        self.assertIn("tzdata=2026c-0ubuntu0.26.04.1", command)

    def test_an_empty_upgrade_refuses(self) -> None:
        with self.assertRaisesMessage(ValueError, "names no package"):
            upgrade_command(())
