import tempfile
from pathlib import Path
from unittest.mock import patch

from django.test import SimpleTestCase

from . import scenarios


def scenario(label: str, *, layer: str = "L0", exclusive: bool = False) -> scenarios.Scenario:
    return scenarios.Scenario(label, (f"{label}.test",), layer, exclusive, "s0", ())


class PlanTests(SimpleTestCase):
    def test_non_exclusive_scenarios_share_a_layer(self) -> None:
        units = scenarios.plan([scenario("a"), scenario("b")], lanes=1)
        self.assertEqual(len(units), 1)
        self.assertEqual([s.label for s in units[0].scenarios], ["a", "b"])

    def test_non_exclusive_scenarios_spread_over_lanes(self) -> None:
        units = scenarios.plan([scenario("a"), scenario("b")], lanes=2)
        self.assertEqual(len(units), 2)
        self.assertEqual({s.label for unit in units for s in unit.scenarios}, {"a", "b"})

    def test_layers_never_share_a_server(self) -> None:
        units = scenarios.plan([scenario("a", layer="L0"), scenario("b", layer="L1")], lanes=1)
        self.assertEqual(len(units), 2)

    def test_an_exclusive_scenario_gets_its_own_unit(self) -> None:
        units = scenarios.plan([scenario("a"), scenario("b", exclusive=True)], lanes=1)
        exclusive = [unit for unit in units if unit.scenarios[0].label == "b"]
        self.assertEqual(len(exclusive), 1)
        self.assertEqual(len(exclusive[0].scenarios), 1)


class LaneFormulaTests(SimpleTestCase):
    def test_follows_the_spike_formula(self) -> None:
        for cpus, mebibytes, expected in ((14, 15.6, 8), (4, 15.6, 2), (2, 15.6, 1)):
            with (
                self.subTest(cpus=cpus),
                patch.dict("os.environ", {"BARECTL_NATIVE_LANES": ""}),
                patch.object(
                    scenarios,
                    "docker",
                    return_value=f"{cpus} {int(mebibytes * 2**30)}",
                ),
            ):
                self.assertEqual(scenarios.default_lanes(), expected)

    def test_an_explicit_lane_count_wins(self) -> None:
        with patch.dict("os.environ", {"BARECTL_NATIVE_LANES": "3"}):
            self.assertEqual(scenarios.default_lanes(), 3)


class JudgeTests(SimpleTestCase):
    def outcome(self, log: str, returncode: int | None) -> scenarios.Outcome:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "log"
            path.write_text(log, encoding="utf-8")
            return scenarios.judge(scenario("a"), path, returncode, 5.0)

    def test_a_killed_item_reads_as_over_three_minutes(self) -> None:
        self.assertIn("over 3 minutes", self.outcome("", None).reason)

    def test_counts_the_tests_that_ran(self) -> None:
        reason = self.outcome("Ran 0 tests in 0.1s\n\nOK\n", 0).reason
        self.assertEqual(reason, "expected 1 tests, ran 0")

    def test_a_passing_item_has_no_reason(self) -> None:
        self.assertEqual(self.outcome("Ran 1 test in 0.1s\n\nOK\n", 0).reason, "")


class EgressTests(SimpleTestCase):
    def test_reports_names_no_mirror_serves(self) -> None:
        asked = ["cache.nixos.org", "example.com", "example.com", "evil.test"]
        self.assertEqual(
            scenarios.unaliased(asked, ["cache.nixos.org"]), ["evil.test", "example.com"]
        )

    def test_the_control_scenario_runs_only_for_the_control(self) -> None:
        normal = {s.label for s in scenarios.discover(["disposable.test_egress_control"])}
        self.assertEqual(normal, set())
        control = scenarios.discover(["disposable.test_egress_control"], egress_control=True)
        self.assertEqual(
            [s.label for s in control],
            ["disposable.test_egress_control.EgressControl"],
        )


class ResidueTests(SimpleTestCase):
    def test_teardown_waits_for_workers_before_deleting_an_account(self) -> None:
        script = scenarios.teardown_command("s4")
        self.assertIn("pgrep -u", script)
        self.assertLess(script.index("pgrep -u"), script.index("userdel"))
        self.assertIn('/var/www/"$prefix"', script)

    def test_residue_checks_the_prefix_and_reports_ok(self) -> None:
        script = scenarios.residue_command("s4")
        self.assertIn('grep -E "^s$prefix"', script)
        self.assertIn("caddy validate", script)
        self.assertIn("lock-held", script)


class DiscoveryTests(SimpleTestCase):
    def test_finds_the_plain_l0_discovery_scenario(self) -> None:
        found = {
            candidate.label for candidate in scenarios.discover(["disposable.test_l0_discovery"])
        }
        self.assertEqual(found, {"disposable.test_l0_discovery.PlainL0Discovery"})
        discovered = scenarios.discover(["disposable.test_l0_discovery"])[0]
        self.assertEqual(discovered.layer, "L0")
        self.assertEqual(discovered.prefix, "s0")
        self.assertIn("pristine-26.04", discovered.records)


class ArgumentsTests(SimpleTestCase):
    def test_defaults_the_build_limit_to_fifteen_minutes(self) -> None:
        self.assertEqual(scenarios.arguments([]).time_limit, 900.0)
        self.assertEqual(scenarios.ITEM_LIMIT, 180.0)

    def test_the_egress_control_passes_only_when_the_item_failed_by_name(self) -> None:
        import io
        import tempfile

        control = scenarios.Scenario(
            "egress", ("egress.test",), "L0", True, "se", (), egress_control=True
        )
        with tempfile.TemporaryDirectory() as directory:
            refused_log = Path(directory) / "refused"
            refused_log.write_text("getent: example.com not found\n", encoding="utf-8")
            allowed_log = Path(directory) / "allowed"
            allowed_log.write_text("OK\n", encoding="utf-8")
            refused = scenarios.Outcome(control, False, 1, 1.0, refused_log, "exit 1")
            named = scenarios.Outcome(control, False, 1, 1.0, refused_log, "asked for example.com")
            allowed = scenarios.Outcome(control, True, 1, 1.0, allowed_log, "")
            output = scenarios.Output(io.StringIO())
            self.assertEqual(scenarios._egress_control([refused], output), 0)
            self.assertEqual(scenarios._egress_control([named], output), 0)
            self.assertEqual(scenarios._egress_control([allowed], output), 1)
