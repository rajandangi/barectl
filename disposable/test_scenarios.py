import io
import tempfile
import time
from pathlib import Path
from typing import override
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

    def test_a_search_suffix_on_an_alias_is_the_same_host(self) -> None:
        self.assertEqual(
            scenarios.unaliased(["cache.nixos.org.azure.internal"], ["cache.nixos.org"]),
            [],
        )

    def test_the_fixture_acme_name_is_a_lane_host(self) -> None:
        self.assertEqual(
            scenarios.unaliased(
                ["site.fixture.test.azure.internal.cloudapp.net"], ["cache.nixos.org"]
            ),
            [],
        )

    def test_a_service_discovery_name_for_an_alias_is_the_same_host(self) -> None:
        self.assertEqual(
            scenarios.unaliased(["_https._tcp.snapshot.ubuntu.com"], ["snapshot.ubuntu.com"]),
            [],
        )

    def test_a_subdomain_of_an_alias_is_still_an_escape(self) -> None:
        self.assertEqual(
            scenarios.unaliased(["evil.snapshot.ubuntu.com"], ["snapshot.ubuntu.com"]),
            ["evil.snapshot.ubuntu.com"],
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
        # The site account and its private proxy account both carry the prefix.
        self.assertIn('grep -E "^[sp]$prefix"', script)
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


class FixtureSelectionTests(SimpleTestCase):
    def test_preparation_scenarios_are_excluded_from_ordinary_discovery(self) -> None:
        label = "disposable.test_prepared_sites.PrepareSites"
        self.assertEqual(scenarios.discover([label]), [])
        selected = scenarios.discover([label], preparations=True)
        self.assertEqual([candidate.label for candidate in selected], [label])

    def test_a_prepared_sites_scenario_declares_the_l2_layer(self) -> None:
        label = "disposable.test_prepared_sites.PreparedSitesReuse"
        found = scenarios.discover([label])
        self.assertEqual([candidate.label for candidate in found], [label])
        self.assertEqual(found[0].layer, "L2")
        self.assertTrue(found[0].tests)

    def test_a_snapshot_fixture_scenario_declares_l1(self) -> None:
        label = "disposable.test_native_fixtures.NativeFixtures"
        found = scenarios.discover([label])
        self.assertEqual([candidate.label for candidate in found], [label])
        self.assertEqual(found[0].layer, "L1")
        self.assertEqual(len(found[0].tests), 4)


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


class ValidatorSelectionTests(SimpleTestCase):
    def test_snapshot_validators_are_separate_from_lifecycle_discovery(self) -> None:
        label = "disposable.test_http_site_validators.HttpSiteValidators"
        self.assertEqual(scenarios.discover([label]), [])
        selected = scenarios.discover([label], validators=True)
        self.assertEqual([item.label for item in selected], [label])
        self.assertEqual(selected[0].layer, "L1")
        self.assertTrue(selected[0].tests)

    def test_all_snapshot_validators_share_one_post_bootstrap_server(self) -> None:
        selected = scenarios.discover(validators=True)
        units = scenarios.plan(selected, lanes=1)
        self.assertEqual(sum(len(item.tests) for item in selected), 14)
        self.assertEqual(len(units), 1)
        self.assertEqual(units[0].layer, "L1")
        self.assertEqual(units[0].scenarios, selected)

    def test_validator_stage_does_not_absorb_lifecycle_or_recording_cases(self) -> None:
        self.assertEqual(
            scenarios.discover(
                ["disposable.test_http_sites.HttpSiteNativeBehavior"], validators=True
            ),
            [],
        )

    def test_validator_stage_refuses_shard_record_and_egress_modes(self) -> None:
        for argument in (("--shard", "1/2"), ("--record", "foundation-26.04"), ("--check-egress",)):
            with (
                self.subTest(argument=argument),
                patch("sys.stderr"),
                self.assertRaises(SystemExit) as refused,
            ):
                scenarios.arguments(["--validators", *argument])
            self.assertEqual(refused.exception.code, 2)


class BuildStopTests(SimpleTestCase):
    """docs/quality.md#limits: the build stops at its limit, counted from the runner's start."""

    class Stalled(scenarios.Runner):
        """A lane whose item never finishes on its own."""

        interrupted = False

        @override
        def lane(self, index: int, image: str, key: Path, units: object) -> None:
            while not scenarios.stopping.is_set():
                time.sleep(0.01)

        @override
        def interrupt(self) -> None:
            self.interrupted = True
            super().interrupt()

    def runner(self, output: object) -> BuildStopTests.Stalled:
        return self.Stalled(
            scenarios.Output(output),  # type: ignore[arg-type]
            Path(tempfile.mkdtemp()),
            record="",
            keep_failed=True,
            quarantined=False,
        )

    def test_an_item_still_running_at_the_limit_is_stopped(self) -> None:
        self.addCleanup(scenarios.stopping.clear)
        output = io.StringIO()
        runner = self.runner(output)
        unit = scenarios.plan([scenario("slow")], 1)
        started = time.monotonic()
        scenarios.execute(runner, unit, "image", Path("key"), 1, 0.3, scenarios.Output(output))
        self.assertLess(time.monotonic() - started, 5)
        self.assertTrue(runner.interrupted)
        self.assertIn("0 s reached; stopping.", output.getvalue())

    def test_foundation_preparation_spends_the_same_limit(self) -> None:
        self.addCleanup(scenarios.stopping.clear)
        limits: list[float] = []

        def prepare(*arguments: object) -> None:
            time.sleep(0.5)

        def execute(*arguments: object) -> None:
            limits.append(float(arguments[5]))  # type: ignore[arg-type]

        with (
            patch.object(scenarios, "discover", return_value=[scenario("one", layer="L1")]),
            patch("disposable.images.ensure", return_value="image"),
            patch("disposable.images.store"),
            patch.object(scenarios, "controller_key", return_value=Path("key")),
            patch.object(scenarios, "prepare_layers", side_effect=prepare),
            patch.object(scenarios, "execute", side_effect=execute),
            patch.object(scenarios, "summarize"),
            patch.object(scenarios, "write_results"),
            patch.object(scenarios, "keep_logs"),
        ):
            scenarios.main(["--time-limit", "10", "--lanes", "1"])
        self.assertEqual(len(limits), 1)
        self.assertLessEqual(limits[0], 9.5)
