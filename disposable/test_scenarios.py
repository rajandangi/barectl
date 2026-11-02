import io
import json
import tempfile
import time
from dataclasses import replace
from pathlib import Path
from typing import override
from unittest.mock import patch

from django.test import SimpleTestCase

from . import scenarios, shard_times


def scenario(label: str, *, layer: str = "L0", exclusive: bool = False) -> scenarios.Scenario:
    return scenarios.Scenario(label, (f"{label}.test",), layer, exclusive, "s0", ())


class PlanTests(SimpleTestCase):
    def test_expired_or_nonfinite_budget_cannot_start_native_preparation(self) -> None:
        for value in ("0", "-1", "nan", "inf"):
            with (
                self.subTest(value=value),
                patch("sys.stderr", new_callable=io.StringIO),
                patch.object(scenarios, "discover") as discover,
                patch("disposable.images.ensure") as ensure,
                self.assertRaises(SystemExit) as stopped,
            ):
                scenarios.main(["--time-limit", value, "--no-lock"])
            self.assertEqual(stopped.exception.code, 2)
            discover.assert_not_called()
            ensure.assert_not_called()

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

    def test_measured_long_items_start_first_without_sharing_exclusive_servers(self) -> None:
        selected = [scenario(name, exclusive=True) for name in ("short", "long", "middle")]
        units = scenarios.plan(selected, lanes=2, weights={"short": 1, "long": 10, "middle": 5})
        self.assertEqual(
            [[item.label for item in unit.scenarios] for unit in units],
            [
                ["long"],
                ["middle"],
                ["short"],
            ],
        )


class LaneTimingTests(SimpleTestCase):
    def test_retains_successful_and_interrupted_stage_times(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lane = scenarios.Lane(
                0, "image", root / "key", root, root, scenarios.Output(io.StringIO())
            )
            lane.name = "lane-0"
            with patch("disposable.scenarios.time.monotonic", side_effect=[10.0, 12.5, 20.0, 21.0]):
                with lane.timing("lane-start"):
                    pass
                with (
                    self.assertRaisesRegex(RuntimeError, "interrupted"),
                    lane.timing("scenario", "a"),
                ):
                    raise RuntimeError("interrupted")
            lane.write_timings()
            self.assertEqual(
                json.loads((root / "logs/lane-0-timings.json").read_text()),
                [
                    {"stage": "lane-start", "scenario": "", "seconds": 2.5},
                    {"stage": "scenario", "scenario": "a", "seconds": 1.0},
                ],
            )


class LaneFormulaTests(SimpleTestCase):
    def test_capacity_stays_within_measured_lanes_and_allocated_memory(self) -> None:
        for cpus, gib, expected in (
            (14, 15.6, 16),
            (4, 15.6, 4),
            (2, 15.6, 2),
            (64, 64, 16),
            (14, 2, 4),
            (1, 0.25, 1),
        ):
            with (
                self.subTest(cpus=cpus),
                patch.dict("os.environ", {"BARECTL_NATIVE_LANES": ""}),
                patch.object(
                    scenarios,
                    "docker",
                    return_value=f"{cpus} {int(gib * 2**30)}",
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


class RecordListingTests(SimpleTestCase):
    def test_every_stored_transcript_has_a_recording_scenario(self) -> None:
        from discovery import recorded

        declared = {state for scenario in scenarios.discover() for state in scenario.records}
        self.assertEqual(set(recorded.stored()), declared)

    def test_list_records_prints_each_state_once(self) -> None:
        scenarios_list = [
            scenarios.Scenario("a", ("a.test",), "L0", False, "s0", ("one", "two")),
            scenarios.Scenario("b", ("b.test",), "L0", False, "s0", ("two",)),
        ]
        output = io.StringIO()
        with (
            patch.object(scenarios, "discover", return_value=scenarios_list),
            patch("sys.stdout", output),
        ):
            self.assertEqual(scenarios.main(["--list-records"]), 0)
        self.assertEqual(output.getvalue().splitlines(), ["one", "two"])


class DiagnosticsTests(SimpleTestCase):
    def test_a_failed_item_keeps_the_native_state(self) -> None:
        class Server:
            name = "server"

            def exec(self, command: str, *, timeout: float) -> str:
                return "ActiveState=failed\n"

        with tempfile.TemporaryDirectory() as directory:
            runner = scenarios.Runner(
                scenarios.Output(io.StringIO()),
                Path(directory),
                record="",
                keep_failed=True,
                quarantined=False,
            )
            runner._diagnose(Server(), scenario("a"))  # type: ignore[arg-type]
            text = (Path(directory) / "logs" / "server-a-diagnostics.txt").read_text()
        self.assertIn("ActiveState=failed", text)


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

    def test_ubuntus_own_release_check_is_not_an_escape(self) -> None:
        for name in (
            "changelogs.ubuntu.com",
            "contracts.canonical.com",
            "_https._tcp.motd.ubuntu.com",
        ):
            with self.subTest(name=name):
                self.assertEqual(scenarios.unaliased([name], ["cache.nixos.org"]), [])

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

    def test_teardown_stops_and_removes_a_sites_automation_before_its_accounts(self) -> None:
        script = scenarios.teardown_command("s4")
        self.assertIn("barectl-site-" + '"$prefix"*.service', script)
        self.assertIn("systemctl unmask --runtime", script)
        self.assertIn("systemctl daemon-reload", script)
        self.assertLess(script.index("systemctl unmask"), script.index("userdel"))

    def test_residue_reports_an_automation_unit_left_behind(self) -> None:
        script = scenarios.residue_command("s4")
        self.assertIn("automation:$path", script)
        self.assertIn("automation-unit:$unit", script)


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
    def test_minimal_foundation_is_preparation_only_and_starts_from_l0(self) -> None:
        label = "disposable.test_prepared_foundation.PrepareFoundation"
        self.assertEqual(scenarios.discover([label]), [])
        selected = scenarios.discover([label], preparations=True)
        self.assertEqual([candidate.layer for candidate in selected], ["L0"])
        self.assertTrue(selected[0].exclusive)
        self.assertEqual(selected[0].records, ())

    def test_wordpress_preparation_uses_l1_without_the_l2_site(self) -> None:
        label = "disposable.test_prepared_wordpress.PrepareWordPress"
        selected = scenarios.discover([label], preparations=True)
        self.assertEqual([candidate.layer for candidate in selected], ["L1"])

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

    def test_prepare_all_is_its_own_stage(self) -> None:
        self.assertTrue(scenarios.arguments(["--prepare-all"]).prepare_all)
        for argument in (
            ["--validators"],
            ["--record", "state"],
            ["--shard", "1/11"],
            ["--check-egress"],
            ["--breadth"],
            ["--quarantined"],
        ):
            with (
                self.subTest(argument=argument),
                patch("sys.stderr"),
                self.assertRaises(SystemExit) as refused,
            ):
                scenarios.arguments(["--prepare-all", *argument])
            self.assertEqual(refused.exception.code, 2)

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
        self.assertEqual(sum(len(item.tests) for item in selected), 25)
        self.assertEqual(len(units), 1)
        self.assertEqual(units[0].layer, "L1")
        self.assertEqual(units[0].scenarios, selected)

    def test_measured_validator_partition_preserves_coverage_and_balances_the_slow_lane(
        self,
    ) -> None:
        selected = scenarios.discover(validators=True)
        weights = scenarios.validator_weights(selected)
        units = scenarios.plan(selected, lanes=2, weights=weights)
        self.assertEqual(len(units), 2)
        assigned = [item.label for unit in units for item in unit.scenarios]
        self.assertCountEqual(assigned, [item.label for item in selected])
        self.assertEqual(len(assigned), len(set(assigned)))
        self.assertTrue(all(unit.layer == "L1" for unit in units))
        previous = scenarios.plan(selected, lanes=2)
        stop = max(sum(weights[item.label] for item in unit.scenarios) for unit in units)
        old_stop = max(sum(weights[item.label] for item in unit.scenarios) for unit in previous)
        self.assertLess(stop, old_stop - 18)
        self.assertLessEqual(stop, 42.0)

    def test_a_new_validator_requires_timing_instead_of_a_guessed_weight(self) -> None:
        with self.assertRaisesMessage(ValueError, "Record validator durations"):
            scenarios.validator_weights([scenario("unmeasured", layer="L1")])

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
        clock = 0.0
        limits: list[float] = []
        prepared_limits: list[float] = []
        stored: list[str] = []

        def prepare(*arguments: object, **options: object) -> None:
            nonlocal clock
            prepared_limits.append(float(arguments[4]))  # type: ignore[arg-type]
            clock += 3

        def ensure(layer: str = "L0") -> str:
            nonlocal clock
            clock += 2
            return "image"

        def store(layer: str) -> None:
            nonlocal clock
            stored.append(layer)
            clock += 1

        def execute(*arguments: object) -> None:
            nonlocal clock
            limits.append(float(arguments[5]))  # type: ignore[arg-type]
            clock += 4

        with (
            patch.object(scenarios, "discover", return_value=[scenario("one", layer="L1")]),
            patch.object(
                shard_times.Record,
                "load",
                return_value=shard_times.Record("test", {"one": 1.0}, {}),
            ),
            patch("disposable.scenarios.time.monotonic", side_effect=lambda: clock),
            patch("disposable.images.ensure", side_effect=ensure),
            patch("disposable.images.store", side_effect=store),
            patch.object(scenarios, "controller_key", return_value=Path("key")),
            patch.object(scenarios, "prepare_layers", side_effect=prepare),
            patch.object(scenarios, "execute", side_effect=execute),
            patch.object(scenarios, "summarize") as summarize,
            patch.object(scenarios, "write_results"),
            patch.object(scenarios, "keep_logs"),
        ):
            scenarios.main(["--time-limit", "20", "--lanes", "1", "--no-lock"])
        self.assertEqual(prepared_limits, [15])
        self.assertEqual(limits, [12])
        self.assertEqual(stored, ["fixture", "L1", "L2", "L3", "L4", "L5"])
        self.assertEqual(summarize.call_args.args[2], 17)

    def test_each_cold_layer_spends_the_same_preparation_limit(self) -> None:
        clock = 0.0
        limits: list[float] = []
        waves: list[list[list[tuple[str, str]]]] = []

        def prepare(*arguments: object) -> list[object]:
            nonlocal clock
            limits.append(float(arguments[4]))  # type: ignore[arg-type]
            waves.append(arguments[1])  # type: ignore[arg-type]
            clock += 3
            return []

        with (
            patch("disposable.scenarios.time.monotonic", side_effect=lambda: clock),
            patch("disposable.images.load", return_value=False),
            patch.object(scenarios, "_prepare_units", side_effect=prepare),
        ):
            scenarios.prepare_layers(
                self.runner(io.StringIO()),
                [scenario("one", layer="L5")],
                "image",
                Path("key"),
                10,
                scenarios.Output(io.StringIO()),
            )
        self.assertEqual(limits, [10, 7])
        self.assertEqual(
            [[unit[0][0] for unit in wave] for wave in waves],
            [
                ["disposable.test_prepared_foundation.PrepareFoundation"],
                ["disposable.test_prepared_laravel.PrepareLaravel"],
            ],
        )

    def test_a_cached_descendant_needs_no_ancestor_archives(self) -> None:
        with (
            patch("disposable.images.load", return_value=True) as load,
            patch.object(scenarios, "_prepare_units") as prepare,
        ):
            scenarios.prepare_layers(
                self.runner(io.StringIO()),
                [scenario("one", layer="L4")],
                "image",
                Path("key"),
                10,
                scenarios.Output(io.StringIO()),
            )
        load.assert_called_once_with("L4")
        prepare.assert_not_called()

    def test_a_cached_parent_prepares_only_the_missing_child(self) -> None:
        waves: list[list[list[tuple[str, str]]]] = []

        def prepare(*arguments: object) -> list[object]:
            waves.append(arguments[1])  # type: ignore[arg-type]
            return []

        with (
            patch("disposable.images.load", side_effect=lambda layer: layer == "L3") as load,
            patch.object(scenarios, "_prepare_units", side_effect=prepare),
        ):
            scenarios.prepare_layers(
                self.runner(io.StringIO()),
                [scenario("one", layer="L4")],
                "image",
                Path("key"),
                10,
                scenarios.Output(io.StringIO()),
            )
        self.assertEqual([call.args[0] for call in load.call_args_list], ["L4", "L3"])
        self.assertEqual(
            [[[layer for _, layer in unit] for unit in wave] for wave in waves],
            [[["L4"]]],
        )

    def test_cold_branches_prepare_every_missing_layer_once(self) -> None:
        waves: list[list[list[tuple[str, str]]]] = []

        def prepare(*arguments: object) -> list[object]:
            waves.append(arguments[1])  # type: ignore[arg-type]
            return []

        with (
            patch("disposable.images.load", return_value=False),
            patch.object(scenarios, "_prepare_units", side_effect=prepare),
        ):
            scenarios.prepare_layers(
                self.runner(io.StringIO()),
                [scenario("one", layer="L4"), scenario("two", layer="L5")],
                "image",
                Path("key"),
                10,
                scenarios.Output(io.StringIO()),
            )
        prepared = [layer for wave in waves for unit in wave for _, layer in unit]
        self.assertEqual(prepared, ["L1", "L3", "L4", "L5"])
        self.assertEqual(
            [[[layer for _, layer in unit] for unit in wave] for wave in waves],
            [[["L1"]], [["L3", "L4"], ["L5"]]],
        )

    def test_an_explicit_l2_request_still_prepares_it(self) -> None:
        waves: list[list[list[tuple[str, str]]]] = []

        def prepare(*arguments: object) -> list[object]:
            waves.append(arguments[1])  # type: ignore[arg-type]
            return []

        with (
            patch("disposable.images.load", return_value=False),
            patch.object(scenarios, "_prepare_units", side_effect=prepare),
        ):
            scenarios.prepare_layers(
                self.runner(io.StringIO()),
                [scenario("one", layer="L2"), scenario("two", layer="L4")],
                "image",
                Path("key"),
                10,
                scenarios.Output(io.StringIO()),
            )
        prepared = [layer for wave in waves for unit in wave for _, layer in unit]
        self.assertEqual(prepared, ["L1", "L3", "L4", "L2"])

    def test_sibling_descendants_share_one_wave_without_waiting_for_each_other(self) -> None:
        waves: list[list[list[tuple[str, str]]]] = []

        def prepare(*arguments: object) -> list[object]:
            waves.append(arguments[1])  # type: ignore[arg-type]
            return []

        with (
            patch("disposable.images.load", return_value=False),
            patch.object(scenarios, "_prepare_units", side_effect=prepare),
        ):
            scenarios.prepare_layers(
                self.runner(io.StringIO()),
                [],
                "image",
                Path("key"),
                10,
                scenarios.Output(io.StringIO()),
                layers=scenarios.PREPARATION_LAYERS,
                lanes=3,
            )
        self.assertEqual(
            [[[layer for _, layer in unit] for unit in wave] for wave in waves],
            [[["L1"]], [["L3", "L4"], ["L2"], ["L5"]]],
        )

    def test_preparation_waves_use_one_lane_per_unit(self) -> None:
        calls: list[int] = []

        def execute(
            runner: scenarios.Runner,
            units: list[scenarios._Unit],
            image: str,
            key: Path,
            lanes: int,
            limit: float,
            output: scenarios.Output,
        ) -> None:
            calls.append(lanes)
            for unit in units:
                for item in unit.scenarios:
                    runner.outcomes.append(
                        scenarios.Outcome(item, True, 1, 1.0, Path("result.log"), "")
                    )

        with (
            patch.object(
                scenarios,
                "discover",
                side_effect=lambda labels, **_: [scenario(labels[0], layer="L1")],
            ),
            patch.object(scenarios, "execute", side_effect=execute),
            patch("disposable.images.exists", return_value=True),
            patch("disposable.images.tag", return_value="image"),
            patch("disposable.images.store"),
        ):
            runner = self.runner(io.StringIO())
            scenarios._prepare_units(
                runner, [[("foundation", "L1")]], "image", Path("key"), 10, runner.output, 3
            )
            scenarios._prepare_units(
                runner,
                [[("wordpress", "L3"), ("cache", "L4")], [("sites", "L2")], [("laravel", "L5")]],
                "image",
                Path("key"),
                10,
                runner.output,
                3,
            )
        self.assertEqual(calls, [1, 3])


class PreparationReuseTests(SimpleTestCase):
    foundation = scenario("disposable.test_foundation.HostFoundation", exclusive=True)
    dependent = scenario("disposable.test_foundation.FoundationValidators", layer="L1")

    def runner(self) -> scenarios.Runner:
        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        return scenarios.Runner(
            scenarios.Output(io.StringIO()),
            directory,
            record="",
            keep_failed=False,
            quarantined=False,
        )

    def outcome(self, selected: scenarios.Scenario, *, passed: bool = True) -> scenarios.Outcome:
        return scenarios.Outcome(selected, passed, len(selected.tests), 1, Path("result.log"), "")

    def test_only_a_selected_complete_s1_uses_the_full_journey_for_preparation(self) -> None:
        full = scenarios.discover([self.foundation.label])[0]
        minimal = "disposable.test_prepared_foundation.PrepareFoundation"
        for selected, expected in (
            ([self.dependent], minimal),
            ([full, self.dependent], full.label),
            ([replace(full, tests=("different.test",)), self.dependent], minimal),
        ):
            runner = self.runner()
            waves: list[list[list[tuple[str, str]]]] = []

            def prepare(
                *arguments: object, captured: list[list[list[tuple[str, str]]]] = waves
            ) -> list[object]:
                captured.append(arguments[1])  # type: ignore[arg-type]
                return []

            with (
                self.subTest(selected=selected),
                patch("disposable.images.load", return_value=False),
                patch.object(scenarios, "_prepare_units", side_effect=prepare),
            ):
                scenarios.prepare_layers(runner, selected, "image", Path("key"), 10, runner.output)
            self.assertEqual(waves[0][0][0][0], expected)

    def test_only_an_exact_selected_scenario_gets_completion_credit(self) -> None:
        for selected, expected in (
            ([self.foundation, self.dependent], [self.foundation]),
            ([self.dependent], []),
            ([replace(self.foundation, tests=("another.test",)), self.dependent], []),
        ):
            with self.subTest(selected=selected):
                runner = self.runner()

                def prepare(*arguments: object, target: scenarios.Runner = runner) -> list[object]:
                    target.outcomes.append(self.outcome(self.foundation))
                    return []

                with (
                    patch("disposable.images.load", return_value=False),
                    patch.object(scenarios, "_prepare_units", side_effect=prepare),
                ):
                    scenarios.prepare_layers(
                        runner, selected, "image", Path("key"), 10, runner.output
                    )
                self.assertEqual([outcome.scenario for outcome in runner.outcomes], expected)

    def test_cold_completed_foundation_is_not_repeated_but_cached_foundation_runs(self) -> None:
        for cached in (False, True):
            executed: list[str] = []

            def prepare(runner: scenarios.Runner, *arguments: object) -> list[object]:
                outcome = self.outcome(self.foundation)
                runner.outcomes.append(outcome)
                return [outcome]

            def execute(
                runner: scenarios.Runner,
                units: list[scenarios._Unit],
                *args: object,
                labels: list[str] = executed,
            ) -> None:
                for unit in units:
                    for item in unit.scenarios:
                        labels.append(item.label)
                        runner.outcomes.append(self.outcome(item))

            with (
                self.subTest(cached=cached),
                patch("disposable.images.ensure", return_value="image"),
                patch("disposable.images.store"),
                patch("disposable.images.load", return_value=cached),
                patch.object(scenarios, "controller_key", return_value=Path("key")),
                patch.object(scenarios, "_prepare_units", side_effect=prepare),
                patch.object(scenarios, "execute", side_effect=execute),
                patch.object(scenarios, "summarize"),
                patch.object(scenarios, "write_results"),
                patch.object(scenarios, "keep_logs"),
            ):
                result = scenarios._run(
                    scenarios.arguments(["--lanes", "1"]),
                    [self.foundation, self.dependent],
                    scenarios.Output(io.StringIO()),
                )
            self.assertEqual(result, 0)
            self.assertEqual(executed.count(self.foundation.label), int(cached))
            self.assertEqual(executed.count(self.dependent.label), 1)

    def test_failed_or_missing_preparation_cannot_reuse_an_earlier_success(self) -> None:
        for produced in ([], [self.outcome(self.foundation, passed=False)]):
            runner = self.runner()
            runner.outcomes.append(self.outcome(self.dependent))

            def execute(
                *arguments: object,
                target: scenarios.Runner = runner,
                outcomes: list[scenarios.Outcome] = produced,
            ) -> None:
                target.outcomes.extend(outcomes)

            with (
                self.subTest(produced=produced),
                patch.object(scenarios, "discover", return_value=[self.foundation]),
                patch.object(scenarios, "execute", side_effect=execute),
                patch.object(scenarios, "summarize"),
                patch.object(scenarios, "write_results"),
                patch.object(scenarios, "keep_logs"),
                self.assertRaises(SystemExit),
            ):
                scenarios._prepare_units(
                    runner,
                    [[(self.foundation.label, "L1")]],
                    "image",
                    Path("key"),
                    10,
                    runner.output,
                    1,
                )

    def test_a_successful_preparation_preserves_its_actual_outcome(self) -> None:
        runner = self.runner()
        expected = self.outcome(self.foundation)

        def execute(*arguments: object) -> None:
            runner.outcomes.append(expected)

        with (
            patch.object(scenarios, "discover", return_value=[self.foundation]),
            patch.object(scenarios, "execute", side_effect=execute),
            patch("disposable.images.exists", return_value=True),
            patch("disposable.images.tag", return_value="image"),
        ):
            resulting = scenarios._prepare_units(
                runner,
                [[(self.foundation.label, "L1")]],
                "image",
                Path("key"),
                10,
                runner.output,
                1,
            )
        self.assertEqual(resulting, [expected])
        self.assertEqual(runner.outcomes, [expected])


class PrepareAllTests(SimpleTestCase):
    def test_prepare_all_prepares_every_layer_and_special_image(self) -> None:
        ensured: list[str] = []
        stored: list[str] = []
        prepared: dict[str, object] = {}

        def ensure(layer: str = "L0") -> str:
            ensured.append(layer)
            return "image"

        def store(layer: str) -> None:
            stored.append(layer)

        def prepare(*arguments: object, **options: object) -> list[object]:
            layers = options["layers"]
            if not isinstance(layers, (set, frozenset, list, tuple)):
                raise TypeError("layers must be a collection")
            prepared["layers"] = set(layers)
            prepared["lanes"] = options["lanes"]
            prepared["scenarios"] = arguments[1]
            return []

        with (
            patch("disposable.images.archived", return_value=False),
            patch("disposable.images.ensure", side_effect=ensure),
            patch("disposable.images.store", side_effect=store),
            patch("disposable.scenarios.mirror.fixture_ca"),
            patch.object(scenarios, "controller_key", return_value=Path("key")),
            patch.object(scenarios, "prepare_layers", side_effect=prepare),
            patch.object(scenarios, "write_results"),
            patch.object(scenarios, "keep_logs"),
        ):
            result = scenarios._run(
                scenarios.arguments(["--prepare-all", "--lanes", "3"]),
                [],
                scenarios.Output(io.StringIO()),
            )
        self.assertEqual(result, 0)
        self.assertEqual(prepared["layers"], set(scenarios.PREPARATION_LAYERS))
        self.assertEqual(prepared["lanes"], 3)
        self.assertEqual(prepared["scenarios"], [])
        for layer in (
            "L0",
            "fixture",
            *scenarios.PREPARATION_LAYERS,
            *scenarios.SPECIAL_LAYERS,
        ):
            self.assertIn(layer, stored)
        for layer in scenarios.SPECIAL_LAYERS:
            self.assertIn(layer, ensured)

    def test_a_fully_archived_run_loads_nothing(self) -> None:
        with (
            patch("disposable.images.archived", return_value=True),
            patch("disposable.images.ensure") as ensure,
            patch.object(scenarios, "prepare_layers") as prepare,
        ):
            result = scenarios._run(
                scenarios.arguments(["--prepare-all", "--lanes", "3"]),
                [],
                scenarios.Output(io.StringIO()),
            )
        self.assertEqual(result, 0)
        ensure.assert_not_called()
        prepare.assert_not_called()


class UnknownLabelTests(SimpleTestCase):
    """A mistyped label names itself instead of surfacing a Django loader failure."""

    def test_a_label_django_cannot_load_is_named_as_typed(self) -> None:
        failed = type("_FailedTest", (), {"__module__": "unittest.loader"})
        by_class = {failed: ["unittest.loader._FailedTest.test_backups.BackupLifecycle"]}
        self.assertEqual(scenarios._unknown_labels(by_class), ["test_backups.BackupLifecycle"])

    def test_a_good_label_is_not_reported(self) -> None:
        good = type("Scenario", (), {"__module__": "disposable.test_backups"})
        self.assertEqual(scenarios._unknown_labels({good: ["disposable.test_backups.X.test"]}), [])

    def test_the_message_names_the_label_a_suggestion_and_the_list_command(self) -> None:
        message = scenarios._unknown_message(["test_backups.BackupLifecycle"])
        self.assertIn("No scenario matches 'test_backups.BackupLifecycle'.", message)
        self.assertIn("Did you mean 'disposable.test_backups.BackupLifecycle'?", message)
        self.assertIn("-- --list", message)
