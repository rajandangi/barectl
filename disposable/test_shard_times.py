import io
import json
import math
import re
from pathlib import Path
from unittest.mock import patch

from django.test import SimpleTestCase

from . import scenarios, shard_times

WORKFLOW = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "native-scenarios.yml"


def hosted() -> tuple[str, int]:
    """The workflow text and the number of shards its matrix runs."""
    text = WORKFLOW.read_text(encoding="utf-8")
    matrix = re.search(r"shard: \[([\d, ]+)\]", text)
    if matrix is None:
        raise AssertionError("native-scenarios.yml declares no shard matrix")
    numbers = [int(value) for value in matrix.group(1).split(",")]
    return text, len(numbers)


class RecordTests(SimpleTestCase):
    """docs/quality.md#limits: the shards balance by recorded item times."""

    def test_every_scenario_has_a_recorded_item_time(self) -> None:
        record = shard_times.Record.load()
        labels = {item.label for item in scenarios.discover(include_quarantined=True)}
        self.assertEqual(set(record.scenarios), labels)
        self.assertTrue(all(seconds > 0 for seconds in record.scenarios.values()))

    def test_the_record_names_the_run_it_came_from(self) -> None:
        record = shard_times.Record.load()
        self.assertRegex(record.recorded, r"hosted .*run \d+ at [0-9a-f]{7}")
        self.assertTrue(all(seconds > 0 for seconds in record.stages.values()))

    def test_every_item_names_the_run_its_time_came_from(self) -> None:
        """docs/quality.md#limits: a placeholder weight is a defect, not a default."""
        record = shard_times.Record.load()
        self.assertEqual(set(record.sources), set(record.scenarios))
        measured = re.compile(
            r"hosted run \d+ at [0-9a-f]{7}|local build at [0-9a-f]{7}|"
            r"local run at [0-9a-f]{7}|local run \d{4}-\d{2}-\d{2}"
        )
        for label, source in record.sources.items():
            self.assertNotEqual(source, "placeholder", f"{label} still carries a placeholder")
            self.assertRegex(source, measured, f"{label} names no recording")

    def test_the_predicted_hosted_stop_is_inside_the_target(self) -> None:
        """The shard packing the workflow uses must fit the 300 s target, not only its limit."""
        record = shard_times.Record.load()
        _, count = hosted()
        labels = [scenario.label for scenario in scenarios.discover(include_quarantined=True)]
        predicted = record.stops(record.partition(labels, count))
        self.assertLessEqual(max(predicted), scenarios.TARGET, predicted)


class LocalRecordTests(SimpleTestCase):
    path = Path(__file__).with_name("local_times.json")

    def test_every_local_scenario_has_a_positive_finite_measured_time(self) -> None:
        record = shard_times.Record.load(self.path)
        self.assertEqual(set(record.scenarios), {item.label for item in scenarios.discover()})
        self.assertEqual(set(record.sources), set(record.scenarios))
        self.assertTrue(
            all(math.isfinite(value) and value > 0 for value in record.scenarios.values())
        )
        self.assertEqual(record.stages, {})
        for source in record.sources.values():
            self.assertRegex(source, r"^local run \d{4}-\d{2}-\d{2} capacity16$")

    def test_the_local_measurement_retains_hardware_and_input_identity(self) -> None:
        record = json.loads(self.path.read_text())
        self.assertEqual(record["lane_count"], 16)
        self.assertEqual(record["hardware"]["docker_cpus"], 14)
        for key in ("source_manifest_sha256", "summary_sha256", "log_sha256"):
            self.assertRegex(record[key], r"^[0-9a-f]{64}$")

    def test_only_unsharded_local_native_uses_the_local_record(self) -> None:
        selected = scenarios.discover(["disposable.test_l0_discovery.PlainL0Discovery"])
        for arguments in (["--lanes", "1"], ["--lanes", "1", "--shard", "1/11"]):
            options = scenarios.arguments(arguments)
            with (
                self.subTest(shard=options.shard),
                patch.object(shard_times.Record, "load", wraps=shard_times.Record.load) as load,
                patch("disposable.images.ensure", return_value="image"),
                patch("disposable.images.store"),
                patch.object(scenarios, "controller_key", return_value=Path("key")),
                patch.object(scenarios, "prepare_layers"),
                patch.object(scenarios, "execute"),
                patch.object(scenarios, "summarize"),
                patch.object(scenarios, "write_results"),
                patch.object(scenarios, "keep_logs"),
            ):
                scenarios._run(options, selected, scenarios.Output(io.StringIO()))
            if options.shard:
                load.assert_called_once_with()
            else:
                load.assert_called_once_with(self.path)


class PartitionTests(SimpleTestCase):
    def test_every_label_lands_in_exactly_one_shard(self) -> None:
        record = shard_times.Record("test", {"a": 50, "b": 40, "c": 30, "d": 20, "e": 10}, {})
        groups = record.partition(list(record.scenarios), 3)
        self.assertEqual(
            sorted(item for group in groups for item in group), ["a", "b", "c", "d", "e"]
        )
        self.assertEqual(len(groups), 3)

    def test_the_first_shard_carries_its_stages_so_it_gets_less_work(self) -> None:
        record = shard_times.Record("test", dict.fromkeys("abcdefghij", 50.0), {"validators": 100})
        groups = record.partition(list(record.scenarios), 2)
        self.assertLess(
            sum(record.weight(label) for label in groups[0]),
            sum(record.weight(label) for label in groups[1]),
        )

    def test_a_heavy_item_avoids_the_shard_that_carries_the_stages(self) -> None:
        record = shard_times.Record(
            "test", {"heavy": 200.0, "one": 50.0, "two": 50.0}, {"validators": 100}
        )
        groups = record.partition(list(record.scenarios), 2)
        self.assertIn("heavy", groups[1])

    def test_a_label_without_a_time_weighs_the_recorded_mean(self) -> None:
        record = shard_times.Record("test", {"known": 10.0}, {})
        self.assertEqual(record.weight("unknown"), 10.0)
        self.assertEqual(record.stops([["unknown"]]), [10.0 + shard_times.OVERHEAD])

    def test_the_same_selection_always_partitions_the_same_way(self) -> None:
        record = shard_times.Record(
            "test", {"a": 90.0, "b": 80.0, "c": 70.0, "d": 60.0, "e": 50.0}, {}
        )
        first = record.partition(list(record.scenarios), 2)
        second = record.partition(list(record.scenarios), 2)
        self.assertEqual(first, second)


class ShardSelectionTests(SimpleTestCase):
    def test_the_partition_uses_the_workflows_actual_lane_count(self) -> None:
        text, _ = hosted()
        lanes = re.findall(r'BARECTL_NATIVE_LANES: "(\d+)"', text)
        self.assertEqual(set(lanes), {str(shard_times.LANES)})
        self.assertEqual(len(lanes), 2)

    def test_the_shards_partition_the_discovered_scenarios(self) -> None:
        discovered = scenarios.discover()
        _, count = hosted()
        groups = [
            {item.label for item in scenarios._shard(discovered, f"{index}/{count}")}
            for index in range(1, count + 1)
        ]
        self.assertEqual(set().union(*groups), {item.label for item in discovered})
        for index, group in enumerate(groups):
            for other in groups[index + 1 :]:
                self.assertEqual(group & other, set())


class HostedBalanceTests(SimpleTestCase):
    """docs/quality.md#test-time-budget: one hosted shard stops at 300 s."""

    def test_the_matrix_runs_the_balanced_shard_count(self) -> None:
        text, count = hosted()
        self.assertEqual(re.findall(r"--shard \${{ matrix\.shard }}/(\d+)", text), [str(count)])

    def test_every_hosted_shard_is_predicted_under_the_target(self) -> None:
        _, count = hosted()
        record = shard_times.Record.load()
        labels = [item.label for item in scenarios.discover()]
        predicted = record.stops(record.partition(labels, count))
        self.assertLessEqual(max(predicted), scenarios.TARGET)
