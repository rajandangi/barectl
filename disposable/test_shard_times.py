import json
import re
from pathlib import Path

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
    """docs/quality.md#native-layer: the shards balance by recorded item times."""

    def test_every_scenario_has_a_recorded_item_time(self) -> None:
        recorded, _ = shard_times.record()
        labels = {item.label for item in scenarios.discover(include_quarantined=True)}
        self.assertEqual(set(recorded), labels)
        self.assertTrue(all(seconds > 0 for seconds in recorded.values()))

    def test_the_record_names_the_run_it_came_from(self) -> None:
        data = json.loads(shard_times.RECORD.read_text(encoding="utf-8"))
        self.assertIn("hosted", data["recorded"])
        self.assertTrue(all(seconds > 0 for seconds in data["stages"].values()))


class PartitionTests(SimpleTestCase):
    def test_every_label_lands_in_exactly_one_shard(self) -> None:
        groups = shard_times.partition(
            ["a", "b", "c", "d", "e"],
            3,
            scenarios={"a": 50, "b": 40, "c": 30, "d": 20, "e": 10},
            stages={},
        )
        self.assertEqual(
            sorted(item for group in groups for item in group), ["a", "b", "c", "d", "e"]
        )
        self.assertEqual(len(groups), 3)

    def test_the_first_shard_carries_its_stages_so_it_gets_less_work(self) -> None:
        weights = dict.fromkeys("abcdefghij", 50.0)
        groups = shard_times.partition(
            list(weights), 2, scenarios=weights, stages={"validators": 100}, lanes=1, overhead=0
        )
        stops = shard_times.stops(
            groups, scenarios=weights, stages={"validators": 100}, lanes=1, overhead=0
        )
        self.assertLessEqual(stops[0], stops[1])
        self.assertLess(len(groups[0]), len(groups[1]))

    def test_a_heavy_item_avoids_the_shard_that_carries_the_stages(self) -> None:
        weights = {"heavy": 200.0, "one": 50.0, "two": 50.0}
        groups = shard_times.partition(
            list(weights), 2, scenarios=weights, stages={"validators": 100}, lanes=1, overhead=0
        )
        self.assertEqual(groups[1], ["heavy"])

    def test_a_label_without_a_time_uses_the_recorded_mean(self) -> None:
        groups = shard_times.partition(
            ["known", "unknown"], 2, scenarios={"known": 10.0}, stages={}, lanes=1, overhead=0
        )
        self.assertEqual(sorted(item for group in groups for item in group), ["known", "unknown"])

    def test_the_same_selection_always_partitions_the_same_way(self) -> None:
        weights = {"a": 90.0, "b": 80.0, "c": 70.0, "d": 60.0, "e": 50.0}
        first = shard_times.partition(list(weights), 2, scenarios=weights, stages={})
        second = shard_times.partition(list(weights), 2, scenarios=weights, stages={})
        self.assertEqual(first, second)


class ShardSelectionTests(SimpleTestCase):
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
        recorded, stages = shard_times.record()
        labels = [item.label for item in scenarios.discover()]
        groups = shard_times.partition(labels, count, scenarios=recorded, stages=stages)
        predicted = shard_times.stops(groups, scenarios=recorded, stages=stages)
        self.assertLessEqual(max(predicted), scenarios.TARGET)
