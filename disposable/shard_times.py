"""Recorded native item times, and the measured balance of the hosted shards.

docs/quality.md#native-layer: the hosted matrix balances its shards by these recorded
item times instead of by scenario count, and gives the first shard the recorded stages
the workflow runs there. Refreshing the record is described in
docs/quality.md#the-required-check.
"""

import json
import statistics
from collections.abc import Mapping, Sequence
from pathlib import Path

RECORD = Path(__file__).with_name("shard_times.json")
LANES = 2
# A lane's start, each item's server boot and residue check, and the scheduling tail,
# as measured by the hosted runs (docs/phase-b-qualification.md#hosted-runs).
OVERHEAD = 90.0


def record(path: Path = RECORD) -> tuple[dict[str, float], dict[str, float]]:
    """Return the recorded item times and the stages the first shard carries."""
    data = json.loads(path.read_text(encoding="utf-8"))
    return data["scenarios"], data["stages"]


def partition(
    labels: Sequence[str],
    count: int,
    *,
    scenarios: Mapping[str, float],
    stages: Mapping[str, float],
    lanes: int = LANES,
    overhead: float = OVERHEAD,
) -> list[list[str]]:
    """Split the labels into ``count`` shards whose longest predicted stop is smallest.

    Each item goes to the shard where it leaves the shortest predicted stop, on that
    shard's least loaded lane. The first shard starts with the recorded stages, so it
    receives less lifecycle work.
    """
    if count < 1:
        raise ValueError("a partition needs at least one shard.")
    unknown = statistics.fmean(scenarios.values()) if scenarios else 0.0
    shards: list[list[str]] = [[] for _ in range(count)]
    loads = [[0.0] * lanes for _ in range(count)]
    fixed = [sum(stages.values()) if index == 0 else 0.0 for index in range(count)]
    for label in sorted(labels, key=lambda item: (-scenarios.get(item, unknown), item)):
        weight = scenarios.get(label, unknown)
        choice, shortest = 0, None
        for index in range(count):
            trial = list(loads[index])
            trial[trial.index(min(trial))] += weight
            stop = max(trial) + fixed[index] + overhead
            if shortest is None or stop < shortest:
                choice, shortest, best = index, stop, trial
        loads[choice] = best
        shards[choice].append(label)
    return shards


def stops(
    shards: Sequence[Sequence[str]],
    *,
    scenarios: Mapping[str, float],
    stages: Mapping[str, float],
    lanes: int = LANES,
    overhead: float = OVERHEAD,
) -> list[float]:
    """Predict each shard's stop from its item times and the lanes the workflow gives it."""
    predicted = []
    for index, shard in enumerate(shards):
        loads = [0.0] * lanes
        for label in sorted(shard, key=lambda item: (-scenarios.get(item, 0.0), item)):
            loads[loads.index(min(loads))] += scenarios.get(label, 0.0)
        fixed = sum(stages.values()) if index == 0 else 0.0
        predicted.append(max(loads, default=0.0) + fixed + overhead)
    return predicted
