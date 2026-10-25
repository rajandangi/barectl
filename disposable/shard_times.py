"""The recorded native item times that balance the hosted shards.

docs/quality.md#limits owns the partition rule; this module reads the record of hosted item
times and applies it.
"""

import json
import statistics
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

RECORD = Path(__file__).with_name("shard_times.json")
# The hosted workflow gives each shard two lanes: `.github/workflows/native-scenarios.yml`.
LANES = 2
# A lane's start, each item's server boot and residue check, and the scheduling tail,
# measured by the hosted runs (docs/phase-b-qualification.md#the-balanced-run).
OVERHEAD = 90.0


@dataclass(frozen=True)
class Record:
    """A hosted run's item times and the stages its first shard carries."""

    recorded: str
    scenarios: Mapping[str, float]
    stages: Mapping[str, float]

    @classmethod
    def load(cls, path: Path = RECORD) -> Record:
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(str(data["recorded"]), data["scenarios"], data["stages"])

    def weight(self, label: str) -> float:
        """A scenario's recorded time, or the record's mean for one it does not name."""
        if label in self.scenarios:
            return self.scenarios[label]
        return statistics.fmean(self.scenarios.values()) if self.scenarios else 0.0

    def fixed(self, index: int) -> float:
        return sum(self.stages.values()) if index == 0 else 0.0

    def stop(self, loads: Sequence[float], index: int) -> float:
        return max(loads, default=0.0) + self.fixed(index) + OVERHEAD

    def partition(self, labels: Sequence[str], count: int) -> list[list[str]]:
        """Split the labels into ``count`` shards whose longest predicted stop is smallest."""
        if count < 1:
            raise ValueError("a partition needs at least one shard.")
        shards: list[list[str]] = [[] for _ in range(count)]
        loads = [[0.0] * LANES for _ in range(count)]
        for label in sorted(labels, key=lambda item: (-self.weight(item), item)):
            choice, shortest = 0, None
            for index in range(count):
                trial = list(loads[index])
                trial[trial.index(min(trial))] += self.weight(label)
                stop = self.stop(trial, index)
                if shortest is None or stop < shortest:
                    choice, shortest, best = index, stop, trial
            loads[choice] = best
            shards[choice].append(label)
        return shards

    def stops(self, shards: Sequence[Sequence[str]]) -> list[float]:
        """Predict each shard's stop from its item times and the lanes it gets."""
        predicted = []
        for index, shard in enumerate(shards):
            loads = [0.0] * LANES
            for label in sorted(shard, key=lambda item: (-self.weight(item), item)):
                loads[loads.index(min(loads))] += self.weight(label)
            predicted.append(self.stop(loads, index))
        return predicted
