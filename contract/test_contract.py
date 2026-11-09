"""The fast guard on Barectl's promised native shapes (docs/contracts.md, ADR 0042).

The test compares the manifest built from the owning modules with the pinned expectation in
``manifest.json``. A changed, removed or renamed shape fails here unless the contract
version and the pinned file change together in the same review.
"""

import json
from pathlib import Path

from django.test import SimpleTestCase

from . import VERSION, manifest
from .manifest import SECTIONS

PINNED = Path(__file__).with_name("manifest.json")


def _mapping(value: object) -> dict[str, object] | None:
    if isinstance(value, dict):
        return {str(key): item for key, item in value.items()}
    return None


def _sequence(value: object) -> list[object] | None:
    if isinstance(value, list):
        return list(value)
    return None


def differences(pinned: object, actual: object, path: str = "$") -> list[str]:
    """Every place ``actual`` leaves ``pinned``, each named by its manifest path."""
    if type(pinned) is not type(actual):
        return [f"{path}: {type(pinned).__name__} -> {type(actual).__name__}"]
    pinned_map, actual_map = _mapping(pinned), _mapping(actual)
    if pinned_map is not None and actual_map is not None:
        changes = [
            f"{path}.{key}: removed" for key in sorted(pinned_map.keys() - actual_map.keys())
        ]
        changes += [f"{path}.{key}: added" for key in sorted(actual_map.keys() - pinned_map.keys())]
        changes += [
            change
            for key in sorted(pinned_map.keys() & actual_map.keys())
            for change in differences(pinned_map[key], actual_map[key], f"{path}.{key}")
        ]
        return changes
    pinned_list, actual_list = _sequence(pinned), _sequence(actual)
    if pinned_list is not None and actual_list is not None:
        changes = (
            []
            if len(pinned_list) == len(actual_list)
            else [f"{path}: {len(pinned_list)} -> {len(actual_list)} entries"]
        )
        changes += [
            change
            for index, (before, after) in enumerate(zip(pinned_list, actual_list, strict=False))
            for change in differences(before, after, f"{path}[{index}]")
        ]
        return changes
    return [] if pinned == actual else [f"{path}: {pinned!r} -> {actual!r}"]


class DifferenceTest(SimpleTestCase):
    def test_each_changed_removed_or_added_shape_is_named_by_path(self) -> None:
        self.assertEqual(
            differences({"a": {"b": 1}}, {"a": {"b": 2}}),
            ["$.a.b: 1 -> 2"],
        )
        self.assertEqual(differences({"a": 1}, {}), ["$.a: removed"])
        self.assertEqual(differences({}, {"a": 1}), ["$.a: added"])


class ManifestContractTest(SimpleTestCase):
    def test_pinned_manifest_matches_the_owning_modules(self) -> None:
        pinned = json.loads(PINNED.read_text(encoding="utf-8"))
        changes = differences(pinned, manifest())
        self.assertEqual(
            changes,
            [],
            "The native contract changed without a versioned update. Changed paths: "
            + "; ".join(changes),
        )

    def test_pinned_manifest_carries_the_contract_version(self) -> None:
        pinned = json.loads(PINNED.read_text(encoding="utf-8"))
        self.assertEqual(pinned.get("version"), VERSION)

    def test_manifest_is_a_json_serializable_mapping(self) -> None:
        built = manifest()
        self.assertEqual(json.loads(json.dumps(built)), built)
        self.assertIs(type(built["version"]), int)

    def test_section_registry_names_are_unique(self) -> None:
        names = [section.name for section in SECTIONS]
        self.assertEqual(len(names), len(set(names)))
