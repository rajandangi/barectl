"""The fast guard on Barectl's promised native shapes (docs/contracts.md, ADR 0042).

The test compares the manifest built from the owning modules with the pinned expectation in
``manifest.json`` and with the released shape digests in ``history.json``. A changed,
removed or renamed shape fails here unless the contract version, the pinned file and a new
history entry change together in the same review.
"""

import hashlib
import json
from pathlib import Path
from typing import cast

from django.test import SimpleTestCase

from logs import journal_retention

from . import foundation
from .manifest import SECTIONS, VERSION, manifest

PINNED = Path(__file__).with_name("manifest.json")
HISTORY = Path(__file__).with_name("history.json")
HISTORY_NOTICE = (
    "Bump contract/version.py and add a contract/history.json entry for the new version "
    "with a migration/dual-read and a deprecation window."
)


def shapes_digest(built: dict[str, object]) -> str:
    """The canonical SHA-256 of a manifest's section shapes, excluding its version."""
    shapes = {name: value for name, value in built.items() if name != "version"}
    encoded = json.dumps(shapes, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def history_problems(built: dict[str, object], history: dict[str, str], version: int) -> list[str]:
    """Every way ``history`` fails to record the built shapes, each naming the fix."""
    problems: list[str] = []
    expected = [str(number) for number in range(1, version + 1)]
    keys = sorted(history, key=lambda key: int(key) if key.isdigit() else -1)
    if keys != expected:
        problems.append(
            f"contract/history.json must name exactly versions 1..{version}; found {keys}. "
            + HISTORY_NOTICE
        )
    recorded = history.get(str(version))
    digest = shapes_digest(built)
    if recorded != digest:
        problems.append(
            f"contract/history.json version {version} records {recorded!r}, but the built "
            f"shapes hash to {digest}. {HISTORY_NOTICE}"
        )
    return problems


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


class FoundationRetentionContractTests(SimpleTestCase):
    def test_the_foundation_section_pins_the_retention_drop_in(self) -> None:
        journald = foundation.build()["journald"]
        if not isinstance(journald, dict):
            self.fail("The foundation journald section is not a mapping.")
        retention = journald["retention"]
        if not isinstance(retention, dict):
            self.fail("The foundation retention section is not a mapping.")
        self.assertEqual(retention["path"], journal_retention.RETENTION_PATH)
        self.assertEqual(retention["owner"], "root")
        self.assertEqual(retention["group"], "root")
        self.assertEqual(retention["mode"], "0644")
        self.assertEqual(retention["shape"], journal_retention.SHAPE)
        self.assertEqual(retention["disk_cap_choices"], list(journal_retention.DISK_CAP_CHOICES))
        self.assertEqual(retention["max_age_choices"], list(journal_retention.MAX_AGE_CHOICES))


class JournalRetentionContractTests(SimpleTestCase):
    def test_version_two_pins_the_new_url_kind_and_reason(self) -> None:
        pinned = json.loads(PINNED.read_text(encoding="utf-8"))
        self.assertEqual(pinned["version"], 2)
        application = cast(dict[str, object], pinned["application"])
        self.assertIn("journal_retention_prepare", cast(list[str], application["url_names"]))
        results = cast(dict[str, object], pinned["results"])
        self.assertEqual(results["contract"], 2)
        reasons = cast(dict[str, object], results["reasons"])
        kinds = cast(dict[str, list[str]], reasons["kinds"])
        self.assertIn("journal_retention", kinds["set_journal_retention"])


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
        self.assertEqual(manifest()["version"], VERSION)

    def test_history_records_every_released_contract_shape(self) -> None:
        history = json.loads(HISTORY.read_text(encoding="utf-8"))
        self.assertEqual(history_problems(manifest(), history, VERSION), [])

    def test_a_changed_shape_without_a_history_entry_fails(self) -> None:
        built = manifest()
        history = json.loads(HISTORY.read_text(encoding="utf-8"))
        changed = dict(built)
        results = cast(dict[str, object], built["results"])
        changed["results"] = {**results, "prefix": "barectl-changed "}

        problems = history_problems(changed, history, VERSION)

        self.assertTrue(problems)
        message = " ".join(problems)
        self.assertIn("contract/version.py", message)
        self.assertIn("deprecation window", message)

    def test_manifest_is_a_json_serializable_mapping(self) -> None:
        built = manifest()
        self.assertEqual(json.loads(json.dumps(built)), built)
        self.assertIs(type(built["version"]), int)

    def test_section_registry_names_are_unique(self) -> None:
        names = [section.name for section in SECTIONS]
        self.assertEqual(len(names), len(set(names)))
