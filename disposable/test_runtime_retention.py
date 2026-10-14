"""A newer controller recognizes an installed retained FastCGI client without installing it."""

import importlib
import json
import tempfile
from pathlib import Path

from django.test import tag

from runtimes import catalog, observation

from .scenario_testing import SCENARIO_TAG, ScenarioTestCase


@tag(SCENARIO_TAG)
class RuntimeClientRetention(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = "s4retention"

    def test_known_retired_client_is_used_when_the_new_offered_path_is_absent(self) -> None:
        architecture = catalog.architecture_of(self.native("uname -m").strip())
        if architecture is None:
            self.fail("No supported native architecture.")
        current = json.loads(catalog.LOCK_PATH.read_text())
        previous = current["entries"]["fcgi"]["builds"][str(architecture)]
        installed = previous["path"]
        missing = "/nix/store/" + "0" * 32 + "-fcgi-absent-future"
        current["retired"].append(
            {
                **previous,
                "entry": "fcgi",
                "kind": "tool",
                "architecture": str(architecture),
                "nixpkgs": current["nixpkgs"],
            }
        )
        current["nixpkgs"] = "1" * 40
        current["entries"]["fcgi"]["builds"][str(architecture)] = {
            **previous,
            "path": missing,
            "version": "2.4.8",
        }
        self.native(f"test ! -e {missing}")
        profile_before = self.native("readlink /nix/var/nix/profiles/barectl/fcgi")
        original_path = catalog.LOCK_PATH
        try:
            with tempfile.TemporaryDirectory() as temporary:
                fixture = Path(temporary) / "catalog_lock.json"
                fixture.write_text(json.dumps(current))
                catalog.LOCK_PATH = fixture
                catalog.load.cache_clear()
                importlib.reload(observation)
                with self.shell() as shell:
                    value = observation.read(shell, "php84", architecture)
                self.assertIsNotNone(value)
                if value is None:
                    self.fail("Native runtime evidence unavailable.")
                rows = observation.observations(value["runtimes"], architecture)
                php = [row for row in rows if row.entry in ("php84", "php85")]
                self.assertEqual(len(php), 2)
                self.assertTrue(
                    all(row.manageable for row in php), tuple(row.problem for row in php)
                )
                self.native(f"test ! -e {missing}; test -x {installed}/bin/cgi-fcgi")
                self.assertEqual(
                    self.native("readlink /nix/var/nix/profiles/barectl/fcgi"), profile_before
                )
        finally:
            catalog.LOCK_PATH = original_path
            catalog.load.cache_clear()
            importlib.reload(observation)
