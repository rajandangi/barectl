"""A newer controller recognizes known retired foundation tools from native evidence."""

from dataclasses import replace
from unittest.mock import patch

from django.test import tag

from bootstrap import foundation
from runtimes.catalog import Architecture, architecture_of, load

from .scenario_testing import SCENARIO_TAG, ScenarioTestCase


@tag(SCENARIO_TAG)
class RetiredFoundationRecognition(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = ""

    def test_known_retired_native_profiles_remain_complete_without_reinstallation(self) -> None:
        catalog = load()
        with self.shell() as shell:
            values = foundation.read(shell)
            self.assertIsNotNone(values)
            if values is None:
                self.fail("The native foundation could not be read.")
            architecture = architecture_of(values["architecture"])
            if architecture is None:
                self.fail("The native architecture is unsupported.")
            retired = replace(
                catalog,
                builds=tuple(
                    replace(build, retired=True)
                    if build.entry in foundation.PROFILES and build.architecture == architecture
                    else build
                    for build in catalog.builds
                )
                + tuple(
                    replace(build, path=build.path + "-next")
                    for build in catalog.offered(architecture)
                    if build.entry in foundation.PROFILES
                ),
            )
            with patch("bootstrap.foundation.load", return_value=retired):
                evidence = foundation.inspect(shell)
                self.assertTrue(evidence.complete)
                self.assertTrue(foundation.review(evidence).no_changes)
                for entry in foundation.PROFILES:
                    with self.subTest(entry=entry):
                        self.assertFalse(
                            foundation.complete(
                                {**values, entry: "/nix/store/unknown"}, architecture
                            )
                        )
                self.assertFalse(
                    foundation.complete({**values, "composer": values["wp-cli"]}, architecture)
                )
                self.assertFalse(
                    foundation.complete({**values, "caddy_version": "v0.0.0"}, architecture)
                )
                self.assertFalse(
                    foundation.complete(
                        values,
                        Architecture.AARCH64
                        if architecture == Architecture.X86_64
                        else Architecture.X86_64,
                    )
                )
            after = foundation.read(shell)
            self.assertIsNotNone(after)
            if after is not None:
                self.assertEqual(after["digest"], values["digest"])
