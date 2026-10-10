"""Native Node runtime admission and reconstruction (docs/node-runtimes-native-design.md)."""

from django.test import SimpleTestCase

from discovery.ssh import CommandResult

from . import runtime


class ObservedShell:
    host_key = "ssh-ed25519 SHA256:fixture"

    def __init__(self, output: str, *, truncated: bool = False) -> None:
        self.output = output
        self.truncated = truncated
        self.commands: list[str] = []

    def run(self, command: str) -> CommandResult:
        self.commands.append(command)
        return CommandResult(0, self.output, self.truncated)


class ReconstructionTests(SimpleTestCase):
    def test_fresh_controller_reads_native_default_and_site_pins(self) -> None:
        shell = ObservedShell("default 24.21.0\ninstalled 24.21.0\nsite shop 22.23.3\n")
        observed = runtime.inspect(shell)
        self.assertEqual(observed.default, "24.21.0")
        self.assertEqual(observed.installed, ("24.21.0",))
        self.assertEqual(observed.sites, {"shop": "22.23.3"})
        self.assertEqual(len(shell.commands), 1)

    def test_truncation_never_becomes_empty_inventory(self) -> None:
        with self.assertRaises(runtime.Unreadable):
            runtime.inspect(ObservedShell("", truncated=True))

    def test_unknown_or_duplicate_native_output_refuses(self) -> None:
        for output in (
            "arbitrary data\n",
            "default 24.21.0\ndefault 22.23.3\n",
            "site ../etc 24.21.0\n",
        ):
            with self.subTest(output=output), self.assertRaises(runtime.Unreadable):
                runtime.inspect(ObservedShell(output))


class SupplyTests(SimpleTestCase):
    def test_current_catalog_is_exact_lts_with_fixed_official_platform_artifacts(self) -> None:
        from . import catalog

        for version in catalog.VERSIONS:
            for architecture in catalog.MISE_SHA256:
                self.assertEqual(len(catalog.SHA256[version, architecture]), 64)
                self.assertEqual(len(catalog.BINARY_SHA256[version, architecture]), 64)
                self.assertIn(
                    f"v{version}/node-v{version}-linux-",
                    catalog.configuration(version, architecture),
                )
        for version in ("latest", "lts", "24", "24.21.0; id", "26.6.0"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                catalog.executable(version)


class ReviewRenderingTests(SimpleTestCase):
    def test_server_review_renders_observed_default_and_on_demand_installation(self) -> None:
        from django.template.loader import render_to_string

        from .models import PlanNodeRuntime

        reviewed = PlanNodeRuntime(
            version="24.21.0",
            identifier="",
            default_before="22.23.3",
            pin_before="",
            executable="/native/node",
            installs_runtime=True,
        )
        rendered = render_to_string("node_runtimes/_review.html", {"site": reviewed})
        for expected in (
            "24.21.0",
            "22.23.3",
            "Server default for future sites",
            "Install the selected verified runtime",
            "/native/node",
        ):
            self.assertIn(expected, rendered)

    def test_site_review_renders_its_pin_and_verified_reuse(self) -> None:
        from django.template.loader import render_to_string

        from .models import PlanNodeRuntime

        reviewed = PlanNodeRuntime(
            version="24.21.0",
            identifier="shop",
            default_before="24.21.0",
            pin_before="22.23.3",
            executable="/native/node",
            installs_runtime=False,
        )
        rendered = render_to_string("node_runtimes/_review.html", {"site": reviewed})
        for expected in ("shop", "22.23.3", "Reuse the installed verified runtime", "/native/node"):
            self.assertIn(expected, rendered)
        self.assertNotIn("Install the selected verified runtime", rendered)
