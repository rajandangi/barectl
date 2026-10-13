"""S0: a fresh controller discovers a plain L0 server.

docs/quality.md#native-layer. This is the first scenario on the harness and the one that
re-records the pristine transcript the fast layer replays.
"""

from django.test import tag

from discovery.models import ObservationOutcome
from discovery.observations import collect

from .scenario_testing import SCENARIO_TAG, ScenarioTestCase


@tag(SCENARIO_TAG)
class PlainL0Discovery(ScenarioTestCase):
    layer = "L0"
    exclusive = False
    prefix = "s0"
    records: tuple[str, ...] = ("pristine-26.04",)

    def test_a_fresh_controller_discovers_a_plain_l0_server(self) -> None:
        with self.shell() as shell:
            snapshot = collect(shell)
            self.checkpoint("pristine-26.04", shell)

        os_release = snapshot.os.value
        if os_release is None:
            self.fail(snapshot.os.warning or "no os-release")
        self.assertEqual(os_release.id, "ubuntu")
        self.assertEqual(os_release.version_id, "26.04")
        self.assertIn(snapshot.architecture.value, {"x86_64", "aarch64"})
        self.assertIsNotNone(snapshot.cpu_count.value)
        self.assertIsNotNone(snapshot.memory_bytes.value)
        self.assertIsNotNone(snapshot.filesystem.value)
        # A plain server has no web stack or database Barectl would manage.
        self.assertTrue(
            all(
                component.package.outcome is ObservationOutcome.ABSENT
                for component in snapshot.components
            ),
            [component.component for component in snapshot.components],
        )
