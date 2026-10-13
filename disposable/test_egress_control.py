"""The harness's egress control: an unaliased lookup must fail the item by name.

docs/quality.md#native-layer. Run by ``run-scenarios.sh -- --check-egress``, which expects
the runner to refuse this item and name the host; it never runs in the required suite.
"""

from django.test import tag

from .scenario_testing import SCENARIO_TAG, ScenarioTestCase
from .scenarios import EGRESS_PROBE


@tag(SCENARIO_TAG)
class EgressControl(ScenarioTestCase):
    layer = "L0"
    exclusive = True
    prefix = "se"
    egress_control = True

    def test_an_unaliased_lookup_is_visible_to_the_runner(self) -> None:
        # The lookup is denied by the lane's resolver; the runner must also fail this item
        # for asking a name no mirror serves.
        self.native(f"getent hosts {EGRESS_PROBE} >/dev/null 2>&1 || true")
