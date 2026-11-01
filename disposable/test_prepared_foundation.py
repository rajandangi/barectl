"""L1 construction through the existing product changes; S1 retains its full journey."""

from django.test import tag

from bootstrap import foundation
from bootstrap.standing import Standing
from discovery.observations import collect
from operations.inputs import PreparationInputs
from runtimes import change

from .change_testing import apply_change
from .foundation_testing import assert_foundation_runtimes, commit_foundation
from .scenario_testing import SCENARIO_TAG, ScenarioTestCase


@tag(SCENARIO_TAG)
class PrepareFoundation(ScenarioTestCase):
    layer = "L0"
    exclusive = True
    prefix = ""
    preparation = True

    def test_commits_verified_foundation_and_runtimes_into_l1(self) -> None:
        self.assert_default_server_packages()
        apply_change(self, foundation.HOST_FOUNDATION, PreparationInputs(), timeout=180)
        for entry in ("php84", "php85"):
            apply_change(self, change.ADD_RUNTIME, PreparationInputs(entry), timeout=180)
        with self.shell() as shell:
            observed = collect(shell)
        if observed.standing is None:
            self.fail("No fresh foundation standing after preparation.")
        self.assertEqual(
            observed.standing.standing, Standing.TARGET_STACK, observed.standing.reasons
        )
        assert_foundation_runtimes(self, observed)
        commit_foundation(self)
