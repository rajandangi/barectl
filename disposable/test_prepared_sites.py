"""The prepared-sites snapshot layer: one site built by the product's own change.

docs/quality.md#native-layer. The L2 layer is L1 plus a site the real Create site change
made, so later scenarios start from an already-created site instead of rebuilding it. Its
key includes the site body, so changing the body rebuilds the layer; it is cached and
reused like L1.
"""

import os

from django.test import tag

from . import images
from .change_testing import apply_change
from .docker import docker
from .scenario_testing import SCENARIO_TAG, ScenarioTestCase

PREPARED_IDENTIFIER = "l2prepared"
PREPARED_DOMAIN = "l2prepared.example.com"


@tag(SCENARIO_TAG)
class PrepareSites(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = ""
    preparation = True

    def test_commits_a_product_created_site_into_the_prepared_sites_layer(self) -> None:
        from operations.inputs import PreparationInputs
        from sites import change

        inputs = PreparationInputs("php84", PREPARED_IDENTIFIER, (PREPARED_DOMAIN,))
        apply_change(self, change.CREATE_SITE, inputs)
        served = self.native(f"curl --fail --silent -H 'Host: {PREPARED_DOMAIN}' http://127.0.0.1/")
        self.assertIn(PREPARED_IDENTIFIER, served)
        image = images.tag("L2")
        if not images.exists(image):
            docker("commit", os.environ["BARECTL_SSH_TEST_CONTAINER"], image, timeout=60)
        self.assertEqual(images.ensure("L2"), image)


@tag(SCENARIO_TAG)
class PreparedSitesReuse(ScenarioTestCase):
    layer = "L2"
    exclusive = True
    prefix = "s2"

    def test_a_scenario_starts_from_the_already_created_site(self) -> None:
        served = self.native(f"curl --fail --silent -H 'Host: {PREPARED_DOMAIN}' http://127.0.0.1/")
        self.assertIn(PREPARED_IDENTIFIER, served)
        from discovery.observations import collect

        with self.shell() as shell:
            observed = collect(shell)
            identifiers = {site.identifier for site in observed.sites.value}
            self.assertIn(PREPARED_IDENTIFIER, identifiers)
