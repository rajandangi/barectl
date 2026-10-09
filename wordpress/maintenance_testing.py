"""An installed WordPress site for the maintenance tests (docs/wordpress.md#maintaining-wordpress).

The simulated server answers every workflow the review stands on, as the inspection's does.
"""

from typing import override

from bootstrap.models import ConfigurationPlan, PlanPreparation
from servers.testing import HTMX_FRAGMENT

from .inspection_testing import CANONICAL, InspectionTestCase
from .maintenance_fakes import MaintenanceServer
from .maintenance_models import Operation

MAINTAIN_VIEW = ("view_server", "view_siteobservation", "view_wordpressplan")
MAINTAIN_PREPARE = (*MAINTAIN_VIEW, "prepare_wordpressplan")
RUN = (*MAINTAIN_PREPARE, "maintain_wordpress", "view_siteapplicationobservation")
ADDRESS = "/servers/{pk}/sites/shop/wordpress/maintenance/prepare/"


class MaintenanceTestCase(InspectionTestCase):
    """The site shop serves an installed WordPress at its canonical name."""

    @override
    def setUp(self) -> None:
        super().setUp()
        self.application = MaintenanceServer(canonical=CANONICAL)

    def maintenance_review(
        self, operation: str = Operation.REWRITE, *, perms: tuple[str, ...] = MAINTAIN_PREPARE
    ) -> PlanPreparation:
        self.sign_in_with(*perms)
        self.answer_all()
        response = self.client.post(
            ADDRESS.format(pk=self.server.pk),
            {"maintenance-operation": operation},
            headers=HTMX_FRAGMENT,
        )
        self.assertEqual(response.status_code, 200, response.content[:300])
        self.run_worker()
        return PlanPreparation.objects.latest("queued_at", "pk")

    def maintained(self, operation: str = Operation.REWRITE) -> ConfigurationPlan:
        preparation = self.maintenance_review(operation)
        plan = ConfigurationPlan.objects.filter(preparation=preparation).first()
        if plan is None:
            raise AssertionError(f"No plan: {preparation.status} {preparation.failure}")
        return plan
