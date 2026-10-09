"""An installed WordPress site for the inspection tests (docs/wordpress.md#inspecting-wordpress).

The simulated server answers every workflow the review stands on: a complete convention site
serving WordPress over HTTPS, the WordPress runtime baseline, WP-CLI, and the application's
fixed state read and journal.
"""

from typing import override

from bootstrap.models import ConfigurationPlan, PlanPreparation
from servers.testing import HTMX_FRAGMENT
from sites.convention import Application, Stage

from .inspection_fakes import InspectionServer
from .inspection_models import Operation
from .install_testing import PREPARE, VIEW, InstallTestCase

INSPECT_VIEW = VIEW
INSPECT_PREPARE = PREPARE
RUN = (*PREPARE, "inspect_wordpress")
ADDRESS = "/servers/{pk}/sites/shop/wordpress/inspection/prepare/"
CANONICAL = "www.shop.example.com"


class InspectionTestCase(InstallTestCase):
    """The site shop serves an installed WordPress at its canonical name."""

    application: InspectionServer

    @override
    def setUp(self) -> None:
        super().setUp()
        self.site.add_activated("shop", Stage.REDIRECT, Application.WORDPRESS, CANONICAL)
        self.application = InspectionServer(canonical=CANONICAL)

    @override
    def answer_all(self) -> None:
        self.database.answer(self.remote)
        self.tls.answer(self.remote)
        self.wpcli.answer(self.remote)
        self.application.answer(self.remote)

    @override
    def assert_read_only(self) -> None:
        from bootstrap.fakes import PREPARATION_READ_ONLY
        from databases.fakes import database_read_only
        from discovery.fakes import READ_ONLY
        from sites.fakes import site_read_only

        from .fakes import wpcli_read_only

        for command in self.remote.commands:
            self.assertTrue(
                READ_ONLY.fullmatch(command)
                or PREPARATION_READ_ONLY.fullmatch(command)
                or site_read_only(command)
                or database_read_only(command)
                or wpcli_read_only(command)
                or self.application.owns(command)
                or self.tls_read(command),
                f"Not a read-only command: {command}",
            )

    def inspection_review(
        self, operation: str = Operation.INSPECT, *, perms: tuple[str, ...] = INSPECT_PREPARE
    ) -> PlanPreparation:
        self.sign_in_with(*perms)
        self.answer_all()
        response = self.client.post(
            ADDRESS.format(pk=self.server.pk),
            {"inspection-operation": operation},
            headers=HTMX_FRAGMENT,
        )
        self.assertEqual(response.status_code, 200, response.content[:300])
        self.run_worker()
        return PlanPreparation.objects.latest("queued_at", "pk")

    def inspected(self, operation: str = Operation.INSPECT) -> ConfigurationPlan:
        preparation = self.inspection_review(operation)
        plan = ConfigurationPlan.objects.filter(preparation=preparation).first()
        if plan is None:
            raise AssertionError(f"No plan: {preparation.status} {preparation.failure}")
        return plan
