"""A partly installed site for the WordPress Finish review's tests (docs/wordpress.md).

The simulated server answers every workflow the review stands on, as the installation
review's does, and in place of an empty site holds a site whose installation stopped behind
the provisioning gate. The reads' formats are the real scripts' output.
"""

from typing import override

from bootstrap.models import PlanPreparation
from servers.testing import HTMX_FRAGMENT
from sites.convention import Application

from .finish_fakes import FinishServer
from .install_testing import PREPARE, InstallTestCase

CANONICAL = "www.shop.example.com"
FORM = {
    "finish-title": "Shop & Sons",
    "finish-admin_login": "owner",
    "finish-admin_email": "owner@example.com",
}
ADDRESS = "/servers/{pk}/sites/shop/wordpress/finish/prepare/"
POLL = "/servers/{pk}/sites/shop/wordpress/finish/"


class FinishTestCase(InstallTestCase):
    """The installation review's prepared site, whose site file is the provisioning gate and
    whose installation stopped after the gate: nothing but the placeholder is published."""

    stranded: FinishServer

    @override
    def setUp(self) -> None:
        super().setUp()
        self.site.applications["shop"] = (Application.WORDPRESS_GATE, CANONICAL)
        self.stranded = FinishServer()
        self.stranded.leave("gate")
        self.state = self.stranded

    @override
    def review(
        self, form: dict[str, str] | None = None, *, perms: tuple[str, ...] = PREPARE
    ) -> PlanPreparation:
        self.sign_in_with(*perms)
        self.answer_all()
        response = self.client.post(
            ADDRESS.format(pk=self.server.pk), FORM if form is None else form, headers=HTMX_FRAGMENT
        )
        self.assertEqual(response.status_code, 200)
        self.run_worker()
        return PlanPreparation.objects.latest("queued_at", "pk")
