"""A controller refuses a direct preparation it cannot recognize (ADR 0042, #536)."""

from django.contrib.messages import get_messages

from contract.version import VERSION
from jobs.testing import change, record_jobs

from .fakes import PREPARE_PERMISSIONS, ChangeTestCase
from .models import ChangePreparation
from .preparation import REASONS, ReasonName

UNIT = "barectl-apply-" + "a" * 32 + ".service"


class ContractRefusalTests(ChangeTestCase):
    def test_a_direct_prepare_post_is_refused_outside_the_supported_contract(self) -> None:
        record_jobs(self.server, changes=(change(unit=UNIT, contract=VERSION + 1),))
        self.sign_in_with(*PREPARE_PERMISSIONS)

        response = self.client.post(
            f"/servers/{self.server.pk}/changes/prepare/",
            {"kind": "create_http_site"},
        )

        self.assertFalse(ChangePreparation.objects.exists())
        self.assertEqual(
            [str(message) for message in get_messages(response.wsgi_request)],
            [REASONS[ReasonName.OUTSIDE_CONTRACT]],
        )
