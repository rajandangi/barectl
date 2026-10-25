"""The previous Laravel cache store a controller records before turning the cache on."""

import uuid
from datetime import timedelta
from typing import override

from django.utils import timezone

from operations.models import ChangeReview, ChangeRun, Consent, Result, Verification
from servers.models import Server
from servers.testing import ControllerConfigTestCase

from . import preimage
from .instance import SLUG

IDENTIFIER = "shop"


class PreviousStoreTests(ControllerConfigTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.server = Server.objects.create(name="Web", ssh_alias="web.example.com")

    def record_run(
        self,
        *,
        previous: str | None = "database",
        enabled: bool = True,
        verification: str = Verification.PASSED,
        status: str = Result.SUCCEEDED,
    ) -> ChangeRun:
        now = timezone.now()
        document: dict[str, object] = {
            "version": 1,
            "identifier": IDENTIFIER,
            "enabled": enabled,
            "previous_store_present": previous is not None,
            "previous_store": previous or "",
        }
        review = ChangeReview.objects.create(
            kind_slug=SLUG,
            intent="Turn on the cache.",
            eligible=True,
            consent=Consent.SITE,
            ssh_alias="web.example.com",
            boot_id="00000000-0000-0000-0000-000000000000",
            uptime_centiseconds=100,
            admission_deadline_centiseconds=90100,
            collected_at=now,
            admission_expires_at=now + timedelta(minutes=15),
            document=document,
        )
        return ChangeRun.objects.create(
            server=self.server,
            review=review,
            requested_by_name="operator",
            server_name="Web",
            unit_name="barectl-apply-" + uuid.uuid4().hex + ".service",
            status=status,
            verification=verification,
            execution=Result.SUCCEEDED,
            finished_at=now,
            ssh_alias="web.example.com",
        )

    def test_an_applied_on_review_supplies_the_previous_store(self) -> None:
        self.record_run()
        self.assertEqual(
            preimage.previous_store(self.server, IDENTIFIER),
            preimage.StorePreimage(True, True, "database"),
        )

    def test_an_absent_store_round_trips_as_known_and_absent(self) -> None:
        self.record_run(previous=None)
        self.assertEqual(
            preimage.previous_store(self.server, IDENTIFIER),
            preimage.StorePreimage(True, False, ""),
        )

    def test_no_applied_on_review_or_an_unverified_one_is_unknown(self) -> None:
        self.assertEqual(
            preimage.previous_store(self.server, IDENTIFIER),
            preimage.StorePreimage(False, True, ""),
        )
        self.record_run(verification=Verification.UNAVAILABLE)
        self.assertEqual(
            preimage.previous_store(self.server, IDENTIFIER),
            preimage.StorePreimage(False, True, ""),
        )
        self.record_run(status=Result.FAILED, verification=Verification.NOT_APPLICABLE)
        self.assertFalse(preimage.previous_store(self.server, IDENTIFIER).known)
