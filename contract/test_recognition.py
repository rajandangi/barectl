"""Which observed contract versions this controller may act on (ADR 0042, #536)."""

from django.test import SimpleTestCase

from bootstrap.standing import Standing

from .recognition import Recognition, recognize
from .version import VERSION


class RecognitionTests(SimpleTestCase):
    def test_a_contract_line_at_this_version_is_recognized(self) -> None:
        self.assertIs(recognize((VERSION,), "Target stack"), Recognition.RECOGNIZED)

    def test_a_pre_field_line_is_the_first_contract(self) -> None:
        # v0.4.0 wrote no field and is contract 1; a stored default of 0 is compatible.
        self.assertIs(recognize((0,), "Target stack"), Recognition.RECOGNIZED)

    def test_a_newer_contract_is_too_new(self) -> None:
        self.assertIs(recognize((VERSION + 1,), "Target stack"), Recognition.TOO_NEW)

    def test_an_older_positive_contract_is_too_old(self) -> None:
        self.assertIs(
            recognize((VERSION,), "Target stack", version=VERSION + 1), Recognition.TOO_OLD
        )

    def test_no_result_lines_are_not_a_shape_this_controller_cannot_act_on(self) -> None:
        self.assertIs(recognize((), "Target stack"), Recognition.RECOGNIZED)
        self.assertIs(recognize((), None), Recognition.RECOGNIZED)

    def test_a_not_manageable_host_keeps_the_existing_host_refusal(self) -> None:
        self.assertIs(
            recognize((VERSION + 1,), Standing.NOT_MANAGEABLE),
            Recognition.RECOGNIZED,
        )
