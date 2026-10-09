"""The disposable PHP source fixture; docs/ssh-connections.md#php-source-fixture."""

from collections.abc import Callable
from unittest import TestCase
from unittest.mock import patch

from . import php_supply

TRUST = "/srv/php-source-fixture/trust"


def trust_fixture(case: TestCase, administer: Callable[[str], str]) -> None:
    """Approve the fixture's throwaway key in place of the publisher's for one test."""
    fingerprint, digest = administer(f"cat {TRUST}").split()
    case.enterContext(patch.object(php_supply, "PRIMARY_FINGERPRINT", fingerprint))
    case.enterContext(patch.object(php_supply, "KEY_SHA256", digest))
