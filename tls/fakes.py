"""Challenge route preparation against the simulated site server (sites.fakes)."""

from django.http import HttpResponseBase

from sites.fakes import SiteTestCase

TLS_PERMISSIONS = ("view_server", "view_tlsplan", "prepare_tlsplan")
NAMES = ("shop.example.com", "www.shop.example.com")


class TlsTestCase(SiteTestCase):
    """TLS preparation through requests and the worker, against a simulated server."""

    def prepare_challenge(
        self, identifier: str = "shop", *, perms: tuple[str, ...] = TLS_PERMISSIONS
    ) -> HttpResponseBase:
        """Request a challenge route preparation as an operator with ``perms``."""
        self.sign_in_with(*perms)
        self.site.answer(self.remote)
        response = self.client.post(
            f"/servers/{self.server.pk}/tls/challenge/prepare/", {"identifier": identifier}
        )
        self.run_worker()
        return response
