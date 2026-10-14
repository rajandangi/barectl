"""Fresh native transcripts preserve target-site identity and review semantics."""

from unittest import TestCase

from bootstrap.standing import Standing
from discovery import recorded
from discovery.models import SiteState
from discovery.observations import collect
from discovery.recorded import ReplayShell
from operations.inputs import PreparationInputs

from . import change


class RecordedHttpSiteTests(TestCase):
    def test_a_fresh_controller_recovers_the_site_and_prepares_no_changes(self) -> None:
        shell = ReplayShell(recorded.load("http-site-26.04"))
        observed = collect(shell)
        if observed.standing is None:
            self.fail("No native host standing.")
        self.assertEqual(observed.standing.standing, Standing.TARGET_STACK)
        sites = observed.sites.value
        self.assertEqual(len(sites), 1)
        site = sites[0]
        self.assertEqual(site.identifier, "s4alpha")
        self.assertEqual(site.state, SiteState.MANAGED)
        self.assertEqual(site.php_version, "php84")
        self.assertEqual(site.server_names, ("s4alpha.example.com",))
        self.assertIsNotNone(site.account)
        inputs = PreparationInputs("php84", "s4alpha", ("s4alpha.example.com",))
        review = change.review(change.inspect(shell, inputs), inputs)
        self.assertTrue(review.eligible, review.refusals)
        self.assertTrue(review.no_changes)
        self.assertEqual(review.current_sites, ("s4alpha",))
        self.assertEqual(review.effects, ())
        if site.account is None:
            self.fail("Native account was not reconstructed.")
        self.assertEqual(review.document["identity"], site.account.uid)

    def test_an_unsafe_master_does_not_hide_an_independent_healthy_site(self) -> None:
        observed = collect(ReplayShell(recorded.load("http-site-unsafe-master-26.04")))
        sites = {site.identifier: site for site in observed.sites.value}
        self.assertEqual(set(sites), {"s4matrix84", "s4matrix85"})
        self.assertEqual(sites["s4matrix84"].state, SiteState.NOT_FOLLOWING)
        self.assertEqual(sites["s4matrix85"].state, SiteState.MANAGED)
        self.assertEqual(sites["s4matrix85"].php_version, "php85")
        self.assertEqual(
            sites["s4matrix85"].server_names,
            ("s4matrix85.example.com", "www.s4matrix85.example.com"),
        )
        self.assertIsNotNone(sites["s4matrix85"].account)
