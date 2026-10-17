"""Fresh native transcripts preserve target-site identity and review semantics."""

from typing import ClassVar
from unittest import TestCase

from bootstrap.standing import Standing
from discovery import recorded
from discovery.models import SiteState
from discovery.observations import collect
from discovery.recorded import ReplayShell
from operations import engine
from operations.inputs import PreparationInputs, decode_inputs

from . import change, recognition


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

    def test_a_host_observed_on_another_site_refuses_a_new_identifier(self) -> None:
        shell = ReplayShell(recorded.load("http-site-26.04"))
        collect(shell)
        original = PreparationInputs("php84", "s4alpha", ("s4alpha.example.com",))
        evidence = change.inspect(shell, original)
        baseline = change.review(evidence, original)
        self.assertTrue(baseline.eligible, baseline.refusals)
        collision = PreparationInputs("php84", "another", original.names)
        refused = change.review(evidence, collision)
        self.assertFalse(refused.eligible)
        self.assertIn("A requested DNS name already belongs to another site.", refused.refusals)


class RecordedReconstructionTests(TestCase):
    """S5's checkpoint: three sites on two PHP runtimes and a server default."""

    sites: ClassVar[dict[str, str]] = {"s5alpha": "php84", "s5beta": "php84", "s5gamma": "php85"}

    def test_a_fresh_controller_recognizes_every_resource_kind(self) -> None:
        observed = collect(ReplayShell(recorded.load("reconstruction-26.04")))
        if observed.standing is None:
            self.fail("No native host standing.")
        self.assertEqual(observed.standing.standing, Standing.TARGET_STACK)
        self.assertEqual(
            dict(observed.standing.foundation),
            dict.fromkeys(("Nix", "Catalog realisation", "Caddy", "journald", "Verify"), "present"),
        )
        runtimes = {runtime.entry: runtime for runtime in observed.runtimes}
        for entry in ("php84", "php85", "nodejs_24"):
            with self.subTest(runtime=entry):
                self.assertTrue(runtimes[entry].manageable, runtimes[entry].problem)
                self.assertTrue(runtimes[entry].generation)
        for entry in ("php84", "php85"):
            with self.subTest(master=entry):
                self.assertEqual(runtimes[entry].master_state, "active")
                self.assertTrue(runtimes[entry].protections)
        if observed.runtime_defaults is None:
            self.fail("No server defaults.")
        defaults = observed.runtime_defaults
        self.assertEqual(
            (defaults.php, defaults.php_problem, defaults.node, defaults.node_problem),
            ("php85", "", "nodejs_24", ""),
        )
        sites = {site.identifier: site for site in observed.sites.value}
        self.assertEqual(
            {identifier: (site.state, site.php_version) for identifier, site in sites.items()},
            {name: (SiteState.MANAGED, runtime) for name, runtime in self.sites.items()},
        )
        for identifier, site in sites.items():
            with self.subTest(site=identifier):
                self.assertEqual(site.server_names, (identifier + ".example.com",))
        accounts = [site.account.uid for site in sites.values() if site.account is not None]
        self.assertEqual(len(set(accounts)), 3)
        self.assertEqual(
            {identifier: site.node_runtime for identifier, site in sites.items()},
            {"s5alpha": "nodejs_24", "s5beta": "", "s5gamma": ""},
        )
        self.assertEqual(
            [(row.path, row.verdict) for row in recognition.site_files(observed)],
            [(f"/etc/caddy/sites/{name}.caddy", "Recognized") for name in sorted(self.sites)],
        )
        # A pool is recognized only once its site's own master has been read and judged.
        self.assertEqual(
            [(row.path, row.verdict) for row in recognition.site_pools(observed)],
            [
                (f"/etc/php-fpm/sites/{name}/{runtime}/pools/{name}.conf", "Recognized")
                for name, runtime in sorted(self.sites.items())
            ],
        )

    def test_every_repeated_review_proposes_no_changes(self) -> None:
        shell = ReplayShell(recorded.load("reconstruction-26.04"))
        collect(shell)
        reviews: list[tuple[str, dict[str, object]]] = [
            ("host_foundation", {"version": 1}),
            ("set_default_php", {"version": 1, "selection": "php85"}),
            ("set_default_node", {"version": 1, "selection": "nodejs_24"}),
            (
                "set_site_node",
                {"version": 1, "selection": "nodejs_24", "identifier": "s5alpha"},
            ),
            *(
                (
                    "create_http_site",
                    {
                        "version": 1,
                        "selection": runtime,
                        "identifier": identifier,
                        "names": [identifier + ".example.com"],
                    },
                )
                for identifier, runtime in (("s5alpha", "php84"), ("s5gamma", "php85"))
            ),
            ("set_site_php", {"version": 1, "selection": "php84", "identifier": "s5alpha"}),
        ]
        for slug, document in reviews:
            with self.subTest(kind=slug, inputs=document):
                kind = engine.kind_of(slug)
                if kind is None:
                    self.fail("Unknown kind " + slug)
                inputs = decode_inputs(document, kind.input_choices, kind.input_shape)
                review = kind.review(kind.inspect(shell, inputs), inputs)
                self.assertTrue(review.eligible, review.refusals)
                self.assertTrue(review.no_changes, review.effects)


class RecordedJudgeByShapeTests(TestCase):
    """S9's checkpoint: adopted hand edits, a hand-made site and one scoped report."""

    def test_supported_edits_are_adopted_and_the_unsupported_one_is_scoped(self) -> None:
        from . import php_change

        shell = ReplayShell(recorded.load("judge-by-shape-26.04"))
        sites = {site.identifier: site for site in collect(shell).sites.value}
        self.assertEqual(set(sites), {"s9alpha", "s9beta", "s9gamma"})
        self.assertEqual(sites["s9alpha"].state, SiteState.MANAGED)
        self.assertEqual(sites["s9gamma"].state, SiteState.MANAGED)
        self.assertEqual(sites["s9beta"].state, SiteState.NOT_FOLLOWING)
        self.assertEqual(len(sites["s9beta"].missing), 1, sites["s9beta"].missing)
        self.assertIn("pool", sites["s9beta"].missing[0])
        adopted_inputs = PreparationInputs("php84", "s9alpha", ("s9alpha.example.com",))
        adopted = change.review(change.inspect(shell, adopted_inputs), adopted_inputs)
        self.assertTrue(adopted.no_changes, adopted.refusals)
        blocked = PreparationInputs("php85", "s9beta")
        self.assertFalse(php_change.review(php_change.inspect(shell, blocked), blocked).eligible)
        allowed = PreparationInputs("php85", "s9alpha")
        permitted = php_change.review(php_change.inspect(shell, allowed), allowed)
        self.assertTrue(permitted.eligible, permitted.refusals)
