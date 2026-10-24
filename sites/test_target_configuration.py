"""Target convention contracts at the renderer and native parser boundary."""

from django.test import SimpleTestCase

from operations.engine import _failure
from operations.models import Result

from .configuration import (
    SiteSettings,
    render_caddy,
    render_laravel_caddy,
    render_pool,
    render_wordpress_caddy,
)
from .names import readiness_ok, readiness_path


class TargetConfigurationTests(SimpleTestCase):
    def test_target_site_accepts_a_full_dns_name_and_routes_through_private_admission(
        self,
    ) -> None:
        hostname = ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 61))
        settings = SiteSettings("shop", (hostname,), "php84")
        caddy = render_caddy(settings)
        pool = render_pool(settings)
        self.assertIn(hostname + " {", caddy)
        self.assertNotIn("http://" + hostname, caddy)
        self.assertIn("reverse_proxy @php unix//run/haproxy/shop/http.sock", caddy)
        self.assertNotIn("/run/php-fpm", caddy)
        self.assertIn("user = sshop\n", pool)
        self.assertIn("listen = /run/php-fpm/sites/shop/php84/app.sock\n", pool)
        self.assertIn("listen.owner = root\n", pool)
        self.assertIn("listen.group = pshop\n", pool)
        self.assertIn("listen.mode = 0660\n", pool)

    def test_a_laravel_site_reaches_its_front_controller_and_denies_private_paths(self) -> None:
        settings = SiteSettings("shop", ("shop.example.com",), "php84")
        caddy = render_laravel_caddy(settings)
        # Every path that is not a file reaches index.php, with the original URI kept for
        # Laravel's router (Phase B #445).
        self.assertIn(
            "        try_files {path}index.php {path}/index.php {path} /index.php?{query}\n",
            caddy,
        )
        self.assertIn("        vars original_uri {http.request.uri}\n", caddy)
        self.assertIn("            header_up X-Forwarded-Uri {vars.original_uri}\n", caddy)
        self.assertIn("        respond @private 404\n", caddy)
        for denied in ("/storage/*", "/vendor/*", "/bootstrap/cache/*"):
            self.assertIn(denied, caddy)
        self.assertIn("@config path_regexp config", caddy)
        # The plain and WordPress forms keep their own routes.
        self.assertNotIn(
            "try_files {path}index.php {path}/index.php {path} /index.php?{query}",
            render_caddy(settings),
        )
        self.assertIn("try_files {path}index.php", render_wordpress_caddy(settings))
        # A single-name file keeps the form written before domains could change, so it
        # remains recognized after an upgrade.
        self.assertNotIn("@alias", render_wordpress_caddy(settings))
        self.assertNotIn("@alias", render_laravel_caddy(settings))
        multi = SiteSettings("shop", ("shop.example.com", "www.example.com"), "php84")
        self.assertIn("@alias expression", render_wordpress_caddy(multi))
        self.assertIn("@alias expression", render_laravel_caddy(multi))

        settings = SiteSettings("shop", ("shop.example.com", "www.example.com"), "php84", False)
        caddy = render_caddy(settings)
        self.assertIn("http://shop.example.com, http://www.example.com {", caddy)

    def test_a_non_default_readiness_path_is_native_caddy_evidence(self) -> None:
        default = render_caddy(SiteSettings("shop", ("shop.example.com",), "php84"))
        self.assertNotIn("readiness_path", default)
        settings = SiteSettings(
            "shop",
            ("shop.example.com",),
            "php84",
            readiness="/health/ready",
        )
        self.assertIn('    vars readiness_path "/health/ready"\n', render_caddy(settings))

    def test_readiness_paths_refuse_urls_traversal_and_server_errors(self) -> None:
        for accepted in ("/", "/health", "/health/ready_2", "/a.b~c"):
            with self.subTest(path=accepted):
                self.assertEqual(readiness_path(accepted), (accepted, ""))
        for refused in ("health", "/health?full=1", "/health#top", "/../etc", "/a//b", ""):
            with self.subTest(path=refused):
                self.assertNotEqual(readiness_path(refused)[1], "")
        self.assertFalse(readiness_ok("/", 500))
        self.assertTrue(readiness_ok("/", 404))
        self.assertFalse(readiness_ok("/health", 204))
        self.assertTrue(readiness_ok("/health", 200))
        self.assertFalse(readiness_ok("/health", 0))
        self.assertIn("below 500", _failure(Result.PARTIAL, "site_readiness"))


class ReadinessReviewTests(SimpleTestCase):
    """A path change is one Site effect, and the same path proposes no changes."""

    def evidence(self, readiness: str = "/") -> object:
        from typing import cast

        from bootstrap.standing import Standing
        from sites.bodies.common import NativeState
        from sites.readiness_change import ReadinessEvidence

        native: dict[str, object] = {
            "digest": "a" * 64,
            "boot": "00000000-0000-0000-0000-000000000000",
            "uptime": 1,
            "sites": [
                {
                    "identifier": "shop",
                    "names": ["shop.example.com"],
                    "runtime": "php84",
                    "node_runtime": "",
                    "https": True,
                    "readiness": readiness,
                    "certificate": None,
                    "account": [4000, 4000, "/var/www/shop", "/usr/sbin/nologin", [4000]],
                    "file": "/etc/caddy/sites/shop.caddy",
                    "state": "complete",
                    "problem": "",
                }
            ],
        }
        return ReadinessEvidence(Standing.TARGET_STACK, cast(NativeState, native))

    def test_a_changed_path_is_one_site_effect(self) -> None:
        from operations.consent import Scope
        from operations.inputs import PreparationInputs
        from sites.readiness_change import review

        draft = review(
            self.evidence(),
            PreparationInputs("", "shop", readiness="/health"),
        )
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertFalse(draft.no_changes)
        self.assertEqual([effect.scope for effect in draft.effects], [Scope.SITE])

    def test_an_unchanged_path_proposes_no_changes(self) -> None:
        from operations.inputs import PreparationInputs
        from sites.readiness_change import review

        draft = review(
            self.evidence("/health"),
            PreparationInputs("", "shop", readiness="/health"),
        )
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertTrue(draft.no_changes)


class DnsWarningTests(SimpleTestCase):
    """A DNS mismatch warns and never refuses (issue #376, docs/tls.md)."""

    def test_a_name_that_does_not_resolve_warns(self) -> None:
        from .change import SiteEvidence, dns_warnings

        evidence = SiteEvidence(None, None, None, None, {"local": ["10.0.0.1"], "resolved": {}})
        warnings = dns_warnings(evidence, ("shop.example.com",))
        self.assertTrue(any("shop.example.com" in warning for warning in warnings))

    def test_a_name_resolving_elsewhere_warns_with_the_answer(self) -> None:
        from .change import SiteEvidence, dns_warnings

        evidence = SiteEvidence(
            None,
            None,
            None,
            None,
            {"local": ["10.0.0.1"], "resolved": {"shop.example.com": ["203.0.113.9"]}},
        )
        warnings = dns_warnings(evidence, ("shop.example.com",))
        self.assertTrue(any("203.0.113.9" in warning for warning in warnings))

    def test_a_name_resolving_to_this_server_warns_about_nothing(self) -> None:
        from .change import SiteEvidence, dns_warnings

        evidence = SiteEvidence(
            None,
            None,
            None,
            None,
            {"local": ["10.0.0.1"], "resolved": {"shop.example.com": ["10.0.0.1"]}},
        )
        self.assertEqual(dns_warnings(evidence, ("shop.example.com",)), ())

    def test_an_unreadable_dns_evidence_warns_about_nothing(self) -> None:
        from .change import SiteEvidence, dns_warnings

        self.assertEqual(dns_warnings(SiteEvidence(None, None, None, None, None), ("a.com",)), ())


class SiteMasterStopTests(SimpleTestCase):
    """docs/site-conventions.md: a stop waits for the longest request a pool may run."""

    def test_stop_waits_out_the_longest_supported_request_well_within_the_apply_limit(
        self,
    ) -> None:
        from .serving import fpm_unit, master_config

        settings = SiteSettings("shop", ("shop.example.com",), "php84")
        self.assertIn("request_terminate_timeout = 300s\n", render_pool(settings))
        self.assertIn("process_control_timeout = 300s\n", master_config(settings))
        for entry in ("php84", "php85"):
            unit = fpm_unit(entry)
            self.assertIn("TimeoutStopSec=310s\n", unit)
            self.assertNotIn("infinity", unit)
            self.assertNotIn("SendSIGKILL", unit)
