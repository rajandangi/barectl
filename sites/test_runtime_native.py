"""Reviewed WordPress runtime replacements fit the existing native boundary."""

import hashlib
from dataclasses import replace

from django.test import SimpleTestCase

from bootstrap import native as bootstrap_native
from bootstrap import profiles
from bootstrap.models import Action
from bootstrap.releases import NOBLE

from . import runtime_native
from .convention import Application, Stage, render_pool, render_site
from .runtime_handler import _catalog_command


class WordPressSwitchBoundaryTests(SimpleTestCase):
    def change(self, application: Application = Application.WORDPRESS) -> runtime_native.Switch:
        def site(branch: str) -> str:
            return render_site(
                "shop",
                ("www.shop.example.com", "shop.example.com"),
                ipv6=True,
                stage=Stage.REDIRECT,
                php_version=branch,
                application=application,
                canonical="shop.example.com",
            )

        return runtime_native.Switch(
            "shop",
            "8.3",
            "8.4",
            4,
            site("8.3"),
            site("8.4"),
            render_pool("shop", php_version="8.3"),
            render_pool("shop", php_version="8.4"),
            hashlib.sha256(b"token").hexdigest()[:32],
            "mariadb",
        )

    def test_complete_wordpress_and_catalog_fences_fit_without_splitting(self) -> None:
        change = self.change()
        binding = (
            (_catalog_command("shop", "mariadb"), hashlib.sha256(b"catalog").hexdigest()),
            (
                profiles.profile(NOBLE, Action.PHP, version="8.4", supply="sury").revalidation,
                hashlib.sha256(b"target").hexdigest(),
            ),
        )
        body = runtime_native.body(
            change,
            default_digest=hashlib.sha256(b"default").hexdigest(),
            site_digest=hashlib.sha256(b"site").hexdigest(),
            binding=binding,
            wordpress_digest=hashlib.sha256(b"wordpress").hexdigest(),
        )
        payload = runtime_native.payload(
            "barectl-apply-" + "a" * 32 + ".service",
            "00000000-0000-0000-0000-000000000000",
            100,
            change,
            default_digest=hashlib.sha256(b"default").hexdigest(),
            site_digest=hashlib.sha256(b"site").hexdigest(),
            body_sha256=hashlib.sha256(body.encode()).hexdigest(),
            binding=binding,
            wordpress_digest=hashlib.sha256(b"wordpress").hexdigest(),
        )
        self.assertLessEqual(len(payload.encode()), bootstrap_native.MAX_PAYLOAD)
        with self.assertRaisesRegex(ValueError, "differs from the reviewed digest"):
            runtime_native.payload(
                "barectl-apply-" + "a" * 32 + ".service",
                "00000000-0000-0000-0000-000000000000",
                100,
                change,
                default_digest=hashlib.sha256(b"default").hexdigest(),
                site_digest=hashlib.sha256(b"site").hexdigest(),
                body_sha256=hashlib.sha256(body.encode()).hexdigest(),
                binding=binding,
                wordpress_digest="0" * 64,
            )

    def test_a_gated_application_or_changed_canonical_route_cannot_switch(self) -> None:
        with self.assertRaisesRegex(ValueError, "supported installed convention"):
            runtime_native.body(
                self.change(Application.WORDPRESS_GATE),
                default_digest=hashlib.sha256(b"default").hexdigest(),
                site_digest=hashlib.sha256(b"site").hexdigest(),
                wordpress_digest=hashlib.sha256(b"wordpress").hexdigest(),
            )
        changed = replace(
            self.change(), new_site=self.change().new_site.replace("wp-config.php", "foreign.php")
        )
        with self.assertRaisesRegex(ValueError, "exact convention"):
            runtime_native.body(
                changed,
                default_digest=hashlib.sha256(b"default").hexdigest(),
                site_digest=hashlib.sha256(b"site").hexdigest(),
                wordpress_digest=hashlib.sha256(b"wordpress").hexdigest(),
            )
