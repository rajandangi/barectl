"""The WordPress installation review's workflow (docs/wordpress.md#installation-review).

Real views, services, the lifecycle, the worker, persistence and rendering run; only
remote execution is substituted, with a simulated server answering at
``discovery.ssh.connect``. The review is read-only and never applied here.
"""

from bootstrap.models import Action, PlanEffect, PlanEvidence, PlanRefusal
from bootstrap.test_workflow import kept_text
from operations.models import RemoteOperation
from sites.convention import Application, Stage, render_placeholder, render_site
from tls.fakes import NAMES

from . import core_native, install, setup_native
from .install_testing import VIEW, InstallTestCase
from .models import InstallationRequest, PlanWordpressInstall

Status = RemoteOperation.Status
Reason = PlanRefusal.Reason
Effect = PlanEffect.Kind
Kind = PlanEvidence.Kind


class ReviewTests(InstallTestCase):
    def test_a_prepared_site_gets_a_complete_immutable_review(self) -> None:
        plan = self.reviewed()
        self.assertTrue(plan.eligible, self.texts(plan))
        self.assertEqual(plan.action, Action.WORDPRESS_INSTALL)
        self.assertFalse(plan.no_changes)
        review = PlanWordpressInstall.objects.get(plan=plan)
        self.assertEqual(
            (review.identifier, review.php_version, review.php_supply, review.canonical_name),
            ("shop", self.packaging.release.php, "ubuntu", "www.shop.example.com"),
        )
        self.assertEqual(review.names, " ".join(NAMES))
        self.assertEqual(review.url, "https://www.shop.example.com")
        self.assertEqual((review.uid, review.gid, review.site_user), (1003, 1003, "sshop"))
        self.assertEqual(
            (review.title, review.admin_login, review.admin_email),
            ("Shop & Sons", "owner", "owner@example.com"),
        )
        self.assertEqual(
            (review.core_version, review.archive_url, review.archive_bytes, review.archive_sha256),
            (
                "7.1.3",
                "https://wordpress.org/wordpress-7.1.3.tar.gz",
                35_368_461,
                "d2a09acb6a15e3b9c471d72557753c266d6f41a79ed19bfe04cbfe49e283b2a5",
            ),
        )
        self.assertEqual(
            (review.tool_version, review.tool_path, review.tool_sha256),
            (setup_native.VERSION, setup_native.PHAR, setup_native.SHA256),
        )
        self.assertEqual(review.database_name, "sshop")
        self.assertEqual(review.certificate_sha256, "ab" * 32)

    def test_the_review_binds_the_exact_routing_forms_and_the_current_file(self) -> None:
        review = PlanWordpressInstall.objects.get(plan=self.reviewed())
        current = render_site("shop", NAMES, ipv6=True, stage=Stage.REDIRECT)
        gate = render_site(
            "shop",
            NAMES,
            ipv6=True,
            stage=Stage.REDIRECT,
            application=Application.WORDPRESS_GATE,
            canonical="www.shop.example.com",
        )
        ready = render_site(
            "shop",
            NAMES,
            ipv6=True,
            stage=Stage.REDIRECT,
            application=Application.WORDPRESS,
            canonical="www.shop.example.com",
        )
        self.assertEqual((review.gate_content, review.ready_content), (gate, ready))
        self.assertEqual(review.gate_sha256, install.digest(gate))
        self.assertEqual(review.ready_sha256, install.digest(ready))
        self.assertEqual(review.preimage_sha256, install.digest(current))

    def test_the_review_records_every_proposed_effect_and_the_evidence_it_stands_on(self) -> None:
        plan = self.reviewed()
        kinds = list(plan.effects.values_list("kind", flat=True))
        for kind in (
            Effect.APP_ARTIFACTS,
            Effect.APP_FILES,
            Effect.APP_SCHEMA,
            Effect.APP_NETWORK,
            Effect.APP_EXPOSURE,
            Effect.APP_ACCOUNT,
            Effect.APP_LIMITS,
            Effect.NO_ROLLBACK,
        ):
            self.assertIn(kind, kinds)
        evidence = set(plan.evidence.values_list("kind", flat=True))
        for expected in (
            Kind.SITE_REVALIDATION,
            Kind.LINEAGE_REVALIDATION,
            Kind.PACKAGE_REVALIDATION,
            Kind.DRIVER,
            Kind.CATALOG,
            Kind.WPCLI_REVALIDATION,
            Kind.WORDPRESS_RUNTIME,
            Kind.WORDPRESS_FILES,
            Kind.WORDPRESS_DATABASE,
        ):
            self.assertIn(expected, evidence)
        self.assertEqual(plan.boot_id != "", True)
        self.assertIsNotNone(plan.admission_deadline_centiseconds)

    def test_the_read_digests_are_what_the_same_script_hashes_under_the_lock(self) -> None:
        plan = self.reviewed()
        evidence = dict(plan.evidence.values_list("kind", "fingerprint"))
        self.assertEqual(evidence[Kind.WORDPRESS_FILES], install.digest(self.state.files()))
        self.assertEqual(evidence[Kind.WORDPRESS_DATABASE], install.digest(self.state.database()))

    def test_preparing_changes_nothing_and_runs_no_application_code(self) -> None:
        self.reviewed()
        self.assert_read_only()
        for command in self.remote.commands:
            self.assertNotRegex(command, r"(php\S*|wp)\s+\S*wp-cli[\w.-]*\.phar")
            self.assertNotIn("core install", command)
            self.assertNotIn("core download", command)
            self.assertNotRegex(command, r"\btar -x|\bcurl .*--output (?!/dev/null)")

    def test_the_review_keeps_no_password_or_salt(self) -> None:
        plan = self.reviewed()
        kept = kept_text(plan)
        for word in ("AUTH_KEY", "NONCE_SALT", "password=", "define("):
            self.assertNotIn(word, kept)
        page = self.client.get(f"/plans/{plan.pk}/").content.decode()
        self.assertIn("Administrator password setup required", page)
        self.assertIn("--prompt=user_pass --skip-email", page)
        self.assertNotIn("define(", page)

    def test_the_plan_page_shows_the_review_and_offers_the_apply_to_installers(self) -> None:
        plan = self.reviewed()
        self.sign_in_with(*VIEW, "install_wordpress")
        page = self.client.get(f"/plans/{plan.pk}/")
        self.assertContains(page, "https://www.shop.example.com/")
        self.assertContains(page, core_native.ARCHIVE_SHA256)
        self.assertContains(page, "never submitted twice")
        self.assertContains(page, f"/plans/{plan.pk}/apply/")
        self.assertNotContains(page, "Not available in this version")
        self.assertContains(
            page,
            f"sudo -u sshop /usr/bin/php{self.site.php} {setup_native.PHAR} "
            "--path=/var/www/shop/public --url=https://www.shop.example.com "
            "user update owner --prompt=user_pass --skip-email",
        )

    def test_an_empty_public_tree_is_admitted_and_replaces_nothing(self) -> None:
        self.state.public = {}
        review = PlanWordpressInstall.objects.get(plan=self.reviewed())
        self.assertFalse(review.placeholder_present)
        self.assertEqual(review.placeholder_sha256, install.digest(render_placeholder("shop")))

    def test_the_exact_placeholder_is_the_only_file_the_review_replaces(self) -> None:
        review = PlanWordpressInstall.objects.get(plan=self.reviewed())
        self.assertTrue(review.placeholder_present)

    def test_the_request_is_recorded_with_the_preparation(self) -> None:
        preparation = self.review()
        request = InstallationRequest.objects.get(preparation=preparation)
        self.assertEqual(
            (request.identifier, request.canonical_name, request.admin_login),
            ("shop", "www.shop.example.com", "owner"),
        )
        self.assertEqual(preparation.status, Status.SUCCEEDED)
