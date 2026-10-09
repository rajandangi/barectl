"""The WordPress installation review on a real, disposable Ubuntu server
(docs/wordpress.md#installation-review).

Tagged ``ssh`` and skipped unless the disposable server is configured, as
``bootstrap/test_apply_remote.py`` describes. The administrator prepares, by hand through
``docker exec``, everything the review stands on: a convention site, its self-signed HTTPS
lineage and redirect form, a MariaDB binding, the PHP extension baseline and the
authenticated WP-CLI artifact. Barectl then reads it through the site page's request, the
worker and its SSH connection only. Ground truth is read as root, independently of Barectl:
the review changes nothing, runs no application code, and every refusal leaves existing
files and tables as they were.
"""

from bootstrap.models import PlanRefusal
from databases.native_testing import mariadb
from operations.models import RemoteOperation
from sites.native_testing import snapshot

from . import convention, core_native, setup_native
from .install_remote_testing import DATABASE, IDENTIFIER, PUBLIC, InstallationServerCase, put
from .models import PlanWordpressInstall

Status = RemoteOperation.Status
Reason = PlanRefusal.Reason


class InstallReviewAcceptanceTests(InstallationServerCase):
    def test_a_prepared_site_is_reviewed_without_any_change_or_application_code(self) -> None:
        before = self.administer(snapshot(self.php))
        tree = self.administer(
            f"find /var/www/{IDENTIFIER} /usr/local/lib -xdev | sort | sha256sum"
        )
        plan = self.review()
        self.assertTrue(plan.eligible, self.texts(plan))
        review = PlanWordpressInstall.objects.get(plan=plan)
        self.assertEqual(review.canonical_name, "www.shop.test")
        self.assertEqual(review.php_version, self.php)
        self.assertEqual(review.archive_sha256, core_native.ARCHIVE_SHA256)
        self.assertEqual(
            review.uid, int(self.administer(f"id -u s{IDENTIFIER}").strip()), "the site user"
        )
        self.assertEqual(self.administer(snapshot(self.php)), before)
        self.assertEqual(
            self.administer(f"find /var/www/{IDENTIFIER} /usr/local/lib -xdev | sort | sha256sum"),
            tree,
        )
        # The database stayed empty, no application file appeared and no unit was submitted.
        self.assertEqual(
            self.tables(),
            "0",
        )
        self.assertEqual(self.administer(f"ls -A {PUBLIC}").strip(), "index.html")
        self.assertEqual(self.units(), [])
        page = self.client.get(f"/plans/{plan.pk}/")
        self.assertContains(page, "https://www.shop.test/")
        self.assertContains(page, "Administrator password setup required")
        # Review is current evidence, not authorization: the same site reviews again.
        again = self.review()
        self.assertTrue(again.eligible, self.texts(again))
        self.assertNotEqual(again.pk, plan.pk)

    def test_existing_application_files_and_tables_refuse_and_stay_untouched(self) -> None:
        self.administer(
            put(f"{PUBLIC}/wp-config.php", "<?php // mine\n", f"s{IDENTIFIER}", "www-data", "640")
        )
        files = self.administer(f"cd {PUBLIC} && sha256sum wp-config.php index.html")
        plan = self.review()
        self.assertFalse(plan.eligible)
        self.assertIn(
            Reason.EXISTING_APPLICATION, list(plan.refusals.values_list("reason", flat=True))
        )
        self.assertIn("wp-config.php", self.texts(plan))
        self.assertEqual(
            self.administer(f"cd {PUBLIC} && sha256sum wp-config.php index.html"), files
        )
        self.administer(f"rm {PUBLIC}/wp-config.php")
        self.administer(mariadb(f"CREATE TABLE `{DATABASE}`.`wp_options` (option_id TEXT)"))
        refused = self.review()
        self.assertFalse(refused.eligible)
        self.assertIn("wp_options", self.texts(refused))
        self.assertEqual(
            self.tables(),
            "1",
        )

    def test_a_missing_tool_and_an_incomplete_runtime_are_named_not_installed(self) -> None:
        php = self.php
        self.administer(f"rm -rf {setup_native.DIRECTORY}")
        self.administer(
            f"DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq php{php}-zip >/dev/null"
        )
        plan = self.review()
        self.assertFalse(plan.eligible)
        text = self.texts(plan)
        self.assertIn("is not installed", text)
        self.assertIn("ZIP archives", text)
        self.assertEqual(self.administer(f"ls -A {setup_native.DIRECTORY} 2>/dev/null; true"), "")
        self.assertEqual(
            self.administer(f"dpkg-query -W -f='${{Status}}' php{php}-zip 2>/dev/null; true").count(
                "installed"
            ),
            0,
        )

    def test_the_fixed_reads_report_the_real_server(self) -> None:
        free = int(self.administer("df -P -B1 /var/www | awk 'NR==2{print $4}'").strip())
        plan = self.review()
        self.assertTrue(plan.eligible, self.texts(plan))
        self.assertGreater(free, core_native.REQUIRED_FREE_BYTES)
        self.assertEqual(convention.public_root(IDENTIFIER), PUBLIC)
