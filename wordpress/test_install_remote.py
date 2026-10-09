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

import shlex
import subprocess
from collections.abc import Callable
from typing import ClassVar, override

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission

from bootstrap.models import ConfigurationPlan, PlanPreparation, PlanRefusal
from bootstrap.native_testing import REMOVE_MARIADB
from bootstrap.test_apply_remote import ApplyAcceptanceTestCase
from bootstrap.test_mariadb_remote import INSTALL_MARIADB
from discovery.fakes import run_worker
from discovery.releases import SUPPORTED
from discovery.services import request_discovery
from discovery.test_databases_remote import drop, mariadb, mariadb_binding
from operations.models import RemoteOperation
from sites.convention import Stage, render_placeholder, render_site
from sites.native_testing import create_site, remove_site, snapshot

from . import convention, core_native, setup_native
from .models import PlanWordpressInstall

Status = RemoteOperation.Status
Reason = PlanRefusal.Reason
PERMISSIONS = (
    "view_server",
    "view_siteobservation",
    "view_wordpressplan",
    "prepare_wordpressplan",
    "install_wordpress",
)
IDENTIFIER = "shop"
DATABASE = "sshop"
NAMES = ("shop.test", "www.shop.test")
PUBLIC = f"/var/www/{IDENTIFIER}/public"
PRIVATE = f"/var/www/{IDENTIFIER}/private"
PACKAGES = ("mysql", "curl", "xml", "mbstring", "zip", "gd", "intl")
LINEAGE = f"/etc/letsencrypt/live/{IDENTIFIER}"
FORM = {
    "wordpress-canonical_name": "www.shop.test",
    "wordpress-title": "Shop & Sons",
    "wordpress-admin_login": "owner",
    "wordpress-admin_email": "owner@example.com",
}


def put(path: str, text: str, owner: str, group: str, mode: str) -> str:
    return (
        f"printf %s {shlex.quote(text)} >{path} && chown {owner}:{group} {path} && "
        f"chmod {mode} {path}"
    )


def remove_baseline(php: str) -> str:
    packages = " ".join(f"php{php}-{name}" for name in PACKAGES)
    return (
        f"DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq {packages} >/dev/null 2>&1; "
        "DEBIAN_FRONTEND=noninteractive apt-get autoremove -y -qq >/dev/null 2>&1; "
        f"systemctl reload php{php}-fpm; true"
    )


def remove_lineage() -> str:
    return (
        f"rm -rf {LINEAGE} /etc/letsencrypt/archive/{IDENTIFIER} "
        f"/etc/letsencrypt/renewal/{IDENTIFIER}.conf /var/lib/letsencrypt/{IDENTIFIER}; true"
    )


def install_tool() -> str:
    """The authenticated artifact an administrator installs by hand: the pinned bytes."""
    return (
        "command -v curl >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y "
        "-qq curl >/dev/null; "
        f"install -d -o root -g root -m 755 {setup_native.DIRECTORY} && "
        f"curl --fail --silent --show-error --location --proto =https "
        f"--output {setup_native.PHAR} {shlex.quote(setup_native.PHAR_URL)} && "
        f"echo '{setup_native.SHA256}  {setup_native.PHAR}' | sha256sum -c --quiet && "
        f"chown root:root {setup_native.PHAR} && chmod 644 {setup_native.PHAR}"
    )


def cleanups(php: str) -> tuple[str, ...]:
    """Undo the administrator's preparation, newest first as cleanups run."""
    return (
        remove_site(IDENTIFIER, php),
        remove_lineage(),
        f"rm -rf {setup_native.DIRECTORY}",
        drop(DATABASE),
        REMOVE_MARIADB,
        remove_baseline(php),
    )


def prepared_server(php: str) -> list[str]:
    """The administrator's own commands for a site WordPress can be reviewed for."""
    packages = " ".join(f"php{php}-{name}" for name in PACKAGES)
    redirect = render_site(IDENTIFIER, NAMES, ipv6=True, stage=Stage.REDIRECT, php_version="")
    san = ",".join(f"DNS:{name}" for name in NAMES)
    return [
        f"DEBIAN_FRONTEND=noninteractive apt-get install -y -qq {packages} >/dev/null",
        INSTALL_MARIADB,
        create_site(IDENTIFIER, NAMES, php),
        put(
            f"{PUBLIC}/index.html",
            render_placeholder(IDENTIFIER),
            f"s{IDENTIFIER}",
            "www-data",
            "640",
        ),
        *mariadb_binding(DATABASE),
        f"mkdir -p {LINEAGE} /etc/letsencrypt/renewal",
        (
            f"openssl ecparam -name prime256v1 -genkey -noout -out {LINEAGE}/privkey.pem && "
            f"openssl req -x509 -new -key {LINEAGE}/privkey.pem -days 30 "
            f"-subj /CN={NAMES[0]} -addext subjectAltName={san} -out {LINEAGE}/cert.pem && "
            f"cp {LINEAGE}/cert.pem {LINEAGE}/fullchain.pem && chmod 600 {LINEAGE}/privkey.pem"
        ),
        f"printf 'version = 1\\n' >/etc/letsencrypt/renewal/{IDENTIFIER}.conf",
        "install -d -m 755 /var/lib/letsencrypt /var/backups/nginx",
        f"install -d -o root -g www-data -m 750 /var/lib/letsencrypt/{IDENTIFIER}",
        "chmod 700 /var/backups/nginx",
        put(f"/etc/nginx/sites-available/{IDENTIFIER}.conf", redirect, "root", "root", "644"),
        "nginx -t -q",
        "systemctl reload nginx",
        f"systemctl reload php{php}-fpm",
        install_tool(),
    ]


def prepare(run: Callable[[str], str], php: str) -> None:
    """Prepare the server as an administrator, naming the step that failed."""
    for step in prepared_server(php):
        try:
            run(step)
        except subprocess.CalledProcessError as failed:
            raise AssertionError(f"{step[:120]}: {failed.stderr[-600:]}") from failed


class InstallationServerCase(ApplyAcceptanceTestCase):
    """A disposable server the administrator prepared by hand for a WordPress installation."""

    php: ClassVar[str]

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        cls.user = get_user_model().objects.create_user("operator")
        for codename in PERMISSIONS:
            cls.user.user_permissions.add(Permission.objects.get(codename=codename))

    @override
    def setUp(self) -> None:
        super().setUp()
        release = self.administer(". /etc/os-release; echo $VERSION_ID").strip()
        type(self).php = SUPPORTED[release].php
        for cleanup in cleanups(self.php):
            self.addCleanup(self.administer, cleanup)
        prepare(self.administer, self.php)

    def review(self) -> ConfigurationPlan:
        request_discovery(self.server)
        run_worker()
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/{IDENTIFIER}/wordpress/install/prepare/", FORM
        )
        self.assertEqual(response.status_code, 302, response.content[:300])
        run_worker()
        preparation = PlanPreparation.objects.latest("queued_at", "pk")
        self.assertEqual(preparation.status, Status.SUCCEEDED, preparation.failure)
        return ConfigurationPlan.objects.get(preparation=preparation)

    def tables(self) -> str:
        """How many tables the site's database holds, read as root."""
        query = f"SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='{DATABASE}'"  # noqa: S608 - the test's own fixed name
        return self.administer(
            f"mariadb --no-defaults --protocol=socket -N -B -e {shlex.quote(query)}"
        ).strip()

    def texts(self, plan: ConfigurationPlan) -> str:
        return " ".join(plan.refusals.values_list("text", flat=True))


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
