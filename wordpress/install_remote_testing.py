"""The disposable server an administrator prepared by hand for a WordPress installation, and
the commands that prepare and undo it (docs/wordpress.md#installation-review).

Tagged ``ssh`` by its users; see ``bootstrap/test_apply_remote.py`` for the contract.
"""

import shlex
import subprocess
from collections.abc import Callable
from typing import ClassVar, override

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission

from bootstrap.apply_remote_testing import ApplyAcceptanceTestCase
from bootstrap.models import ConfigurationPlan, PlanPreparation
from bootstrap.native_testing import INSTALL_MARIADB, REMOVE_MARIADB
from databases.native_testing import drop, mariadb_binding
from discovery.fakes import run_worker
from discovery.releases import SUPPORTED
from discovery.services import request_discovery
from operations.models import RemoteOperation
from sites.convention import Stage, render_placeholder, render_site
from sites.native_testing import create_site, remove_site

from . import qualification_testing, setup_native

Status = RemoteOperation.Status
PASSWORD = "Barectl-Journey-Passw0rd-3tQ8mZ"  # noqa: S105 - the test's own throwaway value
NAME = "www.shop.test"


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
        self.enterContext(qualification_testing.native_candidates_qualified())
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
