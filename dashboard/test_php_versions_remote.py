"""Selected Sury branches through public workflows on disposable native Ubuntu.

The public qualification gate is opened only by this fixture. Trust, package admission,
SSH execution, native verification and fresh-controller recognition remain real. This
service/client journey does not qualify the Sury workflow in Chromium.
"""

import json
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import override
from unittest import skipUnless
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings, tag

from bootstrap import php_supply
from bootstrap.models import Action, ApplyRun, ConfigurationPlan, Execution, Verification
from bootstrap.php_source_testing import trust_fixture
from dashboard.testing import TEST_MANIFEST
from databases.models import RunDatabaseBinding
from databases.services import request_binding_preparation, request_driver_preparation
from discovery.fakes import current, run_worker
from discovery.models import DatabaseEngine, SiteState
from discovery.native_testing import reconstruct
from discovery.releases import RESOLUTE
from discovery.services import request_discovery
from disposable import acme
from operations.models import RemoteOperation
from servers.models import Server
from sites import native as site_native
from sites.convention import SitePaths, render_pool, render_site
from sites.models import RunSite
from tls import native as tls_native
from tls.services import (
    request_activation_preparation,
    request_challenge_preparation,
    request_issuance_preparation,
    request_readiness_preparation,
    request_setup_preparation,
)

CONFIGURED = bool(os.environ.get("BARECTL_SSH_TEST_CONTAINER")) and acme.CONFIGURED
AUTHORITY = {"directory": acme.DIRECTORY, "caa": "pebble", "name": "Pebble"}
DATABASE_CONTROLLER = """
import json
import os
import sys
from pathlib import Path

os.environ["DJANGO_SETTINGS_MODULE"] = "config.settings"
from config import settings as configured
database, ssh_config, manifest = sys.argv[1:4]
configured.DATABASES["default"]["NAME"] = database
configured.SSH_CONFIG_PATH = ssh_config
configured.VITE_MANIFEST_PATH = Path(manifest)
configured.VITE_DEV_SERVER_URL = ""
import django
django.setup()
from django.contrib.auth import get_user_model
from django.core.management import call_command
from bootstrap import php_supply
from bootstrap.models import ApplyRun, ConfigurationPlan
from databases.models import PlanCatalogObservation
from databases.services import request_inspection
from discovery.fakes import run_worker
from servers.models import Server
php_supply.PRIMARY_FINGERPRINT, php_supply.KEY_SHA256 = sys.argv[4:6]
call_command("migrate", verbosity=0)
user = get_user_model().objects.create_superuser("fresh-inspector")
server = Server.objects.create(name="Reconstructed", ssh_alias="disposable")
request_inspection(server, user)
run_worker()
plan = ConfigurationPlan.objects.get()
print(json.dumps({
    "eligible": plan.eligible,
    "refusals": list(plan.refusals.values_list("text", flat=True)),
    "runs": ApplyRun.objects.count(),
    "bindings": list(PlanCatalogObservation.objects.values(
        "identifier", "engine", "status", "conforms", "principal", "database")),
}))
"""


@tag("ssh")
@skipUnless(CONFIGURED, "Requires disposable native Ubuntu and the ACME fixtures.")
@override_settings(ACME_AUTHORITIES=[AUTHORITY], ACME_PRODUCTION_DIRECTORY=acme.DIRECTORY)
class SelectedPhpHostingJourneyTests(TestCase):
    @classmethod
    @override
    def setUpClass(cls) -> None:
        super().setUpClass()
        acme.install_trust_and_resolver(cls)

    @override
    def setUp(self) -> None:
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        config = self.directory / "config"
        self.write_config(config, "KEY")
        self.enterContext(
            override_settings(SSH_CONFIG_PATH=str(config), VITE_MANIFEST_PATH=TEST_MANIFEST)
        )
        self.enterContext(patch("bootstrap.php_supply.qualified", return_value=True))
        trust_fixture(self, acme.on_server)
        self.user = get_user_model().objects.create_superuser("operator")
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="Disposable", ssh_alias="disposable")
        acme.on_server(
            "set -e; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
            "--no-install-recommends gpg >/dev/null; "
            "p=$(dpkg-query -W -f='${Package} ${db:Status-Abbrev}\\n' 'php*' 2>/dev/null "
            "| awk '$2 != \"un\" {print $1}'); "
            'if [ -n "$p" ]; then DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq $p '
            ">/dev/null; fi; "
            "rm -f /etc/nginx/sites-enabled/private /etc/nginx/sites-available/private; "
            f"pg_dropcluster --stop {RESOLUTE.postgresql} archive; "
            f"pg_dropcluster --stop {RESOLUTE.postgresql} reports; "
            "systemctl daemon-reload; nginx -t -q; systemctl reload nginx; "
            f"usermod -aG shadow {shlex.quote(os.environ['BARECTL_SSH_TEST_USER'])}"
        )
        addresses = acme.server_addresses()
        for name in ("shop.test", "blog.test", "wiki.test"):
            acme.add_a(self, name, [addresses.ipv4])
            if not acme.IPV6_UNAVAILABLE:
                acme.add_aaaa(self, name, [addresses.ipv6])

    def write_config(self, path: Path, key: str) -> None:
        path.write_text(
            "Host disposable\n"
            f"  HostName {os.environ['BARECTL_SSH_TEST_HOST']}\n"
            f"  Port {os.environ['BARECTL_SSH_TEST_PORT']}\n"
            f"  User {os.environ['BARECTL_SSH_TEST_USER']}\n"
            f"  UserKnownHostsFile {os.environ['BARECTL_SSH_TEST_KNOWN_HOSTS']}\n"
            f"  IdentityFile {os.environ[f'BARECTL_SSH_TEST_{key}']}\n",
            encoding="utf-8",
        )

    def prepared(self) -> ConfigurationPlan:
        run_worker()
        plan = ConfigurationPlan.objects.latest("pk")
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        review = self.client.get(f"/plans/{plan.pk}/", secure=True)
        self.assertEqual(review.status_code, 200)
        return plan

    def apply(self, plan: ConfigurationPlan) -> ApplyRun:
        response = self.client.post(f"/plans/{plan.pk}/apply/", secure=True)
        self.assertEqual(response.status_code, 302)
        run_worker()
        run = ApplyRun.objects.get(plan=plan)
        expected = (RemoteOperation.Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED)
        actual = (run.status, run.execution, run.verification)
        failure = f"{run.action}: {run.failure}"
        if actual != expected:
            failure += "\n" + acme.on_server(
                f"journalctl --no-pager -o cat -n 100 -u {shlex.quote(run.unit_name)}"
            )
        self.assertEqual(
            actual,
            expected,
            failure,
        )
        return run

    def profile(self, action: Action, branch: str = "") -> ApplyRun:
        data: dict[str, str] = {"action": action}
        if branch:
            data.update(php_version=branch, php_supply="sury")
        response = self.client.post(f"/servers/{self.server.pk}/plans/prepare/", data, secure=True)
        self.assertEqual(response.status_code, 302)
        return self.apply(self.prepared())

    def discover(self) -> None:
        request_discovery(self.server)
        run_worker()

    def create_site(self, identifier: str, branch: str) -> None:
        self.discover()
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/prepare/",
            {"identifier": identifier, "names": f"{identifier}.test", "php_version": branch},
            secure=True,
        )
        self.assertEqual(response.status_code, 302)
        plan = self.prepared()
        self.assertEqual((plan.site.php_version, plan.site.convention_revision), (branch, 4))
        run = self.apply(plan)
        retained = RunSite.objects.get(run=run)
        self.assertEqual((retained.php_version, retained.convention_revision), (branch, 4))
        self.assertEqual(
            acme.on_server(f"cat /etc/nginx/sites-available/{identifier}.conf"),
            render_site(identifier, (f"{identifier}.test",), ipv6=True, php_version=branch),
        )
        self.assertEqual(
            acme.on_server(f"cat /etc/php/{branch}/fpm/pool.d/{identifier}.conf"),
            render_pool(identifier, php_version=branch),
        )

    def fingerprint(self, identifier: str, branch: str) -> str:
        paths = SitePaths(identifier, branch, revision=4)
        return acme.on_server(
            f"sha256sum {paths.source} {paths.pool}; "
            f"stat -c '%i %Y %U %G %a' {paths.source} {paths.pool}; "
            f"readlink {paths.enabled}"
        )

    def assert_native_php(self, identifier: str, branch: str) -> None:
        probe = f"/var/www/{identifier}/public/version.php"
        source = '<?php echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION,"|",posix_geteuid();'
        acme.on_server(f"printf %s {shlex.quote(source)} >{probe}")
        self.addCleanup(acme.on_server, f"rm -f {probe}")
        uid = acme.on_server(f"id -u s{identifier}").strip()
        body = acme.on_server(
            f"{site_native.http_client(branch)}; k 127.0.0.1 {identifier}.test /version.php"
        )
        self.assertEqual(body, f"{branch}|{uid}")
        self.assertEqual(
            acme.on_server(f"stat -c '%U %G %a' /run/php/s{identifier}-php{branch}.sock"),
            "www-data www-data 600\n",
        )

    def install_driver(
        self, identifier: str, branch: str, action: Action = Action.PHP_PGSQL
    ) -> None:
        request_driver_preparation(self.server, self.user, action, identifier=identifier)
        plan = self.prepared()
        self.assertEqual((plan.php_version, plan.php_supply), (branch, "sury"))
        self.assertEqual(
            list(plan.driver_pools.values_list("name", "socket")),
            [
                ("www", f"/run/php/php{branch}-fpm.sock"),
                (identifier, f"/run/php/s{identifier}-php{branch}.sock"),
            ],
        )
        self.apply(plan)

    def fresh_bindings(self, config: Path) -> None:
        directory = self.directory / "fresh-bindings"
        directory.mkdir()
        result = subprocess.run(  # noqa: S603 - fixed fixture controller script and paths
            [
                sys.executable,
                "-c",
                DATABASE_CONTROLLER,
                str(directory / "db.sqlite3"),
                str(config),
                str(TEST_MANIFEST),
                php_supply.PRIMARY_FINGERPRINT,
                php_supply.KEY_SHA256,
            ],
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
            env={**os.environ, "SSH_AUTH_SOCK": ""},
        )
        self.assertEqual(result.returncode, 0, result.stderr[-4000:])
        value: object = json.loads(result.stdout.strip().splitlines()[-1])
        if not isinstance(value, dict) or not isinstance(value.get("bindings"), list):
            raise AssertionError("The fresh controller did not return catalog observations.")
        self.assertTrue(value["eligible"], value["refusals"])
        self.assertEqual(value["runs"], 0)
        bindings = {
            item["identifier"]: item for item in value["bindings"] if isinstance(item, dict)
        }
        for identifier, engine in (
            ("shop", "postgresql"),
            ("blog", "mariadb"),
            ("wiki", "postgresql"),
        ):
            principal = f"s{identifier}@localhost" if engine == "mariadb" else f"s{identifier}"
            self.assertEqual(
                (
                    bindings[identifier]["engine"],
                    bindings[identifier]["status"],
                    bindings[identifier]["conforms"],
                    bindings[identifier]["principal"],
                    bindings[identifier]["database"],
                ),
                (engine, "observed", True, principal, f"s{identifier}"),
            )

    def test_source_two_branches_database_https_and_fresh_finish(self) -> None:
        self.profile(Action.PHP_SOURCE)
        self.assertEqual(
            acme.on_server(
                "dpkg-query -W -f='${db:Status-Abbrev}' 'php*-fpm' 2>/dev/null || true"
            ).strip(),
            "",
        )
        self.profile(Action.METADATA_REFRESH)
        for branch in ("8.3", "8.4"):
            self.profile(Action.PHP, branch)
        self.create_site("shop", "8.3")
        self.create_site("blog", "8.4")
        for identifier, branch in (("shop", "8.3"), ("blog", "8.4")):
            self.assert_native_php(identifier, branch)

        blog = self.fingerprint("blog", "8.4")
        self.install_driver("shop", "8.3")
        self.assertEqual(self.fingerprint("blog", "8.4"), blog)
        self.assertEqual(
            acme.on_server("php8.3 -r 'echo (int)extension_loaded(\"pdo_pgsql\");'"), "1"
        )
        self.assertEqual(
            acme.on_server("php8.4 -r 'echo (int)extension_loaded(\"pdo_pgsql\");'"), "0"
        )
        self.install_driver("blog", "8.4")
        request_binding_preparation(self.server, self.user, "shop", DatabaseEngine.POSTGRESQL)
        binding = self.apply(self.prepared())
        audit = RunDatabaseBinding.objects.get(run=binding)
        self.assertEqual((audit.php_version, audit.site_revision), ("8.3", 4))
        self.assertEqual(
            acme.on_server(
                "runuser -u sshop -- psql -X -A -t -q -h /var/run/postgresql -d sshop "
                "-c 'SELECT current_user'"
            ),
            "sshop\n",
        )

        request_challenge_preparation(self.server, self.user, "shop")
        self.apply(self.prepared())
        challenge = "/var/lib/letsencrypt/shop/.well-known/acme-challenge/selected-branch"
        acme.on_server(
            f"install -d -o root -g www-data -m 0750 {challenge.rpartition('/')[0]}; "
            f"printf 'challenge retained' >{challenge}"
        )
        self.addCleanup(acme.on_server, f"rm -f {challenge}")
        self.assertEqual(
            acme.on_server(
                f"{site_native.http_client('8.3')}; "
                "k 127.0.0.1 shop.test /.well-known/acme-challenge/selected-branch"
            ),
            "challenge retained",
        )
        request_setup_preparation(self.server, self.user)
        self.apply(self.prepared())
        request_readiness_preparation(self.server, self.user, "shop")
        readiness = self.prepared()
        self.assertEqual(
            (readiness.readiness.php_version, readiness.readiness.site_revision), ("8.3", 4)
        )
        self.assertEqual(readiness.readiness.name_list, ("shop.test",))
        self.assertFalse(ApplyRun.objects.filter(plan=readiness).exists())
        request_issuance_preparation(self.server, self.user, "shop", "operator@example.com")
        self.apply(self.prepared())
        request_activation_preparation(self.server, self.user, "shop")
        self.apply(self.prepared())
        self.assertEqual(
            acme.on_server(
                f"{tls_native.status_client('8.3')}; s 127.0.0.1 shop.test / | head -c 3"
            ),
            "301",
        )
        body = acme.on_server(
            "printf 'GET /version.php HTTP/1.0\\r\\nHost: shop.test\\r\\n\\r\\n' | "
            "timeout 10 openssl s_client -quiet -verify_return_error -verify_hostname "
            "shop.test -connect 127.0.0.1:443 -servername shop.test 2>/dev/null; true"
        )
        self.assertIn("8.3|" + acme.on_server("id -u sshop").strip(), body)
        self.assertEqual(
            acme.on_server(
                f"{site_native.http_client('8.3')}; "
                "k 127.0.0.1 shop.test /.well-known/acme-challenge/selected-branch"
            ),
            "challenge retained",
        )
        self.assertEqual(self.fingerprint("blog", "8.4"), blog)
        self.assert_native_php("blog", "8.4")

        shop = self.fingerprint("shop", "8.3")
        self.profile(Action.PHP, "8.5")
        self.assertEqual(self.fingerprint("shop", "8.3"), shop)
        self.assertEqual(self.fingerprint("blog", "8.4"), blog)

        self.create_site("wiki", "8.5")
        self.assert_native_php("wiki", "8.5")
        self.install_driver("wiki", "8.5")
        request_binding_preparation(self.server, self.user, "wiki", DatabaseEngine.POSTGRESQL)
        wiki_binding = self.apply(self.prepared())
        wiki_audit = RunDatabaseBinding.objects.get(run=wiki_binding)
        self.assertEqual((wiki_audit.php_version, wiki_audit.site_revision), ("8.5", 4))
        self.assertEqual(
            acme.on_server(
                "runuser -u swiki -- psql -X -A -t -q -h /var/run/postgresql -d swiki "
                "-c 'SELECT current_user'"
            ),
            "swiki\n",
        )
        request_challenge_preparation(self.server, self.user, "wiki")
        self.apply(self.prepared())
        request_readiness_preparation(self.server, self.user, "wiki")
        wiki_readiness = self.prepared()
        self.assertEqual(
            (wiki_readiness.readiness.php_version, wiki_readiness.readiness.site_revision),
            ("8.5", 4),
        )
        request_issuance_preparation(self.server, self.user, "wiki", "operator@example.com")
        self.apply(self.prepared())
        request_activation_preparation(self.server, self.user, "wiki")
        self.apply(self.prepared())
        self.assertEqual(
            acme.on_server(
                f"{tls_native.status_client('8.5')}; s 127.0.0.1 wiki.test / | head -c 3"
            ),
            "301",
        )
        wiki_body = acme.on_server(
            "printf 'GET /version.php HTTP/1.0\\r\\nHost: wiki.test\\r\\n\\r\\n' | "
            "timeout 10 openssl s_client -quiet -verify_return_error -verify_hostname "
            "wiki.test -connect 127.0.0.1:443 -servername wiki.test 2>/dev/null; true"
        )
        self.assertIn("8.5|" + acme.on_server("id -u swiki").strip(), wiki_body)
        self.assertEqual(self.fingerprint("shop", "8.3"), shop)
        self.assertEqual(self.fingerprint("blog", "8.4"), blog)

        config = self.directory / "second-config"
        self.write_config(config, "SECOND_KEY")
        source = acme.on_server("cat /etc/nginx/sites-available/blog.conf")
        acme.on_server("rm /etc/php/8.4/fpm/pool.d/blog.conf; systemctl reload php8.4-fpm")
        finished = reconstruct(
            self.directory / "fresh-finish",
            config,
            TEST_MANIFEST,
            finish_identifier="blog",
            qualified_php=True,
        )
        self.assertEqual(
            finished["finished"],
            {"execution": "succeeded", "verification": "passed", "changes": ["pool", "probe"]},
        )
        self.assertEqual(acme.on_server("cat /etc/nginx/sites-available/blog.conf"), source)
        self.assertEqual(
            acme.on_server("cat /etc/php/8.4/fpm/pool.d/blog.conf"),
            render_pool("blog", php_version="8.4"),
        )
        self.assert_native_php("blog", "8.4")
        wiki = self.fingerprint("wiki", "8.5")
        self.install_driver("blog", "8.4", Action.PHP_MYSQL)
        self.profile(Action.MARIADB)
        request_binding_preparation(self.server, self.user, "blog", DatabaseEngine.MARIADB)
        blog_binding = self.apply(self.prepared())
        blog_audit = RunDatabaseBinding.objects.get(run=blog_binding)
        self.assertEqual((blog_audit.php_version, blog_audit.site_revision), ("8.4", 4))
        self.assertEqual(
            acme.on_server(
                "runuser -u sblog -- mariadb --no-defaults -N -B sblog -e 'SELECT CURRENT_USER()'"
            ),
            "sblog@localhost\n",
        )
        request_challenge_preparation(self.server, self.user, "blog")
        self.apply(self.prepared())
        request_readiness_preparation(self.server, self.user, "blog")
        blog_readiness = self.prepared()
        self.assertEqual(
            (blog_readiness.readiness.php_version, blog_readiness.readiness.site_revision),
            ("8.4", 4),
        )
        request_issuance_preparation(self.server, self.user, "blog", "operator@example.com")
        self.apply(self.prepared())
        request_activation_preparation(self.server, self.user, "blog")
        self.apply(self.prepared())
        self.assertEqual(
            acme.on_server(
                f"{tls_native.status_client('8.4')}; s 127.0.0.1 blog.test / | head -c 3"
            ),
            "301",
        )
        blog_body = acme.on_server(
            "printf 'GET /version.php HTTP/1.0\\r\\nHost: blog.test\\r\\n\\r\\n' | "
            "timeout 10 openssl s_client -quiet -verify_return_error -verify_hostname "
            "blog.test -connect 127.0.0.1:443 -servername blog.test 2>/dev/null; true"
        )
        self.assertIn("8.4|" + acme.on_server("id -u sblog").strip(), blog_body)
        self.assertEqual(self.fingerprint("shop", "8.3"), shop)
        self.assertEqual(self.fingerprint("wiki", "8.5"), wiki)
        self.discover()
        sites = {site.identifier: site for site in current(self.server).collected.sites.value}
        self.assertEqual((sites["shop"].php_version, sites["blog"].php_version), ("8.3", "8.4"))
        self.assertEqual(
            (sites["shop"].state, sites["blog"].state), (SiteState.MANAGED, SiteState.MANAGED)
        )
        self.assertEqual(
            (sites["wiki"].php_version, sites["wiki"].state), ("8.5", SiteState.MANAGED)
        )

        reconstructed = reconstruct(self.directory / "fresh", config, TEST_MANIFEST)
        self.assertEqual((reconstructed["runs"], reconstructed["preparations"]), (0, 0))
        self.assertEqual(reconstructed["status"], "succeeded")
        fresh_sites = reconstructed["sites"]
        if not isinstance(fresh_sites, list):
            raise AssertionError("The fresh controller did not return site observations.")
        found = {
            item["identifier"]: item
            for item in fresh_sites
            if isinstance(item, dict) and item.get("identifier") in {"shop", "blog", "wiki"}
        }
        for identifier, branch in (("shop", "8.3"), ("blog", "8.4"), ("wiki", "8.5")):
            self.assertEqual(
                (
                    found[identifier]["php_version"],
                    found[identifier]["convention_revision"],
                    found[identifier]["state"],
                ),
                (branch, 4, "managed"),
            )
        self.assertEqual(found["shop"]["stage"], "redirect")
        self.assertEqual(
            found["shop"]["certificate_reference"], "/etc/letsencrypt/live/shop/fullchain.pem"
        )
        self.assertEqual(found["wiki"]["stage"], "redirect")
        self.assertEqual(
            found["wiki"]["certificate_reference"], "/etc/letsencrypt/live/wiki/fullchain.pem"
        )
        self.assertEqual(found["blog"]["stage"], "redirect")
        self.assertEqual(
            found["blog"]["certificate_reference"], "/etc/letsencrypt/live/blog/fullchain.pem"
        )
        self.fresh_bindings(config)
        retained = self.fingerprint("shop", "8.3")
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/prepare/",
            {"identifier": "shop", "names": "shop.test", "php_version": "8.4"},
            secure=True,
        )
        self.assertEqual(response.status_code, 302)
        run_worker()
        refused = ConfigurationPlan.objects.latest("pk")
        self.assertFalse(refused.eligible)
        self.assertTrue(refused.refusals.exists())
        self.assertFalse(ApplyRun.objects.filter(plan=refused).exists())
        self.assertEqual(self.fingerprint("shop", "8.3"), retained)
