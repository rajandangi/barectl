"""Site plan preparation against a real, disposable Ubuntu server (docs/sites.md).

Tagged ``ssh`` and skipped unless the disposable server is configured, as
``discovery/test_remote.py`` describes; these tests also need ``BARECTL_SSH_TEST_CONTAINER``
to change fixtures as the server's administrator and ``BARECTL_SSH_TEST_UNPRIVILEGED_USER``.
Barectl prepares through the dashboard request, the worker and its SSH connection only.
Ground truth is read as root through ``docker exec``, before and after each preparation:
nothing under /etc, /var/www, /run/php or /var/backups, no account, no service master process and
no log may change, and no transient unit or staged file may appear.
"""

import hashlib
import os
import shlex
import subprocess
import tempfile
from pathlib import Path
from typing import ClassVar, override
from unittest import mock, skipUnless

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission, User
from django.test import TestCase, override_settings, tag

from bootstrap.models import ConfigurationPlan, PlanEvidence, PlanPreparation, PlanRefusal
from dashboard.testing import TEST_MANIFEST
from discovery.fakes import pool_config, run_worker, site_config
from discovery.releases import SUPPORTED
from discovery.test_remote import CONFIGURED, setting
from operations.models import RemoteOperation
from servers.models import Server

from . import native
from .convention import SitePaths, render_site
from .names import MAX_NAME_OCTETS, MAX_NAMES
from .test_payload import BOOT, UNIT, longest

Reason = PlanRefusal.Reason
FIXTURES = CONFIGURED and all(
    os.environ.get(f"BARECTL_SSH_TEST_{name}") for name in ("CONTAINER", "UNPRIVILEGED_USER")
)
PERMISSIONS = ("view_server", "view_siteplan", "prepare_siteplan")
NAMES = "shop.test www.shop.test"
# The provisioned root-only site, which site admission refuses, set aside for most tests.
SET_ASIDE = (
    "mv /etc/nginx/sites-enabled/private /root/private.link && "
    "mv /etc/nginx/sites-available/private /root/private.site"
)
PUT_BACK = (
    "test -e /etc/nginx/sites-available/private || "
    "mv /root/private.site /etc/nginx/sites-available/private; "
    "test -L /etc/nginx/sites-enabled/private || "
    "mv /root/private.link /etc/nginx/sites-enabled/private; true"
)
SUDOERS = "/etc/sudoers.d/deploy"


def snapshot(php: str) -> str:
    """What preparation must leave as it was, read as root."""
    return "; ".join(
        (
            (
                "find /etc /var/www /run/php /var/backups -xdev "
                "-printf '%p %y %m %U %G %s %T@\\n' 2>/dev/null | LC_ALL=C sort | sha256sum"
            ),
            "sha256sum /etc/passwd /etc/group /etc/shadow /etc/gshadow",
            # The master PIDs only: a reload another test's cleanup triggers can be
            # settling while this snapshot runs, and then the workers' PIDs differ
            # even though preparation changed nothing.
            "echo nginx $(cat /run/nginx.pid)",
            (f"echo fpm $(systemctl show -p MainPID --value php{php}-fpm.service)"),
            "echo; stat -c '%n %s' /var/log/nginx/* /var/log/php*-fpm.log 2>/dev/null",
            "systemctl list-units --all --plain --no-legend 'barectl-apply-*'",
            "find /etc/nginx /etc/php /var/www -name '.*' 2>/dev/null",
        )
    )


def _write(path: str, content: str, mode: str) -> str:
    return f"printf %s {shlex.quote(content)} >{path} && chmod {mode} {path}"


def create_site(identifier: str, names: tuple[str, ...], php: str) -> str:
    """The administrator's own commands for a site that meets the convention."""
    user = f"s{identifier}"
    return " && ".join(
        (
            (
                f"useradd --home-dir /var/www/{identifier} --no-create-home "
                f"--shell /usr/sbin/nologin --user-group {user}"
            ),
            f"install -d -o root -g root -m 755 /var/www/{identifier}",
            f"install -d -o {user} -g www-data -m 750 /var/www/{identifier}/public",
            f"install -d -o {user} -g {user} -m 700 /var/www/{identifier}/private",
            _write(
                f"/etc/nginx/sites-available/{identifier}.conf",
                site_config(identifier, names),
                "644",
            ),
            (
                f"ln -s /etc/nginx/sites-available/{identifier}.conf "
                f"/etc/nginx/sites-enabled/{identifier}.conf"
            ),
            _write(f"/etc/php/{php}/fpm/pool.d/{identifier}.conf", pool_config(identifier), "644"),
            "nginx -t -q",
            f"php-fpm{php} -t 2>/dev/null",
            f"systemctl reload php{php}-fpm",
            "systemctl reload nginx",
            f"for _ in $(seq 50); do test -S /run/php/{user}.sock && break; sleep 0.2; done",
            f"test -S /run/php/{user}.sock",
        )
    )


def _socket_cleanup(identifier: str) -> str:
    """Wait for the pool reload to close the site's socket, then remove any lingering file.

    A present socket is not absent, so a stale one would block the identifier's next plan.
    """
    socket = f"/run/php/s{identifier}.sock"
    return f"for _ in $(seq 50); do test -S {socket} || break; sleep 0.2; done; rm -f {socket}"


def remove_site(identifier: str, php: str) -> str:
    return "; ".join(
        (
            f"rm -f /etc/nginx/sites-enabled/{identifier}.conf",
            f"rm -f /etc/nginx/sites-available/{identifier}.conf",
            f"rm -f /etc/php/{php}/fpm/pool.d/{identifier}.conf",
            # Files an interrupted run staged beside their destinations.
            f"rm -f /etc/nginx/sites-available/.{identifier}.conf.*",
            f"rm -f /etc/php/{php}/fpm/pool.d/.{identifier}.conf.*",
            # A service a broken fixture stopped is started again.
            f"systemctl reload php{php}-fpm 2>/dev/null || systemctl restart php{php}-fpm",
            "systemctl reload nginx 2>/dev/null || systemctl restart nginx",
            _socket_cleanup(identifier),
            f"rm -rf /var/www/{identifier}",
            # A challenge route's webroot and recovery preimages.
            f"rm -rf /var/lib/letsencrypt/{identifier} /var/backups/nginx/{identifier}.conf.*",
            f"id s{identifier} >/dev/null 2>&1 && userdel s{identifier}",
            f"getent group s{identifier} >/dev/null && groupdel s{identifier}",
            "true",
        )
    )


class _RemoteSiteTestCase(TestCase):
    user: ClassVar[User]
    baseline: str

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        cls.user = get_user_model().objects.create_user("operator")
        for codename in PERMISSIONS:
            cls.user.user_permissions.add(Permission.objects.get(codename=codename))

    @override
    def setUp(self) -> None:
        directory = Path(self.enterContext(tempfile.TemporaryDirectory(dir="/tmp")))
        self.config = directory / "config"
        self.write_config(setting("USER"))
        self.enterContext(
            override_settings(SSH_CONFIG_PATH=str(self.config), VITE_MANIFEST_PATH=TEST_MANIFEST)
        )
        self.enterContext(mock.patch.dict(os.environ, {"SSH_AUTH_SOCK": ""}))
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="Disposable", ssh_alias="disposable")
        release = self.administer(". /etc/os-release; echo $VERSION_ID").strip()
        self.php = SUPPORTED[release].php

    def write_config(self, user: str) -> None:
        self.config.write_text(
            "Host disposable\n"
            f"  HostName {setting('HOST')}\n  Port {setting('PORT')}\n  User {user}\n"
            f"  UserKnownHostsFile {setting('KNOWN_HOSTS')}\n  IdentityFile {setting('KEY')}\n",
            encoding="utf-8",
        )

    def administer(self, script: str) -> str:
        """Run ``script`` as the server's administrator, outside Barectl; return its output."""
        result = subprocess.run(  # noqa: S603 - the tests' own fixture scripts
            ["docker", "exec", setting("CONTAINER"), "sh", "-c", script],  # noqa: S607
            check=True,
            capture_output=True,
            text=True,
            timeout=300,
        )
        return result.stdout

    def change_fixture(self, script: str, restore: str) -> None:
        self.addCleanup(self.administer, restore)
        self.administer(script)

    def prepare(self, identifier: str = "shop", names: str = NAMES) -> ConfigurationPlan:
        """Prepare through the dashboard and the worker, proving nothing changed."""
        before = self.administer(snapshot(self.php))
        self.client.post(
            f"/servers/{self.server.pk}/sites/prepare/",
            {"identifier": identifier, "names": names},
        )
        run_worker()
        self.assertEqual(self.administer(snapshot(self.php)), before, "Preparation changed it")
        preparation = PlanPreparation.objects.latest("queued_at", "pk")
        self.assertEqual(preparation.status, RemoteOperation.Status.SUCCEEDED, preparation.failure)
        return ConfigurationPlan.objects.get(preparation=preparation)

    def reasons(self, plan: ConfigurationPlan) -> set[str]:
        return set(plan.refusals.values_list("reason", flat=True))

    def refusals(self, plan: ConfigurationPlan) -> str:
        return " ".join(plan.refusals.values_list("text", flat=True))


@tag("ssh")
@skipUnless(FIXTURES, "Set BARECTL_SSH_TEST_* and the server's container to review sites")
class SiteReviewAcceptanceTests(_RemoteSiteTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.change_fixture(SET_ASIDE, PUT_BACK)

    def test_preparation_reviews_the_site_read_only_with_the_servers_own_digest(self) -> None:
        plan = self.prepare()
        self.assertTrue(plan.eligible, self.refusals(plan))
        self.assertFalse(plan.no_changes)
        release = self.administer(". /etc/os-release; echo $VERSION_ID").strip()
        self.assertEqual(plan.release, release)
        site = plan.site
        self.assertEqual((site.identifier, site.php_version, site.ipv6), ("shop", self.php, True))
        files = dict(plan.site_files.values_list("role", "content"))
        expected = render_site("shop", ("shop.test", "www.shop.test"), ipv6=True)
        self.assertEqual(files["nginx_source"], expected)
        self.assertEqual(files["pool"], pool_config("shop"))
        uid_max = self.administer("awk '$1 == \"UID_MAX\" {print $2}' /etc/login.defs").strip()
        self.assertEqual(plan.site_account.uid_max, int(uid_max))
        # The digest preparation recorded is the one the server computes as root.
        text = native.site_digest(SitePaths("shop", self.php))
        computed = self.administer(f"env -i PATH=/usr/bin:/bin sh -c {shlex.quote(text)}")
        recorded = plan.evidence.get(kind=PlanEvidence.Kind.SITE_REVALIDATION).fingerprint
        self.assertEqual(computed.split()[0], recorded)
        self.assertLessEqual(site.payload_bytes or 0, 16 * 1024 - 2048)
        page = self.client.get(f"/plans/{plan.pk}/")
        # Applying needs its own permission, which this account lacks.
        self.assertNotContains(page, "Apply plan")

    def test_existing_sites_collide_are_satisfied_or_refused_by_shape(self) -> None:
        self.change_fixture(
            create_site("blog", ("blog.test", "shop.test"), self.php), remove_site("blog", self.php)
        )
        plan = self.prepare()
        self.assertEqual(self.reasons(plan), {Reason.NOT_FOLLOWING}, self.refusals(plan))
        self.assertIn(
            "The site blog already declares shop.test (/etc/nginx/sites-available/blog.conf)",
            self.refusals(plan),
        )

        plan = self.prepare("blog", "blog.test shop.test")
        self.assertTrue(plan.eligible, self.refusals(plan))
        self.assertTrue(plan.no_changes)

        self.change_fixture(
            "useradd --no-create-home --home-dir /var/www/shop --shell /usr/sbin/nologin "
            "--user-group sshop",
            "userdel sshop",
        )
        plan = self.prepare("shop", "www.shop.test")
        self.assertTrue(plan.eligible, self.refusals(plan))
        self.assertIn("Finish", plan.intent)
        self.assertEqual(plan.site_account.command, "")
        self.assertEqual(plan.site_account.predicted_uid, int(self.administer("id -u sshop")))

    def test_inaccessible_evidence_refuses_for_privilege(self) -> None:
        original = self.administer(f"cat {SUDOERS}")
        self.change_fixture(
            f"printf 'deploy ALL=(root) NOPASSWD: /usr/bin/systemd-run\\n' >{SUDOERS}",
            f"printf %s {shlex.quote(original)} >{SUDOERS}",
        )
        plan = self.prepare()
        self.assertEqual(self.reasons(plan), {Reason.PRIVILEGE}, self.refusals(plan))
        self.assertFalse(plan.site_files.exists())

        self.write_config(setting("UNPRIVILEGED_USER"))
        plan = self.prepare()
        self.assertIn(Reason.PRIVILEGE, self.reasons(plan))


@tag("ssh")
@skipUnless(FIXTURES, "Set BARECTL_SSH_TEST_* and the server's container to review sites")
class ProvisionedServerTests(_RemoteSiteTestCase):
    def test_the_root_only_site_is_tolerated_beside_a_new_site(self) -> None:
        plan = self.prepare()
        self.assertTrue(plan.eligible, self.refusals(plan))


@tag("ssh")
@skipUnless(FIXTURES, "Set BARECTL_SSH_TEST_* and the server's container to review sites")
class NameBoundTests(_RemoteSiteTestCase):
    """docs/sites.md#names: the release's own nginx and stock configuration load two sites of
    ten 46-octet names beside the default site; one 47-octet name does not load."""

    def check(
        self, label: str, sites: dict[str, tuple[str, ...]]
    ) -> subprocess.CompletedProcess[str]:
        """``nginx -t`` of a copy of the stock configuration with ``sites`` enabled."""
        # Inside the disposable container: the test's own scratch copy, never /etc/nginx.
        directory = f"/tmp/barectl-bound-{label}"  # noqa: S108
        steps = [
            f"rm -rf {directory} && cp -a /etc/nginx {directory}",
            f"sed -i 's#/etc/nginx/#{directory}/#g' {directory}/nginx.conf",
            f"rm -f {directory}/sites-enabled/private {directory}/sites-available/private",
        ]
        for identifier, names in sites.items():
            source = f"{directory}/sites-available/{identifier}.conf"
            steps.append(_write(source, render_site(identifier, names, ipv6=True), "644"))
            steps.append(f"ln -s {source} {directory}/sites-enabled/{identifier}.conf")
        self.administer(" && ".join(steps))
        self.addCleanup(self.administer, f"rm -rf {directory}")
        return subprocess.run(  # noqa: S603 - the tests' own fixture
            [  # noqa: S607
                "docker",
                "exec",
                setting("CONTAINER"),
                "nginx",
                "-t",
                "-q",
                "-e",
                f"{directory}/error.log",
                "-c",
                f"{directory}/nginx.conf",
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    @staticmethod
    def names(prefix: str, length: int) -> tuple[str, ...]:
        names = tuple(
            f"{prefix}{index}".ljust(length - len(".test"), "a") + ".test"
            for index in range(MAX_NAMES)
        )
        assert all(len(name) == length for name in names)  # noqa: S101 - the fixture's own
        return names

    def test_two_maximal_sites_load_and_a_longer_name_does_not(self) -> None:
        maximal = {
            "first": self.names("first", MAX_NAME_OCTETS),
            "second": self.names("second", MAX_NAME_OCTETS),
        }
        accepted = self.check("maximal", maximal)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        refused = self.check("longer", {"first": ("a" * 42 + ".test",)})
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("could not build server_names_hash", refused.stderr)
        self.assertIn("server_names_hash_bucket_size: 64", refused.stderr)


@tag("ssh")
@skipUnless(FIXTURES, "Set BARECTL_SSH_TEST_* and the server's container to run the helpers")
class PayloadHelperTests(_RemoteSiteTestCase):
    """The draft payload's publication helpers, run as root by the release's own shell and
    tools against a scratch tree in /tmp that mirrors the document root's ownership."""

    def test_files_are_published_only_into_safe_absent_destinations(self) -> None:
        steps = native.site_steps(UNIT, BOOT, 10**12, longest())
        (helpers,) = [step.text for step in steps if step.name == "helpers"]
        content = "<p>ready</p>\n"
        digest = hashlib.sha256(content.encode()).hexdigest()
        # Inside the disposable container: the test's own scratch tree, below root's own
        # directories, since publication checks every directory up to /.
        tree = "/var/lib/barectl-helpers"
        public = f"{tree}/public"
        publish = f"printf '%s\\n' '<p>ready</p>' | w {public} index.html root:www-data 0640"
        script = "\n".join(
            (
                f"rm -rf {tree}; mkdir -m 0755 {tree} && mkdir -m 0750 {public}",
                f"chown root:www-data {public}",
                helpers,
                f"a {public} && echo safe",
                f"{publish} {digest} && echo published",
                f"stat -c '%U %G %a' {public}/index.html; cat {public}/index.html",
                f"m {public}/index.html 'regular file root www-data 640' && echo matches",
                f"{publish} {digest} || echo refused existing",
                f"cat {public}/index.html",
                (
                    f"printf '%s\\n' x | w {public} other.html root:www-data 0640 {digest} "
                    "|| echo refused digest"
                ),
                f"test -e {public}/other.html || echo absent",
                f"ls -A {public} | grep -c '^\\.' || true",
                f"chmod 0770 {public}; a {public} || echo refused group write; chmod 0750 {public}",
                f"ln -s {public} {tree}/link; a {tree}/link || echo refused link",
                (
                    f"mkdir {tree}/other; chown www-data {tree}/other; a {tree}/other "
                    "|| echo refused owner"
                ),
                f"rm -rf {tree}",
            )
        )
        output = self.administer(script)
        self.assertEqual(
            output.splitlines(),
            [
                "safe",
                "published",
                "root www-data 640",
                "<p>ready</p>",
                "matches",
                "refused existing",
                "<p>ready</p>",
                "refused digest",
                "absent",
                # Each refused file's stage stays for inspection; the published one's is gone.
                "2",
                "refused group write",
                "refused link",
                "refused owner",
            ],
        )
