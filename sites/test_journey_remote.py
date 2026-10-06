"""Two sites, from review to reconstruction, on a real, disposable server (docs/sites.md).

An operator creates two sites through the dashboard, the worker and actual systemd. The
server then serves each by Host with its own PHP identity, keeps each site's private data
and socket from the other, is reconstructed by another installation with its own database,
account and key, and shows external edits and removal.
"""

import json
import shlex
import subprocess
import sys
from typing import override
from unittest import mock

from django.contrib.auth.models import Permission

from bootstrap.models import ApplyRun, ConfigurationPlan, PlanPreparation, PlanRefusal
from dashboard.testing import TEST_MANIFEST
from discovery.fakes import current, run_worker
from discovery.services import request_discovery
from discovery.test_remote import setting
from operations.models import RemoteOperation
from servers.registration import remove_server

from . import native
from .convention import render_placeholder
from .models import RunFileChange
from .test_apply_remote import IDENTITY, SiteApplyTestCase
from .test_review_remote import remove_site

Status = RemoteOperation.Status
# A PHP script asking whether its pool's user can reach another site's socket and file.
REACH = (
    "<?php $s = @stream_socket_client('unix:///run/php/sblog.sock', $e, $m, 2);\n"
    "echo $s ? 'socket open' : 'socket denied', ' ';\n"
    "echo @file_get_contents('/var/www/blog/private/data') === false ? 'file denied' : "
    "'file read', \"\\n\";\n"
)

# Another installation: its own database, account and the second key. It registers the
# server, discovers it and reviews both sites again.
OTHER = """
import json
import os
import sys
from pathlib import Path

os.environ["DJANGO_SETTINGS_MODULE"] = "config.settings"
from config import settings as configured

database, ssh_config, manifest = sys.argv[1:4]
finish = len(sys.argv) > 4 and sys.argv[4] == "finish"
configured.DATABASES["default"]["NAME"] = database
configured.SSH_CONFIG_PATH = ssh_config
configured.VITE_MANIFEST_PATH = Path(manifest)
configured.VITE_DEV_SERVER_URL = ""
configured.ALLOWED_HOSTS = ["testserver"]

import django

django.setup()

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.management import call_command
from django.test import Client

from bootstrap.models import ApplyRun, ConfigurationPlan
from discovery.fakes import current, run_worker
from discovery.services import request_discovery
from servers.models import Server

call_command("migrate", verbosity=0)
user = get_user_model().objects.create_user("other-installation")
for codename in ("view_server", "view_siteobservation", "view_siteplan",
                 "prepare_siteplan", "apply_siteplan"):
    user.user_permissions.add(Permission.objects.get(codename=codename))
server = Server.objects.create(name="Reconstructed", ssh_alias="disposable-second")
request_discovery(server)
run_worker()
sites = {
    site.identifier: {
        "state": site.state,
        "names": list(site.server_names),
        "uid": site.account.uid if site.account else None,
    }
    for site in current(server).collected.sites.value
}
client = Client()
client.force_login(user)
reviews = {}
for identifier, names in (("shop", "shop.test www.shop.test"), ("blog", "blog.test")):
    client.post(
        f"/servers/{server.pk}/sites/prepare/",
        {"identifier": identifier, "names": names},
        secure=True,
    )
    run_worker()
    plan = ConfigurationPlan.objects.latest("pk")
    reviews[identifier] = plan.no_changes
finished = None
if finish:
    client.post(f"/servers/{server.pk}/sites/prepare/",
                {"identifier": "shop", "names": "shop.test www.shop.test"}, secure=True)
    run_worker()
    plan = ConfigurationPlan.objects.latest("pk")
    assert plan.eligible and "Finish" in plan.intent
    client.post(f"/plans/{plan.pk}/apply/", secure=True)
    run_worker()
    run = ApplyRun.objects.get()
    finished = {"execution": run.execution, "verification": run.verification,
                "site": {item.identifier: item.state
                         for item in current(server).collected.sites.value}}
report = {"sites": sites, "reviews": reviews, "runs": ApplyRun.objects.count()}
if finish:
    report["finished"] = finished
print(json.dumps(report))
"""


class SiteJourneyTests(SiteApplyTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        for codename in ("view_configurationplan", "prepare_configurationplan", "delete_server"):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        # Discovery reads the password lock as a member of the shadow group.
        self.addCleanup(self.administer, f"gpasswd -d {setting('USER')} shadow >/dev/null")
        self.administer(f"usermod -aG shadow {setting('USER')}")

    def create(self, identifier: str, names: str) -> ApplyRun:
        run = self.apply_site(self.site_plan(identifier, names))
        self.assertEqual(run.status, Status.SUCCEEDED, run.failure)
        return run

    def put(self, identifier: str, name: str, text: str) -> None:
        path = f"/var/www/{identifier}/public/{name}"
        self.administer(
            f"printf %s {shlex.quote(text)} >{path} && chown s{identifier}:www-data {path} "
            f"&& chmod 640 {path}"
        )

    def ids(self, identifier: str) -> str:
        fields = self.administer(f"getent passwd s{identifier}").split(":")
        return f"{fields[2]} {fields[3]}"

    def other_installation(self, *, finish: bool = False) -> str:
        directory = self.directory / "other"
        directory.mkdir()
        process = subprocess.run(  # noqa: S603 - the test's own script
            [
                sys.executable,
                "-c",
                OTHER,
                str(directory / "db.sqlite3"),
                str(self.config),
                str(TEST_MANIFEST),
                "finish" if finish else "",
            ],
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        self.assertEqual(process.returncode, 0, process.stderr[-3000:])
        return process.stdout.strip().splitlines()[-1]

    def test_a_fresh_controller_finishes_an_interrupted_site_without_previous_records(self) -> None:
        self.create("blog", "blog.test")
        plan = self.site_plan()
        real = native.site_steps

        def interrupt(unit: str, boot: str, deadline: int, change: native.SiteChange) -> str:
            steps = real(unit, boot, deadline, change)
            names = [step.name for step in steps]
            steps.insert(names.index("site file") + 1, native.Step("interruption", "kill -9 $$"))
            return "; ".join(step.text for step in steps)

        with mock.patch.object(native, "site_payload", interrupt):
            run = self.apply_site(plan)
        self.assertEqual(run.execution, "killed", run.failure)
        identity = self.ids("shop")
        other = json.loads(self.other_installation(finish=True))
        self.assertEqual(other["sites"]["shop"]["state"], "partly_applied")
        self.assertEqual(other["runs"], 1)
        self.assertEqual(other["finished"]["execution"], "succeeded")
        self.assertEqual(other["finished"]["verification"], "passed")
        self.assertEqual(other["finished"]["site"]["shop"], "managed")
        self.assertEqual(self.ids("shop"), identity)
        self.assertEqual(self.get("shop.test"), render_placeholder("shop"))

    def test_two_sites_serve_apart_and_another_installation_reconstructs_them(self) -> None:
        shop = self.create("shop", "shop.test www.shop.test")
        blog = self.create("blog", "blog.test")
        # Host routing, static content and each site's own PHP identity.
        self.assertEqual(self.get("www.shop.test"), render_placeholder("shop"))
        self.assertEqual(self.get("blog.test", address="[::1]"), render_placeholder("blog"))
        self.assertIn("Welcome to nginx", self.get("other.test"))
        self.put("shop", "who.php", IDENTITY)
        self.put("blog", "who.php", IDENTITY)
        self.assertEqual(self.get("shop.test", "/who.php"), f"{self.ids('shop')}\n")
        self.assertEqual(self.get("blog.test", "/who.php"), f"{self.ids('blog')}\n")
        self.assertNotEqual(self.ids("shop"), self.ids("blog"))
        # Neither site's user can read the other's private data or use its socket.
        self.administer(
            "printf 'blog secret\\n' >/var/www/blog/private/data && "
            "chown sblog:sblog /var/www/blog/private/data && chmod 600 /var/www/blog/private/data"
        )
        denied = subprocess.run(  # noqa: S603 - the tests' own container
            [  # noqa: S607
                "docker",
                "exec",
                setting("CONTAINER"),
                "runuser",
                "-u",
                "sshop",
                "--",
                "cat",
                "/var/www/blog/private/data",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(denied.returncode, 0)
        self.assertIn("Permission denied", denied.stderr)
        self.put("shop", "reach.php", REACH)
        self.assertEqual(self.get("shop.test", "/reach.php"), "socket denied file denied\n")
        # Dotfiles and PHP beyond the script path are refused.
        self.put("shop", ".env", "secret\n")
        self.assertEqual(self.get("shop.test", "/.env"), "")
        self.assertEqual(self.get("shop.test", "/who.php/extra"), "")

        # Repeating a request changes nothing; the stock Nginx profile is refused as
        # customized, as its admission is unchanged.
        self.assertTrue(self.site_plan("shop", "shop.test www.shop.test").no_changes)
        self.client.post(f"/servers/{self.server.pk}/plans/prepare/", {"action": "nginx"})
        run_worker()
        nginx = ConfigurationPlan.objects.latest("pk")
        self.assertFalse(nginx.eligible)
        customized = nginx.refusals.filter(reason=PlanRefusal.Reason.CUSTOMIZED)
        self.assertIn("/etc/nginx/sites-available/shop.conf", customized.get().text)

        # Removing the registration keeps both runs' audit, with their reviewed files.
        remove_server(self.server)
        self.assertEqual(ApplyRun.objects.filter(server__isnull=True).count(), 2)
        self.assertEqual(RunFileChange.objects.filter(run=shop).count(), 5)
        self.assertEqual(RunFileChange.objects.filter(run=blog).count(), 5)
        self.assertFalse(PlanPreparation.objects.exists())
        page = self.client.get(f"/applies/{shop.pk}/")
        self.assertContains(page, "registration removed")
        self.assertContains(page, "Publish /etc/nginx/sites-available/shop.conf")

        # Another installation with its own database and key reconstructs both sites and
        # reviews them as already satisfied.
        other = json.loads(self.other_installation())
        self.assertEqual(other["runs"], 0)
        sites = other["sites"]
        self.assertEqual(
            {name: site["state"] for name, site in sites.items()},
            {"shop": "managed", "blog": "managed"},
        )
        self.assertEqual(sites["shop"]["names"], ["shop.test", "www.shop.test"])
        self.assertEqual(other["reviews"], {"shop": True, "blog": True})

    def test_external_edits_and_removal_are_observed(self) -> None:
        self.create("shop", "shop.test www.shop.test")
        self.create("blog", "blog.test")
        self.administer(
            f"sed -i 's/pm.max_children = 5/pm.max_children = 50/' "
            f"/etc/php/{self.php}/fpm/pool.d/shop.conf && systemctl reload php{self.php}-fpm"
        )
        self.administer(remove_site("blog", self.php))
        request_discovery(self.server)
        run_worker()
        sites = {site.identifier: site for site in current(self.server).collected.sites.value}
        self.assertNotIn("blog", sites)
        self.assertEqual(sites["shop"].state, "changed", sites["shop"].expected)
        self.assertEqual(sites["shop"].file, f"/etc/php/{self.php}/fpm/pool.d/shop.conf")
        self.assertIn("pm.max_children = 5", sites["shop"].expected)
        # A new review refuses the edited pool rather than adopting or replacing it.
        self.client.post(
            f"/servers/{self.server.pk}/sites/prepare/",
            {"identifier": "shop", "names": "shop.test www.shop.test"},
        )
        run_worker()
        plan = ConfigurationPlan.objects.latest("pk")
        self.assertFalse(plan.eligible)
        self.assertIn(
            f"/etc/php/{self.php}/fpm/pool.d/shop.conf",
            " ".join(plan.refusals.values_list("text", flat=True)),
        )
