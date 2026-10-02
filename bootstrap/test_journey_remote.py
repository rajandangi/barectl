"""The v0.2 operator journey on a real, disposable Ubuntu server, end to end.

Tagged ``ssh`` and skipped unless the disposable server is configured, as
``bootstrap/test_apply_remote.py`` describes. The earlier suites qualify each mechanism on
its own; this one runs them in the order an operator meets them, on one server and through
the dashboard: a clean server without package indexes, an explicit metadata refresh, an
Nginx installation that an external listener leaves partly done, recovery with ordinary
tools and a fresh review, the independent PHP profile, satisfied profiles, a rejected
customization, removal refused while a run is reconciled and allowed after it, with the
apply audit kept, and finally this controller's database destroyed and the server
reconstructed by another installation with its own key and database.

Ground truth is read through ``docker exec``. No payload is changed: faults come from the
server's administrator, or from losing a real connection's answer.
"""

import json
import shlex
import subprocess
import sys
from dataclasses import dataclass
from typing import override

from django.apps import apps
from django.contrib.auth.models import Permission
from django.db.models import ProtectedError

from dashboard.testing import TEST_MANIFEST
from discovery.models import ComponentObservation, DiscoveryAttempt
from discovery.test_remote import setting
from operations.models import RemoteOperation
from servers.models import Server

from . import native
from .models import (
    ApplyRun,
    ConfigurationPlan,
    Execution,
    PlanEffect,
    PlanPreparation,
    PlanRefusal,
    Verification,
)
from .test_apply_remote import UPDATE_OUTPUT, _is_submission
from .test_package_remote import RESTORE as RESTORE_NGINX
from .test_php_remote import PhpAcceptanceTestCase
from .test_remote import PHP, PHP_FPM, RELEASE, REMOVE_NGINX

Status = RemoteOperation.Status
Effect = PlanEffect.Kind
Reason = PlanRefusal.Reason
# The package indexes moved aside, as on a server whose lists were cleaned, and put back.
REMOVE_INDEXES = "mv /var/lib/apt/lists /root/lists; mkdir -p /var/lib/apt/lists/partial"
RESTORE_INDEXES = (
    "test ! -d /root/lists || { rm -rf /var/lib/apt/lists; mv /root/lists /var/lib/apt/lists; }"
)
# Another service that takes port 80 on every address as soon as the nginx binary is
# unpacked, before the package's maintainer script would start Nginx.
SQUATTER = (
    "import os, socket, time\n"
    "while not os.path.exists('/usr/sbin/nginx'):\n"
    "    time.sleep(0.01)\n"
    "s = socket.socket(socket.AF_INET6)\n"
    "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
    "s.bind(('::', 80))\n"
    "s.listen()\n"
    "time.sleep(900)\n"
)
STOP_SQUATTER = "pkill -f '[b]arectl-test-squatter'; true"
# Another device: a new installation in its own process with its own database, account,
# SSH configuration and key. It registers the server, discovers it, reviews both profiles
# and a cleanup, and reports what it holds and what its pages show.
SECOND_DEVICE = """
import json
import os
import sys
from pathlib import Path

os.environ["DJANGO_SETTINGS_MODULE"] = "config.settings"
from config import settings as configured

database, ssh_config, manifest, *numbers = sys.argv[1:]
configured.DATABASES["default"]["NAME"] = database
configured.SSH_CONFIG_PATH = ssh_config
configured.VITE_MANIFEST_PATH = Path(manifest)
configured.VITE_DEV_SERVER_URL = ""
configured.ALLOWED_HOSTS = ["testserver"]

import django

django.setup()

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.db.models import ProtectedError
from django.core.management import call_command
from django.test import Client

from bootstrap.models import ApplyRun, ConfigurationPlan, PlanPreparation
from databases.models import PlanCatalogObservation
from tls.models import PlanTlsActivation
from discovery.fakes import run_worker
from discovery.models import (
    ComponentObservation,
    DiscoveryAttempt,
    SiteCertificateObservation,
    SiteDatabaseObservation,
    SiteObservation,
)
from discovery.services import request_discovery
from servers.models import Server

call_command("migrate", verbosity=0)
user = get_user_model().objects.create_user("second-device")
for codename in (
    "view_server",
    "view_configurationplan",
    "prepare_configurationplan",
    "view_databaseplan",
    "prepare_databaseplan",
    "view_tlsplan",
    "prepare_tlsplan",
):
    user.user_permissions.add(Permission.objects.get(codename=codename))
server = Server.objects.create(name="Reconstructed", ssh_alias="disposable-second")
request_discovery(server)
run_worker()
attempt = DiscoveryAttempt.objects.get()
client = Client()
client.force_login(user)
plans = {}
for action in ("nginx", "php", "clear_results"):
    client.post(f"/servers/{server.pk}/plans/prepare/", {"action": action}, secure=True)
    run_worker()
    plan = ConfigurationPlan.objects.latest("pk")
    plans[action] = {"eligible": plan.eligible, "no_changes": plan.no_changes}
cleanup_units = list(plan.native_units.values_list("unit_name", flat=True))
sites_now = list(SiteObservation.objects.filter(snapshot__attempt=attempt))
identifiers = [site.identifier for site in sites_now]
activated = [site.identifier for site in sites_now if site.stage in {"https", "redirect"}]
catalog = {}
activation = {}
if identifiers:
    client.post(
        f"/servers/{server.pk}/databases/prepare/", {"action": "database_inspection"}, secure=True
    )
    run_worker()
    inspection = ConfigurationPlan.objects.latest("pk")
    catalog = {
        row.identifier: {"engine": row.engine, "status": row.status, "conforms": row.conforms}
        for row in PlanCatalogObservation.objects.filter(plan=inspection)
    }
if activated:
    client.post(
        f"/servers/{server.pk}/tls/activation/prepare/",
        {"activation-identifier": activated[0]},
        secure=True,
    )
    run_worker()
    reviewed = ConfigurationPlan.objects.latest("pk")
    activation_plan = PlanTlsActivation.objects.filter(plan=reviewed).first()
    activation = {
        "identifier": activated[0],
        "fingerprint": activation_plan.fingerprint if activation_plan else "",
        "not_after": activation_plan.not_after if activation_plan else "",
        "no_changes": reviewed.no_changes,
    }
components = {
    component.component: {
        "packages": component.packages.splitlines(),
        "units": [f"{u.name} {u.active_state} {u.unit_file_state}"
                  for u in component.service_units.all()],
    }
    for component in ComponentObservation.objects.filter(snapshot__attempt=attempt)
}
snapshot = attempt.snapshot
activity = client.get("/activity/", secure=True).content.decode()
print(json.dumps({
    "discovery": attempt.status,
    "components": components,
    "sites": list(snapshot.nginx_site_files.values_list("name", flat=True)),
    "site_stages": {
        site.identifier: site.stage
        for site in SiteObservation.objects.filter(snapshot__attempt=attempt)
    },
    "site_certificates": {
        certificate.site.identifier: {
            "status": certificate.status,
            "fingerprint": certificate.fingerprint,
            "reference": certificate.site.certificate_reference,
            "renewal": certificate.renewal,
        }
        for certificate in SiteCertificateObservation.objects.filter(
            site__snapshot__attempt=attempt
        )
    },
    "site_bindings": {
        binding.site.identifier: {
            "engine": binding.engine,
            "status": binding.status,
            "conforms": binding.conforms,
        }
        for binding in SiteDatabaseObservation.objects.filter(site__snapshot__attempt=attempt)
    },
    "catalog": catalog,
    "activation": activation,
    "pools": [f"{p.version} {p.name} {p.listen}" for p in snapshot.php_fpm_pools.all()],
    "plans": plans,
    "cleanup_units": cleanup_units,
    "users": list(get_user_model().objects.values_list("username", flat=True)),
    "servers": list(Server.objects.values_list("name", flat=True)),
    "runs": ApplyRun.objects.count(),
    "preparations": PlanPreparation.objects.count(),
    "activity_applies": "Apply:" in activity,
    "activity_names": [name for name in ("Disposable",) if name in activity],
    "earlier_runs": [client.get(f"/applies/{n}/", secure=True).status_code for n in numbers],
}))
"""


@dataclass(frozen=True)
class SecondDevice:
    """What the other installation holds and shows after reconstructing the server."""

    discovery: str
    components: dict[str, dict[str, list[str]]]
    sites: list[str]
    pools: list[str]
    site_stages: dict[str, str]
    site_certificates: dict[str, dict[str, str]]
    site_bindings: dict[str, dict[str, object]]
    catalog: dict[str, dict[str, object]]
    activation: dict[str, object]
    plans: dict[str, dict[str, bool]]
    cleanup_units: list[str]
    users: list[str]
    servers: list[str]
    runs: int
    preparations: int
    activity_applies: bool
    activity_names: list[str]
    earlier_runs: list[int]


class OperatorJourneyTests(PhpAcceptanceTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        for codename in ("delete_server", "clear_native_results"):
            self.user.user_permissions.add(Permission.objects.get(codename=codename))
        self.administer(REMOVE_NGINX)
        self.addCleanup(self.administer, RESTORE_NGINX)
        self.addCleanup(self.administer, STOP_SQUATTER)
        self.remove_php()
        self.administer(REMOVE_INDEXES)
        self.addCleanup(self.administer, RESTORE_INDEXES)

    def nginx_serving(self) -> None:
        self.assertEqual(
            self.administer("systemctl is-enabled nginx; systemctl is-active nginx").split(),
            ["enabled", "active"],
        )
        listening = self.administer("ss -Hltnp sport = :80")
        self.assertIn("0.0.0.0:80", listening)
        self.assertIn("[::]:80", listening)
        self.assertIn('"nginx"', listening)

    def second_device(self, numbers: list[int]) -> SecondDevice:
        directory = self.directory / "second-device"
        directory.mkdir()
        config = directory / "config"
        # Only its own alias and key: nothing of this controller's configuration.
        config.write_text(
            f"Host disposable-second\n  HostName {setting('HOST')}\n  Port {setting('PORT')}\n"
            f"  User {setting('USER')}\n  UserKnownHostsFile {setting('KNOWN_HOSTS')}\n"
            f"  IdentityFile {setting('SECOND_KEY')}\n",
            encoding="utf-8",
        )
        completed = subprocess.run(  # noqa: S603 - the test's own script
            [
                sys.executable,
                "-c",
                SECOND_DEVICE,
                str(directory / "db.sqlite3"),
                str(config),
                str(TEST_MANIFEST),
                *map(str, numbers),
            ],
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr[-3000:])
        return SecondDevice(**json.loads(completed.stdout.strip().splitlines()[-1]))

    def test_from_a_clean_server_to_recovery_removal_and_another_device(self) -> None:
        # A clean server: no Nginx, no PHP, and no package indexes. Installing is refused
        # until the metadata is refreshed through its own reviewed plan.
        refused = self.plan("nginx")
        self.assertIn(Reason.PACKAGE_METADATA, refused.refusals.values_list("reason", flat=True))
        refresh = self.plan()
        self.assertTrue(refresh.eligible)
        self.assertFalse(refresh.transitions.exists())
        run = self.apply(refresh)
        self.assertEqual((run.status, run.verification), (Status.SUCCEEDED, "passed"))
        self.assertRegex(self.journal(run.unit_name), UPDATE_OUTPUT)
        self.assertContains(
            self.client.get(f"/plans/{refused.pk}/"), "A later package metadata refresh"
        )

        # Nginx: while it installs, another service takes port 80, so the package's
        # maintainer script does not start it. The packages are installed exactly; the
        # run fails its postconditions, and nothing is repaired or rolled back.
        nginx = self.eligible_plan("nginx")
        nginx_versions = dict(nginx.transitions.values_list("package", "version"))
        self.administer(
            f"exec python3 -c {shlex.quote(SQUATTER)} barectl-test-squatter", detach=True
        )
        run = self.apply(nginx)
        self.assertEqual(run.status, Status.FAILED)
        self.assertEqual(run.execution, Execution.SUCCEEDED)
        self.assertEqual(run.verification, Verification.FAILED)
        self.assertIn("postconditions do not hold", run.failure)
        self.assertEqual(self.journal(run.unit_name).count(native.GUARD_ADMITTED + "\n"), 1)
        for name, version in nginx_versions.items():
            self.assertEqual(self.status(name)[name], f"{version} ii")
        self.assertEqual(self.administer("systemctl is-active nginx; true").strip(), "failed")
        page = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(page, "Completed successfully")
        self.assertContains(page, "Postconditions do not hold")
        # Discovery was refreshed after the run and shows what is there now.
        attempt = DiscoveryAttempt.objects.filter(server=self.server).latest("pk")
        observed = ComponentObservation.objects.get(snapshot__attempt=attempt, component="nginx")
        self.assertIn("nginx.service", {unit.name for unit in observed.service_units.all()})
        self.assertEqual(observed.service_units.get(name="nginx.service").active_state, "failed")

        # Recovery: a failed unit is refused rather than repaired. The administrator stops
        # the other service and clears the failure with ordinary tools; a fresh review
        # proposes only starting Nginx, applied without APT and verified.
        self.administer(STOP_SQUATTER)
        refused = self.plan("nginx")
        self.assertIn(Reason.SERVICE_UNIT, refused.refusals.values_list("reason", flat=True))
        self.administer("systemctl reset-failed nginx")
        start = self.eligible_plan("nginx")
        self.assertEqual(
            list(start.effects.values_list("kind", flat=True)),
            [Effect.SERVICE_START, Effect.HTTP_LISTENER],
        )
        run = self.apply(start)
        self.assertEqual((run.status, run.verification), (Status.SUCCEEDED, "passed"))
        self.assertNotIn("Reading package lists", self.journal(run.unit_name))
        self.nginx_serving()

        # PHP, independently of Nginx, which it leaves alone.
        nginx_state = self.status("nginx", "nginx-common")
        php = self.eligible_plan("php")
        self.assertNotIn("nginx", set(php.transitions.values_list("package", flat=True)))
        run = self.apply(php)
        self.assertEqual((run.status, run.verification), (Status.SUCCEEDED, "passed"))
        self.assert_serving()
        self.assertEqual(self.status("nginx", "nginx-common"), nginx_state)
        self.nginx_serving()

        # Both profiles are satisfied: no changes, nothing to apply.
        for action in ("nginx", "php"):
            satisfied = self.plan(action)
            self.assertTrue(satisfied.no_changes, action)
            self.assertNotContains(self.client.get(f"/plans/{satisfied.pk}/"), "Apply plan")

        # A customization is refused and never adopted; PHP's review is unaffected.
        self.administer("echo 'server_tokens off;' >/etc/nginx/conf.d/local.conf")
        customized = self.plan("nginx")
        self.assertIn(Reason.CUSTOMIZED, customized.refusals.values_list("reason", flat=True))
        self.assertTrue(customized.refusals.filter(text__contains="local.conf").exists())
        self.assertTrue(self.plan("php").no_changes)
        self.administer("rm /etc/nginx/conf.d/local.conf")
        self.assertTrue(self.plan("nginx").no_changes)

        # Removing the registration is refused while a run is being reconciled, and
        # allowed after Check outcome closes it; the apply audit stays.
        with self.losing(_is_submission, after=True):
            lost = self.apply(self.eligible_plan("metadata_refresh"))
        self.assertEqual(lost.status, Status.RECONCILING)
        removal = f"/servers/{self.server.pk}/remove/"
        self.assertEqual(self.client.post(removal, {"confirm": "remove"}).status_code, 409)
        self.assertTrue(Server.objects.filter(pk=self.server.pk).exists())
        self.wait_terminal(lost.unit_name)
        self.assertEqual(self.check(lost).status, Status.SUCCEEDED)
        runs = sorted(ApplyRun.objects.values_list("pk", flat=True))
        units = set(ApplyRun.objects.values_list("unit_name", flat=True))
        self.assertEqual(len(runs), 5)
        self.assertRedirects(self.client.post(removal, {"confirm": "remove"}), "/")
        self.assertFalse(Server.objects.exists())
        self.assertFalse(DiscoveryAttempt.objects.exists())
        self.assertFalse(PlanPreparation.objects.exists())
        self.assertFalse(ConfigurationPlan.objects.exists())
        self.assertEqual(sorted(ApplyRun.objects.values_list("pk", flat=True)), runs)
        self.assertContains(self.client.get("/activity/"), "Disposable (removed)", count=5)
        self.assertContains(self.client.get(f"/applies/{runs[1]}/"), "(registration removed)")
        # Removal never touched the server: its units are still there.
        self.assertEqual(set(self.units()), units)

        # This controller's database is destroyed. Another installation, with its own
        # account, key and database, reconstructs the server from the server alone.
        self.destroy_records()
        other = self.second_device(runs)
        self.assertEqual(other.discovery, Status.SUCCEEDED)
        self.assertIn(f"nginx {nginx_versions['nginx']}", other.components["nginx"]["packages"])
        self.assertIn("nginx.service active enabled", other.components["nginx"]["units"])
        self.assertIn(f"{PHP_FPM}.service active enabled", other.components["php-fpm"]["units"])
        self.assertEqual(other.sites, ["default"])
        self.assertEqual(other.pools, [f"{RELEASE.php} www {PHP.socket}"])
        for action in ("nginx", "php"):
            self.assertEqual(other.plans[action], {"eligible": True, "no_changes": True})
        # It sees this controller's finished runs only as native units to clear, and
        # none of its accounts, approvals, plans or history.
        self.assertEqual(set(other.cleanup_units), units)
        self.assertEqual(other.users, ["second-device"])
        self.assertEqual(other.servers, ["Reconstructed"])
        self.assertEqual((other.runs, other.preparations), (0, 3))
        self.assertFalse(other.activity_applies)
        self.assertEqual(other.activity_names, [])
        self.assertEqual(other.earlier_runs, [404] * len(runs))

    def destroy_records(self) -> None:
        """Delete every record of this installation, as losing its database would."""
        remaining = list(apps.get_models())
        while remaining:
            protected = []
            for model in remaining:
                try:
                    model._default_manager.all().delete()
                except ProtectedError:
                    protected.append(model)
            if len(protected) == len(remaining):
                raise AssertionError(f"Records could not be deleted: {protected}")
            remaining = protected

    def eligible_plan(self, action: str) -> ConfigurationPlan:
        plan = self.plan(action)
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        return plan
