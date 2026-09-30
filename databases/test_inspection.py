"""The privileged database inspection (docs/databases.md#privileged-inspection).

Discovery's own simulated server answers the inspection's reads, which the inspection runs
as root through noninteractive sudo; nothing else is read or written.
"""

import shlex
from typing import override

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission

from bootstrap.fakes import PREPARATION_READ_ONLY, PreparationTestCase, UbuntuServer
from bootstrap.models import ApplyRun, ConfigurationPlan, PlanPreparation, PlanRefusal
from discovery.fakes import READ_ONLY, add_site, mariadb_rows
from discovery.ssh import CommandResult
from discovery.test_databases import SHOP
from servers.models import Server

from .fakes import DATABASE_APPLY, DATABASE_PERMISSIONS
from .models import PlanCatalogObservation

Reason = PlanRefusal.Reason


class InspectionTests(PreparationTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        add_site(self.remote, "shop", ("shop.test",))
        self.remote.catalogs.mariadb[SHOP] = mariadb_rows(SHOP)
        self.allowed = True
        self.remote.answers.insert(0, self.as_root)

    def as_root(self, command: str) -> CommandResult | None:
        argv = shlex.split(command)
        if argv[:5] == ["sudo", "-n", "-l", "/usr/bin/sh", "-c"]:
            return CommandResult(0 if self.allowed else 1, "")
        if argv[:4] != ["sudo", "-n", "/usr/bin/sh", "-c"] or len(argv) != 5:
            return None
        if not self.allowed:
            return CommandResult(1, "")
        if argv[4] == "id -u":
            return CommandResult(0, "0\n")
        return self.remote.run(argv[4])

    @override
    def assert_read_only(self) -> None:
        for command in self.remote.commands:
            inner = command
            argv = shlex.split(command)
            if argv[:2] == ["sudo", "-n"] and "/usr/bin/sh" in argv:
                inner = argv[-1]
            self.assertTrue(
                READ_ONLY.fullmatch(inner)
                or PREPARATION_READ_ONLY.fullmatch(inner)
                or inner == "id -u",
                f"Not a read-only command: {command}",
            )

    def inspect(self) -> ConfigurationPlan:
        self.sign_in_with(*DATABASE_PERMISSIONS)
        UbuntuServer(self.packaging).answer(self.remote)
        self.client.post(
            f"/servers/{self.server.pk}/databases/prepare/", {"action": "database_inspection"}
        )
        self.run_worker()
        preparation = PlanPreparation.objects.latest("queued_at", "pk")
        return ConfigurationPlan.objects.get(preparation=preparation)

    def test_an_inspection_reads_catalogs_as_root_and_is_never_applied(self) -> None:
        plan = self.inspect()
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        (observation,) = PlanCatalogObservation.objects.filter(plan=plan)
        self.assertEqual(
            (observation.identifier, observation.engine, observation.conforms),
            ("shop", "mariadb", True),
        )
        page = self.client.get(f"/plans/{plan.pk}/")
        self.assertContains(page, "never updates discovery")
        self.assertNotContains(page, f"Apply plan {plan.pk}")
        self.sign_in_with(*DATABASE_APPLY)
        self.client.post(f"/plans/{plan.pk}/apply/")
        self.assertFalse(ApplyRun.objects.exists())
        # Discovery keeps seeing the catalogs as inaccessible: the inspection is not merged.
        self.assertFalse(Server.objects.get().snapshots.exists())

    def test_without_privilege_the_catalogs_stay_inaccessible(self) -> None:
        self.allowed = False
        plan = self.inspect()
        self.assertEqual([refusal.reason for refusal in plan.refusals.all()], [Reason.PRIVILEGE])
        self.assertFalse(PlanCatalogObservation.objects.exists())

    def test_the_inspection_is_hidden_from_other_permissions(self) -> None:
        plan = self.inspect()
        other = get_user_model().objects.create_user("bootstrap-viewer")
        for codename in ("view_server", "view_configurationplan", "view_siteplan"):
            other.user_permissions.add(Permission.objects.get(codename=codename))
        self.client.force_login(other)
        self.assertEqual(self.client.get(f"/plans/{plan.pk}/").status_code, 403)
        activity = self.client.get("/activity/")
        self.assertNotContains(activity, "Privileged database inspection")
