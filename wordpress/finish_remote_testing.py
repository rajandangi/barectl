"""Fixtures for the Finish's native suites (docs/wordpress.md#finishing-a-partial-installation).

A partly installed site is made the way the product makes one: Barectl installs through the
dashboard's request, the worker and a real unit, and one administrator command is inserted
between two named fragments of the production body, here an ``exit``, so the run stops at that
boundary exactly as an interrupted run does. Nothing is simulated about the files, tables or
Nginx a Finish then finds. Ground truth is read as root through ``docker exec``.
"""

from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from types import ModuleType
from unittest import mock

from django.test import Client

from bootstrap.models import ApplyRun, ConfigurationPlan, Execution, PlanPreparation, Verification
from discovery.fakes import run_worker
from discovery.services import request_discovery
from operations.models import RemoteOperation
from servers.models import Server

from . import finish_native, install_apply, install_native
from .install_apply_remote_testing import BASE, SECRET_WORDS, SITE_FILE, USER, InstallApplyTestCase
from .install_native import Evidence, Step
from .install_remote_testing import DATABASE, FORM, IDENTIFIER, PRIVATE, PUBLIC
from .models import (
    InstallationReview,
    InstallRunResult,
    PlanWordpressFinish,
    PlanWordpressInstall,
    RunWordpressFinish,
)

Status = RemoteOperation.Status
FINISH_FORM = {
    "finish-title": "Shop & Sons",
    "finish-admin_login": "owner",
    "finish-admin_email": "owner@example.com",
}
# The status an interruption exits with, which no fragment of the body uses.
INTERRUPTED = 77


@contextmanager
def _injected(
    native: ModuleType,
    model: type[PlanWordpressInstall] | type[PlanWordpressFinish],
    plan: ConfigurationPlan,
    after: str,
    step: str,
) -> Iterator[None]:
    """Insert ``step`` after the named fragment of ``native``'s body and bind the plan's
    review to the resulting text, as preparing it would."""
    real = native.body_steps

    def steps(row: InstallationReview, evidence: Evidence, release: str) -> list[Step]:
        built: list[Step] = real(row, evidence, release)
        names = [item.name for item in built]
        built.insert(names.index(after) + 1, Step("injected", step))
        return built

    with mock.patch.object(native, "body_steps", steps):
        row = model.objects.get(plan=plan)
        text = native.body(row, install_apply._evidence(plan), plan.release)
        model.objects.filter(plan=plan).update(body_sha256=install_native.digest(text))
        yield


def injected_install(
    plan: ConfigurationPlan, after: str, step: str
) -> AbstractContextManager[None]:
    return _injected(install_native, PlanWordpressInstall, plan, after, step)


def injected_finish(plan: ConfigurationPlan, after: str, step: str) -> AbstractContextManager[None]:
    return _injected(finish_native, PlanWordpressFinish, plan, after, step)


def review(client: Client, server: Server, address: str, form: dict[str, str]) -> ConfigurationPlan:
    """Discover the server, post ``form`` to a review's address and return its plan."""
    request_discovery(server)
    run_worker()
    response = client.post(f"/servers/{server.pk}/sites/{IDENTIFIER}/wordpress/{address}", form)
    if response.status_code != 302:
        raise AssertionError(response.content[:300])
    run_worker()
    preparation = PlanPreparation.objects.latest("queued_at", "pk")
    plan = ConfigurationPlan.objects.filter(preparation=preparation).first()
    if plan is None:
        raise AssertionError(f"No plan: {preparation.status} {preparation.failure}")
    return plan


def review_install(client: Client, server: Server) -> ConfigurationPlan:
    return review(client, server, "install/prepare/", FORM)


def review_finish(
    client: Client, server: Server, form: dict[str, str] | None = None
) -> ConfigurationPlan:
    return review(client, server, "finish/prepare/", FINISH_FORM if form is None else form)


def apply(client: Client, plan: ConfigurationPlan) -> ApplyRun:
    client.post(f"/plans/{plan.pk}/apply/")
    run = ApplyRun.objects.get(plan_number=plan.pk)
    run_worker()
    run.refresh_from_db()
    return run


def interrupt_installation(
    client: Client, server: Server, after: str, step: str | None = None
) -> ApplyRun:
    """Install through Barectl and stop the unit after the named fragment of its body."""
    plan = review_install(client, server)
    if not plan.eligible:
        raise AssertionError(list(plan.refusals.values_list("text", flat=True)))
    with injected_install(plan, after, step or f"exit {INTERRUPTED}"):
        return apply(client, plan)


class FinishCase(InstallApplyTestCase):
    """A prepared site whose installation can be stopped at a named boundary."""

    def interrupted(self, after: str, step: str | None = None, undo: str = "true") -> ApplyRun:
        """Install through Barectl and stop after the named fragment of its body."""
        self.addCleanup(self.administer, undo)
        run = interrupt_installation(self.client, self.server, after, step)
        self.assertEqual(
            (run.status, run.exit_status),
            (Status.FAILED, INTERRUPTED),
            f"{run.failure}\n{self.journal_tail(run)}",
        )
        return run

    def finish_review(self, form: dict[str, str] | None = None) -> ConfigurationPlan:
        return review_finish(self.client, self.server, form)

    def eligible_finish(self) -> ConfigurationPlan:
        plan = self.finish_review()
        self.assertTrue(plan.eligible, self.texts(plan))
        return plan

    def apply_finish(self, plan: ConfigurationPlan) -> ApplyRun:
        return apply(self.client, plan)

    def mariadb(self, sql: str) -> str:
        return self.administer(
            f'mariadb --no-defaults --protocol=socket -N -B -e "{sql}" 2>/dev/null; true'
        )

    def count(self, table: str) -> str:
        return self.mariadb(f"SELECT COUNT(*) FROM {DATABASE}.{table}").strip()  # noqa: S608 - fixed names

    def deep(self) -> dict[str, str]:
        """Everything a Finish must preserve: every published file's bytes and attributes, the
        private configuration, the accounts and the canonical options, the tables and the
        site file."""
        database = DATABASE
        reads = {
            "files": f"cd {PUBLIC} 2>/dev/null && find . -type f -exec sha256sum {{}} + | sort; :",
            "attributes": (
                f"find {PUBLIC} {PRIVATE} -printf '%y %m %U %G %p\\n' 2>/dev/null | sort; :"
            ),
            "private": f"sha256sum {PRIVATE}/wp-config.php 2>/dev/null; true",
            "site": f"sha256sum {SITE_FILE}",
            "backups": "ls -A /var/backups/nginx",
            "staging": f"ls -A {BASE} | grep '^[.]wp' || true",
        }
        state = {name: self.administer(command) for name, command in reads.items()}
        state["tables"] = self.mariadb(
            f"SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA='{database}' "  # noqa: S608 - fixed names
            "ORDER BY 1"
        )
        state["users"] = self.mariadb(
            f"SELECT ID,user_login,user_pass,user_registered,user_email FROM {database}.wp_users"  # noqa: S608 - fixed names
        )
        state["options"] = self.mariadb(
            f"SELECT option_name,option_value FROM {database}.wp_options "  # noqa: S608 - fixed names
            "WHERE option_name IN ('siteurl','home','blogname','admin_email','auth_key') ORDER BY 1"
        )
        return state

    def assert_finished(self, run: ApplyRun, before: dict[str, str], *, installed: bool) -> None:
        """The Finish succeeded and verified, preserved what existed, ran core installation
        only when the database was empty and left the application served."""
        journal = self.journal(run.unit_name)
        self.assertEqual(
            (run.status, run.execution, run.verification, run.exit_status),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED, 0),
            f"{run.failure}\n{journal[-3000:]}",
        )
        self.assertEqual(InstallRunResult.objects.get(run=run).problems, "")
        self.assertIn("barectl-wordpress: gate verified", journal)
        self.assertIn("barectl-wordpress: HTTPS verified", journal)
        for word in SECRET_WORDS:
            self.assertNotIn(word, journal)
        after = self.deep()
        # Every file that existed is the same file with the same bytes, except the exact
        # placeholder, which publication replaces and keeps as a preimage.
        for line in before["files"].splitlines():
            if not line.endswith("  ./index.html"):
                self.assertIn(line, after["files"].splitlines(), "a file changed or disappeared")
        if before["private"]:
            self.assertEqual(after["private"], before["private"], "the salts were rotated")
        if installed:
            for name in ("users", "options", "tables"):
                self.assertEqual(after[name], before[name], f"{name} changed")
        self.assertEqual(self.tables().strip() == "12" or installed, True)
        self.assertEqual(self.administer(f"ls -A {BASE}").split(), ["private", "public"])
        self.assertEqual(self.curl("/"), "200")
        self.assertEqual(self.curl("/wp-login.php"), "200")
        for denied in ("/wp-config.php", "/wp-content/uploads/x.php", "/.hidden"):
            self.assertEqual(self.curl(denied), "403", denied)
        self.assertEqual(self.curl("/", host="shop.test", scheme="http"), "301")
        self.assertEqual(self.curl("/.well-known/acme-challenge/x", scheme="http"), "404")
        self.assertEqual(self.units().count(run.unit_name), 1)
        self.assertEqual(self.administer_home_residue(), "", "the run's staging was cleaned")
        row = RunWordpressFinish.objects.get(run=run)
        backup = f"/var/backups/nginx/{IDENTIFIER}.conf.{run.unit_name.split('-')[2][:32]}"
        self.assertEqual(self.administer(f"sha256sum {backup}").split()[0], row.gate_sha256)
        self.assertEqual(self.administer(f"stat -c '%U:%G %a' {backup}").strip(), "root:root 600")
        self.assertEqual(self.site_sha(), row.ready_sha256)
        self.assertEqual(
            self.administer(f"stat -c '%U:%G %a' {PUBLIC}/wp-config.php {PRIVATE}/wp-config.php")
            .strip()
            .splitlines(),
            [f"{USER}:www-data 640", f"{USER}:{USER} 600"],
        )
