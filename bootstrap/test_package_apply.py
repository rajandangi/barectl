"""Applying a reviewed package profile through the request, worker and rendered audit.

Real views, services, the lifecycle, the ``db_worker`` command, persistence and rendering
run against a simulated Ubuntu server whose systemd answers ``bootstrap.native``. These
tests establish what Barectl submits for a package plan and how it records the outcome:
the exact root versions, the complete reviewed closure in the inline guard, the service
effects, the separate verification and the discovery refresh. They establish nothing
about real APT, dpkg or systemd behaviour; ``bootstrap/test_package_remote.py`` does,
against a disposable Ubuntu server.
"""

import re
import shlex
from typing import override

from django.utils import timezone
from django.utils.html import escape

from discovery.models import DiscoveryAttempt
from discovery.ssh import CommandResult
from operations.models import RemoteOperation
from servers.registration import remove_server

from . import apply, inspection, native
from .fakes import (
    NGINX_DEPENDENCIES,
    NGINX_VERSION,
    NOBLE_PACKAGING,
    PHP_RUNTIME,
    PHP_VERSION,
)
from .models import (
    ApplyRun,
    ConfigurationPlan,
    Execution,
    PlanEffect,
    PlanEvidence,
    PlanRefusal,
    Privilege,
    Verification,
)
from .native import Exit
from .test_apply import ApplyTestCase

Status = RemoteOperation.Status
Effect = PlanEffect.Kind
# Options a reviewed installation must never pass to APT or dpkg.
FORBIDDEN = re.compile(r"--allow|--force|force-|Dpkg::Options|--fix-missing|-m\b|--reinstall")


class PackageApplyTestCase(ApplyTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        # A successful run leaves Nginx installed, enabled and running on the server.
        self.systemd.on_submit = self.installed

    def installed(self) -> None:
        if self.systemd.exit_status == 0:
            self.ubuntu.nginx = "installed"
            self.ubuntu.nginx_active = "active"
            self.ubuntu.nginx_enabled = "enabled"
            self.ubuntu.answer(self.remote)

    def nginx_plan(self) -> ConfigurationPlan:
        plan = self.plan("nginx")
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        return plan

    def fresh(self) -> None:
        self.fresh_server()
        self.systemd.submissions.clear()
        self.systemd.answer(self.remote)
        ApplyRun.objects.all().delete()
        DiscoveryAttempt.objects.all().delete()

    def payload(self) -> str:
        """The payload of the one submission, as the transient unit's shell receives it."""
        (submission,) = self.systemd.submissions
        return shlex.split(submission)[-1]


class PackageApplyTests(PackageApplyTestCase):
    def test_a_reviewed_installation_runs_exactly_and_refreshes_discovery(self) -> None:
        plan = self.nginx_plan()
        self.assertTrue(plan.evidence.filter(kind=PlanEvidence.Kind.PACKAGE_REVALIDATION))
        self.assertIn(Effect.PACKAGE_GUARD, plan.effects.values_list("kind", flat=True))
        page = self.client.get(f"/plans/{plan.pk}/")
        self.assertNotContains(page, f"Apply plan {plan.pk}")
        self.sign_in_with("view_server", "view_configurationplan", "apply_configurationplan")
        self.assertContains(self.client.get(f"/plans/{plan.pk}/"), f"Apply plan {plan.pk}")
        run = self.apply(plan)
        self.assertEqual(run.status, Status.SUCCEEDED, run.failure)
        self.assertEqual(run.execution, Execution.SUCCEEDED)
        self.assertEqual(run.verification, Verification.PASSED)
        self.assertRegex(run.auto_marks_before, r"\A[0-9a-f]{64}\Z")
        payload = self.payload()
        # Only the root is named to APT, at its reviewed version; the closure is the guard's.
        install = re.search(r"apt-get (-q -y .*?) install (\S+) 2>&1", payload)
        if install is None:
            self.fail("The payload runs no installation.")
        self.assertEqual(install[2], f"nginx={NGINX_VERSION}")
        options = shlex.split(install[1])
        self.assertEqual(
            options[:9],
            [
                "-q",
                "-y",
                "--no-remove",
                "-o",
                "APT::Install-Recommends=0",
                "-o",
                "APT::Install-Suggests=0",
                "-o",
                "APT::Get::Fix-Missing=0",
            ],
        )
        self.assertNotRegex(install[1], FORBIDDEN)
        guard = options[10].removeprefix("DPkg::Pre-Install-Pkgs::=")
        self.assertEqual(guard, native.guard(self.actions(plan)))
        self.assertEqual(options[12], "DPkg::Tools::Options::barectl_package_guard()::Version=3")
        for name, version, arch, _ in NGINX_DEPENDENCIES:
            archive = f"{name}_{version.replace(':', '%3a')}_{arch}.deb"
            self.assertIn(f"'U {name} {version} {arch} {archive}'", guard)
            self.assertIn(f"'C {name} {version} {arch}'", guard)
        # The digests are rechecked under the lock before APT runs, and the syntax last.
        self.assertLess(payload.index("sha256sum"), payload.index("apt-get -q -y"))
        self.assertTrue(payload.endswith("/usr/sbin/nginx -t -q || exit 24; exit 0"))
        self.assertNotIn("systemctl start", payload)
        # Discovery refreshes the observations after the run.
        attempt = DiscoveryAttempt.objects.get()
        self.assertEqual(attempt.status, Status.SUCCEEDED)
        page = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(page, "Applied and verified")
        self.assertContains(page, "collected after this run finished")

    def actions(self, plan: ConfigurationPlan) -> list[native.PackageAction]:
        return [
            native.PackageAction(t.step == "install", t.package, t.version, t.architecture)
            for t in plan.transitions.all()
        ]

    def test_the_reviewed_transaction_stays_in_the_audit_after_removal(self) -> None:
        plan = self.nginx_plan()
        expected = [
            f"{t.get_step_display()} {t.package} {t.version} ({t.architecture}) from "
            f"{', '.join(t.origins.splitlines())}"
            for t in plan.transitions.all()
        ]
        self.sign_in_with("view_server", "view_configurationplan", "apply_configurationplan")
        run = self.apply(plan)
        self.assertEqual(run.status, Status.SUCCEEDED, run.failure)
        self.assertEqual(run.reviewed_changes.splitlines(), expected)
        for name, version, arch, _ in NGINX_DEPENDENCIES:
            self.assertIn(f"Install {name} {version} ({arch}) from ", run.reviewed_changes)
            self.assertIn(f"Configure {name} {version} ({arch}) from ", run.reviewed_changes)
        remove_server(self.server)
        self.assertFalse(ConfigurationPlan.objects.exists())
        kept = ApplyRun.objects.get(pk=run.pk)
        self.assertIsNone(kept.plan_id)
        page = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(page, "Web (registration removed)")
        self.assertContains(page, "Reviewed changes")
        for line in expected:
            self.assertContains(page, escape(line))

    def test_a_healthy_baseline_is_never_applied(self) -> None:
        self.ubuntu.nginx = "installed"
        self.ubuntu.upgrades = ()
        plan = self.plan("nginx")
        self.assertTrue(plan.no_changes)
        self.sign_in_with(*self.apply_permissions())
        self.assertNotContains(self.client.get(f"/plans/{plan.pk}/"), "Apply plan")
        self.client.post(f"/plans/{plan.pk}/apply/")
        self.assertFalse(ApplyRun.objects.exists())
        self.assertFalse(self.systemd.submissions)

    def apply_permissions(self) -> tuple[str, ...]:
        return (
            "view_server",
            "view_configurationplan",
            "prepare_configurationplan",
            "apply_configurationplan",
        )

    def test_a_stopped_disabled_baseline_is_enabled_and_started_without_apt(self) -> None:
        self.ubuntu.nginx = "installed"
        self.ubuntu.nginx_active = "inactive"
        self.ubuntu.nginx_enabled = "disabled"
        plan = self.nginx_plan()
        self.assertEqual(
            list(plan.effects.values_list("kind", flat=True)),
            [Effect.SERVICE_ENABLE, Effect.SERVICE_START, Effect.HTTP_LISTENER],
        )
        run = self.apply(plan)
        self.assertEqual(run.status, Status.SUCCEEDED, run.failure)
        payload = self.payload()
        self.assertNotIn("apt-get -q -y", payload)
        self.assertIn(
            "systemctl enable nginx.service || exit 22; systemctl start nginx.service || exit 22",
            payload,
        )

    def test_refusals_before_changes_need_a_new_plan_and_refresh_nothing(self) -> None:
        for status, execution, wording in (
            (Exit.TRANSACTION_REFUSED, Execution.TRANSACTION_REFUSED, "pre-install guard"),
            (Exit.DRIFT, Execution.DRIFT, "changed after review"),
            (Exit.PACKAGE_MANAGER_BUSY, Execution.PACKAGE_MANAGER_BUSY, "frontend lock"),
            (Exit.LOCK_CONFLICT, Execution.LOCK_CONFLICT, "mutation lock"),
        ):
            with self.subTest(execution=execution):
                self.fresh()
                self.systemd.exit_status = status
                self.systemd.result = "exit-code"
                run = self.apply(self.nginx_plan())
                self.assertEqual(run.status, Status.FAILED)
                self.assertEqual(run.execution, execution)
                self.assertEqual(run.verification, Verification.NOT_APPLICABLE)
                self.assertIn(wording, run.failure)
                self.assertFalse(DiscoveryAttempt.objects.exists())
                page = self.client.get(f"/applies/{run.pk}/")
                self.assertContains(page, escape(execution.label))

    def test_failures_after_changes_keep_partial_completion_and_refresh_discovery(self) -> None:
        for status, execution, wording in (
            (Exit.INSTALL_FAILED, Execution.INSTALL_FAILED, "unpacked but not configured"),
            (Exit.SERVICE_FAILED, Execution.SERVICE_FAILED, "refused to enable or start"),
            (Exit.VALIDATION_FAILED, Execution.VALIDATION_FAILED, "syntax check"),
            (Exit.INSTALL_NOT_STARTED, Execution.INSTALL_NOT_STARTED, "before dpkg changed"),
        ):
            with self.subTest(execution=execution):
                self.fresh()
                self.systemd.exit_status = status
                self.systemd.result = "exit-code"
                run = self.apply(self.nginx_plan())
                self.assertEqual(run.status, Status.FAILED)
                self.assertEqual(run.execution, execution)
                self.assertIn(wording, run.failure)
                self.assertNotIn("rolled back", run.failure)
                self.assertEqual(DiscoveryAttempt.objects.count(), 1)

    def test_postconditions_are_verified_separately_from_execution(self) -> None:
        # The payload exits zero, but nothing is installed afterwards.
        self.systemd.on_submit = None
        run = self.apply(self.nginx_plan())
        self.assertEqual(run.status, Status.FAILED)
        self.assertEqual(run.execution, Execution.SUCCEEDED)
        self.assertEqual(run.verification, Verification.FAILED)
        self.assertEqual(run.failure, apply.PACKAGE_VERIFICATION_FAILED)
        self.assertEqual(DiscoveryAttempt.objects.count(), 1)

    def test_a_changed_mark_of_an_earlier_package_fails_verification(self) -> None:
        self.ubuntu.php = "installed"

        def installed_and_marked() -> None:
            self.installed()
            self.ubuntu.automatic = tuple(n for n in self.ubuntu.automatic if n != "php-common")

        self.systemd.on_submit = installed_and_marked
        run = self.apply(self.nginx_plan())
        self.assertEqual(run.execution, Execution.SUCCEEDED)
        self.assertEqual(run.verification, Verification.FAILED)

    def test_unreadable_postconditions_keep_the_execution_outcome(self) -> None:
        def installed_without_listeners() -> None:
            self.installed()
            query = inspection.listeners(80, Privilege.UNAVAILABLE, attributed=False)
            self.remote.results[query] = CommandResult(1, "")

        self.systemd.on_submit = installed_without_listeners
        run = self.apply(self.nginx_plan())
        self.assertEqual(run.status, Status.FAILED)
        self.assertEqual(run.execution, Execution.SUCCEEDED)
        self.assertEqual(run.verification, Verification.UNAVAILABLE)

    def test_a_later_refresh_refuses_an_earlier_package_plan(self) -> None:
        plan = self.nginx_plan()
        self.systemd.on_submit = None
        self.apply()
        self.sign_in_with(*self.apply_permissions())
        response = self.client.post(f"/plans/{plan.pk}/apply/", follow=True)
        self.assertContains(response, "A later package metadata refresh")
        self.assertFalse(ApplyRun.objects.filter(plan_number=plan.pk).exists())

    def test_a_run_queued_before_a_refresh_is_refused_by_the_worker(self) -> None:
        plan = self.nginx_plan()
        run = self.request(plan)
        # A refresh this installation dispatched after the review, recorded as finished.
        ApplyRun.objects.create(
            server=self.server,
            ssh_alias=self.server.ssh_alias,
            status=Status.SUCCEEDED,
            dispatched_at=timezone.now(),
            plan_number=plan.pk + 1000,
            requested_by_name="operator",
            server_name=self.server.name,
            action="metadata_refresh",
            intent="Refresh",
            profile_revision=2,
            reviewed_host_key=plan.host_key,
            boot_id=plan.boot_id,
            admission_deadline_centiseconds=plan.admission_deadline_centiseconds or 0,
            admission_expires_at=plan.admission_expires_at,
            effects="",
            unit_name=native.new_unit_name(),
            execution=Execution.SUCCEEDED,
        )
        self.run_worker()
        run.refresh_from_db()
        self.assertEqual(run.status, Status.FAILED)
        self.assertEqual(run.failure, apply.INVALIDATED)
        self.assertFalse(self.systemd.submissions)


class PackageReviewTests(PackageApplyTestCase):
    def test_local_and_removable_sources_are_refused_for_package_plans(self) -> None:
        self.ubuntu.extra = {
            inspection.CONFIGURED_SOURCES: CommandResult(
                0, "cdrom://Ubuntu 24.04/|noble|main\nhttp://archive.ubuntu.com/ubuntu|noble|main\n"
            )
        }
        plan = self.plan("nginx")
        self.assertIn(PlanRefusal.Reason.PACKAGE_SOURCE, self.reasons(plan))
        self.assertTrue(plan.refusals.filter(text__contains="removable media").exists())

    def test_the_package_digest_must_be_read_and_stable(self) -> None:
        self.ubuntu.extra = {NOBLE_PACKAGING.nginx.revalidation: CommandResult(1, "")}
        plan = self.plan("nginx")
        self.assertIn(PlanRefusal.Reason.INCOMPLETE, self.reasons(plan))
        self.assertFalse(plan.evidence.filter(kind=PlanEvidence.Kind.PACKAGE_REVALIDATION))
        # The digest read after the other evidence differs from the one read before it.
        answers = iter(["a" * 64, "b" * 64])
        self.ubuntu.extra = {}
        self.remote.answers.insert(
            0,
            lambda command: (
                CommandResult(0, f"{next(answers)}  -\n")
                if command == NOBLE_PACKAGING.nginx.revalidation
                else None
            ),
        )
        plan = self.plan("nginx")
        self.assertTrue(plan.refusals.filter(text__contains="changed while Barectl read").exists())


class PhpApplyTests(PackageApplyTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        # A successful run leaves PHP 8.3 FPM and CLI installed, enabled and running.
        self.systemd.on_submit = self.php_installed

    def php_installed(self) -> None:
        if self.systemd.exit_status == 0:
            self.ubuntu.php = "installed"
            self.ubuntu.php_cli_only = False
            self.ubuntu.php_active = "active"
            self.ubuntu.php_enabled = "enabled"
            self.ubuntu.answer(self.remote)

    def php_plan(self) -> ConfigurationPlan:
        plan = self.plan("php")
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        return plan

    def test_a_reviewed_php_installation_runs_exactly_and_is_verified(self) -> None:
        plan = self.php_plan()
        # PHP needs no web server: nothing in the transaction is Nginx.
        self.assertFalse(plan.transitions.filter(package__startswith="nginx").exists())
        run = self.apply(plan)
        self.assertEqual(run.status, Status.SUCCEEDED, run.failure)
        self.assertEqual(run.verification, Verification.PASSED)
        payload = self.payload()
        install = re.search(r" install (\S+ \S+) 2>&1", payload)
        if install is None:
            self.fail("The payload runs no installation.")
        self.assertEqual(install[1], f"php8.3-fpm={PHP_VERSION} php8.3-cli={PHP_VERSION}")
        # The epoch in php-common's version is %-encoded in its archive's name, as APT does.
        self.assertIn(
            "'U php-common 2:93ubuntu2 all php-common_2%3a93ubuntu2_all.deb'",
            native.guard(self.actions(plan)),
        )
        self.assertIn(
            shlex.quote(f"DPkg::Pre-Install-Pkgs::={native.guard(self.actions(plan))}"), payload
        )
        self.assertTrue(payload.endswith("/usr/sbin/php-fpm8.3 -t || exit 24; exit 0"))
        self.assertIn(NOBLE_PACKAGING.php.revalidation, payload)
        # Verification read the pool's socket and the CLI's version.
        commands = self.remote.commands
        self.assertIn(inspection.socket_listeners("/run/php/php8.3-fpm.sock"), commands)
        self.assertIn(PHP_RUNTIME, commands)
        self.assertEqual(DiscoveryAttempt.objects.count(), 1)

    def actions(self, plan: ConfigurationPlan) -> list[native.PackageAction]:
        return [
            native.PackageAction(t.step == "install", t.package, t.version, t.architecture)
            for t in plan.transitions.all()
        ]

    def test_a_partial_baseline_names_only_the_missing_root(self) -> None:
        self.ubuntu.php = "installed"
        self.ubuntu.php_cli_only = True
        self.ubuntu.automatic = (*self.ubuntu.automatic, "php8.3-cli")
        run = self.apply(self.php_plan())
        self.assertEqual(run.status, Status.SUCCEEDED, run.failure)
        install = re.search(r" install (\S+) 2>&1", self.payload())
        if install is None:
            self.fail("The payload runs no installation.")
        # php8.3-cli stays automatically installed: APT is never asked for it.
        self.assertEqual(install[1], f"php8.3-fpm={PHP_VERSION}")

    def test_a_stopped_disabled_pool_is_enabled_and_started_without_apt(self) -> None:
        self.ubuntu.php = "installed"
        self.ubuntu.php_active = "inactive"
        self.ubuntu.php_enabled = "disabled"
        run = self.apply(self.php_plan())
        self.assertEqual(run.status, Status.SUCCEEDED, run.failure)
        payload = self.payload()
        self.assertNotIn("apt-get -q -y", payload)
        self.assertIn(
            "systemctl enable php8.3-fpm.service || exit 22; "
            "systemctl start php8.3-fpm.service || exit 22; /usr/sbin/php-fpm8.3 -t || exit 24",
            payload,
        )

    def test_a_missing_socket_or_another_runtime_fails_verification(self) -> None:
        for case, result in (
            ("socket", (inspection.socket_listeners("/run/php/php8.3-fpm.sock"), "")),
            ("runtime", (PHP_RUNTIME, "PHP 8.2.28 (cli) (built: Mar  1 2026 00:00:00) (NTS)\n")),
        ):
            with self.subTest(case=case):
                self.fresh()
                command, output = result

                def installed_differently(command: str = command, output: str = output) -> None:
                    self.php_installed()
                    self.remote.results[command] = CommandResult(0, output)

                self.systemd.on_submit = installed_differently
                run = self.apply(self.php_plan())
                self.assertEqual(run.execution, Execution.SUCCEEDED)
                self.assertEqual(run.verification, Verification.FAILED)
                self.assertIn("default pool's socket", run.failure)
                self.assertEqual(DiscoveryAttempt.objects.count(), 1)
