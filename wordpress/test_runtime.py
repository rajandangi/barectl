"""The WordPress PHP runtime plan's workflow (docs/wordpress.md#php-runtime).

Real views, services, the lifecycle, the worker, persistence and rendering run; only remote
execution is substituted, with ``SiteServer`` answering at ``discovery.ssh.connect``.
"""

import re
import shlex
import subprocess
from dataclasses import replace
from typing import override
from unittest import mock

from django.test import SimpleTestCase
from django.utils import timezone

from bootstrap import apply as bootstrap_apply
from bootstrap import native
from bootstrap.fakes import (
    BUILTIN_MODULES,
    WORDPRESS_DRIVERS,
    NativeSystemd,
)
from bootstrap.models import (
    Action,
    ApplyRun,
    ConfigurationPlan,
    Execution,
    PlanEffect,
    PlanPreparation,
    PlanRefusal,
    Verification,
)
from bootstrap.profiles import WORDPRESS_BUILTINS, WORDPRESS_PACKAGES
from databases import drivers
from discovery.fakes import COLLECTED, record_attempt
from discovery.models import DiscoveryAttempt, ObservationOutcome, SiteState, WebStackComponent
from discovery.snapshot import (
    Observation,
    ObservedSite,
    Package,
    SiteAccount,
    WebStackComponentObservation,
    save_snapshot,
)
from operations.models import RemoteOperation
from servers.models import Server
from servers.testing import HTMX_FRAGMENT
from sites.convention import SitePaths
from sites.fakes import SiteTestCase

from . import qualification, qualification_testing, runtime, runtime_native
from .models import (
    PlanRuntimeCapability,
    PlanWordpressRuntime,
    RunRuntimeCapability,
    RuntimeRunResult,
    RunWordpressRuntime,
    WordpressRequest,
)
from .runtime_native import Exit as runtime_exit

Reason = PlanRefusal.Reason
Effect = PlanEffect.Kind
VIEW = ("view_server", "view_siteobservation", "view_configurationplan")
PREPARE = (*VIEW, "prepare_configurationplan")
APPLY = (*PREPARE, "apply_configurationplan")
# What applying adds to preparation's reads: the submission, its inspection and the
# verification's reads.
APPLY_READS = re.compile(
    r"\A(sudo -n (-l )?)?/usr/bin/systemd-run --unit=barectl-apply-[0-9a-f]{32}"
    r"|\A(id -u|cat /proc/sys/kernel/random/boot_id; systemctl show .*)\Z"
    r"|\Asystemctl list-units .*|\Asha256sum /var/lib/dpkg/status.*"
    r"|\Aapt-mark (showauto|showmanual).*"
    r"|\Areadlink -f -- /etc/php/8\.[35]/(fpm|cli)/conf\.d/\S+\Z",
    re.DOTALL,
)


RECORDED_MATRIX = qualification.COMBINATIONS


class RuntimeTestCase(SiteTestCase):
    """A convention site `blog` on a server with PHP, observed by its controller."""

    @override
    def setUp(self) -> None:
        self.site_observed = True
        super().setUp()
        self.enterContext(qualification_testing.simulated_servers_qualified())
        self.site.add_site("blog", ("blog.example.com",))
        self.record_php_snapshot()

    @override
    def record_php_snapshot(self) -> None:
        attempt = record_attempt(self.server, DiscoveryAttempt.Status.SUCCEEDED)
        component = WebStackComponentObservation(
            WebStackComponent.PHP_FPM,
            Observation(
                ObservationOutcome.OBSERVED,
                ("dpkg-query",),
                "",
                (Package(f"php{self.site.php}-fpm", self.packaging.php_version),),
            ),
            Observation(ObservationOutcome.OBSERVED, ("systemctl",), "", ()),
        )
        sites: tuple[ObservedSite, ...] = ()
        if getattr(self, "site_observed", False) and "blog" in self.site.sites:
            sites = (
                ObservedSite(
                    "blog",
                    ("blog.example.com",),
                    self.site.php,
                    SiteAccount(1003, 1003, "/var/www/blog", "/usr/sbin/nologin"),
                    SiteState.MANAGED,
                    ObservationOutcome.OBSERVED,
                ),
            )
        collected = replace(
            COLLECTED,
            components=(*COLLECTED.components, component),
            sites=Observation(ObservationOutcome.OBSERVED, (), "", sites),
        )
        save_snapshot(attempt, collected, timezone.now())

    def prepare_runtime(self, *, perms: tuple[str, ...] = PREPARE) -> PlanPreparation:
        self.sign_in_with(*perms)
        self.site.answer(self.remote)
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/blog/wordpress/runtime/prepare/",
            headers=HTMX_FRAGMENT,
        )
        self.assertEqual(response.status_code, 200)
        self.run_worker()
        return PlanPreparation.objects.latest("queued_at", "pk")

    def runtime_plan(self) -> ConfigurationPlan:
        preparation = self.prepare_runtime()
        plan = ConfigurationPlan.objects.filter(preparation=preparation).first()
        if plan is None:
            raise AssertionError(f"No plan: {preparation.status} {preparation.failure}")
        return plan

    def texts(self, plan: ConfigurationPlan) -> str:
        return " ".join(plan.refusals.values_list("text", flat=True))

    @property
    def packages(self) -> list[str]:
        php = self.packaging.release.php
        return [f"php{php}-{suffix}" for suffix, _ in WORDPRESS_PACKAGES]


class RuntimeReviewTests(RuntimeTestCase):
    def test_a_site_without_the_baseline_gets_an_exact_reviewed_transaction(self) -> None:
        plan = self.runtime_plan()
        self.assertTrue(plan.eligible, self.texts(plan))
        self.assertEqual(plan.action, Action.PHP_WORDPRESS)
        self.assertEqual(plan.php_version, self.packaging.release.php)
        self.assertEqual(
            list(plan.roots.values_list("name", "version", "installed")),
            [(name, self.packaging.php_version, False) for name in self.packages],
        )
        installed = list(plan.transitions.filter(step="install").values_list("package", flat=True))
        for name in self.packages:
            self.assertIn(name, installed)
        self.assertIn("libgd3", installed)
        kinds = list(plan.effects.values_list("kind", flat=True))
        for kind in (
            Effect.PACKAGES,
            Effect.PACKAGE_GUARD,
            Effect.SERVICE_RELOAD,
            Effect.WORDPRESS_RUNTIME,
            Effect.INVALIDATES_PLANS,
            Effect.NO_ROLLBACK,
        ):
            self.assertIn(kind, kinds)
        self.assertNotIn(Effect.DRIVER_MODULES, kinds)

    def test_the_request_binds_the_site_and_the_plan_keeps_its_branch_and_probe(self) -> None:
        preparation = self.prepare_runtime()
        self.assertEqual(WordpressRequest.objects.get(preparation=preparation).identifier, "blog")
        plan = ConfigurationPlan.objects.get(preparation=preparation)
        review = PlanWordpressRuntime.objects.get(plan=plan)
        paths = self.site.site_paths("blog")
        self.assertEqual(
            (review.identifier, review.php_version, review.php_supply, review.socket),
            ("blog", self.packaging.release.php, "ubuntu", paths.socket),
        )
        self.assertEqual((review.uid, review.gid), (1003, 1003))
        self.assertEqual(review.probe_path, f"/var/www/blog/wpprobe-{review.probe_token}.php")
        self.assertEqual(review.probe_content, runtime.render_probe(review.probe_token))
        self.assertEqual(review.probe_sha256, runtime.digest(review.probe_content))
        self.assertEqual(
            list(plan.driver_pools.values_list("name", "default")), [("www", True), ("blog", False)]
        )

    def test_the_observed_capabilities_are_kept_with_the_plan_and_its_time(self) -> None:
        plan = self.runtime_plan()
        rows = {row.name: row for row in PlanRuntimeCapability.objects.filter(plan=plan)}
        self.assertEqual(sorted(rows), sorted(item.name for item in runtime.CAPABILITIES))
        self.assertEqual(rows["mysqli"].state, "planned")
        self.assertEqual(rows["mysqli"].package, f"php{self.site.php}-mysql")
        self.assertFalse(rows["mysqli"].cli)
        self.assertEqual(
            {name: rows[name].state for name in WORDPRESS_BUILTINS},
            dict.fromkeys(WORDPRESS_BUILTINS, "enabled"),
        )
        self.assertTrue(rows["json"].cli and rows["json"].fpm)
        self.assertLessEqual(plan.collected_at, timezone.now())


class RuntimeSatisfiedTests(RuntimeTestCase):
    def test_satisfied_packages_need_no_transaction(self) -> None:
        self.site.drivers = WORDPRESS_DRIVERS
        plan = self.runtime_plan()
        self.assertTrue(plan.eligible, self.texts(plan))
        self.assertTrue(plan.no_changes)
        self.assertEqual(plan.transitions.count(), 0)
        self.assertEqual(
            list(plan.effects.values_list("kind", flat=True)).count(Effect.NO_CHANGES), 1
        )
        self.assertNotIn(Effect.WORDPRESS_RUNTIME, plan.effects.values_list("kind", flat=True))
        states = set(
            PlanRuntimeCapability.objects.filter(plan=plan).values_list("state", flat=True)
        )
        self.assertEqual(states, {"enabled"})

    def test_only_the_missing_packages_are_requested(self) -> None:
        self.site.drivers = ("mysql", "curl")
        plan = self.runtime_plan()
        self.assertTrue(plan.eligible, self.texts(plan))
        php = self.packaging.release.php
        self.assertEqual(
            list(plan.roots.values_list("name", "installed")),
            [(name, name in {f"php{php}-mysql", f"php{php}-curl"}) for name in self.packages],
        )
        installs = set(plan.transitions.filter(step="install").values_list("package", flat=True))
        self.assertNotIn(f"php{php}-mysql", installs)
        self.assertIn(f"php{php}-intl", installs)
        rows = {row.name: row.state for row in PlanRuntimeCapability.objects.filter(plan=plan)}
        self.assertEqual(
            (rows["mysqli"], rows["curl"], rows["intl"]), ("enabled", "enabled", "planned")
        )


class RuntimeRefusalTests(RuntimeTestCase):
    @override
    def reasons(self, plan: ConfigurationPlan) -> list[str]:
        return list(plan.refusals.values_list("reason", flat=True))

    def test_php_must_be_installed_first(self) -> None:
        self.site.ubuntu.php = "absent"
        plan = self.runtime_plan()
        self.assertFalse(plan.eligible)
        self.assertIn(Reason.PREREQUISITE, self.reasons(plan))

    def test_an_architecture_without_native_statuses_gets_no_runtime_plan(self) -> None:
        with mock.patch.object(qualification, "COMBINATIONS", RECORDED_MATRIX):
            plan = self.runtime_plan()
        self.assertFalse(plan.eligible)
        self.assertIn(Reason.UNSUPPORTED_VERSION, self.reasons(plan))
        self.assertIn("amd64 is not qualified", self.texts(plan))

    def test_a_missing_builtin_capability_refuses_without_installing_it(self) -> None:
        self.site.ubuntu.removed_builtins = ("json",)
        plan = self.runtime_plan()
        self.assertFalse(plan.eligible)
        self.assertIn(Reason.CUSTOMIZED, self.reasons(plan))
        self.assertIn("does not load json (PHP-FPM); json (the CLI)", self.texts(plan))
        self.assertIn("never installs or repairs", self.texts(plan))

    def test_an_installed_module_the_cli_does_not_load_refuses(self) -> None:
        self.site.drivers = WORDPRESS_DRIVERS
        listed = "mysqlnd mysqli pdo_mysql curl xml dom simplexml xmlreader xmlwriter xsl mbstring"
        self.site.ubuntu.cli_modules = (*listed.split(), "zip", "gd", *BUILTIN_MODULES)
        plan = self.runtime_plan()
        self.assertFalse(plan.eligible)
        self.assertIn("intl (not loaded by the CLI)", self.texts(plan))

    def test_a_module_php_fpm_does_not_load_refuses(self) -> None:
        self.site.drivers = WORDPRESS_DRIVERS
        self.site.ubuntu.unloaded_modules = ("gd",)
        plan = self.runtime_plan()
        self.assertFalse(plan.eligible)
        self.assertIn("gd (not loaded)", self.texts(plan))

    def test_an_installed_php_the_archive_no_longer_offers_is_refused(self) -> None:
        php = self.packaging.release.php
        older = "8.3.6-0ubuntu0.24.04.5" if php == "8.3" else "8.5.4-0ubuntu1.1"
        self.site.ubuntu.installed_versions = {f"php{php}-common": older}
        plan = self.runtime_plan()
        self.assertFalse(plan.eligible)
        self.assertIn("could not be authenticated from native evidence", self.texts(plan))
        self.assertEqual(plan.transitions.count(), 0)

    def test_a_held_package_is_refused(self) -> None:
        self.site.ubuntu.holds = (f"php{self.packaging.release.php}-gd",)
        plan = self.runtime_plan()
        self.assertFalse(plan.eligible)
        self.assertIn(Reason.HELD_PACKAGE, self.reasons(plan))

    def test_a_site_that_is_not_complete_is_refused(self) -> None:
        self.site.paths.pop(self.site.site_paths("blog").private)
        plan = self.runtime_plan()
        self.assertFalse(plan.eligible, plan.refusals.all())
        self.assertEqual(plan.runtime_capabilities.count(), 0)
        self.assertFalse(PlanWordpressRuntime.objects.filter(plan=plan).exists())

    def test_a_third_party_supply_is_not_enabled(self) -> None:
        selected = drivers.DriverDraft(
            Action.PHP_WORDPRESS, "Install.", None, None, php_version="8.4", php_supply="sury"
        )
        with mock.patch.object(drivers, "prepare", return_value=selected):
            draft = runtime.prepare(mock.Mock(), "blog")
        self.assertFalse(draft.eligible)
        self.assertEqual([reason for reason, _ in draft.refusals], [Reason.UNSUPPORTED_VERSION])
        self.assertIn("has not completed Barectl's qualification", draft.refusals[0][1])
        self.assertEqual(draft.effects, [])


class RuntimeApplyTests(RuntimeTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.systemd = NativeSystemd()
        self.systemd.answer(self.remote)
        self.systemd.on_submit = self.installed
        self.enterContext(mock.patch.object(bootstrap_apply, "POLL_INTERVAL", 0))

    @override
    def assert_read_only(self) -> None:
        self.remote.commands[:] = [c for c in self.remote.commands if not APPLY_READS.match(c)]
        super().assert_read_only()

    def installed(self) -> None:
        if self.systemd.exit_status == 0:
            self.site.drivers = WORDPRESS_DRIVERS
            self.site.answer(self.remote)

    def apply(self) -> ApplyRun:
        plan = self.runtime_plan()
        self.assertTrue(plan.eligible, self.texts(plan))
        self.sign_in_with(*APPLY)
        self.client.post(f"/plans/{plan.pk}/apply/")
        self.run_worker()
        return ApplyRun.objects.get(plan_number=plan.pk)

    @property
    def payload(self) -> str:
        (submission,) = self.systemd.submissions
        return shlex.split(submission)[-1]

    def test_the_run_installs_reloads_probes_and_verifies(self) -> None:
        run = self.apply()
        php = self.packaging.release.php
        self.assertEqual(
            (run.status, run.execution, run.verification),
            (RemoteOperation.Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED),
            run.failure,
        )
        payload = self.payload
        requested = " ".join(f"{name}={self.packaging.php_version}" for name in self.packages)
        self.assertIn(f"install {requested}", payload)
        check = payload.index(f"/usr/sbin/php-fpm{php} -t")
        reload = payload.index(f"systemctl reload php{php}-fpm.service || exit 26")
        probe = payload.index("wpprobe-")
        self.assertLess(check, reload)
        self.assertLess(reload, probe)
        self.assertIn(f"/run/php/php{php}-fpm.sock /run/php/sblog.sock", payload)
        self.assertIn(f"runuser -u sblog -- /usr/bin/env -i /usr/bin/php{php} ", payload)
        self.assertTrue(payload.rstrip().endswith("exit 0"))
        self.assertNotIn("php8.4", payload)
        self.assertNotIn("wp-cli", payload)
        self.assertIn(f"Install php{php}-gd", run.reviewed_changes)
        self.assertIn("temporary probe /var/www/blog/wpprobe-", run.reviewed_changes)

    def test_the_review_sizes_the_payload_it_will_submit(self) -> None:
        estimates: list[int | None] = []
        real = runtime.payload_size

        def measured(draft: runtime.RuntimeDraft) -> int | None:
            estimates.append(real(draft))
            return estimates[-1]

        with mock.patch.object(runtime, "payload_size", measured):
            self.apply()
        (estimate,) = estimates
        actual = len(self.payload.encode())
        self.assertIsNotNone(estimate)
        self.assertAlmostEqual(estimate or 0, actual, delta=16)
        self.assertLess(actual, native.MAX_PAYLOAD)

    def test_a_review_that_cannot_be_submitted_in_one_run_is_refused(self) -> None:
        with mock.patch.object(native, "MAX_PAYLOAD", 2000):
            plan = self.runtime_plan()
        self.assertFalse(plan.eligible)
        self.assertIn(Reason.PAYLOAD_TOO_LARGE, plan.refusals.values_list("reason", flat=True))
        self.assertIn("Barectl submits in one run", self.texts(plan))
        self.assertNotIn(Effect.WORDPRESS_RUNTIME, plan.effects.values_list("kind", flat=True))

    def test_the_run_keeps_the_review_and_separately_verified_readiness(self) -> None:
        run = self.apply()
        plan = ConfigurationPlan.objects.get(pk=run.plan_number)
        review = RunWordpressRuntime.objects.get(run=run)
        self.assertEqual(
            review.probe_token, PlanWordpressRuntime.objects.get(plan=plan).probe_token
        )
        self.assertEqual(
            RunRuntimeCapability.objects.filter(run=run).count(),
            len(runtime.CAPABILITIES),
        )
        result = RuntimeRunResult.objects.get(run=run)
        self.assertEqual(result.problems, "")
        page = self.client.get(f"/applies/{run.pk}/")
        self.assertContains(page, "list every baseline capability")
        self.assertContains(page, "temporary probe confirmed the site&#x27;s own pool")

    def test_the_finished_audit_survives_removing_the_server(self) -> None:
        run = self.apply()
        from servers.registration import remove_server

        remove_server(self.server)
        self.assertTrue(RunWordpressRuntime.objects.filter(run=run).exists())
        self.assertTrue(RuntimeRunResult.objects.filter(run=run).exists())

    def test_a_probe_that_finds_different_capabilities_is_named_and_not_verified(self) -> None:
        self.systemd.exit_status = runtime_exit.CAPABILITIES_DIFFER
        self.systemd.result = "exit-code"
        run = self.apply()
        self.assertEqual(run.execution, Execution.CAPABILITY_FAILED)
        self.assertIn("did not report every baseline capability", run.failure)
        self.assertIn("leftover wpprobe-*.php", run.failure)
        self.assertEqual(run.verification, Verification.NOT_APPLICABLE)
        self.assertFalse(RuntimeRunResult.objects.filter(run=run).exists())

    def test_a_probe_that_cannot_be_removed_is_named(self) -> None:
        self.systemd.exit_status = runtime_exit.PROBE_LEFT
        self.systemd.result = "exit-code"
        run = self.apply()
        self.assertEqual(run.execution, Execution.CAPABILITY_FAILED)
        self.assertIn("could not be removed", run.failure)

    def test_changed_evidence_refuses_before_any_package_changes(self) -> None:
        self.systemd.exit_status = native.Exit.DRIFT
        self.systemd.result = "exit-code"
        run = self.apply()
        self.assertEqual(run.execution, Execution.DRIFT)
        self.assertEqual(run.verification, Verification.NOT_APPLICABLE)
        self.assertIn("changed after review", run.failure)

    def test_a_refused_transaction_changes_nothing(self) -> None:
        self.systemd.exit_status = native.Exit.TRANSACTION_REFUSED
        self.systemd.result = "exit-code"
        run = self.apply()
        self.assertEqual(run.execution, Execution.TRANSACTION_REFUSED)
        self.assertIn("pre-install guard stopped APT", run.failure)

    def test_a_failed_reload_is_named_without_a_probe(self) -> None:
        self.systemd.exit_status = native.Exit.RELOAD_FAILED
        self.systemd.result = "exit-code"
        run = self.apply()
        self.assertEqual(run.execution, Execution.RELOAD_FAILED)
        self.assertIn("could not reload the service", run.failure)

    def test_a_cli_that_lost_a_capability_fails_verification(self) -> None:
        def installed_without_gd_in_the_cli() -> None:
            self.installed()
            self.site.ubuntu.cli_modules = ("mysqli", "curl", *BUILTIN_MODULES)
            self.site.answer(self.remote)

        self.systemd.on_submit = installed_without_gd_in_the_cli
        run = self.apply()
        self.assertEqual(run.verification, Verification.FAILED)
        result = RuntimeRunResult.objects.get(run=run)
        self.assertIn("gd is not loaded by the CLI.", result.problems)
        self.assertIn("gd is not loaded by the CLI.", run.failure)

    def test_a_site_pool_that_does_not_listen_again_fails_verification(self) -> None:
        def installed_without_the_site_socket() -> None:
            self.installed()
            self.site.sockets.discard(self.site.site_paths("blog").socket)

        self.systemd.on_submit = installed_without_the_site_socket
        run = self.apply()
        self.assertEqual(run.verification, Verification.FAILED)
        self.assertIn(f"{self.site.site_paths('blog').socket} is not listening.", run.failure)

    def test_applying_needs_its_own_permission(self) -> None:
        plan = self.runtime_plan()
        self.sign_in_with(*PREPARE)
        self.assertEqual(self.client.post(f"/plans/{plan.pk}/apply/").status_code, 403)
        self.assertFalse(ApplyRun.objects.exists())
        self.assertEqual(self.systemd.submissions, [])

    def test_a_satisfied_plan_cannot_be_applied(self) -> None:
        self.site.drivers = WORDPRESS_DRIVERS
        plan = self.runtime_plan()
        self.assertTrue(plan.no_changes)
        self.sign_in_with(*APPLY)
        self.client.post(f"/plans/{plan.pk}/apply/")
        self.assertFalse(ApplyRun.objects.exists())


class RuntimeSectionTests(RuntimeTestCase):
    @property
    def url(self) -> str:
        return f"/servers/{self.server.pk}/sites/blog/wordpress/"

    def test_the_section_shows_the_branch_prerequisites_and_the_empty_observation(self) -> None:
        self.sign_in_with(*PREPARE)
        page = self.client.get(self.url)
        self.assertContains(page, f"PHP <strong>{self.site.php}</strong>")
        self.assertContains(page, f"/servers/{self.server.pk}/sites/blog/database/")
        self.assertContains(page, f"/servers/{self.server.pk}/sites/blog/https/")
        self.assertContains(page, f"/servers/{self.server.pk}/advanced/#wordpress-plans")
        self.assertContains(page, "Prepare WordPress PHP runtime plan")
        self.assertContains(page, "The capability state is not observed until a plan reads")
        self.assertContains(page, "nothing here installs WP-CLI, WordPress, a database")

    def test_the_section_shows_the_observed_capabilities_and_their_time(self) -> None:
        self.site.drivers = ("mysql", "curl")
        self.runtime_plan()
        page = self.client.get(self.url)
        self.assertContains(page, "Capabilities observed")
        self.assertContains(page, "Baseline capabilities in the selected CLI and PHP-FPM")
        self.assertContains(page, "Installed by this plan")
        self.assertContains(page, "Enabled in the CLI and PHP-FPM")
        self.assertContains(page, f"php{self.site.php}-gd")
        self.assertContains(page, "/var/www/blog/wpprobe-")
        self.assertContains(
            page, "blog as sblog".replace("blog as sblog", "<code>blog</code> as sblog")
        )

    def test_the_section_shows_the_supported_combinations_beside_every_card(self) -> None:
        self.sign_in_with(*VIEW)
        with mock.patch.object(qualification, "COMBINATIONS", RECORDED_MATRIX):
            page = self.client.get(self.url)
        self.assertContains(page, "Supported combinations")
        self.assertContains(page, "Ubuntu 24.04, PHP 8.3, MariaDB 10.11, arm64")
        self.assertContains(page, "Not qualified, disabled")
        self.assertContains(page, "v0.4 is not released")

    def test_the_section_hides_the_button_without_the_prepare_permission(self) -> None:
        self.sign_in_with(*VIEW)
        page = self.client.get(self.url)
        self.assertNotContains(page, "Prepare WordPress PHP runtime plan")
        self.assertContains(page, "PHP runtime")

    def test_plan_details_need_the_plan_permission(self) -> None:
        self.runtime_plan()
        self.sign_in_with("view_server", "view_siteobservation", "view_siteapplicationobservation")
        self.user.user_permissions.remove(
            *self.user.user_permissions.filter(codename="view_configurationplan")
        )
        page = self.client.get(self.url)
        self.assertContains(page, "who may view configuration plans")
        self.assertNotContains(page, "wpprobe-")
        self.assertNotContains(page, "Baseline capabilities in the selected CLI")

    def test_the_application_permission_alone_does_not_open_the_runtime_card(self) -> None:
        self.runtime_plan()
        self.user.user_permissions.clear()
        self.sign_in_with("view_server", "view_siteobservation")
        self.assertEqual(self.client.get(self.url).status_code, 403)
        self.assertNotContains(
            self.client.get(f"/servers/{self.server.pk}/sites/blog/overview/"), "/wordpress/"
        )

    def test_the_plan_permissions_alone_open_only_the_runtime_card(self) -> None:
        self.sign_in_with(*PREPARE)
        page = self.client.get(self.url)
        self.assertContains(page, 'id="site-wordpress-runtime"')
        self.assertNotContains(page, "WordPress application")
        self.assertContains(page, f"/servers/{self.server.pk}/sites/blog/wordpress/")

    def test_the_section_requires_the_observation_permission(self) -> None:
        self.sign_in_with("view_server", "view_configurationplan")
        self.assertEqual(self.client.get(self.url).status_code, 403)

    def test_prepare_requires_the_prepare_permission_and_queues_nothing(self) -> None:
        self.sign_in_with(*VIEW)
        response = self.client.post(f"{self.url}runtime/prepare/")
        self.assertEqual(response.status_code, 403)
        self.assertFalse(PlanPreparation.objects.exists())

    def test_polling_requires_the_view_permission(self) -> None:
        self.sign_in_with("view_server", "view_siteobservation")
        response = self.client.get(f"{self.url}runtime/", headers=HTMX_FRAGMENT)
        self.assertEqual(response.status_code, 403)

    def test_a_site_the_observation_does_not_show_is_not_found(self) -> None:
        self.sign_in_with(*PREPARE)
        for identifier in ("absent1", "shop"):
            response = self.client.post(
                f"/servers/{self.server.pk}/sites/{identifier}/wordpress/runtime/prepare/"
            )
            self.assertEqual(response.status_code, 404)
        self.assertFalse(PlanPreparation.objects.exists())

    def test_the_request_is_bound_to_the_url_site_not_the_form(self) -> None:
        self.sign_in_with(*PREPARE)
        self.client.post(f"{self.url}runtime/prepare/", {"identifier": "other"})
        self.assertEqual(WordpressRequest.objects.get().identifier, "blog")

    def test_another_active_operation_is_reported_and_nothing_is_queued(self) -> None:
        self.sign_in_with(*PREPARE)
        self.client.post(f"{self.url}runtime/prepare/", headers=HTMX_FRAGMENT)
        response = self.client.post(f"{self.url}runtime/prepare/", headers=HTMX_FRAGMENT)
        self.assertContains(response, "another remote operation")
        self.assertEqual(PlanPreparation.objects.count(), 1)

    def test_polling_returns_the_card_as_a_fragment(self) -> None:
        self.sign_in_with(*PREPARE)
        self.client.post(f"{self.url}runtime/prepare/", headers=HTMX_FRAGMENT)
        response = self.client.get(f"{self.url}runtime/", headers=HTMX_FRAGMENT)
        self.assertContains(response, 'id="site-wordpress-runtime"')
        self.assertContains(response, 'hx-trigger="every 2s"')
        plain = self.client.get(f"{self.url}runtime/")
        self.assertRedirects(plain, self.url, fetch_redirect_response=False)

    def test_the_site_activity_lists_the_runtime_plan(self) -> None:
        self.runtime_plan()
        page = self.client.get(f"/servers/{self.server.pk}/sites/blog/activity/")
        self.assertContains(page, "WordPress PHP extensions")

    def test_the_other_server_sites_page_does_not_show_the_plan(self) -> None:
        self.runtime_plan()
        other = Server.objects.create(name="Other", ssh_alias="stage.example.net")
        self.assertEqual(
            self.client.post(
                f"/servers/{other.pk}/sites/blog/wordpress/runtime/prepare/"
            ).status_code,
            404,
        )


class RuntimeProbeTests(SimpleTestCase):
    """The probe and its native steps, which no fake server executes."""

    token = "0123456789abcdef0123456789abcdef"  # noqa: S105 - a probe token, not a credential

    def steps(self) -> tuple[str, ...]:
        paths = SitePaths("blog", "8.3", revision=3)
        return runtime_native.probe_steps(
            "barectl-apply-" + "a" * 32 + ".service",
            paths=paths,
            token=self.token,
            uid=1003,
            content=runtime.render_probe(self.token),
        )

    def test_the_steps_are_valid_shell_and_end_with_the_probe_removed(self) -> None:
        script = "; ".join(self.steps())
        subprocess.run(["sh", "-n"], input=script, text=True, check=True)  # noqa: S607
        self.assertLess(script.index("wpprobe-"), script.index("barectl-wordpress: verified"))
        self.assertTrue(self.steps()[-1].startswith("r || exit 43"))

    def test_the_pool_and_the_cli_are_asked_for_the_same_line(self) -> None:
        expected = shlex.quote(runtime.expected_probe(self.token, 1003))
        steps = self.steps()
        pool = next(step for step in steps if "f /run/php/sblog.sock" in step)
        cli = next(step for step in steps if "runuser -u sblog" in step)
        self.assertTrue(pool.endswith(f"= {expected} ] || x 42"))
        self.assertTrue(cli.endswith(f"= {expected} ] || x 42"))
        self.assertIn("/usr/bin/env -i /usr/bin/php8.3 /var/www/blog/wpprobe-", cli)

    def test_the_probe_reports_each_baseline_capability_for_the_site_user(self) -> None:
        content = runtime.render_probe(self.token)
        for item in runtime.CAPABILITIES:
            self.assertIn(f"'{item.name}'", content)
        self.assertEqual(
            runtime.expected_probe(self.token, 1003),
            f"barectl-wordpress {self.token} 1003 " + " ".join(["1"] * len(runtime.CAPABILITIES)),
        )
        self.assertNotIn("\n$", content.split("<?php\n", 1)[0])

    def test_a_probe_other_than_the_conventions_is_refused(self) -> None:
        paths = SitePaths("blog", "8.3", revision=3)
        unit = "barectl-apply-" + "a" * 32 + ".service"
        for content, uid in (
            ("<?php system($_GET['c']);", 1003),
            (runtime.render_probe(self.token), 0),
        ):
            with self.subTest(uid=uid), self.assertRaises(ValueError):
                runtime_native.probe_steps(
                    unit, paths=paths, token=self.token, uid=uid, content=content
                )
        for token in ("../x", "short", self.token.upper()):
            with self.subTest(token=token), self.assertRaises(ValueError):
                runtime.render_probe(token)

    def test_the_probe_lives_in_the_root_owned_site_directory(self) -> None:
        self.assertEqual(
            runtime.probe_path("blog", self.token), f"/var/www/blog/wpprobe-{self.token}.php"
        )
        with self.assertRaises(ValueError):
            runtime.probe_path("../etc", self.token)

    def test_the_baseline_is_the_design_list(self) -> None:
        self.assertEqual(
            {item.name for item in runtime.CAPABILITIES},
            {
                "mysqli",
                "json",
                "hash",
                "fileinfo",
                "exif",
                "mbstring",
                "curl",
                "dom",
                "xml",
                "zip",
                "gd",
                "intl",
            },
        )
        self.assertEqual(
            [suffix for suffix, _ in WORDPRESS_PACKAGES],
            ["mysql", "curl", "xml", "mbstring", "zip", "gd", "intl"],
        )
        packages = {suffix for suffix, _ in WORDPRESS_PACKAGES}
        self.assertLessEqual(
            {item.package for item in runtime.CAPABILITIES if item.package}, packages
        )
        self.assertEqual(
            {item.name for item in runtime.CAPABILITIES if not item.package},
            set(WORDPRESS_BUILTINS),
        )
