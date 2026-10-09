"""The WordPress PHP runtime plan on a real, disposable Ubuntu server
(docs/wordpress.md#php-runtime).

Tagged ``ssh`` and skipped unless the disposable server is configured, as
``bootstrap/test_apply_remote.py`` describes. Every plan goes through the site page's
request, the worker, Barectl's SSH connection and actual APT, dpkg, ucf, systemd and PHP-FPM
on the server. Ground truth is read as root through ``docker exec``, independently of
Barectl. A second site the administrator created by hand keeps its files while the reload
restarts its pool.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from typing import ClassVar, override
from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission

from bootstrap import native as bootstrap_native
from bootstrap.apply_remote_testing import ApplyAcceptanceTestCase
from bootstrap.models import (
    ApplyRun,
    ConfigurationPlan,
    Execution,
    PlanPreparation,
    PlanRefusal,
    Verification,
)
from bootstrap.profiles import WORDPRESS_BUILTINS
from discovery.fakes import run_worker
from discovery.releases import SUPPORTED
from discovery.services import request_discovery
from operations.models import RemoteOperation
from sites.native_testing import create_site, remove_site

from . import runtime
from .models import PlanRuntimeCapability, RuntimeRunResult
from .runtime_native import Exit

Status = RemoteOperation.Status
Reason = PlanRefusal.Reason
PERMISSIONS = (
    "view_server",
    "view_siteobservation",
    "view_configurationplan",
    "prepare_configurationplan",
    "apply_configurationplan",
)
PACKAGES = ("mysql", "curl", "xml", "mbstring", "zip", "gd", "intl")


class RuntimeAcceptanceTestCase(ApplyAcceptanceTestCase):
    php: ClassVar[str]

    @classmethod
    @override
    def setUpTestData(cls) -> None:
        cls.user = get_user_model().objects.create_user("operator")
        for codename in PERMISSIONS:
            cls.user.user_permissions.add(Permission.objects.get(codename=codename))

    @override
    def setUp(self) -> None:
        super().setUp()
        release = self.administer(". /etc/os-release; echo $VERSION_ID").strip()
        type(self).php = SUPPORTED[release].php
        self.version = release
        self.addCleanup(self.administer, remove_site("blog", self.php))
        self.addCleanup(self.administer, remove_site("shop", self.php))
        self.addCleanup(self.administer, self.remove_baseline())
        self.administer(create_site("blog", ("blog.test",), self.php))

    def remove_baseline(self) -> str:
        """Purge the baseline once PHP-FPM runs its valid configuration again, since the
        purge's trigger restarts it."""
        php = self.php
        packages = " ".join(f"php{php}-{name}" for name in PACKAGES)
        return (
            f"rm -f /etc/php/{php}/fpm/conf.d/99-broken.ini /etc/php/{php}/fpm/pool.d/broken.conf; "
            f"systemctl start php{php}-fpm; "
            f"DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq {packages} >/dev/null 2>&1; "
            "DEBIAN_FRONTEND=noninteractive apt-get autoremove -y -qq >/dev/null 2>&1; "
            f'systemctl reload php{php}-fpm; test -z "$(dpkg --audit)"'
        )

    def observe(self) -> None:
        """Discovery shows the site the administrator made, so its page can prepare."""
        request_discovery(self.server)
        run_worker()

    def runtime_plan(self, identifier: str = "blog") -> ConfigurationPlan:
        self.observe()
        response = self.client.post(
            f"/servers/{self.server.pk}/sites/{identifier}/wordpress/runtime/prepare/"
        )
        self.assertEqual(response.status_code, 302, response.content[:300])
        run_worker()
        preparation = PlanPreparation.objects.latest("queued_at", "pk")
        self.assertEqual(preparation.status, Status.SUCCEEDED, preparation.failure)
        return ConfigurationPlan.objects.get(preparation=preparation)

    def texts(self, plan: ConfigurationPlan) -> str:
        return " ".join(plan.refusals.values_list("text", flat=True))

    def main_pid(self) -> str:
        return self.administer(f"systemctl show -p MainPID --value php{self.php}-fpm").strip()

    def installed(self, package: str) -> str:
        return self.administer(
            f"dpkg-query -W -f='${{db:Status-Abbrev}}${{Version}}' {package} 2>/dev/null; true"
        )

    def modules(self, sapi: str = "cli") -> set[str]:
        command = f"php{self.php} -m" if sapi == "cli" else f"php-fpm{self.php} -m"
        return {line.strip() for line in self.administer(command).splitlines()}

    @contextmanager
    def injected(self, before: str, step: str) -> Iterator[None]:
        """The production payload with ``step`` run just before its fragment ``before``."""
        real = bootstrap_native.package_change

        def payload(*args: object, **kwargs: object) -> str:
            text = real(*args, **kwargs)  # type: ignore[arg-type]
            self.assertIn(before, text)
            return text.replace(before, f"{step}; {before}", 1)

        with mock.patch.object(bootstrap_native, "package_change", payload):
            yield


class RuntimeAcceptanceTests(RuntimeAcceptanceTestCase):
    def test_the_baseline_installs_is_verified_in_cli_and_pool_and_is_then_established(
        self,
    ) -> None:
        php = self.php
        common = self.installed(f"php{php}-common").removeprefix("ii ")
        before = self.main_pid()
        plan = self.runtime_plan()
        self.assertTrue(plan.eligible, self.texts(plan))
        self.assertEqual(plan.php_version, php)
        self.assertEqual(
            list(plan.roots.values_list("name", "version", "installed")),
            [(f"php{php}-{name}", common, False) for name in PACKAGES],
        )
        # Review: the exact transaction, the reload of the selected branch's pools and the probe.
        self.assertIn(
            "blog as sblog on /run/php/sblog.sock",
            plan.effects.get(kind="service_reload").text,
        )
        planned = {row.name: row.state for row in PlanRuntimeCapability.objects.filter(plan=plan)}
        self.assertEqual(planned["mysqli"], "planned")
        self.assertEqual({planned[name] for name in WORDPRESS_BUILTINS}, {"enabled"})
        sizes: list[int] = []
        real = bootstrap_native.submission

        def measured(
            unit: str,
            script: str,
            *,
            isolated_archives: bool = False,
            limits: bootstrap_native.Limits | None = None,
        ) -> list[str]:
            sizes.append(len(script.encode()))
            return real(unit, script, isolated_archives=isolated_archives, limits=limits)

        with mock.patch.object(bootstrap_native, "submission", measured):
            run = self.apply(plan)
        self.assertLess(sizes[0], bootstrap_native.MAX_PAYLOAD)
        self.assertEqual(
            (run.status, run.execution, run.verification, run.exit_status),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED, 0),
            run.failure,
        )
        self.assertEqual(run.php_version, php)
        for name in PACKAGES:
            self.assertEqual(self.installed(f"php{php}-{name}"), f"ii {common}")
        # Both the selected CLI and PHP-FPM list every baseline capability, and the unit's
        # own probe asked the site's pool.
        for sapi in ("cli", "fpm"):
            self.assertLessEqual(
                {item.name for item in runtime.CAPABILITIES},
                {module.lower() for module in self.modules(sapi)},
            )
        journal = self.journal(run.unit_name)
        self.assertIn("barectl-wordpress: verified", journal)
        self.assertNotIn("wpprobe-", self.administer("ls /var/www/blog"))
        self.assertNotEqual(self.main_pid(), before)
        self.assertEqual(self.units(), [run.unit_name])
        self.assertEqual(RuntimeRunResult.objects.get(run=run).problems, "")
        self.assertIn("list every baseline capability", self.client.get(f"/applies/{run.pk}/").text)
        self.clear_units()
        # Established: another review changes nothing and applying it is refused.
        again = self.runtime_plan()
        self.assertTrue(again.eligible and again.no_changes, self.texts(again))
        # Every unit the run left is gone; nothing installs WP-CLI, WordPress or a database.
        self.assertEqual(self.administer("ls /usr/local/lib/wp-cli 2>/dev/null; true"), "")
        self.assertEqual(self.installed("mariadb-server"), "")

    def test_an_existing_partial_baseline_installs_only_what_is_missing(self) -> None:
        php = self.php
        self.administer(
            "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
            f"php{php}-mysql php{php}-curl >/dev/null"
        )
        plan = self.runtime_plan()
        self.assertTrue(plan.eligible, self.texts(plan))
        installed = dict(plan.roots.values_list("name", "installed"))
        self.assertTrue(installed[f"php{php}-mysql"] and installed[f"php{php}-curl"])
        self.assertFalse(installed[f"php{php}-gd"])
        run = self.apply(plan)
        self.assertEqual(run.verification, Verification.PASSED, run.failure)
        # Packages already installed kept their manual marks, and the new roots are manual.
        manual = self.administer("apt-mark showmanual").split()
        for name in PACKAGES:
            self.assertIn(f"php{php}-{name}", manual)

    def test_other_sites_keep_their_files_and_the_reload_keeps_their_pools(self) -> None:
        php = self.php
        self.administer(create_site("shop", ("shop.test",), php))
        watched = (
            f"/etc/nginx/sites-available/shop.conf /etc/php/{php}/fpm/pool.d/shop.conf "
            f"/etc/nginx/sites-available/blog.conf /etc/php/{php}/fpm/pool.d/blog.conf"
        )
        files = self.administer(f"sha256sum {watched}")
        plan = self.runtime_plan()
        self.assertIn(
            "shop as sshop on /run/php/sshop.sock", plan.effects.get(kind="service_reload").text
        )
        run = self.apply(plan)
        self.assertEqual(run.verification, Verification.PASSED, run.failure)
        self.assertEqual(self.administer(f"sha256sum {watched}"), files)
        self.administer("test -S /run/php/sshop.sock && ss -Hlx src /run/php/sshop.sock")
        self.assertEqual(self.administer("ls /etc/php").split(), [php], "no other branch appeared")
        self.assertEqual(self.installed("nginx")[:2], "ii")

    def test_a_pool_that_does_not_list_the_baseline_fails_the_run_and_removes_the_probe(
        self,
    ) -> None:
        php = self.php
        plan = self.runtime_plan()
        # The reload then loads PHP-FPM without GD, while the CLI keeps it.
        with self.injected(f"systemctl reload php{php}-fpm.service", "phpdismod -s fpm gd"):
            run = self.apply(plan)
        self.assertEqual(
            (run.execution, run.exit_status),
            (Execution.CAPABILITY_FAILED, Exit.CAPABILITIES_DIFFER),
            run.failure,
        )
        self.assertEqual(run.verification, Verification.NOT_APPLICABLE)
        self.assertIn("did not report every baseline capability", run.failure)
        self.assertNotIn("wpprobe-", self.administer("ls /var/www/blog"))
        self.assertEqual(self.installed(f"php{php}-gd")[:2], "ii")
        self.administer(f"phpenmod -s fpm gd; systemctl reload php{php}-fpm")

    def test_a_change_after_review_refuses_before_apt(self) -> None:
        php = self.php
        plan = self.runtime_plan()
        self.administer(
            f"printf '%s\\n' '; operator setting' > /etc/php/{php}/fpm/conf.d/99-broken.ini"
        )
        run = self.apply(plan)
        self.assertEqual((run.execution, run.exit_status), (Execution.DRIFT, 15), run.failure)
        for name in PACKAGES:
            self.assertEqual(self.installed(f"php{php}-{name}"), "")
        refused = self.runtime_plan()
        self.assertIn(f"/etc/php/{php}/fpm/conf.d/99-broken.ini", self.texts(refused))
        self.assertFalse(ApplyRun.objects.filter(plan_number=refused.pk).exists())

    def test_the_site_changing_after_review_refuses_before_apt(self) -> None:
        php = self.php
        plan = self.runtime_plan()
        self.administer("printf '\\n# external change\\n' >>/etc/nginx/sites-available/blog.conf")
        run = self.apply(plan)
        self.assertEqual(run.execution, Execution.DRIFT, run.failure)
        self.assertEqual(self.installed(f"php{php}-gd"), "")

    def test_a_package_installed_after_review_refuses_the_stale_transaction(self) -> None:
        php = self.php
        plan = self.runtime_plan()
        self.administer(
            f"DEBIAN_FRONTEND=noninteractive apt-get install -y -qq php{php}-curl >/dev/null"
        )
        run = self.apply(plan)
        self.assertIn(run.execution, {Execution.DRIFT, Execution.TRANSACTION_REFUSED}, run.failure)
        self.assertEqual(self.installed(f"php{php}-gd"), "")

    def test_a_module_disabled_through_ordinary_administration_is_refused(self) -> None:
        php = self.php
        plan = self.runtime_plan()
        self.assertEqual(self.apply(plan).verification, Verification.PASSED)
        self.clear_units()
        self.administer("phpdismod intl")
        refused = self.runtime_plan()
        self.assertFalse(refused.eligible)
        self.assertEqual(
            {r.reason for r in refused.refusals.all()}, {Reason.CUSTOMIZED, Reason.CUSTOMIZED}
        )
        self.assertIn("intl", self.texts(refused))
        self.administer(f"phpenmod intl; systemctl reload php{php}-fpm")

    def test_a_custom_pool_the_reload_would_load_is_refused(self) -> None:
        php = self.php
        self.administer(f"printf '[custom]\\n' >/etc/php/{php}/fpm/pool.d/custom.conf")
        self.addCleanup(self.administer, f"rm -f /etc/php/{php}/fpm/pool.d/custom.conf")
        plan = self.runtime_plan()
        self.assertFalse(plan.eligible)
        self.assertIn("custom.conf", self.texts(plan))
        self.assertEqual(self.installed(f"php{php}-gd"), "")
