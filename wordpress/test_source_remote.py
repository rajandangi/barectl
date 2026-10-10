"""Approved-source WordPress candidates (docs/wordpress-native-design.md)."""

from typing import ClassVar, cast, override
from unittest import mock

from discovery.fakes import run_worker
from discovery.native_testing import setting

from . import first_access_remote_testing as access_tests
from . import install_controllers_remote_testing as controllers_tests
from . import tls_remote_testing as tls_tests
from .controllers_remote_testing import CONTROLLER
from .finish_remote_testing import FinishCase
from .install_apply_remote_testing import InstallApplyTestCase
from .install_remote_testing import (
    InstallationServerCase,
)
from .maintenance_models import Operation
from .maintenance_remote_testing import MaintenanceServerCase
from .source_remote_testing import prepare_source_site


class SourceWordpressCase(MaintenanceServerCase):
    @override
    def setUp(self) -> None:
        self.enterContext(mock.patch.object(InstallationServerCase, "setUp", prepare_source_site))
        tls_tests.InstalledWordpressTlsCase.setUp(cast(tls_tests.InstalledWordpressTlsCase, self))

    def qualify_operations(self) -> None:
        self.assertEqual(self.tables(), "12")
        result = self.assert_inspected(self.run_inspection())
        self.assertEqual(
            (result.state, result.core_installed, result.core_version), ("available", True, "7.1.3")
        )
        earlier = self.units()
        pending = self.request(self.eligible_maintenance(Operation.CACHE))
        with self.losing(
            lambda command: command.startswith("sudo -n /usr/bin/systemd-run"), after=True
        ):
            run_worker()
        pending.refresh_from_db()
        self.assertEqual(pending.status, "reconciling", pending.failure)
        self.wait_terminal(pending.unit_name, timeout=300)
        checked = self.check(pending)
        self.assert_maintained(checked)
        self.assertEqual(sorted(self.units()), sorted([*earlier, pending.unit_name]))
        self.assertEqual(self.residue(), "")
        config = self.directory / "fresh-config"
        config.write_text(
            f"Host disposable-root\n  HostName {setting('HOST')}\n  Port {setting('PORT')}\n"
            f"  User root\n  IdentityFile {setting('SECOND_KEY')}\n"
            f"  UserKnownHostsFile {setting('KNOWN_HOSTS')}\n",
            encoding="utf-8",
        )
        self.barrier = self.directory / "barrier"
        self.barrier.mkdir()
        self.enterContext(
            mock.patch("wordpress.install_controllers_remote_testing.CONTROLLER", CONTROLLER)
        )
        controller_case = cast(controllers_tests.InstallControllerCase, self)
        fresh = controllers_tests.InstallControllerCase.finish(
            controller_case,
            controllers_tests.InstallControllerCase.controller(
                controller_case, "fresh", "disposable-root", "fresh", config=config
            ),
        )
        self.assertEqual((fresh["status"], fresh["runs"], fresh["plans"]), (200, 0, 0))
        html = str(fresh["html"])
        self.assertIn("Installed", html[html.index("site-application-heading") :][:3000])
        self.assertIn("7.1.3", html)
        cast(tls_tests.InstalledWordpressTlsCase, self).assert_public_application()


class Source83WordpressTests(SourceWordpressCase, tls_tests.InstalledWordpressTlsCase):
    php: ClassVar[str] = "8.3"

    def test_inspection_maintenance_reconciliation_and_fresh_controller(self) -> None:
        self.qualify_operations()


class Source84WordpressTests(SourceWordpressCase, tls_tests.InstalledWordpressTlsCase):
    php: ClassVar[str] = "8.4"

    def test_inspection_maintenance_reconciliation_and_fresh_controller(self) -> None:
        self.qualify_operations()


class Source85WordpressTests(SourceWordpressCase, tls_tests.InstalledWordpressTlsCase):
    php: ClassVar[str] = "8.5"

    def test_inspection_maintenance_reconciliation_and_fresh_controller(self) -> None:
        self.qualify_operations()


class SourceControllerCase(InstallApplyTestCase):
    @override
    def setUp(self) -> None:
        self.enterContext(mock.patch.object(InstallationServerCase, "setUp", prepare_source_site))
        controllers_tests.InstallControllerCase.setUp(
            cast(controllers_tests.InstallControllerCase, self)
        )
        version = self.administer(". /etc/os-release; echo $VERSION_ID").strip()
        architecture = self.administer("dpkg --print-architecture").strip()
        fingerprint, digest = self.administer("cat /srv/php-source-fixture/trust").split()
        script = CONTROLLER.replace(
            "from wordpress.qualification_testing import native_candidates_qualified",
            "from wordpress.qualification_testing import (native_candidates_qualified, "
            "source_candidate_qualified)\n"
            "from unittest.mock import patch\nfrom bootstrap import php_supply",
        ).replace(
            "with native_candidates_qualified():",
            "with (native_candidates_qualified(), "
            f"source_candidate_qualified({version!r}, {architecture!r}, {self.php!r}), "
            f"patch.object(php_supply, 'PRIMARY_FINGERPRINT', {fingerprint!r}), "
            f"patch.object(php_supply, 'KEY_SHA256', {digest!r})):",
        )
        self.enterContext(mock.patch.object(controllers_tests, "CONTROLLER", script))


class Source83ControllerTests(SourceControllerCase, controllers_tests.InstallControllerCase):
    php: ClassVar[str] = "8.3"


class Source84ControllerTests(SourceControllerCase, controllers_tests.InstallControllerCase):
    php: ClassVar[str] = "8.4"


class Source85ControllerTests(SourceControllerCase, controllers_tests.InstallControllerCase):
    php: ClassVar[str] = "8.5"


class SourceFinishCase(InstallApplyTestCase):
    @override
    def setUp(self) -> None:
        self.enterContext(mock.patch.object(InstallationServerCase, "setUp", prepare_source_site))
        super().setUp()

    def qualify_finish(self, after: str, *, installed: bool) -> None:
        case = cast(FinishCase, self)
        case.interrupted(after)
        case.assert_gated()
        before = case.deep()
        plan = case.eligible_finish()
        run = case.apply_finish(plan)
        case.assert_finished(run, before, installed=installed)


class Source83FinishTests(SourceFinishCase, FinishCase):
    php: ClassVar[str] = "8.3"

    def test_empty_schema_is_finished_once(self) -> None:
        self.qualify_finish("configuration", installed=False)

    def test_installed_schema_is_preserved_without_reinstall(self) -> None:
        self.qualify_finish("access", installed=True)


class Source84FinishTests(Source83FinishTests):
    php: ClassVar[str] = "8.4"


class Source85FinishTests(Source83FinishTests):
    php: ClassVar[str] = "8.5"


class SourceFirstAccessCase(InstallationServerCase):
    @override
    def setUp(self) -> None:
        self.enterContext(mock.patch.object(InstallationServerCase, "setUp", prepare_source_site))
        access_tests.FirstAccessAcceptanceCase.setUp(
            cast(access_tests.FirstAccessAcceptanceCase, self)
        )


class Source83FirstAccessTests(SourceFirstAccessCase, access_tests.FirstAccessAcceptanceCase):
    php: ClassVar[str] = "8.3"


class Source84FirstAccessTests(SourceFirstAccessCase, access_tests.FirstAccessAcceptanceCase):
    php: ClassVar[str] = "8.4"


class Source85FirstAccessTests(SourceFirstAccessCase, access_tests.FirstAccessAcceptanceCase):
    php: ClassVar[str] = "8.5"
