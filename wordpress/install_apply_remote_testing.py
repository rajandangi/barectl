"""A reviewed WordPress installation applied on a real, disposable Ubuntu server: the case and
the ground-truth reads its suites share (docs/wordpress.md#applying-an-installation).

See ``bootstrap/test_apply_remote.py`` for the contract.
"""

import shlex
from collections.abc import Iterator
from contextlib import contextmanager
from unittest import mock

from bootstrap.models import ApplyRun, ConfigurationPlan, Execution
from discovery.fakes import run_worker
from operations.models import RemoteOperation

from . import install_apply, install_native
from .install_remote_testing import (
    DATABASE,
    IDENTIFIER,
    LINEAGE,
    NAME,
    PUBLIC,
    InstallationServerCase,
)
from .models import PlanWordpressInstall

Status = RemoteOperation.Status
Exit = install_native.Exit


NEW_BOOT = "0badb007-0000-4000-8000-000000000248"
BASE = f"/var/www/{IDENTIFIER}"
SITE_FILE = f"/etc/nginx/sites-available/{IDENTIFIER}.conf"
USER = f"s{IDENTIFIER}"
SECRET_WORDS = ("AUTH_KEY", "NONCE_SALT", "--admin_password", "admin_password=")
REPLACE_CERTIFICATE = (
    "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes "
    f"-keyout {LINEAGE}/privkey.pem -out {LINEAGE}/fullchain.pem -subj /CN={NAME} "
    "-days 2 -addext subjectAltName=DNS:shop.test,DNS:www.shop.test >/dev/null 2>&1"
)
RESTORE_PHP = "systemctl start php{php}-fpm; true"


class InstallApplyTestCase(InstallationServerCase):
    def eligible(self) -> ConfigurationPlan:
        plan = self.review()
        self.assertTrue(plan.eligible, self.texts(plan))
        return plan

    def apply_install(self, plan: ConfigurationPlan) -> ApplyRun:
        run = self.request(plan)
        run_worker()
        run.refresh_from_db()
        return run

    @contextmanager
    def injected(self, plan: ConfigurationPlan, after: str, step: str) -> Iterator[None]:
        """Insert one administrator command between two named fragments of the production
        body, and bind the reviewed row to the resulting text as a review would."""
        real = install_native.body_steps

        def steps(row: object, evidence: object, release: str) -> list[install_native.Step]:
            built = real(row, evidence, release)  # type: ignore[arg-type]
            names = [item.name for item in built]
            built.insert(names.index(after) + 1, install_native.Step("injected", step))
            return built

        with mock.patch.object(install_native, "body_steps", steps):
            row = PlanWordpressInstall.objects.get(plan=plan)
            text = install_native.body(row, install_apply._evidence(plan), plan.release)
            PlanWordpressInstall.objects.filter(plan=plan).update(
                body_sha256=install_native.digest(text)
            )
            yield

    def fault(self, after: str, step: str, undo: str = "true") -> ApplyRun:
        plan = self.eligible()
        self.addCleanup(self.administer, undo)
        with self.injected(plan, after, step):
            return self.apply_install(plan)

    def curl(self, path: str, *, host: str = NAME, scheme: str = "https") -> str:
        resolve = f"--resolve {host}:443:127.0.0.1" if scheme == "https" else f"-H 'Host: {host}'"
        target = f"{scheme}://{host}{path}" if scheme == "https" else f"http://127.0.0.1{path}"
        return self.administer(
            f"curl -sk --max-time 20 {resolve} -o /dev/null -w '%{{http_code}}' {target}; true"
        ).strip()

    def ground(self) -> dict[str, str]:
        """Everything an installation could change that a refusal must leave as it was."""
        reads = {
            "site": f"sha256sum {SITE_FILE}",
            "public": f"find {PUBLIC} -printf '%y %m %U %G %p\\n' | sort",
            "base": f"find {BASE} -maxdepth 1 -printf '%y %m %U %G %p\\n' | sort",
            "backups": "ls -A /var/backups/nginx",
            "tables": self.tables_command(),
            "lineage": f"sha256sum {LINEAGE}/fullchain.pem {LINEAGE}/privkey.pem",
            "staging": f"ls -A {BASE} | grep '^[.]wp' || true",
        }
        return {name: self.administer(command) for name, command in reads.items()}

    def tables_command(self) -> str:
        query = f"SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='{DATABASE}'"  # noqa: S608 - the test's own fixed name
        return f"mariadb --no-defaults --protocol=socket -N -B -e {shlex.quote(query)}"

    def preimage(self, plan: ConfigurationPlan) -> str:
        return PlanWordpressInstall.objects.get(plan=plan).preimage_sha256

    def site_sha(self) -> str:
        return self.administer(f"sha256sum {SITE_FILE}").split()[0]

    def journal_tail(self, run: ApplyRun) -> str:
        return self.journal(run.unit_name)[-3000:]

    def assert_run(self, run: ApplyRun, execution: Execution, status: int | None) -> None:
        self.assertEqual(
            (run.status, run.execution, run.exit_status),
            (Status.FAILED, execution, status),
            f"{run.failure}\n{self.journal_tail(run)}",
        )

    def assert_gated(self) -> None:
        for path in ("/", "/index.php", "/wp-login.php", "/wp-admin/install.php"):
            self.assertEqual(self.curl(path), "503", path)
        self.assertEqual(self.curl("/.well-known/acme-challenge/x", scheme="http"), "404")

    def assert_untouched_by(self, before: dict[str, str], run: ApplyRun) -> None:
        """A run that stopped before any change left the server exactly as it was."""
        after = self.ground()
        self.assertEqual(after, before, f"{run.failure}")

    def administer_home_residue(self) -> str:
        return self.administer(f"ls -A {BASE} | grep '^[.]wp' || true").strip()
