"""A reviewed WordPress installation applied on a real, disposable Ubuntu server: the case and
the ground-truth reads its suites share (docs/wordpress.md#applying-an-installation).

See ``bootstrap/test_apply_remote.py`` for the contract.
"""

import json
import shlex
import subprocess
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import override
from unittest import mock

from bootstrap.inspection import Reader
from bootstrap.models import ApplyRun, ConfigurationPlan, Execution
from databases import admission as binding_admission
from discovery.fakes import run_worker
from discovery.observations.databases import POSTGRESQL_CLIENT, mariadb_command
from discovery.ssh import CommandResult, RemoteShell
from operations.models import RemoteOperation

from . import finish_native, install_apply, install_native
from .install_native import Evidence, Step
from .install_remote_testing import (
    DATABASE,
    IDENTIFIER,
    LINEAGE,
    NAME,
    PUBLIC,
    InstallationServerCase,
)
from .models import FinishReview, InstallationReview, PlanWordpressInstall

Status = RemoteOperation.Status
Exit = install_native.Exit


class _CatalogShell:
    def __init__(self, shell: RemoteShell, reads: list[dict[str, int | bool]]) -> None:
        self.shell = shell
        self.reads = reads
        self.host_key = shell.host_key

    def run(self, command: str) -> CommandResult:
        result = self.shell.run(command)
        if "mysql.global_priv" in command and not command.startswith("sudo -n -l "):
            self.reads.append(
                {
                    "exit_status": result.exit_status,
                    "truncated": result.truncated,
                    "stdout_bytes": len(result.stdout.encode()),
                    "other_engine": "runuser -u postgres" in command,
                }
            )
        return result


@contextmanager
def catalog_read_diagnostics(reads: list[dict[str, int | bool]]) -> Iterator[type[Reader]]:
    class CatalogReader(Reader):
        def __init__(self, shell: RemoteShell) -> None:
            super().__init__(_CatalogShell(shell, reads))

    with mock.patch.object(binding_admission, "Reader", CatalogReader):
        yield CatalogReader


def catalog_failure_receipt(
    reads: list[dict[str, int | bool]], administer: Callable[[str], str]
) -> str:
    catalog = mariadb_command((DATABASE,))
    commands = {
        "units": (
            "timeout 15 systemctl show mariadb.service postgresql.service "
            "'postgresql@*-main.service' "
            "-p Id -p ActiveState -p SubState -p Result -p MainPID "
            "-p ExecMainCode -p ExecMainStatus -p NRestarts"
        ),
        "mariadb": (
            "{ timeout 15 mariadb --no-defaults --protocol=socket -N -B "
            "-e 'SELECT 1' >/dev/null; "
            'printf "native-read-exit=%s\\n" "$?"; } 2>&1 | '
            "sed -nE 's/^ERROR ([0-9]+).*$/MariaDB error code=\\1/p; "
            "/^native-read-exit=[0-9]+$/p'"
        ),
        "mariadb_catalog": (
            f"{{ timeout 15 {catalog} >/dev/null; "
            'printf "native-read-exit=%s\\n" "$?"; } 2>&1 | '
            "sed -nE 's/^ERROR ([0-9]+).*$/MariaDB error code=\\1/p; "
            "/^native-read-exit=[0-9]+$/p'"
        ),
        "postgresql": (
            f"{{ timeout 15 {POSTGRESQL_CLIENT} "
            "-v VERBOSITY=sqlstate -d postgres -c 'SELECT 1' >/dev/null; "
            'printf "native-read-exit=%s\\n" "$?"; } 2>&1 | '
            "sed -nE 's/.*(ERROR|FATAL):[[:space:]]+([A-Z0-9]{5}).*$/"
            "PostgreSQL error code=\\2/p; /^native-read-exit=[0-9]+$/p'"
        ),
    }
    native = {}
    for label, command in commands.items():
        try:
            native[label] = administer(
                f'({command}; printf "diagnostic-exit=%s\\n" "$?") | tail -c 2048'
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
            native[label] = f"Native diagnostic unavailable: {type(error).__name__}"
    return json.dumps({"catalog_reads": reads, "native": native}, sort_keys=True)


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


def _diagnostic_steps(steps: list[Step]) -> list[Step]:
    """Retain a failed pre-load checksum command's output within the 3,000-character
    assertion journal tail. Application-executing commands retain their suppression
    (docs/wordpress-native-design.md#installation-admission-and-execution).
    """
    ending = f" >/dev/null 2>&1 || exit {Exit.CHECKSUMS}"
    observed: list[Step] = []
    for step in steps:
        if step.name != "checksums":
            observed.append(step)
            continue
        if not step.text.endswith(ending):
            raise ValueError("The checksum diagnostic does not match the native fragment.")
        command = step.text.removesuffix(ending)
        text = (
            f'{command} >"$stg/tmp/checksums.out" 2>&1 || {{ rc=$?; '
            "printf 'barectl-test: extracted-tree checksum command failed, WP-CLI exit %s\\n' "
            '"$rc"; '
            'if [ "$(wc -c <"$stg/tmp/checksums.out")" -le 2048 ]; then '
            'head -c 2048 "$stg/tmp/checksums.out"; else '
            'head -c 1024 "$stg/tmp/checksums.out"; '
            "printf '\\nbarectl-test: checksum output truncated\\n'; "
            'tail -c 1024 "$stg/tmp/checksums.out"; fi; '
            f"printf '\\n'; exit {Exit.CHECKSUMS}; }}"
        )
        observed.append(Step(step.name, text))
    return observed


@contextmanager
def checksum_failure_diagnostics() -> Iterator[None]:
    """Bind test-only checksum failure diagnostics into installation and Finish reviews."""
    install = install_native.body_steps
    finish = finish_native.body_steps

    def install_steps(row: InstallationReview, evidence: Evidence, release: str) -> list[Step]:
        return _diagnostic_steps(install(row, evidence, release))

    def finish_steps(row: FinishReview, evidence: Evidence, release: str) -> list[Step]:
        return _diagnostic_steps(finish(row, evidence, release))

    with (
        mock.patch.object(install_native, "body_steps", install_steps),
        mock.patch.object(finish_native, "body_steps", finish_steps),
    ):
        yield


class InstallApplyTestCase(InstallationServerCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.enterContext(checksum_failure_diagnostics())
        self.catalog_reads: list[dict[str, int | bool]] = []
        self.enterContext(catalog_read_diagnostics(self.catalog_reads))
        self.addCleanup(self.clear_units)

    def eligible(self) -> ConfigurationPlan:
        plan = self.review()
        failure = self.texts(plan)
        if not plan.eligible:
            failure += "\nCatalog failure receipt: " + catalog_failure_receipt(
                self.catalog_reads, self.administer
            )
        self.assertTrue(plan.eligible, failure)
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
