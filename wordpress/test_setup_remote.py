"""WP-CLI tool setup on a real, disposable server (docs/wordpress.md#wp-cli-setup).

Tagged ``ssh`` and skipped unless the disposable server is configured, as
``bootstrap/test_apply_remote.py`` describes. Every run goes through the dashboard
request, the worker, Barectl's SSH connection, actual systemd, GPG and curl, and the
official release artifacts over the real network, with at most one administrator command
inserted between two named fragments of the production payload. Ground truth is read as
root through ``docker exec``.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from typing import override
from unittest import mock

from bootstrap.models import (
    ApplyRun,
    ConfigurationPlan,
    Execution,
    PlanPreparation,
    Verification,
)
from bootstrap.test_apply_remote import ApplyAcceptanceTestCase
from discovery.fakes import run_worker
from operations.models import RemoteOperation
from sites import native as site_native

from . import setup_native
from .models import WpcliRunResult

Status = RemoteOperation.Status
PURGE = f"rm -rf {setup_native.DIRECTORY}; rm -rf /run/barectl-wpcli-*; true"
STAGED = f"{setup_native.DIRECTORY}/.{setup_native.VERSION}.phar.*"


class SetupTestCase(ApplyAcceptanceTestCase):
    def setup_plan(self) -> ConfigurationPlan:
        self.client.post(f"/servers/{self.server.pk}/wordpress/wp-cli/prepare/")
        run_worker()
        preparation = PlanPreparation.objects.latest("queued_at", "pk")
        self.assertEqual(preparation.status, Status.SUCCEEDED, preparation.failure)
        return ConfigurationPlan.objects.get(preparation=preparation)

    def eligible(self) -> ConfigurationPlan:
        plan = self.setup_plan()
        self.assertTrue(plan.eligible, list(plan.refusals.values_list("text", flat=True)))
        return plan

    def apply_setup(self, plan: ConfigurationPlan) -> ApplyRun:
        run = self.request(plan)
        run_worker()
        run.refresh_from_db()
        return run

    @contextmanager
    def injected(self, after: str, step: str) -> Iterator[None]:
        real = setup_native.setup_steps

        def payload(unit: str, boot: str, deadline: int, **reviewed: object) -> str:
            steps = real(unit, boot, deadline, **reviewed)  # type: ignore[arg-type]
            names = [item.name for item in steps]
            steps.insert(names.index(after) + 1, site_native.Step("injected", step))
            return "; ".join(item.text for item in steps)

        with mock.patch.object(setup_native, "setup_payload", payload):
            yield

    def fault(self, after: str, step: str, undo: str = "true") -> ApplyRun:
        plan = self.eligible()
        self.addCleanup(self.administer, undo)
        with self.injected(after, step):
            return self.apply_setup(plan)


class SetupAcceptanceTests(SetupTestCase):
    @override
    def setUp(self) -> None:
        super().setUp()
        self.administer(
            "command -v gpg >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get -q -y "
            "install gpg >/dev/null; "
            "command -v curl >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get -q -y "
            "install curl >/dev/null; true"
        )
        self.administer(PURGE)
        self.addCleanup(self.administer, PURGE)

    def test_a_reviewed_setup_installs_the_authenticated_tool(self) -> None:
        plan = self.eligible()
        # Preparing changed nothing.
        self.assertEqual(self.administer(f"ls {setup_native.DIRECTORY} 2>/dev/null; true"), "")
        run = self.apply_setup(plan)
        self.assertEqual(
            (run.status, run.execution, run.verification, run.exit_status),
            (Status.SUCCEEDED, Execution.SUCCEEDED, Verification.PASSED, 0),
            run.failure,
        )
        self.assertEqual(WpcliRunResult.objects.get(run=run).problems, "")
        self.assertEqual(
            self.administer(f"stat -c '%F %U %G %a' {setup_native.PHAR}").split(),
            ["regular", "file", "root", "root", "644"],
        )
        self.assertEqual(
            self.administer(f"sha256sum {setup_native.PHAR}").split()[0], setup_native.SHA256
        )
        self.assertEqual(
            self.administer(f"ls -A {setup_native.DIRECTORY}").strip(),
            setup_native.PHAR.rpartition("/")[2],
        )
        self.assertEqual(self.administer("ls -d /run/barectl-wpcli-* 2>/dev/null; true"), "")
        journal = self.administer(
            f"journalctl --no-pager -o cat -u {run.unit_name} | grep '^barectl-wpcli:'; true"
        )
        self.assertIn(f"verified {setup_native.VERSION} signed by", journal)
        self.assertIn(setup_native.FINGERPRINT, journal)
        # A repeated review has no changes.
        again = self.setup_plan()
        self.assertTrue(again.no_changes, list(again.refusals.values_list("text", flat=True)))

    def test_a_corrupted_artifact_is_refused_before_installation(self) -> None:
        # One byte of the staged archive is zeroed between its download and verification.
        corrupt = (
            f"for f in {STAGED}; do "
            'dd if=/dev/zero of="$f" bs=1 count=1 conv=notrunc >/dev/null 2>&1; done; true'
        )
        run = self.fault("download", corrupt)
        self.assertEqual(
            (run.status, run.execution, run.exit_status),
            (Status.FAILED, Execution.TOOL_REFUSED, setup_native.Exit.SIGNATURE),
            run.failure,
        )
        self.assertIn("did not authenticate", run.failure)
        self.assertEqual(
            self.administer(f"test -e {setup_native.PHAR}; true"), "", "nothing was installed"
        )
        self.assertEqual(self.administer("ls -d /run/barectl-wpcli-* 2>/dev/null; true"), "")

    def test_an_unapproved_signing_key_is_refused_before_any_artifact_is_downloaded(self) -> None:
        # The key the publisher location serves has a primary fingerprint the payload does not
        # approve, as after a key rotation Barectl has not reviewed: the run's curl is replaced
        # by a function that answers the key request with a freshly generated key.
        home = "/tmp/barectl-test-other-key"  # noqa: S108 - a path in the disposable server
        gpg = f"GNUPGHOME={home} /usr/bin/gpg --batch"
        serve = (
            f"rm -rf {home}; mkdir -m 0700 {home}; "
            f"{gpg} --pinentry-mode loopback --passphrase '' "
            "--quick-gen-key 'Other <other@example.com>' default default never >/dev/null 2>&1; "
            f"{gpg} --armor --export >{home}/other.asc; GNUPGHOME={home} gpgconf --kill all; "
            'curl(){ if [ "${*#*wp-cli.pgp}" != "$*" ]; then o=; p=; '
            'for a in "$@"; do [ "$p" = --output ] && o=$a; p=$a; done; '
            f'cat {home}/other.asc >|"$o"; else command curl "$@"; fi; }}'
        )
        run = self.fault("tools", serve, f"rm -rf {home}")
        self.assertEqual(
            (run.status, run.execution, run.exit_status),
            (Status.FAILED, Execution.TOOL_REFUSED, setup_native.Exit.KEY),
            run.failure,
        )
        self.assertEqual(self.administer(f"ls -A {setup_native.DIRECTORY} 2>/dev/null; true"), "")
        self.assertEqual(self.administer("ls -d /run/barectl-wpcli-* 2>/dev/null; true"), "")

    def test_an_unreachable_artifact_installs_nothing_and_cleans_its_private_state(self) -> None:
        hosts = "/etc/hosts"
        self.addCleanup(self.administer, f"sed -i '/barectl-test-block/d' {hosts}; true")
        block = f"printf '127.0.0.1 github.com # barectl-test-block\\n' >>{hosts}"
        run = self.fault("keyring", block, f"sed -i '/barectl-test-block/d' {hosts}; true")
        self.assertEqual(
            (run.status, run.execution, run.exit_status),
            (Status.FAILED, Execution.TOOL_REFUSED, setup_native.Exit.DOWNLOAD),
            run.failure,
        )
        self.assertEqual(self.administer(f"test -e {setup_native.PHAR}; true"), "")
        self.assertEqual(self.administer(f"ls -A {setup_native.DIRECTORY} 2>/dev/null; true"), "")
        self.assertEqual(self.administer("ls -d /run/barectl-wpcli-* 2>/dev/null; true"), "")

    def test_a_signature_that_does_not_belong_to_the_artifact_is_refused(self) -> None:
        # The detached signature is replaced by text that is not a signature.
        replace = 'printf "not a signature\\n" >|"$k/phar.asc"'
        run = self.fault("download", replace)
        self.assertEqual(
            (run.status, run.execution, run.exit_status),
            (Status.FAILED, Execution.TOOL_REFUSED, setup_native.Exit.SIGNATURE),
            run.failure,
        )
        self.assertEqual(self.administer(f"test -e {setup_native.PHAR}; true"), "")

    def test_a_writable_ancestor_of_the_installation_refuses_the_review(self) -> None:
        self.administer("mkdir -p /usr/local/lib && chmod 0777 /usr/local/lib")
        self.addCleanup(self.administer, "chmod 0755 /usr/local/lib")
        plan = self.setup_plan()
        self.assertFalse(plan.eligible)
        self.assertIn("/usr/local/lib", " ".join(plan.refusals.values_list("text", flat=True)))
        self.assertEqual(self.administer(f"test -e {setup_native.DIRECTORY}; true"), "")

    def test_a_missing_destination_boundary_reports_the_staged_file(self) -> None:
        run = self.fault(
            "download",
            f"printf other >{setup_native.PHAR}",
        )
        self.assertEqual(
            (run.execution, run.exit_status),
            (Execution.PARTIAL, setup_native.Exit.FILE),
            run.failure,
        )
        self.assertIn("Stopped at exit status", run.failure)
        self.assertIn("staged file", run.failure)

    def test_a_foreign_tool_is_never_overwritten(self) -> None:
        self.administer(
            f"mkdir -m 0755 {setup_native.DIRECTORY} && "
            f"printf not-wp-cli >{setup_native.PHAR} && chmod 0644 {setup_native.PHAR}"
        )
        plan = self.setup_plan()
        self.assertFalse(plan.eligible)
        self.assertIn(
            "does not overwrite foreign tools",
            " ".join(plan.refusals.values_list("text", flat=True)),
        )
        self.assertEqual(self.administer(f"cat {setup_native.PHAR}"), "not-wp-cli")

    def test_changed_evidence_refuses_before_changes(self) -> None:
        plan = self.eligible()
        self.administer(
            f"mkdir -m 0755 {setup_native.DIRECTORY} && touch {setup_native.DIRECTORY}/wp"
        )
        run = self.apply_setup(plan)
        self.assertEqual(run.execution, Execution.DRIFT, run.failure)
        self.assertEqual(
            self.administer(f"test -e {setup_native.PHAR}; true"), "", "nothing was installed"
        )
