"""S1 and S2 require real daemon, listener, permissions and native lock evidence."""

import os
import shlex
import subprocess
import tempfile
import time
from pathlib import Path
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import override_settings, tag

from bootstrap import foundation
from bootstrap.standing import Standing
from dashboard.testing import TEST_MANIFEST
from discovery.fakes import run_worker
from discovery.models import DiscoveryAttempt
from discovery.observations import collect
from discovery.services import read_discovery
from operations.models import ChangePreparation, ChangeReview, ChangeRun, Result, Verification
from servers.models import Server

from . import images
from .docker import docker
from .scenario_testing import SCENARIO_TAG, ScenarioTestCase


@tag(SCENARIO_TAG)
class HostFoundation(ScenarioTestCase):
    layer = "L0"
    exclusive = True
    prefix = ""
    records: tuple[str, ...] = ("foundation-26.04",)

    def test_saved_agent_fingerprint_setup_and_fresh_controller_reconstruction(self) -> None:
        target = self.target()
        self.native("[ -z \"$(ss -Hlnpt '( sport = :2019 )')\" ]")
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            agent_socket = root / "agent"
            trust_file = root / "known_hosts"
            trust_file.touch()
            agent = subprocess.Popen(  # noqa: S603
                ["ssh-agent", "-D", "-a", str(agent_socket)],  # noqa: S607
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                deadline = time.monotonic() + 5
                while not agent_socket.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                with (
                    mock.patch.dict(os.environ, {"SSH_AUTH_SOCK": str(agent_socket)}),
                    override_settings(
                        SSH_KNOWN_HOSTS_PATH=str(trust_file), VITE_MANIFEST_PATH=TEST_MANIFEST
                    ),
                ):
                    subprocess.run(  # noqa: S603
                        ["ssh-add", str(target.identity_files[0])],  # noqa: S607
                        check=True,
                        capture_output=True,
                    )
                    user = get_user_model().objects.create_superuser(username="foundation")
                    self.client.force_login(user)
                    response = self.client.post(
                        "/servers/add/",
                        {
                            "name": "Foundation",
                            "address": target.hostname,
                            "username": target.user,
                            "port": target.port,
                        },
                    )
                    self.assertEqual(response.status_code, 302)
                    run_worker()
                    server = Server.objects.get()
                    attempt = DiscoveryAttempt.objects.get(server=server)
                    self.assertTrue(attempt.challenge_key_blob)
                    fingerprint = self.native(
                        "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256 | cut -d' ' -f2"
                    ).strip()
                    response = self.client.post(
                        f"/servers/{server.pk}/confirm-host/",
                        {
                            "attempt": attempt.pk,
                            "revision": server.connection_revision,
                            "fingerprint": fingerprint,
                        },
                    )
                    self.assertEqual(response.status_code, 302)
                    run_worker()
                    snapshot = read_discovery(server).snapshot
                    self.assertIsNotNone(snapshot)
                    if snapshot is None or snapshot.collected.standing is None:
                        self.fail("No readiness observation after console confirmation.")
                    self.assertEqual(snapshot.collected.standing.standing, Standing.FRESH)
                    self.assertContains(self.client.get(f"/servers/{server.pk}/"), "Set up server")
                    self.assertEqual(
                        self.client.post(
                            f"/servers/{server.pk}/changes/prepare/", {"kind": foundation.SLUG}
                        ).status_code,
                        302,
                    )
                    run_worker()
                    preparation = ChangePreparation.objects.get(server=server)
                    review = ChangeReview.objects.get(preparation=preparation)
                    self.assertTrue(review.eligible, review.document)
                    self.assertEqual(review.consent, "shared")
                    self.native(
                        "systemd-run --quiet --unit=foundation-admin-watch /bin/sh -c "
                        + shlex.quote(
                            "while :; do ss -Hlnpt '( sport = :2019 )' "
                            ">>/run/foundation-admin-listeners; sleep 0.02; done"
                        )
                    )
                    try:
                        response = self.client.post(
                            f"/changes/{preparation.pk}/apply/", {"affected_sites": "on"}
                        )
                        self.assertEqual(response.status_code, 302)
                        run_worker()
                    finally:
                        self.native("systemctl stop foundation-admin-watch")
                    run = ChangeRun.objects.get(review=review)
                    self.assertEqual(
                        run.execution,
                        Result.SUCCEEDED,
                        run.failure
                        + "\n"
                        + self.native(f"journalctl -u {run.unit_name} --no-pager -n 80")
                        + self.native(
                            "stat -c '%n %a %U %G' /run/caddy /run/caddy/admin.sock; "
                            "systemctl is-active nix-daemon.service caddy.service; "
                            "curl -s -o /dev/null -w '%{http_code}\\n' "
                            "-H 'Host: unknown.invalid' http://127.0.0.1/"
                        ),
                    )
                    self.assertEqual(
                        run.verification,
                        Verification.PASSED,
                        run.failure
                        + "\n"
                        + self.native(foundation.READ_COMMAND)
                        + self.native("getent passwd nixbld1; getent group nixbld"),
                    )
                    run_worker()
                    refreshed = read_discovery(server).snapshot
                    if refreshed is None or refreshed.collected.standing is None:
                        self.fail("The verified setup did not refresh discovery.")
                    self.assertEqual(refreshed.collected.standing.standing, Standing.TARGET_STACK)
                    self.assertContains(
                        self.client.get(f"/servers/{server.pk}/stack/?tab=web"), "v2.11.7"
                    )
                    self.assertEqual(self.native("cat /run/foundation-admin-listeners").strip(), "")
                    self.assertContains(self.client.get(f"/runs/{run.pk}/"), "Applied and verified")
                    self.assertEqual(
                        self.client.post(
                            f"/servers/{server.pk}/changes/prepare/", {"kind": foundation.SLUG}
                        ).status_code,
                        302,
                    )
                    run_worker()
                    repeated = ChangeReview.objects.filter(preparation__server=server).latest(
                        "collected_at", "pk"
                    )
                    self.assertIsNotNone(repeated)
                    if repeated is not None:
                        self.assertTrue(repeated.no_changes, repeated.document)
            finally:
                agent.terminate()
                agent.wait(timeout=5)
        with self.shell() as shell:
            observed = collect(shell)
            fresh_review = foundation.review(foundation.inspect(shell))
            self.checkpoint("foundation-26.04", shell)
        self.assertIsNotNone(observed.standing)
        if observed.standing:
            self.assertEqual(
                observed.standing.standing, Standing.TARGET_STACK, observed.standing.reasons
            )
        self.assertTrue(fresh_review.no_changes, fresh_review.refusals)
        self.native("useradd --system --shell /usr/sbin/nologin foundation-observer")
        denied = self.native(
            "runuser -u foundation-observer -- /nix/var/nix/profiles/default/bin/nix-store "
            "--store daemon -q --references /nix/var/nix/profiles/barectl/caddy 2>&1 "
            "; printf '\\nstatus=%s\\n' $?"
        )
        self.assertIn(
            "foundation-observer",
            self.native(
                "journalctl -u nix-daemon.service -n 20 --no-pager -o cat "
                "--grep="
                + shlex.quote(
                    "user 'foundation-observer' is not allowed to connect to the Nix daemon"
                )
            ),
        )
        self.assertNotIn("status=0", denied)
        socket = self.native(
            "runuser -u foundation-observer -- python3 -c "
            + shlex.quote(
                "import socket; s=socket.socket(socket.AF_UNIX); s.connect('/run/caddy/admin.sock')"
            )
            + " 2>&1; printf '\\nstatus=%s\\n' $?"
        )
        self.assertIn("Permission denied", socket)
        self.assertNotIn("status=0", socket)
        self.native("userdel foundation-observer")
        listeners = self.native("ss -Hlnpt").splitlines()
        for line in listeners:
            local = line.split()[3]
            if local.startswith("127.") or local.startswith("[::1]"):
                continue
            self.assertRegex(line, r":(?:22|80)\s")
        self.assertEqual(
            self.native(
                "curl -s -o /dev/null -w '%{http_code}' "
                "-H 'Host: unknown.invalid' http://127.0.0.1/"
            ).strip(),
            "404",
        )
        self.native("systemctl stop caddy.service nix-daemon.service nix-daemon.socket")
        self.native(
            "rm -f /root/.ssh/authorized_keys /etc/ssh/ssh_host_* /run/foundation-admin-listeners"
        )
        docker("commit", os.environ["BARECTL_SSH_TEST_CONTAINER"], images.tag("L1"), timeout=60)


@tag(SCENARIO_TAG)
class FoundationAdmission(ScenarioTestCase):
    reviewed_evidence: foundation.FoundationEvidence
    layer = "L0"
    exclusive = True
    prefix = ""

    def run_reviewed_payload(self, expected_class: str, reason: str = "") -> None:
        from operations import engine, native

        with self.shell() as shell:
            evidence = self.reviewed_evidence
            draft = foundation.review(evidence)
            context = engine.BodyContext(
                unit=native.new_unit_name(),
                boot_id=evidence.boot_id,
                deadline_centiseconds=(evidence.uptime_centiseconds or 0) + 90000,
            )
            review = ChangeReview(document=draft.document, sites_read="", sites_digest="")
            body = foundation.body(review.document, context)
            path = engine.body_path(context.unit)
            payload = engine.payload(foundation.HOST_FOUNDATION, review, context, body, path)
            staged = shell.run(
                shlex.join(engine.stage_command(path, foundation.BODY_SHA256)), stdin=body.source
            )
            self.assertEqual(staged.exit_status, 0)
            submitted = shell.run(
                shlex.join(native.submission(context.unit, payload, collect=True))
            )
            self.assertEqual(submitted.exit_status, 0)
            deadline = time.monotonic() + 10
            line = engine.read_result(shell, context.unit)
            while line is None and time.monotonic() < deadline:
                time.sleep(0.1)
                line = engine.read_result(shell, context.unit)
            self.assertIsNotNone(line, self.native(f"journalctl -u {context.unit} -n 30"))
            if line:
                self.assertEqual(line.result_class, expected_class)
                self.assertEqual(line.reason, reason)
            after = foundation.read(shell)
            self.assertIsNotNone(after)
            if after:
                self.assertEqual(after["digest"], evidence.precondition_digest)
        self.native(
            "test ! -e /nix && test ! -e /etc/caddy && "
            "test ! -e /etc/systemd/journald.conf.d/50-barectl.conf"
        )

    def test_active_and_lingering_apt_children_then_held_lock_refuse_without_changes(self) -> None:
        from operations import native

        with self.shell() as shell:
            self.reviewed_evidence = foundation.inspect(shell)

        self.native(
            "install -d /run/systemd/system/apt-daily.service.d; "
            "printf '[Service]\\nType=simple\\nExecStart=\\nExecStart=/bin/sleep 90\\n' "
            ">/run/systemd/system/apt-daily.service.d/fixture.conf; "
            "systemctl daemon-reload; systemctl start apt-daily.service"
        )
        try:
            self.run_reviewed_payload("refused", "apt_active")
        finally:
            self.native("systemctl stop apt-daily.service")
        self.native(
            "printf '[Service]\\nType=simple\\nExecStart=\\n"
            'ExecStart=/bin/sh -c "sleep 90 & wait"\\nKillMode=process\\n\' '
            ">/run/systemd/system/apt-daily.service.d/fixture.conf; "
            "systemctl daemon-reload; systemctl start apt-daily.service; "
            "systemctl kill --kill-whom=main --signal=KILL apt-daily.service"
        )
        try:
            self.run_reviewed_payload("refused", "apt_active")
        finally:
            self.native(
                "systemctl kill --kill-whom=all --signal=KILL apt-daily.service || true; "
                "systemctl stop apt-daily.service; "
                "rm -rf /run/systemd/system/apt-daily.service.d; "
                "systemctl reset-failed apt-daily.service; systemctl daemon-reload"
            )
        self.native(
            f"install -d -m 700 {native.LOCK_DIRECTORY}; "
            f"touch {native.LOCK_FILE}; "
            "systemd-run --quiet --unit=foundation-lock-holder "
            + shlex.join(["/usr/bin/flock", native.LOCK_FILE, "/bin/sleep", "90"])
        )
        try:
            self.run_reviewed_payload("lock_busy")
        finally:
            self.native("systemctl stop foundation-lock-holder")
