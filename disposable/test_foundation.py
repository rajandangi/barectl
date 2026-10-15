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
from discovery.snapshot import CollectedSnapshot
from operations.models import ChangePreparation, ChangeReview, ChangeRun, Result, Verification
from runtimes import change as runtime_change
from runtimes.observation import RuntimeObservation
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
    runtimes_after_apply: tuple[RuntimeObservation, ...]

    def assert_runtime_reconstruction(self, observed: CollectedSnapshot) -> None:
        self.assertEqual(observed.runtimes, self.runtimes_after_apply)
        self.assertEqual({row.entry for row in observed.runtimes}, {"php84", "php85"})
        self.assertTrue(
            all(row.manageable and row.master_state == "active" for row in observed.runtimes)
        )
        for entry in ("php84", "php85"):
            self.native(
                f"/nix/var/nix/profiles/barectl/{entry}/bin/php-fpm -t "
                f"-y /etc/php-fpm/{entry}/php-fpm.conf -c /etc/php-fpm/{entry}/php.ini"
            )
            self.assertIn(
                "0600", self.native(f"stat -c '0%a' /run/php-fpm/{entry}/diagnostic.sock")
            )

    def add_php_runtimes(self, server: Server) -> None:
        for entry in ("php84", "php85"):
            response = self.client.post(
                f"/servers/{server.pk}/changes/prepare/",
                {"kind": runtime_change.SLUG, "selection": entry},
            )
            self.assertEqual(response.status_code, 302)
            run_worker()
            preparation = ChangePreparation.objects.filter(server=server).latest("pk")
            review = ChangeReview.objects.get(preparation=preparation)
            self.assertTrue(review.eligible, review.document)
            self.assertFalse(review.no_changes)
            self.assertEqual(review.consent, "shared")
            self.client.post(f"/changes/{preparation.pk}/apply/", {"affected_sites": "on"})
            run_worker()
            applied = ChangeRun.objects.get(review=review)
            self.assertEqual(applied.execution, Result.SUCCEEDED, applied.failure)
            if applied.verification != Verification.PASSED:
                from runtimes import observation

                with self.shell() as shell:
                    value = observation.read(
                        shell,
                        entry,
                        runtime_change.decode_document(review.document)[0].architecture,
                    )
                self.fail(f"Live runtime verification failed: {value}")
            run_worker()
            snapshot = read_discovery(server).snapshot
            self.assertIsNotNone(snapshot)
            if snapshot is None:
                self.fail("No runtime discovery after apply.")
            self.runtimes_after_apply = snapshot.collected.runtimes
            current = next(row for row in snapshot.collected.runtimes if row.entry == entry)
            self.assertTrue(current.manageable, current.problem)
            self.assertEqual(current.master_state, "active")
            self.assertTrue(current.extensions)
            self.assertContains(self.client.get(f"/servers/{server.pk}/stack/?tab=php"), entry)
            self.client.post(
                f"/servers/{server.pk}/changes/prepare/",
                {"kind": runtime_change.SLUG, "selection": entry},
            )
            run_worker()
            repeated_runtime = ChangeReview.objects.filter(preparation__server=server).latest("pk")
            self.assertTrue(repeated_runtime.no_changes, repeated_runtime.document)

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
                    self.assertContains(
                        self.client.get(f"/servers/{server.pk}/setup/"),
                        'class="usa-step-indicator__heading-text">Connect</span>',
                    )
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
                    self.assertContains(
                        self.client.get(f"/servers/{server.pk}/setup/"),
                        'class="usa-step-indicator__heading-text">Review</span>',
                    )
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
                    self.assertContains(
                        self.client.get(f"/servers/{server.pk}/setup/"),
                        'class="usa-step-indicator__heading-text">Apply and verify</span>',
                    )
                    reviewed_page = self.client.get(f"/changes/{preparation.pk}/")
                    for disclosed in (
                        "Storage=persistent",
                        "NoNewPrivileges=true",
                        "strict_sni_host on",
                        "ExecReload=",
                        "UMask=0077",
                    ):
                        self.assertContains(reviewed_page, disclosed)
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
                    self.assertIn(
                        "HAProxy version 3.3.11",
                        self.native("/nix/var/nix/profiles/barectl/haproxy/bin/haproxy -v"),
                    )
                    self.native('[ -z "$(pgrep -x haproxy || true)" ]')
                    run_worker()
                    refreshed = read_discovery(server).snapshot
                    if refreshed is None or refreshed.collected.standing is None:
                        self.fail("The verified setup did not refresh discovery.")
                    self.assertEqual(refreshed.collected.standing.standing, Standing.TARGET_STACK)
                    self.assertContains(
                        self.client.get(f"/servers/{server.pk}/setup/"), "Server setup verified"
                    )
                    self.assertContains(
                        self.client.get(f"/servers/{server.pk}/stack/?tab=web"), "v2.11.7"
                    )
                    self.assertEqual(self.native("cat /run/foundation-admin-listeners").strip(), "")
                    self.assertContains(self.client.get(f"/runs/{run.pk}/"), "Applied and verified")
                    self.add_php_runtimes(server)
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
        self.assert_runtime_reconstruction(observed)
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
            if local.startswith(("127.", "[::1]")):
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
        image = images.tag("L1")
        if not images.exists(image):
            docker("commit", os.environ["BARECTL_SSH_TEST_CONTAINER"], image, timeout=60)
        self.assertEqual(images.ensure("L1"), image)
        first = docker("image", "inspect", "--format", "{{.Id}}", image).strip()
        self.assertEqual(images.ensure("L1"), image)
        self.assertEqual(docker("image", "inspect", "--format", "{{.Id}}", image).strip(), first)


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
            "printf '[Service]\\nType=notify\\nNotifyAccess=all\\nExecStart=\\n"
            'ExecStart=/bin/sh -c "sleep 90 & systemd-notify --ready; wait"'
            "\\nKillMode=process\\n' "
            ">/run/systemd/system/apt-daily.service.d/fixture.conf; "
            "systemctl daemon-reload; systemctl start apt-daily.service; "
            "systemctl kill --kill-whom=main --signal=KILL apt-daily.service"
        )
        try:
            self.assertEqual(
                self.native("systemctl show apt-daily.service -p MainPID --value").strip(), "0"
            )
            children = self.native(
                "cat /sys/fs/cgroup/system.slice/apt-daily.service/cgroup.procs"
            ).split()
            self.assertTrue(
                children, "The fixture left no apt child after killing its main process."
            )
            self.assertIn(
                "sleep",
                self.native(
                    "cat " + " ".join(f"/proc/{pid}/comm" for pid in children)
                ).splitlines(),
            )
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


@tag(SCENARIO_TAG)
class SupportedFoundationResume(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = ""

    def test_completed_nix_and_catalog_resume_later_stages_without_reinstalling(self) -> None:
        from operations import engine, native

        self.native(
            "systemctl stop caddy.service; systemctl disable caddy.service; "
            "rm -f /etc/systemd/system/caddy.service; rm -rf /etc/caddy /var/lib/caddy; "
            "userdel caddy; groupdel caddy 2>/dev/null || true"
        )
        self.native(
            "rm -f /etc/systemd/journald.conf.d/50-barectl.conf; "
            "systemctl daemon-reload; systemctl restart systemd-journald.service"
        )
        installed = self.native("readlink -f /nix/var/nix/profiles/default; getent passwd nixbld1")
        generation = self.native("readlink /nix/var/nix/profiles/barectl/caddy")
        with self.shell() as shell:
            evidence = foundation.inspect(shell)
            draft = foundation.review(evidence)
            self.assertTrue(draft.eligible, draft.refusals)
            self.assertFalse(draft.no_changes)
            self.assertEqual(draft.document["nix_mode"], "keep")
            context = engine.BodyContext(
                native.new_unit_name(),
                evidence.boot_id,
                (evidence.uptime_centiseconds or 0) + 90000,
            )
            review = ChangeReview(document=draft.document, sites_read="", sites_digest="")
            body = foundation.body(review.document, context)
            path = engine.body_path(context.unit)
            staged = shell.run(
                shlex.join(engine.stage_command(path, foundation.BODY_SHA256)), stdin=body.source
            )
            self.assertEqual(staged.exit_status, 0)
            payload = engine.payload(foundation.HOST_FOUNDATION, review, context, body, path)
            self.assertEqual(
                shell.run(
                    shlex.join(native.submission(context.unit, payload, collect=True))
                ).exit_status,
                0,
            )
            deadline = time.monotonic() + 30
            outcome = engine.read_result(shell, context.unit)
            while outcome is None and time.monotonic() < deadline:
                time.sleep(0.1)
                outcome = engine.read_result(shell, context.unit)
            self.assertIsNotNone(outcome, self.native(f"journalctl -u {context.unit} -n 40"))
            if outcome:
                self.assertEqual(
                    outcome.result_class,
                    "succeeded",
                    self.native(f"journalctl -u {context.unit} -n 40"),
                )
            self.assertTrue(foundation.verify(shell, review))
            self.assertTrue(foundation.review(foundation.inspect(shell)).no_changes)
        self.assertEqual(
            self.native("readlink -f /nix/var/nix/profiles/default; getent passwd nixbld1"),
            installed,
        )
        self.assertEqual(self.native("readlink /nix/var/nix/profiles/barectl/caddy"), generation)


@tag(SCENARIO_TAG)
class FoundationSudoDiscovery(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = "sudo339"

    def test_passwordless_sudo_reconstructs_target_stack_through_exact_fixed_reads(self) -> None:
        from dataclasses import replace

        from discovery import ssh
        from operations.inputs import PreparationInputs
        from sites.change import CREATE_SITE

        from .change_testing import apply_change

        apply_change(
            self, CREATE_SITE, PreparationInputs("php84", "sudo339", ("sudo339.example.com",))
        )
        target = self.target()
        public = Path(f"{target.identity_files[0]}.pub").read_text().strip()
        self.native(
            "useradd --create-home --shell /bin/bash foundation-sudo; "
            "install -d -m 700 -o foundation-sudo -g foundation-sudo "
            "/home/foundation-sudo/.ssh; "
            f"printf '%s\\n' {shlex.quote(public)} "
            ">/home/foundation-sudo/.ssh/authorized_keys; "
            "chown foundation-sudo:foundation-sudo "
            "/home/foundation-sudo/.ssh/authorized_keys; "
            "chmod 600 /home/foundation-sudo/.ssh/authorized_keys; "
            "printf 'foundation-sudo ALL=(root) NOPASSWD: ALL\\n' "
            ">/etc/sudoers.d/foundation-sudo; chmod 440 /etc/sudoers.d/foundation-sudo"
        )
        os.environ["SSH_AUTH_SOCK"] = ""
        with ssh.connect(replace(target, user="foundation-sudo")) as shell:
            evidence = foundation.inspect(shell)
            self.assertIsNotNone(evidence.standing)
            if evidence.standing:
                self.assertEqual(
                    evidence.standing.standing, Standing.TARGET_STACK, evidence.standing.reasons
                )
            self.assertTrue(foundation.review(evidence).no_changes)
            from runtimes.catalog import architecture_of
            from sites import node_change

            architecture = architecture_of(self.native("uname -m").strip())
            if architecture is None:
                self.fail("Unsupported native architecture.")
            self.assertIsNotNone(node_change.read(shell, "sudo339", architecture))
        from discovery.root_read import run_root

        self.native(
            "printf 'foundation-sudo ALL=(root) PASSWD: ALL\\n' >/etc/sudoers.d/foundation-sudo"
        )
        with ssh.connect(replace(target, user="foundation-sudo")) as shell:
            shell.run("sudo -k")
            password_required = run_root(shell, "id -u")
        self.assertNotEqual(password_required.exit_status, 0)
        self.assertEqual(password_required.stdout, "")
        self.native("rm /etc/sudoers.d/foundation-sudo")
        with ssh.connect(replace(target, user="foundation-sudo")) as shell:
            denied = run_root(shell, "id -u")
        self.assertNotEqual(denied.exit_status, 0)
        self.assertEqual(denied.stdout, "")
        self.native(
            "rm -f /etc/sudoers.d/foundation-sudo; "
            "userdel --remove foundation-sudo 2>/dev/null || true"
        )


@tag(SCENARIO_TAG)
class FoundationValidators(ScenarioTestCase):
    layer = "L1"
    exclusive = True
    prefix = ""

    def test_real_scratch_payload_refuses_drift_and_tampered_installer(self) -> None:
        from urllib.parse import urlsplit

        from . import mirror
        from .scenarios import SCRIPTS

        container = os.environ["BARECTL_SSH_TEST_CONTAINER"]
        network = docker(
            "inspect",
            "-f",
            "{{range $name, $value := .NetworkSettings.Networks}}{{$name}}{{end}}",
            container,
        ).strip()
        self.native("systemctl stop caddy.service")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "root.tar"
            exported = docker("create", images.ensure("L0")).strip()
            mirror_name = f"{container}-tampered"
            try:
                docker("export", "--output", str(archive), exported)
                self.native("mkdir /var/lib/foundation-validator")
                with archive.open("rb") as archive_stream:
                    subprocess.run(  # noqa: S603
                        [  # noqa: S607
                            "docker",
                            "exec",
                            "-i",
                            container,
                            "tar",
                            "-xf",
                            "-",
                            "-C",
                            "/var/lib/foundation-validator",
                        ],
                        stdin=archive_stream,
                        capture_output=True,
                        check=True,
                        timeout=120,
                    )
                self.native(
                    "cp /etc/resolv.conf /var/lib/foundation-validator/etc/resolv.conf; "
                    "mount --bind /proc /var/lib/foundation-validator/proc; "
                    "mount --bind /sys /var/lib/foundation-validator/sys; "
                    "mount --bind /dev /var/lib/foundation-validator/dev"
                )
                with self.shell() as shell:
                    draft = foundation.review(foundation.inspect(shell))
                document = draft.document
                profiles = document["profiles"]
                self.assertIsInstance(profiles, dict)
                if not isinstance(profiles, dict):
                    return
                source = foundation.READ_SOURCE + "\nfoundation_digest\n"
                digest = docker(
                    "exec",
                    "-i",
                    container,
                    "chroot",
                    "/var/lib/foundation-validator",
                    "/bin/sh",
                    "-s",
                    stdin=source,
                ).strip()
                arguments = [
                    str(document["installer_url"]),
                    str(document["installer_sha256"]),
                    str(profiles["caddy"]),
                    str(profiles["composer"]),
                    str(profiles["wp-cli"]),
                    "install",
                    "install",
                ]
                self.assertIn("precondition", self.scratch_payload("0" * 64, arguments))
                self.assertEqual(
                    docker(
                        "exec",
                        "-i",
                        container,
                        "chroot",
                        "/var/lib/foundation-validator",
                        "/bin/sh",
                        "-s",
                        stdin=source,
                    ).strip(),
                    digest,
                )
                url = urlsplit(str(document["installer_url"]))
                host = url.hostname or ""
                mirrored = root / "mirror" / host / url.path.lstrip("/")
                mirrored.parent.mkdir(parents=True)
                mirrored.write_bytes(b"tampered upstream installer bytes\n")
                certificate, key = mirror.mirror_certificate(mirror.load().hosts())
                docker(
                    "run",
                    "-d",
                    "--name",
                    mirror_name,
                    "--network",
                    network,
                    "-v",
                    f"{root / 'mirror'}:/mirror-root:ro",
                    "-v",
                    f"{certificate}:/mirror.crt:ro",
                    "-v",
                    f"{key}:/mirror.key:ro",
                    "-v",
                    f"{SCRIPTS}:/native:ro",
                    "--entrypoint",
                    "python3",
                    images.ensure(),
                    "/native/native_mirror/serve.py",
                    "--root",
                    "/mirror-root",
                    "--certificate",
                    "/mirror.crt",
                    "--key",
                    "/mirror.key",
                    "--host",
                    host,
                )
                address = docker(
                    "inspect",
                    "-f",
                    "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                    mirror_name,
                ).strip()
                self.native(
                    f"printf '%s\\n' {shlex.quote(address + ' ' + host)} "
                    ">>/var/lib/foundation-validator/etc/hosts"
                )
                probe = self.native(
                    shlex.join(
                        [
                            "chroot",
                            "/var/lib/foundation-validator",
                            "curl",
                            "--retry",
                            "3",
                            "--retry-connrefused",
                            "-v",
                            str(document["installer_url"]),
                        ]
                    )
                    + " 2>&1 || true"
                )
                self.assertIn(
                    "tampered upstream installer bytes", probe, probe + docker("logs", mirror_name)
                )
                self.assertIn("installer_digest", self.scratch_payload(digest, arguments))
                self.native(
                    "test ! -e /var/lib/foundation-validator/nix; "
                    "test ! -e /var/lib/foundation-validator/etc/caddy; "
                    "test ! -e /var/lib/foundation-validator/etc/systemd/journald.conf.d/"
                    "50-barectl.conf; "
                    'test -z "$(find /var/lib/foundation-validator/run -maxdepth 1 '
                    "-name 'barectl-foundation.*')\""
                )
                self.assertEqual(
                    docker(
                        "exec",
                        "-i",
                        container,
                        "chroot",
                        "/var/lib/foundation-validator",
                        "/bin/sh",
                        "-s",
                        stdin=source,
                    ).strip(),
                    digest,
                )
            finally:
                docker("rm", "-f", exported)
                docker("rm", "-f", mirror_name)
                self.native(
                    "umount /var/lib/foundation-validator/dev /var/lib/foundation-validator/sys "
                    "/var/lib/foundation-validator/proc; "
                    "rm -rf /var/lib/foundation-validator /tmp/validator-root.tar"
                )

    def scratch_payload(self, digest: str, arguments: list[str]) -> str:
        container = os.environ["BARECTL_SSH_TEST_CONTAINER"]
        docker(
            "exec",
            "-i",
            container,
            "sh",
            "-c",
            "cat >/var/lib/foundation-validator/run/body.sh",
            stdin=foundation.BODY_BYTES.decode(),
        )
        return self.native(
            shlex.join(
                [
                    "chroot",
                    "/var/lib/foundation-validator",
                    "/bin/sh",
                    "/run/body.sh",
                    digest,
                    *arguments,
                ]
            )
            + " || true"
        )
