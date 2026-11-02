"""The cloud-image VM lane (docs/quality.md#the-cloud-image-vm-lane).

The smoke class is tagged ``vm`` and runs only through ``manage.py test --tag vm`` inside
``disposable.vm_lane``; its ``scenario`` tag keeps it out of the fast gate, and the runner
excludes every ``vm`` scenario from ordinary native discovery. The remaining tests are fast
configuration checks that need neither QEMU nor a guest.
"""

import contextlib
import io
import socket
import tempfile
import threading
import time
from pathlib import Path
from typing import override
from unittest.mock import patch

import yaml
from django.test import SimpleTestCase, tag

from discovery import ssh
from operations import engine
from operations.consent import DeclaredEffect, Scope
from security import restart

from . import mirror, scenarios, vm, vm_lane
from .change_testing import submit_draft
from .native_mirror import guestfwd
from .scenario_testing import SCENARIO_TAG, ScenarioTestCase

VM_TAG = "vm"
WORKFLOW = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "native-vm.yml"


@tag(SCENARIO_TAG, VM_TAG)
class VmReboot(ScenarioTestCase):
    """A real kernel reboot changes the boot ID and the guest answers SSH again."""

    vm = True
    layer = "L0"
    exclusive = True
    prefix = "vm"

    @override
    def native(self, command: str, *, timeout: float = 300) -> str:
        """The VM lane has no container; every harness command runs over its SSH shell."""
        with self.shell() as shell:
            return shell.run(command).stdout

    def test_a_real_reboot_changes_the_boot_id_and_ssh_returns(self) -> None:
        with self.shell() as shell:
            before = shell.run("cat /proc/sys/kernel/random/boot_id").stdout.strip()
            self.assertRegex(before, r"^[0-9a-f-]{36}$")
            with contextlib.suppress(ssh.ConnectionFailed):
                result = shell.run("sudo systemctl reboot --no-block")
                self.assertEqual(result.exit_status, 0, result.stdout)
        deadline = time.monotonic() + 240
        after = ""
        while time.monotonic() < deadline:
            time.sleep(2)
            try:
                with self.shell() as shell:
                    current = shell.run("cat /proc/sys/kernel/random/boot_id").stdout.strip()
                    if current and current != before:
                        after = current
                        break
            except ssh.ConnectionFailed:
                continue
        self.assertNotEqual(after, before, "the guest did not reboot")
        with self.shell() as shell:
            state = shell.run("systemctl is-system-running || true").stdout.strip()
            self.assertIn(state, {"running", "degraded"})

    def test_the_guest_reaches_the_mirror_and_nothing_else(self) -> None:
        with self.shell() as shell:
            resolved = shell.run("getent hosts snapshot.ubuntu.com").stdout.split()
            self.assertIn(vm.SEED_HOST, resolved)
            fetched = shell.run(
                'python3 -c "import urllib.request;'
                " urllib.request.urlopen("
                f"'https://snapshot.ubuntu.com/{mirror.SNAPSHOT_ROOT}/dists/"
                f"{mirror.SNAPSHOT_SUITES[0]}/InRelease', timeout=15);"
                " print('ok')\""
            )
            self.assertEqual(fetched.exit_status, 0, fetched.stdout)
            refused = shell.run(
                'python3 -c "import socket; socket.setdefaulttimeout(5);'
                " socket.create_connection(('1.1.1.1', 443))\""
            )
            self.assertNotEqual(refused.exit_status, 0)
            unresolved = shell.run("getent hosts example.com")
            self.assertNotEqual(unresolved.exit_status, 0)


@tag(SCENARIO_TAG, VM_TAG)
class VmRestart(ScenarioTestCase):
    """The restart body and verification on the real cloud image."""

    vm = True
    layer = "L0"
    exclusive = True
    prefix = "vmrestart"

    @override
    def native(self, command: str, *, timeout: float = 300) -> str:
        with self.shell() as shell:
            return shell.run(command).stdout

    def test_a_reviewed_restart_returns_with_a_new_boot_and_running_services(self) -> None:
        # The review and consent path is proven in the fast layer. This item proves the
        # native body, the real kernel reboot and the fresh-connection verification.
        with self.shell() as shell:
            before = shell.run("cat /proc/sys/kernel/random/boot_id").stdout.strip()
            uptime = int(shell.run("cut -d' ' -f1 /proc/uptime | tr -d .").stdout.strip())
            self.assertEqual(
                shell.run("printf 'test-package\\n' > /run/reboot-required.pkgs").exit_status,
                0,
            )
            draft = engine.ReviewDraft(
                kind=restart.SLUG,
                intent="Restart the server.",
                effects=(
                    DeclaredEffect(
                        Scope.SERVER,
                        "Restart the server. Sites, scheduled tasks and queue workers stop "
                        "and start again.",
                        (),
                    ),
                ),
                stages=restart.STAGES,
                postconditions=("The server returns with a new boot identity.",),
                boot_id=before,
                uptime_centiseconds=uptime,
                document={
                    "version": 1,
                    "body_sha256": restart.BODY_SHA256,
                    "boot_id": before,
                    "packages": ["test-package"],
                    "sites": [],
                    "services": ["ssh.service"],
                    "details": [],
                },
            )
            submitted = submit_draft(self, shell, restart.RESTART_SERVER, draft)
        deadline = time.monotonic() + 300
        after = ""
        while time.monotonic() < deadline:
            time.sleep(2)
            try:
                with self.shell() as shell:
                    current = shell.run("cat /proc/sys/kernel/random/boot_id").stdout.strip()
                    if current and current != before:
                        after = current
                        break
            except ssh.ConnectionFailed:
                continue
        self.assertNotEqual(after, before, "the guest did not restart")
        with self.shell() as shell:
            line = engine.read_result(shell, submitted.unit)
            if line is None:
                self.fail("The restart run reported no native result line.")
            self.assertEqual(line.result_class, "succeeded", line.reason)
            self.assertTrue(restart.verify(shell, submitted.review))


class CloudImagePinTests(SimpleTestCase):
    def test_both_supported_architectures_are_pinned_by_sha256_and_size(self) -> None:
        pins = vm.load_pins()
        self.assertEqual(set(pins), {"amd64", "arm64"})
        for architecture, pin in pins.items():
            with self.subTest(architecture=architecture):
                self.assertEqual(pin.architecture, architecture)
                self.assertTrue(pin.url.startswith("https://cloud-images.ubuntu.com/"))
                self.assertRegex(pin.sha256, r"^[0-9a-f]{64}$")
                self.assertGreater(pin.size, 0)
                self.assertEqual(pin.name, f"resolute-server-cloudimg-{architecture}.img")

    def test_the_committed_pin_file_names_the_current_release(self) -> None:
        document = yaml.safe_load(vm.PINS.read_text(encoding="utf-8"))
        self.assertEqual(document["release"], vm.RELEASE)
        self.assertEqual(document["format"], vm.FORMAT)

    def test_an_incomplete_pin_file_is_refused(self) -> None:
        for text in (
            "{}",
            '{"format": 1, "release": "26.04", "images": {}}',
            '{"format": 1, "release": "26.04", "images": {"amd64": {}}}',
            '{"format": 1, "release": "26.04", "images": {"amd64": '
            '{"url": "http://example.test/x.img", "sha256": "' + "0" * 64 + '", "size": 1}}}',
        ):
            with self.subTest(text=text), self.assertRaises(vm.VmError):
                vm.load_pins(text)


class CloudInitSeedTests(SimpleTestCase):
    hosts = ("archive.ubuntu.com", "snapshot.ubuntu.com", "cache.nixos.org")

    def seed(self) -> dict[str, str]:
        return vm.seed_files(
            public_key="ssh-ed25519 AAAAC3Nza controller\n",
            ca_certificate="-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n",
            hosts=self.hosts,
            apt_source=mirror.apt_sources(),
        )

    def test_the_seed_is_valid_yaml_and_installs_the_controller_key(self) -> None:
        document = yaml.safe_load(self.seed()["user-data"])
        self.assertIn("ssh-ed25519 AAAAC3Nza controller", document["ssh_authorized_keys"])
        self.assertFalse(document["ssh_pwauth"])
        self.assertFalse(document["manage_etc_hosts"])
        paths = [item["path"] for item in document["write_files"]]
        self.assertIn("/etc/sudoers.d/90-barectl-vm", paths)

    def test_the_seed_keeps_the_guest_offline_but_aliases_every_mirror_host(self) -> None:
        document = yaml.safe_load(self.seed()["user-data"])
        hosts = next(item for item in document["write_files"] if item["path"] == "/etc/hosts")
        for host in self.hosts:
            self.assertIn(f"{vm.SEED_HOST} {host}", hosts["content"])
        prepare = next(
            item
            for item in document["write_files"]
            if item["path"] == "/usr/local/sbin/barectl-vm-prepare.sh"
        )
        self.assertIn("systemctl disable --now systemd-resolved", prepare["content"])
        self.assertIn("systemctl mask apt-news.service", prepare["content"])
        self.assertIn("nameserver 127.0.0.1", prepare["content"])
        self.assertIn("apt-get update", prepare["content"])
        self.assertIn("/var/log/barectl-vm-apt.log", prepare["content"])
        self.assertIn("/etc/cloud/cloud-init.disabled", prepare["content"])
        self.assertIn("systemd-networkd-wait-online.service", prepare["content"])
        apt = next(
            item
            for item in document["write_files"]
            if item["path"] == "/etc/apt/apt.conf.d/99barectl-fixture"
        )
        self.assertIn('Acquire::By-Hash "no";', apt["content"])
        self.assertIn('Acquire::Languages "none";', apt["content"])
        self.assertIn('DEP-11::DefaultEnabled "false";', apt["content"])
        self.assertIn('Acquire::https::Timeout "15";', apt["content"])

    def test_the_seed_trusts_the_fixture_ca_and_uses_the_mirrored_snapshot(self) -> None:
        document = yaml.safe_load(self.seed()["user-data"])
        certificate = next(
            item
            for item in document["write_files"]
            if item["path"] == "/usr/local/share/ca-certificates/barectl-native-fixture-ca.crt"
        )
        self.assertIn("-----BEGIN CERTIFICATE-----", certificate["content"])
        source = next(
            item
            for item in document["write_files"]
            if item["path"] == "/etc/apt/sources.list.d/barectl-snapshot.sources"
        )
        self.assertIn(
            f"https://snapshot.ubuntu.com/ubuntu/{mirror.SNAPSHOT_TIMESTAMP}", source["content"]
        )
        self.assertIn("Suites: resolute resolute-updates resolute-security", source["content"])


class QemuCommandTests(SimpleTestCase):
    def command(self, architecture: str, accel: str) -> list[str]:
        firmware = Path("build/efi.fd") if architecture == "arm64" else None
        return vm.qemu_command(
            architecture=architecture,
            accel=accel,
            disk=Path("build/disk.qcow2"),
            ssh_port=2222,
            seed_port=8000,
            mirror_port=8443,
            seed_command=Path("build/guestfwd-seed.sh"),
            mirror_command=Path("build/guestfwd-mirror.sh"),
            pid_file=Path("build/qemu.pid"),
            console_log=Path("build/console.log"),
            firmware_path=firmware,
        )

    def test_arm64_uses_hvf_kvm_or_tcg_with_uefi_firmware(self) -> None:
        text = " ".join(self.command("arm64", "hvf"))
        self.assertIn("qemu-system-aarch64", text)
        self.assertIn("virt,accel=hvf", text)
        self.assertIn("-cpu host", text)
        self.assertIn("-bios build/efi.fd", text)

    def test_x86_64_uses_its_default_bios(self) -> None:
        text = " ".join(self.command("amd64", "kvm"))
        self.assertIn("qemu-system-x86_64", text)
        self.assertIn("q35,accel=kvm", text)
        self.assertNotIn("-bios", text)

    def test_the_guest_is_offline_and_reaches_only_the_two_proxies(self) -> None:
        text = " ".join(self.command("amd64", "tcg"))
        self.assertIn("-cpu max", text)
        self.assertIn("type=1,serial=ds=nocloud;s=http://10.0.2.100:8000/", text)
        self.assertIn("restrict=on", text)
        self.assertIn("hostfwd=tcp:127.0.0.1:2222-:22", text)
        self.assertIn("guestfwd=tcp:10.0.2.100:8000-cmd:build/guestfwd-seed.sh", text)
        self.assertIn("guestfwd=tcp:10.0.2.100:443-cmd:build/guestfwd-mirror.sh", text)
        self.assertNotIn("tap", text)
        self.assertIn("-display none", text)
        self.assertIn("-serial file:build/console.log", text)
        self.assertIn("-daemonize", text)


class LaneCliTests(SimpleTestCase):
    def test_defaults_run_the_vm_tagged_module_and_keep_the_guest_ephemeral(self) -> None:
        options = vm_lane.arguments([])
        self.assertEqual(options.labels, [vm_lane.TEST_MODULE])
        self.assertEqual(options.tag, "vm")
        self.assertFalse(options.keep)
        self.assertEqual(options.timeout, vm.BOOT_TIMEOUT)
        self.assertEqual(options.ssh_port, 0)

    def test_a_local_image_override_and_keep_are_available(self) -> None:
        options = vm_lane.arguments(
            ["--keep", "--image", "build/image.img", "--arch", "arm64", "--ssh-port", "2222"]
        )
        self.assertTrue(options.keep)
        self.assertEqual(options.image, Path("build/image.img"))
        self.assertEqual(options.arch, "arm64")
        self.assertEqual(options.ssh_port, 2222)

    def test_a_nonpositive_timeout_is_refused(self) -> None:
        with patch("sys.stderr", new_callable=io.StringIO), self.assertRaises(SystemExit):
            vm_lane.arguments(["--timeout", "0"])

    def test_the_environment_is_the_native_scenario_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            machine = vm.Vm(
                work=root,
                architecture="arm64",
                ssh_port=2222,
                seed_port=8000,
                mirror_port=8443,
                key=root / "id",
                known_hosts=root / "known_hosts",
                console_log=root / "console.log",
                qemu_log=root / "qemu.log",
                seed_log=root / "seed.log",
                mirror_log=root / "mirror.log",
            )
            environment = vm_lane.environment(machine)
        self.assertEqual(environment["BARECTL_SSH_TEST_HOST"], "127.0.0.1")
        self.assertEqual(environment["BARECTL_SSH_TEST_PORT"], "2222")
        self.assertEqual(environment["BARECTL_SSH_TEST_USER"], "root")
        self.assertEqual(environment["BARECTL_SCENARIO_ARCH"], "aarch64")
        self.assertEqual(environment["BARECTL_SCENARIO_RELEASE"], "26.04")


class GuestForwardTests(SimpleTestCase):
    def test_relays_both_directions_and_stops_when_the_guest_closes(self) -> None:
        guest = socket.socketpair()
        service = socket.socketpair()
        thread = threading.Thread(
            target=guestfwd._pump,
            args=(guest[1].fileno(), guest[1].fileno(), service[0]),
            daemon=True,
        )
        try:
            thread.start()
            guest[0].sendall(b"request")
            self.assertEqual(service[1].recv(16), b"request")
            service[1].sendall(b"reply")
            self.assertEqual(guest[0].recv(16), b"reply")
        finally:
            guest[0].close()
            thread.join(timeout=5)
            guest[1].close()
            service[0].close()
            service[1].close()
        self.assertFalse(thread.is_alive())


class SelectionTests(SimpleTestCase):
    def test_the_vm_smoke_scenario_is_outside_ordinary_native_discovery(self) -> None:
        self.assertTrue(getattr(VmReboot, "vm", False))
        self.assertEqual(scenarios.discover(["disposable.test_vm_lane.VmReboot"]), [])


class WorkflowTests(SimpleTestCase):
    def test_the_workflow_is_scheduled_dispatchable_and_never_a_pull_request_check(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("schedule:", text)
        self.assertIn("workflow_dispatch:", text)
        self.assertNotIn("pull_request:", text)
        self.assertIn("runs-on: ubuntu-26.04", text)
        self.assertIn("qemu-system-x86", text)
        self.assertIn("python -m disposable.vm_lane", text)
        self.assertIn("actions/upload-artifact", text)

    def test_a_failure_opens_or_comments_on_the_vm_lane_issue(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('title="Native VM lane failed"', text)
        self.assertIn("gh issue list", text)
        self.assertIn("gh issue create", text)
        self.assertIn("gh issue comment", text)
