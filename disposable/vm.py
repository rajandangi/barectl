"""Boot the pinned Ubuntu cloud image under QEMU for the VM lane.

docs/quality.md#the-cloud-image-vm-lane. The guest is a real machine, so a kernel reboot
changes its boot ID, unlike a container sharing the Docker host's kernel. The official
Ubuntu 26.04 cloud image is pinned by SHA-256 in
``docker/disposable-server/cloud-image.json``. Cloud-init installs the lane's generated SSH
keys, the fixture CA and an APT source for the local mirror; QEMU user networking runs with
``restrict=on`` and two ``guestfwd`` proxies, so the guest reaches only the NoCloud seed and
the mirror.
"""

import contextlib
import hashlib
import json
import logging
import os
import platform
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TextIO, override

import paramiko

from . import mirror

# The boot loop retries while sshd is still starting; paramiko logs every expected reset.
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

REPOSITORY = Path(__file__).resolve().parent.parent
SCRIPTS = REPOSITORY / "disposable"
PINS = REPOSITORY / "docker" / "disposable-server" / "cloud-image.json"
FORMAT = 1
RELEASE = "26.04"
CACHE = "cloud-images"
SEED_HOST = "10.0.2.100"
SSH_USER = "root"
SSH_PORT = 22
DOWNLOAD_ATTEMPTS = 4
DOWNLOAD_CHUNK = 4 * 1024 * 1024
BOOT_TIMEOUT = 600.0
_MACHINES = {
    "x86_64": "amd64",
    "amd64": "amd64",
    "aarch64": "arm64",
    "arm64": "arm64",
}


class VmError(Exception):
    """The VM lane could not prepare, boot or reach its guest."""


@dataclass(frozen=True)
class ImagePin:
    architecture: str
    url: str
    sha256: str
    size: int

    @property
    def name(self) -> str:
        return self.url.rsplit("/", 1)[-1]


def load_pins(text: str | None = None) -> dict[str, ImagePin]:
    """The pinned cloud image for each supported architecture."""
    document = json.loads(PINS.read_text(encoding="utf-8") if text is None else text)
    if not isinstance(document, dict) or document.get("format") != FORMAT:
        raise VmError(f"The cloud image pins are not format {FORMAT}.")
    if not isinstance(document.get("release"), str) or not document["release"]:
        raise VmError("The cloud image pins name no release.")
    images = document.get("images")
    if not isinstance(images, dict):
        raise VmError("The cloud image pins list no images.")
    pins: dict[str, ImagePin] = {}
    for architecture in ("amd64", "arm64"):
        value = images.get(architecture)
        if not isinstance(value, dict):
            raise VmError(f"The cloud image pins have no {architecture} image.")
        url = value.get("url")
        digest = value.get("sha256")
        size = value.get("size")
        if not isinstance(url, str) or not url.startswith("https://"):
            raise VmError(f"The {architecture} cloud image has no HTTPS URL.")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise VmError(f"The {architecture} cloud image has no SHA-256.")
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            raise VmError(f"The {architecture} cloud image has no positive size.")
        pins[architecture] = ImagePin(architecture, url, digest, size)
    return pins


def host_architecture() -> str:
    machine = os.environ.get("BARECTL_VM_ARCH") or platform.machine()
    try:
        return _MACHINES[machine]
    except KeyError:
        raise VmError(
            f"Unknown machine architecture {machine!r}; set BARECTL_VM_ARCH to amd64 or arm64."
        ) from None


def cache_root() -> Path:
    root = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    directory = root / "barectl" / "native" / CACHE
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def ensure(pin: ImagePin, *, root: Path | None = None, output: TextIO | None = None) -> Path:
    """Download the pinned image if absent and verify its SHA-256 and size."""
    directory = root or cache_root()
    destination = directory / pin.name
    if _verified(destination, pin):
        return destination
    partial = destination.with_name(destination.name + ".partial")
    last: Exception | None = None
    for attempt in range(DOWNLOAD_ATTEMPTS):
        try:
            digest = hashlib.sha256()
            downloaded = 0
            with (
                urllib.request.urlopen(pin.url, timeout=120) as response,  # noqa: S310
                partial.open("wb") as stream,
            ):
                while chunk := response.read(DOWNLOAD_CHUNK):
                    digest.update(chunk)
                    stream.write(chunk)
                    downloaded += len(chunk)
                    if output is not None and downloaded % (64 * 1024 * 1024) < DOWNLOAD_CHUNK:
                        output.write(f"vm: downloaded {downloaded // 2**20} MiB\n")
                        output.flush()
            if digest.hexdigest() != pin.sha256:
                raise VmError(
                    f"{pin.url} has SHA-256 {digest.hexdigest()}, expected {pin.sha256}; "
                    "upstream rotated the image or the pin is stale."
                )
            if partial.stat().st_size != pin.size:
                raise VmError(f"{pin.url} is {partial.stat().st_size} bytes, expected {pin.size}.")
            os.replace(partial, destination)
            return destination
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as error:
            last = error
            if attempt + 1 < DOWNLOAD_ATTEMPTS:
                time.sleep(min(30.0, 2.0**attempt))
    partial.unlink(missing_ok=True)
    raise VmError(f"Could not fetch {pin.url}: {last}")


def _verified(path: Path, pin: ImagePin) -> bool:
    if not path.is_file() or path.stat().st_size != pin.size:
        return False
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(DOWNLOAD_CHUNK):
            digest.update(chunk)
    return digest.hexdigest() == pin.sha256


def backing_format(base: Path) -> str:
    completed = subprocess.run(  # noqa: S603 - fixed QEMU image inspection
        ["qemu-img", "info", "--output=json", str(base)],  # noqa: S607 - QEMU on PATH
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if completed.returncode != 0:
        raise VmError(f"qemu-img could not read {base}: {completed.stderr.strip()[-400:]}")
    try:
        value = json.loads(completed.stdout).get("format")
    except json.JSONDecodeError, AttributeError:
        raise VmError(f"qemu-img reported no format for {base}.") from None
    if not isinstance(value, str) or not value:
        raise VmError(f"qemu-img reported no format for {base}.")
    return value


def overlay(base: Path, destination: Path, *, size_gib: int = 8) -> Path:
    """A disposable qcow2 overlay so a boot never writes to the pinned image."""
    destination.unlink(missing_ok=True)
    command = [
        "qemu-img",
        "create",
        "-f",
        "qcow2",
        "-b",
        str(base),
        "-F",
        backing_format(base),
        str(destination),
        f"{size_gib}G",
    ]
    completed = subprocess.run(  # noqa: S603 - fixed QEMU image creation
        command,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if completed.returncode != 0:
        raise VmError(f"qemu-img could not create the overlay: {completed.stderr.strip()[-400:]}")
    return destination


def _key(path: Path, *, comment: str) -> Path:
    if not path.exists():
        completed = subprocess.run(  # noqa: S603 - fixed key generation
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", str(path)],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if completed.returncode != 0:
            raise VmError(f"ssh-keygen could not write {path}: {completed.stderr.strip()}")
    return path


def user_data(
    *,
    public_key: str,
    ca_certificate: str,
    hosts: Sequence[str],
    apt_source: str,
) -> str:
    """The NoCloud user-data that prepares the cloud image for the lane."""
    hosts_file = [
        "127.0.0.1 localhost",
        "127.0.1.1 barectl-vm",
        *(f"{SEED_HOST} {host}" for host in sorted(set(hosts))),
    ]
    prepare = """#!/bin/sh
set -eu
rm -f /etc/apt/sources.list.d/ubuntu.sources /etc/apt/sources.list
systemctl disable --now systemd-resolved 2>/dev/null || true
# The cloud image runs auxiliary daemons the native server images do not: chrony and
# snapd expose listeners the foundation's public-listener check refuses. The lane keeps
# the image's kernel and package defaults but removes these non-managed services.
systemctl stop chrony.service snapd.service snapd.socket multipathd.service 2>/dev/null || true
systemctl disable chrony.service snapd.service snapd.socket multipathd.service 2>/dev/null || true
systemctl mask apt-news.service esm-cache.service apt-news.timer 2>/dev/null || true
systemctl stop apt-daily.service apt-daily-upgrade.service 2>/dev/null || true
systemctl mask apt-daily.service apt-daily-upgrade.service 2>/dev/null || true
systemctl mask apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true
rm -f /etc/resolv.conf
printf 'nameserver 127.0.0.1\\n' >/etc/resolv.conf
update-ca-certificates
systemctl restart ssh
if ! apt-get update >/var/log/barectl-vm-apt.log 2>&1; then
    cat /var/log/barectl-vm-apt.log >&2
    exit 1
fi
cat /var/log/barectl-vm-apt.log
# Later boots are test reboots: keep the applied seed state and skip cloud-init's network
# wait, which times out under QEMU's restricted user networking.
touch /etc/cloud/cloud-init.disabled
systemctl mask systemd-networkd-wait-online.service 2>/dev/null || true
"""
    return f"""#cloud-config
hostname: barectl-vm
manage_etc_hosts: false
ssh_pwauth: false
disable_root: false
package_update: false
package_upgrade: false
ssh_authorized_keys:
  - {public_key.strip()}
users:
  - default
  - name: root
    ssh_authorized_keys:
      - {public_key.strip()}
write_files:
  - path: /etc/sudoers.d/90-barectl-vm
    permissions: '0440'
    content: |
      ubuntu ALL=(ALL) NOPASSWD:ALL
  - path: /etc/hosts
    permissions: '0644'
    content: |
{_indent(chr(10).join(hosts_file), 6)}
  - path: /etc/apt/apt.conf.d/99barectl-fixture
    permissions: '0644'
    content: |
      Acquire::By-Hash "no";
      Acquire::Languages "none";
      Acquire::IndexTargets::deb::DEP-11::DefaultEnabled "false";
      Acquire::http::Timeout "15";
      Acquire::https::Timeout "15";
  - path: /etc/apt/sources.list.d/barectl-snapshot.sources
    permissions: '0644'
    content: |
{_indent(apt_source, 6)}
  - path: /usr/local/share/ca-certificates/barectl-native-fixture-ca.crt
    permissions: '0644'
    content: |
{_indent(ca_certificate, 6)}
  - path: /usr/local/sbin/barectl-vm-prepare.sh
    permissions: '0755'
    content: |
{_indent(prepare, 6)}
runcmd:
  - /usr/local/sbin/barectl-vm-prepare.sh
"""


def _indent(text: str, spaces: int) -> str:
    prefix = " " * spaces
    return "\n".join(prefix + line for line in text.rstrip("\n").splitlines())


def meta_data() -> str:
    return "instance-id: barectl-vm\nlocal-hostname: barectl-vm\n"


def seed_files(
    *,
    public_key: str,
    ca_certificate: str,
    hosts: Sequence[str],
    apt_source: str,
) -> dict[str, str]:
    return {
        "user-data": user_data(
            public_key=public_key,
            ca_certificate=ca_certificate,
            hosts=hosts,
            apt_source=apt_source,
        ),
        "meta-data": meta_data(),
    }


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _free_port(used: set[int]) -> int:
    while True:
        port = free_port()
        if port not in used:
            used.add(port)
            return port


def accelerator() -> str:
    configured = os.environ.get("BARECTL_VM_ACCEL")
    if configured:
        return configured
    if Path("/dev/kvm").exists():
        return "kvm"
    if platform.system() == "Darwin":
        return "hvf"
    return "tcg"


def firmware(architecture: str) -> Path | None:
    """The UEFI firmware an ARM ``virt`` machine needs; x86 uses its default BIOS."""
    if architecture != "arm64":
        return None
    candidates = [
        os.environ.get("BARECTL_QEMU_EFI"),
        "/opt/homebrew/share/qemu/edk2-aarch64-code.fd",
        "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd",
        "/usr/share/AAVMF/AAVMF_CODE.fd",
        "/usr/share/edk2/aarch64/QEMU_EFI.fd",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return Path(candidate)
    raise VmError(
        "No ARM UEFI firmware was found; install qemu-efi-aarch64 or set BARECTL_QEMU_EFI."
    )


def qemu_command(
    *,
    architecture: str,
    accel: str,
    disk: Path,
    ssh_port: int,
    seed_port: int,
    mirror_port: int,
    seed_command: Path,
    mirror_command: Path,
    pid_file: Path,
    console_log: Path,
    firmware_path: Path | None,
    memory_gib: int = 2,
    cpus: int = 2,
) -> list[str]:
    """The QEMU invocation: offline user networking, two guestfwd proxies, serial log."""
    for path in (seed_command, mirror_command):
        if "," in str(path):
            raise VmError(f"A guestfwd command path cannot contain a comma: {path}")
    binary = "qemu-system-aarch64" if architecture == "arm64" else "qemu-system-x86_64"
    machine = "virt" if architecture == "arm64" else "q35"
    cpu = "host" if accel in {"kvm", "hvf"} else "max"
    network = ",".join(
        [
            "user",
            "id=net0",
            "restrict=on",
            f"hostfwd=tcp:127.0.0.1:{ssh_port}-:{SSH_PORT}",
            f"guestfwd=tcp:{SEED_HOST}:{seed_port}-cmd:{seed_command}",
            f"guestfwd=tcp:{SEED_HOST}:443-cmd:{mirror_command}",
        ]
    )
    command = [
        binary,
        "-machine",
        f"{machine},accel={accel}",
        "-cpu",
        cpu,
        "-smp",
        str(cpus),
        "-m",
        f"{memory_gib}G",
        "-smbios",
        f"type=1,serial=ds=nocloud;s=http://{SEED_HOST}:{seed_port}/",
        "-drive",
        f"file={disk},if=virtio,format=qcow2",
        "-netdev",
        network,
        "-device",
        "virtio-net-pci,netdev=net0",
        "-display",
        "none",
        "-serial",
        f"file:{console_log}",
        "-monitor",
        "none",
        "-daemonize",
        "-pidfile",
        str(pid_file),
    ]
    if firmware_path is not None:
        command += ["-bios", str(firmware_path)]
    return command


@contextlib.contextmanager
def _client(
    *, port: int, key: Path, known_hosts: Path, timeout: float = 10
) -> Iterator[paramiko.SSHClient]:
    client = paramiko.SSHClient()
    client.load_host_keys(str(known_hosts))
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(
            "127.0.0.1",
            port=port,
            username=SSH_USER,
            key_filename=str(key),
            look_for_keys=False,
            allow_agent=False,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
        )
        yield client
    finally:
        client.close()


def _run(client: paramiko.SSHClient, command: str, *, timeout: float) -> tuple[int, str, str]:
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode("utf-8", "replace")
    error = stderr.read().decode("utf-8", "replace")
    return stdout.channel.recv_exit_status(), output, error


def wait_for_ssh(*, port: int, key: Path, known_hosts: Path, timeout: float = BOOT_TIMEOUT) -> None:
    """Wait for SSH and pin the guest's host key on this first, localhost-only connection.

    Cloud-init generates the image's host keys itself, so the lane cannot install one in the
    seed. The guest is reached only through ``hostfwd`` on the host's loopback; the key it
    presents here is written to ``known_hosts`` and every later connection verifies it.
    """
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # noqa: S507 - localhost-only first connection pins the key
        try:
            client.connect(
                "127.0.0.1",
                port=port,
                username=SSH_USER,
                key_filename=str(key),
                look_for_keys=False,
                allow_agent=False,
                timeout=10,
                banner_timeout=10,
                auth_timeout=10,
            )
            transport = client.get_transport()
            if transport is None:
                raise VmError("The SSH transport disappeared before its host key was read.")
            presented = transport.get_remote_server_key()
            known_hosts.write_text(
                f"[127.0.0.1]:{port} {presented.get_name()} {presented.get_base64()}\n",
                encoding="utf-8",
            )
            return
        except (paramiko.SSHException, OSError, EOFError) as error:
            last = f"{type(error).__name__}: {error}"
            time.sleep(2)
        finally:
            client.close()
    raise VmError(f"SSH did not answer on 127.0.0.1:{port} in {timeout:.0f} s ({last})")


def wait_for_cloud_init(
    *, port: int, key: Path, known_hosts: Path, timeout: float = BOOT_TIMEOUT
) -> str:
    """Wait for cloud-init's final stage and return its long status for the lane log.

    The image's ``systemd-networkd-wait-online`` probe times out under QEMU user
    networking even though the guest has a working lease, so cloud-init reports a
    ``degraded`` extended status after a successful run. ``status: done`` with no
    ``errors`` is finished; only ``status: error`` fails the lane.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with _client(port=port, key=key, known_hosts=known_hosts) as client:
                _, detail, detail_error = _run(
                    client, "cloud-init status --long 2>&1 || true", timeout=30
                )
                report = detail + detail_error
                if re.search(r"^status: error$", report, re.MULTILINE):
                    _, apt, apt_error = _run(
                        client,
                        "sudo cat /var/log/barectl-vm-apt.log 2>/dev/null || true",
                        timeout=30,
                    )
                    raise VmError(
                        "cloud-init did not finish:\n"
                        f"{report.strip()}\n"
                        f"apt-get update:\n{apt.strip()}\n{apt_error.strip()}"
                    )
                if re.search(r"^status: (done|disabled)$", report, re.MULTILINE):
                    return report
                time.sleep(2)
        except paramiko.SSHException, OSError, EOFError:
            time.sleep(2)
    raise VmError(f"cloud-init did not finish in {timeout:.0f} s")


def _wait_for_port(port: int, *, process: subprocess.Popen[bytes] | None, what: str) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            raise VmError(f"{what} exited before listening on 127.0.0.1:{port}.")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.1)
    raise VmError(f"{what} did not listen on 127.0.0.1:{port} in 30 s.")


def _kill_qemu(pid_file: Path, *, timeout: float = 30) -> None:
    try:
        pid = int(pid_file.read_text(encoding="utf-8").strip())
    except OSError, ValueError:
        return
    with contextlib.suppress(ProcessLookupError):
        os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.2)
    with contextlib.suppress(ProcessLookupError):
        os.kill(pid, signal.SIGKILL)


def _wrapper(directory: Path, name: str, *, python: str, script: Path, connect: str) -> Path:
    path = directory / name
    path.write_text(
        "#!/bin/sh\nexec " + shlex.join([python, str(script), "--connect", connect]) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


@dataclass
class Vm:
    """A booted guest and the host-side services that keep it reachable and offline."""

    work: Path
    architecture: str
    ssh_port: int
    seed_port: int
    mirror_port: int
    key: Path
    known_hosts: Path
    console_log: Path
    qemu_log: Path
    seed_log: Path
    mirror_log: Path
    _cleanups: list[Callable[[], None]] = field(default_factory=list)
    _seed_stream: TextIO | None = None
    _mirror_stream: TextIO | None = None

    def stop(self) -> None:
        while self._cleanups:
            action = self._cleanups.pop()
            with contextlib.suppress(Exception):
                action()
        if self._seed_stream is not None:
            self._seed_stream.close()
            self._seed_stream = None
        if self._mirror_stream is not None:
            self._mirror_stream.close()
            self._mirror_stream = None

    @classmethod
    def boot(
        cls,
        *,
        work: Path,
        image: Path | None = None,
        architecture: str | None = None,
        ssh_port: int = 0,
        seed_port: int = 0,
        mirror_port: int = 0,
        output: TextIO | None = None,
        timeout: float = BOOT_TIMEOUT,
    ) -> Vm:
        stream = output or sys.stderr
        work.mkdir(parents=True, exist_ok=True)
        logs = work / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        chosen = architecture or host_architecture()
        pin = load_pins()[chosen]
        stream.write(f"vm: using {pin.name} for {chosen}\n")
        stream.flush()
        base = image or ensure(pin, output=stream)
        disk = overlay(base, work / "disk.qcow2")
        used: set[int] = set()
        ssh_port = ssh_port or _free_port(used)
        used.add(ssh_port)
        seed_port = seed_port or _free_port(used)
        used.add(seed_port)
        mirror_port = mirror_port or _free_port(used)
        used.add(mirror_port)
        controller_key = _key(work / "id", comment="barectl-vm-controller")
        known_hosts = work / "known_hosts"
        known_hosts.write_text("", encoding="utf-8")
        manifest = mirror.load()
        hosts = manifest.hosts()
        certificate, certificate_key = mirror.mirror_certificate(hosts)
        mirror_root = mirror.cache_root()
        inrelease = (
            mirror_root
            / mirror.SNAPSHOT_HOST
            / mirror.SNAPSHOT_ROOT
            / "dists"
            / mirror.SNAPSHOT_SUITES[0]
            / "InRelease"
        )
        if not inrelease.is_file():
            raise VmError(
                "The local mirror is missing its snapshot index. "
                "Run docker/disposable-server/mirror.sh -- fetch first."
            )
        fixture_ca, _ = mirror.fixture_ca()
        seed_directory = work / "seed"
        seed_directory.mkdir()
        files = seed_files(
            public_key=Path(f"{controller_key}.pub").read_text(encoding="utf-8"),
            ca_certificate=fixture_ca.read_text(encoding="utf-8"),
            hosts=hosts,
            apt_source=mirror.apt_sources(),
        )
        for name, text in files.items():
            (seed_directory / name).write_text(text, encoding="utf-8")
        instance = cls(
            work=work,
            architecture=chosen,
            ssh_port=ssh_port,
            seed_port=seed_port,
            mirror_port=mirror_port,
            key=controller_key,
            known_hosts=known_hosts,
            console_log=logs / "console.log",
            qemu_log=logs / "qemu.log",
            seed_log=logs / "seed.log",
            mirror_log=logs / "mirror.log",
        )
        try:
            instance._start_seed(seed_directory)
            instance._start_mirror(mirror_root, certificate, certificate_key, hosts)
            instance._start_qemu(chosen, disk, work)
            stream.write(f"vm: guest booted, SSH on 127.0.0.1:{ssh_port}\n")
            stream.flush()
            wait_for_ssh(
                port=ssh_port,
                key=controller_key,
                known_hosts=known_hosts,
                timeout=timeout,
            )
            stream.write("vm: SSH is up; waiting for cloud-init\n")
            stream.flush()
            cloud_init = wait_for_cloud_init(
                port=ssh_port,
                key=controller_key,
                known_hosts=known_hosts,
                timeout=timeout,
            )
            (logs / "cloud-init.txt").write_text(cloud_init, encoding="utf-8")
            if "degraded" in cloud_init:
                stream.write("vm: cloud-init finished with recoverable warnings\n")
                stream.flush()
        except Exception:
            instance.stop()
            raise
        return instance

    def _start_seed(self, directory: Path) -> None:
        stream = self.seed_log.open("w", encoding="utf-8")
        self._seed_stream = stream

        class Handler(SimpleHTTPRequestHandler):
            @override
            def log_message(self, format: str, *args: object) -> None:
                stream.write((format % args) + "\n")
                stream.flush()

        handler = partial(Handler, directory=str(directory))
        server = ThreadingHTTPServer(("127.0.0.1", self.seed_port), handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self._cleanups.append(lambda: _stop_server(server, thread))
        _wait_for_port(self.seed_port, process=None, what="the NoCloud seed server")

    def _start_mirror(
        self,
        root: Path,
        certificate: Path,
        key: Path,
        hosts: Sequence[str],
    ) -> None:
        stream = self.mirror_log.open("w", encoding="utf-8")
        self._mirror_stream = stream
        command = [
            sys.executable,
            str(SCRIPTS / "native_mirror" / "serve.py"),
            "--root",
            str(root),
            "--certificate",
            str(certificate),
            "--key",
            str(key),
            "--address",
            "127.0.0.1",
            "--port",
            str(self.mirror_port),
        ]
        for host in hosts:
            command += ["--host", host]
        process = subprocess.Popen(  # noqa: S603 - this repository's own mirror
            command,
            stdout=stream,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        self._cleanups.append(lambda: _stop_process(process))
        _wait_for_port(self.mirror_port, process=process, what="the mirror")
        stream.write(f"mirror: 127.0.0.1:{self.mirror_port}\n")
        stream.flush()

    def _start_qemu(self, architecture: str, disk: Path, work: Path) -> None:
        seed_wrapper = _wrapper(
            work,
            "guestfwd-seed.sh",
            python=sys.executable,
            script=SCRIPTS / "native_mirror" / "guestfwd.py",
            connect=f"127.0.0.1:{self.seed_port}",
        )
        mirror_wrapper = _wrapper(
            work,
            "guestfwd-mirror.sh",
            python=sys.executable,
            script=SCRIPTS / "native_mirror" / "guestfwd.py",
            connect=f"127.0.0.1:{self.mirror_port}",
        )
        command = qemu_command(
            architecture=architecture,
            accel=accelerator(),
            disk=disk,
            ssh_port=self.ssh_port,
            seed_port=self.seed_port,
            mirror_port=self.mirror_port,
            seed_command=seed_wrapper,
            mirror_command=mirror_wrapper,
            pid_file=work / "qemu.pid",
            console_log=self.console_log,
            firmware_path=firmware(architecture),
        )
        completed = subprocess.run(  # noqa: S603 - fixed QEMU invocation
            command,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        self.qemu_log.write_text(completed.stdout + completed.stderr, encoding="utf-8")
        if completed.returncode != 0:
            raise VmError(
                f"QEMU did not start: {completed.stderr.strip()[-800:] or completed.stdout}"
            )
        pid_file = work / "qemu.pid"
        deadline = time.monotonic() + 10
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.1)
        if not pid_file.exists():
            raise VmError(f"QEMU did not write {pid_file}; see {self.qemu_log}.")
        self._cleanups.append(lambda: _kill_qemu(pid_file))


def _stop_server(server: ThreadingHTTPServer, thread: threading.Thread) -> None:
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def keep_logs(work: Path, output: TextIO) -> Path:
    source = work / "logs"
    destination = Path(
        os.environ.get("BARECTL_DISPOSABLE_LOGS")
        or Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
        / "barectl"
        / "native"
        / "vm-logs"
    )
    shutil.rmtree(destination, ignore_errors=True)
    if source.exists():
        shutil.copytree(source, destination)
    output.write(f"vm: logs kept at {destination}\n")
    output.flush()
    return destination
