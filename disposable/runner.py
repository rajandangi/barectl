"""Run the native suites across many disposable servers at once.

docs/quality.md#native-suites describes the contract. Every selected test class runs on a
fresh server booted from a provisioned baseline image, so no class sees another's changes.
Each release gets several lanes, each with its own Docker network and ACME and DNS
fixtures; a lane takes the longest remaining class, runs it with ``manage.py test`` and
boots its next server while it does. ``--shard I/N`` keeps only the I-th of N partitions,
balanced by recorded durations, for a CI matrix.
"""

import argparse
import contextlib
import fcntl
import hashlib
import json
import math
import os
import queue
import re
import secrets
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from collections.abc import Iterator, Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import TextIO

REPOSITORY = Path(__file__).resolve().parent.parent
FIXTURE = REPOSITORY / "docker" / "disposable-server"
DURATIONS = FIXTURE / "durations.json"
RELEASES = ("24.04", "26.04")
PROVIDER = {"24.04": "", "26.04": "/srv/provider-repository"}
IMAGE = "barectl-disposable-server"
BASELINE = "barectl-disposable-baseline"
# Raise when build_baseline changes what a baseline holds.
BASELINE_FORMAT = "3"
# Mirrors drop superseded packages, so a baseline's package indexes must stay recent.
BASELINE_MAX_AGE = 12 * 3600
PEBBLE = (
    "ghcr.io/letsencrypt/pebble:2.10.1@sha256:"
    "ddf230642b1a584f519f32e347de1b05a6e4c1f6c35c1863b33effeab5f78199"
)
CHALLTESTSRV = (
    "ghcr.io/letsencrypt/pebble-challtestsrv:2.10.1@sha256:"
    "12ce21884def456bcf9786542113949e1f19dc7738d2c70e156c2d0c38a1405b"
)
SSH_TAG = "ssh"
BROWSER_TAG = "native-browser"
ITEM_LIMIT = 45 * 60
UNKNOWN_DURATION = 20.0
# Two servers (one running, one booting) and the ACME and DNS fixtures.
LANE_MEMORY_GIB = 1.25
RAN = re.compile(r"^Ran (\d+) tests? in ", re.MULTILINE)
VERDICT = re.compile(r"^(OK|FAILED)\b.*$", re.MULTILINE)

stopping = threading.Event()


class RunnerError(Exception):
    """A fixture could not be prepared; the run stops."""


def docker(*arguments: str, timeout: float = 300, stdin: str | None = None) -> str:
    try:
        completed = subprocess.run(  # noqa: S603 - the runner's own Docker commands
            ["docker", *arguments],  # noqa: S607 - Docker on PATH
            input=stdin,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RunnerError(f"docker {arguments[0]} timed out after {timeout:.0f} s") from exc
    if completed.returncode != 0:
        raise RunnerError(f"docker {' '.join(arguments[:2])}: {completed.stderr.strip()}")
    return completed.stdout


def quietly(*arguments: str) -> None:
    subprocess.run(  # noqa: S603 - the runner's own Docker commands
        ["docker", *arguments],  # noqa: S607 - Docker on PATH
        capture_output=True,
        timeout=120,
        check=False,
    )


def run(*arguments: str, cwd: Path | None = None) -> None:
    subprocess.run(arguments, cwd=cwd, capture_output=True, check=True, timeout=120)  # noqa: S603


class Output:
    """Whole lines from many threads, each prefixed with its release."""

    def __init__(self, stream: TextIO) -> None:
        self.stream = stream
        self.lock = threading.Lock()

    def say(self, release: str, text: str) -> None:
        with self.lock:
            for line in text.rstrip("\n").splitlines() or [""]:
                self.stream.write(f"[{release}] {line}\n")
            self.stream.flush()


# Selection


@dataclass(frozen=True)
class Item:
    """Tests of one class run by one ``manage.py test`` invocation on one fresh server."""

    browser: bool
    label: str
    tests: tuple[str, ...]
    labels: tuple[str, ...]
    estimate: float


def discover(labels: Sequence[str], *, browser: bool) -> dict[str, list[str]]:
    """Test ids by class, in suite order, as ``manage.py test`` would select them."""
    import django
    from django.test.runner import DiscoverRunner

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    django.setup()
    selector = DiscoverRunner(
        tags=[BROWSER_TAG if browser else SSH_TAG],
        exclude_tags=[] if browser else [BROWSER_TAG],
        verbosity=0,
    )
    classes: dict[str, list[str]] = {}
    for test in tests_of(selector.build_suite(list(labels) or None)):
        test_id = test.id()
        classes.setdefault(test_id.rsplit(".", 1)[0], []).append(test_id)
    return classes


def tests_of(suite: unittest.TestSuite | unittest.TestCase) -> Iterator[unittest.TestCase]:
    if isinstance(suite, unittest.TestCase):
        yield suite
        return
    for member in suite:
        yield from tests_of(member)


def read_durations(*paths: Path) -> dict[str, float]:
    durations: dict[str, float] = {}
    for path in paths:
        with contextlib.suppress(FileNotFoundError, ValueError):
            loaded: object = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                durations.update(
                    (str(name), float(value))
                    for name, value in loaded.items()
                    if isinstance(value, int | float)
                )
    return durations


def plan(
    classes: dict[str, list[str]], durations: dict[str, float], *, browser: bool, lanes: int
) -> list[Item]:
    """Whole classes, with any class longer than half a lane's fair share split by method."""
    known = [durations[test] for tests in classes.values() for test in tests if test in durations]
    fallback = sum(known) / len(known) if known else UNKNOWN_DURATION
    estimates = {
        test: durations.get(test, fallback) for tests in classes.values() for test in tests
    }
    total = sum(estimates.values())
    target = max(60.0, total / max(lanes, 1) / 2)
    items: list[Item] = []
    for label, tests in classes.items():
        chunk: list[str] = []
        for test in tests:
            if chunk and sum(estimates[t] for t in chunk) + estimates[test] > target:
                items.append(make_item(label, chunk, estimates, browser=browser, split=True))
                chunk = []
            chunk.append(test)
        whole = len(chunk) == len(tests)
        items.append(make_item(label, chunk, estimates, browser=browser, split=not whole))
    return items


def make_item(
    label: str, tests: list[str], estimates: dict[str, float], *, browser: bool, split: bool
) -> Item:
    return Item(
        browser=browser,
        label=label if not split else f"{label} [{tests[0].rsplit('.', 1)[1]}…]",
        tests=tuple(tests),
        labels=tuple(tests) if split else (label,),
        estimate=sum(estimates[test] for test in tests),
    )


def longest_first(items: list[Item]) -> list[Item]:
    return sorted(items, key=lambda candidate: (-candidate.estimate, candidate.label))


def shard(items: list[Item], index: int, count: int) -> list[Item]:
    """The ``index``-th (from 1) of ``count`` partitions, filled longest first."""
    loads = [0.0] * count
    chosen: list[Item] = []
    for candidate in longest_first(items):
        lightest = loads.index(min(loads))
        loads[lightest] += candidate.estimate
        if lightest == index - 1:
            chosen.append(candidate)
    return chosen


# Baseline image


def cache_directory() -> Path:
    root = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    directory = root / "barectl" / "native"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


@dataclass(frozen=True)
class Keys:
    first: Path
    second: Path

    def authorized(self) -> str:
        return Path(f"{self.first}.pub").read_text(encoding="utf-8") + Path(
            f"{self.second}.pub"
        ).read_text(encoding="utf-8")


def controller_keys(directory: Path) -> Keys:
    """Two independent controllers' keys, kept with the baselines that authorize them."""
    keys = Keys(directory / "id", directory / "id2")
    for key in (keys.first, keys.second):
        if not key.exists():
            run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key))
    return keys


def fingerprint(release: str, keys: Keys) -> str:
    digest = hashlib.sha256(f"{BASELINE_FORMAT} {release}".encode())
    for name in (
        "Dockerfile",
        "provision.sh",
        "provider-repository.sh",
        "provider-repository.service",
    ):
        digest.update((FIXTURE / name).read_bytes())
    digest.update(keys.authorized().encode())
    return digest.hexdigest()[:12]


@dataclass(frozen=True)
class Baseline:
    release: str
    image: str
    server: str
    host_key: str
    architecture: str
    revisions: str
    services: frozenset[str]


@contextlib.contextmanager
def file_lock(path: Path) -> Iterator[None]:
    with path.open("w") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def image_age(image: str) -> float | None:
    try:
        built = docker("image", "inspect", "-f", '{{index .Config.Labels "barectl.built"}}', image)
    except RunnerError:
        return None
    return time.time() - float(built.strip() or 0)


def baseline(release: str, keys: Keys, output: Output) -> Baseline:
    """The release's provisioned server, built at most once per period for every run."""
    tag = f"{BASELINE}:{release}-{fingerprint(release, keys)}"
    server = f"{IMAGE}:{release}"
    with file_lock(cache_directory() / f"baseline-{release}.lock"):
        age = image_age(tag)
        rebuild = os.environ.get("BARECTL_NATIVE_REBUILD") == "1"
        if rebuild or age is None or age > BASELINE_MAX_AGE:
            output.say(release, "Building the provisioned baseline image…")
            build_baseline(release, server, tag, keys)
    probe = Server.boot(tag, network=None, name=f"{IMAGE}-{release}-probe-{secrets.token_hex(4)}")
    try:
        host_key = probe.exec("cut -d' ' -f1-2 /etc/ssh/ssh_host_ed25519_key.pub").strip()
        architecture = probe.exec("uname -m").strip()
        revisions = probe.exec(REVISIONS)
    finally:
        probe.remove()
    label = docker("image", "inspect", "-f", '{{index .Config.Labels "barectl.services"}}', tag)
    services = frozenset(label.split())
    return Baseline(release, tag, server, host_key, architecture, revisions, services)


# Packages the tests install beyond provision.sh, fetched into APT's cache, not installed.
PREFETCH = (
    "export DEBIAN_FRONTEND=noninteractive; php=$(ls /etc/php); "
    "apt-get install -y -qq --download-only -o APT::Install-Recommends=0 mariadb-server "
    '"php$php-mysql" "php$php-pgsql" "php$php-cli" certbot >/dev/null'
)
# The running services the native tests compare; user sessions come and go.
RUNNING = (
    "systemctl list-units --type=service --state=running --no-legend --plain "
    "| cut -d' ' -f1 | grep -v '^user@'"
)
# docs/v0.2-qualification.md#environments cites these revisions.
REVISIONS = """. /etc/os-release; echo "$PRETTY_NAME $(uname -m)";
php=$(dpkg-query -W -f="\\${Package}\\n" "php[0-9]*-fpm" 2>/dev/null | head -1);
dpkg-query -W apt dpkg systemd systemd-resolved util-linux sudo sudo-rs needrestart \
    debconf nginx packagekit ubuntu-helper-virt-hwe "$php" 2>/dev/null;
readlink -f /usr/bin/sudo"""


def build_baseline(release: str, server: str, tag: str, keys: Keys) -> None:
    """Provision under systemd as on a real server, then keep the result as an image.

    provision.sh needs systemd as PID 1, which ``docker build`` does not run.
    """
    with tempfile.TemporaryDirectory() as context:
        for name in ("Dockerfile", "provider-repository.sh", "provider-repository.service"):
            shutil.copy(FIXTURE / name, context)
        docker("build", "-q", "--build-arg", f"RELEASE={release}", "-t", server, context,
               timeout=1800)  # fmt: skip
    builder = Server.boot(
        server, network=None, name=f"{IMAGE}-{release}-build-{secrets.token_hex(4)}"
    )
    try:
        builder.exec((FIXTURE / "provision.sh").read_text(encoding="utf-8"), timeout=1800)
        builder.exec(
            f"keys={shlex.quote(keys.authorized())}; "
            "for home in /home/deploy /home/observer /root; do "
            'printf %s "$keys" >"$home/.ssh/authorized_keys"; '
            'chown "$(stat -c %U "$home"):" "$home/.ssh/authorized_keys"; '
            'chmod 600 "$home/.ssh/authorized_keys"; done'
        )
        services = " ".join(sorted(builder.exec(RUNNING).split()))
        # Every server would otherwise download the packages the tests install from the mirror.
        builder.exec(PREFETCH, timeout=1800)
        # Stopped services leave consistent data; boot starts them again.
        builder.exec(
            "systemctl stop nginx 'php*-fpm' postgresql 'postgresql@*' 2>/dev/null; sync; true"
        )
        docker(
            "commit",
            "-c", "CMD [\"/lib/systemd/systemd\"]",
            "-c", f"LABEL barectl.built={int(time.time())}",
            "-c", f"LABEL barectl.services={json.dumps(services)}",
            builder.name,
            tag,
            timeout=600,
        )  # fmt: skip
    finally:
        builder.remove()
    for line in docker("images", BASELINE, "--format", "{{.Repository}}:{{.Tag}}").splitlines():
        if line.startswith(f"{BASELINE}:{release}-") and line != tag:
            quietly("rmi", line)


# Servers and lanes


@dataclass
class Server:
    name: str
    port: int = 0

    @classmethod
    def boot(cls, image: str, *, network: str | None, name: str) -> Server:
        options = ["--network", network] if network else []
        # A fixed host port, since tests restart the container and SSH must find it again.
        port = 0
        for attempt in range(5):
            port = free_port()
            try:
                docker("run", "-d", "--privileged", "--name", name, *options,
                       "-p", f"127.0.0.1:{port}:22", image)  # fmt: skip
                break
            except RunnerError:
                quietly("rm", "-f", name)
                if attempt == 4:
                    raise
        server = cls(name, port)
        try:
            server.wait_for_systemd()
        except Exception:
            server.remove()
            raise
        return server

    def wait_for_systemd(self) -> None:
        state = ""
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            with contextlib.suppress(RunnerError):
                state = self.exec("systemctl is-system-running || true").strip()
            # systemd reports degraded when a unit fails that the tests do not use.
            if state in {"running", "degraded"}:
                return
            time.sleep(0.2)
        raise RunnerError(f"systemd did not start in {self.name} (state: {state or 'unknown'})")

    def settle(self, services: frozenset[str]) -> None:
        """Run exactly the services provisioning left running.

        Booting starts every automatic PostgreSQL cluster, including the stopped ``archive``,
        and services that exit once idle, which a test would see stop.
        """
        deadline = time.monotonic() + 60
        while True:
            running = frozenset(self.exec(RUNNING).split())
            if running == services:
                return
            if time.monotonic() > deadline:
                raise RunnerError(f"{self.name} runs {sorted(running ^ services)} unexpectedly")
            extra, missing = sorted(running - services), sorted(services - running)
            if extra:
                self.exec("systemctl stop " + " ".join(map(shlex.quote, extra)))
            if missing:
                self.exec("systemctl start " + " ".join(map(shlex.quote, missing)))
            time.sleep(0.5)

    def exec(self, script: str, *, timeout: float = 300, stdin: str | None = None) -> str:
        return docker("exec", "-i", self.name, "sh", "-c", script, timeout=timeout, stdin=stdin)

    def remove(self) -> None:
        quietly("rm", "-f", self.name)


@dataclass
class Lane:
    release: str
    index: int
    baseline: Baseline
    keys: Keys
    fixtures: Path
    output: Output
    name: str = ""
    network: str = ""
    ipv6_unavailable: str = ""
    containers: list[str] = field(default_factory=list)
    serial: int = 0

    def start(self) -> None:
        self.name = f"{IMAGE}-{self.release}-{os.getpid()}-{secrets.token_hex(3)}-{self.index}"
        self.create_network()
        self.start_fixtures()

    def create_network(self) -> None:
        # Each lane's network has its own IPv6 prefix, so lanes never share one.
        self.network = self.name
        error = ""
        for _ in range(5):
            subnet = f"fd00:bc:{secrets.token_hex(2)}::/64"
            try:
                docker("network", "create", "--ipv6", "--subnet", subnet, self.network)
            except RunnerError as exc:
                error = str(exc)
                continue
            return
        self.ipv6_unavailable = f"Docker could not create an IPv6 network: {error}"
        docker("network", "create", self.network)

    def start_fixtures(self) -> None:
        # The ACME and DNS fixtures: docs/ssh-connections.md#acme-and-dns-fixtures
        alias = ("--network", self.network, "--network-alias")
        self.container(
            "challtestsrv", *alias, "challtestsrv", "-p", "127.0.0.1::8055", CHALLTESTSRV,
            "-defaultIPv4", "", "-defaultIPv6", "", "-http01", "", "-https01", "",
            "-tlsalpn01", "", "-doh", "",
        )  # fmt: skip
        for instance in ("pebble", "pebble-short"):
            self.container(
                instance, *alias, instance,
                "-e", "PEBBLE_VA_NOSLEEP=1", "-e", "PEBBLE_WFE_NONCEREJECT=0",
                "-e", "PEBBLE_AUTHZREUSE=0", "-p", "127.0.0.1::14000", "-p", "127.0.0.1::15000",
                PEBBLE, "-config", "/config/pebble.json", "-dnsserver", "challtestsrv:8053",
                copy=(self.fixtures / instance, "/config"),
            )  # fmt: skip
        self.container(
            "acme-fault-proxy", *alias, "acme-fault-proxy",
            "-p", "127.0.0.1::14000", "-p", "127.0.0.1::8080",
            "--entrypoint", "python3", self.baseline.server, "/fixture/fault_proxy.py",
            "--upstream", "pebble:14000", "--cafile", "/fixture/minica.pem",
            "--certificate", "/fixture/fixture.pem", "--key", "/fixture/fixture.key",
            "--dns-upstream", "challtestsrv:8053",
            copy=(self.fixtures / "proxy", "/fixture"),
        )  # fmt: skip

    def container(self, role: str, *arguments: str, copy: tuple[Path, str] | None = None) -> None:
        name = f"{self.name}-{role}"
        self.containers.append(name)
        if copy is None:
            docker("run", "-d", "--name", name, *arguments)
            return
        docker("create", "--name", name, *arguments)
        docker("cp", str(copy[0]), f"{name}:{copy[1]}")
        docker("start", name)

    def boot(self) -> Server:
        self.serial += 1
        server = Server.boot(
            self.baseline.image, network=self.network, name=f"{self.name}-server-{self.serial}"
        )
        try:
            server.settle(self.baseline.services)
        except Exception:
            server.remove()
            raise
        return server

    def environment(self, server: Server, work: Path) -> dict[str, str]:
        known_hosts = work / f"{server.name}.known_hosts"
        known_hosts.write_text(f"[127.0.0.1]:{server.port} {self.baseline.host_key}\n")
        return {
            "BARECTL_SSH_TEST_HOST": "127.0.0.1",
            "BARECTL_SSH_TEST_PORT": str(server.port),
            "BARECTL_SSH_TEST_USER": "deploy",
            "BARECTL_SSH_TEST_KEY": str(self.keys.first),
            "BARECTL_SSH_TEST_KNOWN_HOSTS": str(known_hosts),
            "BARECTL_SSH_TEST_SECOND_KEY": str(self.keys.second),
            "BARECTL_SSH_TEST_UNPRIVILEGED_USER": "observer",
            "BARECTL_SSH_TEST_CONTAINER": server.name,
            "BARECTL_SSH_TEST_RELEASE": self.release,
            "BARECTL_SSH_TEST_PROVIDER_REPOSITORY": PROVIDER[self.release],
            "BARECTL_ACME_TEST_NETWORK": self.network,
            "BARECTL_ACME_TEST_ROOT": str(self.fixtures / "minica.pem"),
            "BARECTL_ACME_TEST_PEBBLE": f"{self.name}-pebble",
            "BARECTL_ACME_TEST_PEBBLE_SHORT": f"{self.name}-pebble-short",
            "BARECTL_ACME_TEST_CHALLTESTSRV": f"{self.name}-challtestsrv",
            "BARECTL_ACME_TEST_FAULT_PROXY": f"{self.name}-acme-fault-proxy",
            "BARECTL_ACME_TEST_IPV6_UNAVAILABLE": self.ipv6_unavailable,
        }

    def remove(self) -> None:
        for name in self.containers:
            quietly("rm", "-f", name)
        if self.network:
            quietly("network", "rm", self.network)


def pebble_config(certificate: str, key: str, validity: int) -> str:
    return json.dumps(
        {
            "pebble": {
                "listenAddress": ":14000",
                "managementListenAddress": ":15000",
                "certificate": certificate,
                "privateKey": key,
                "httpPort": 80,
                "tlsPort": 443,
                "ocspResponderURL": "",
                "externalAccountBindingRequired": False,
                "domainBlocklist": ["blocked.barectl.test"],
                "retryAfter": {"authz": 3, "order": 5},
                "keyAlgorithm": "ecdsa",
                "profiles": {
                    "default": {"description": "Barectl fixture", "validityPeriod": validity}
                },
            }
        },
        indent=2,
    )


def acme_fixtures(directory: Path) -> Path:
    """Pebble's test root and a fixture certificate from it, shared by every lane.

    Pebble's own TLS certificate names only localhost and pebble, so the other fixtures get
    one from the same test root, which the tests install on the disposable server.
    """
    acme = directory / "acme"
    for name in ("pebble", "pebble-short", "proxy"):
        (acme / name).mkdir(parents=True)
    holder = f"{IMAGE}-certificates-{secrets.token_hex(4)}"
    docker("create", "--name", holder, PEBBLE)
    try:
        docker("cp", f"{holder}:/test/certs/pebble.minica.pem", str(acme / "minica.pem"))
        docker("cp", f"{holder}:/test/certs/pebble.minica.key.pem", str(acme / "minica.key"))
    finally:
        quietly("rm", "-f", holder)
    run("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "fixture.key",
        cwd=acme)  # fmt: skip
    run("openssl", "req", "-new", "-key", "fixture.key", "-subj", "/CN=acme-fault-proxy",
        "-out", "fixture.csr", cwd=acme)  # fmt: skip
    (acme / "fixture.ext").write_text(
        "subjectAltName=DNS:acme-fault-proxy,DNS:pebble-short,DNS:localhost,IP:127.0.0.1\n"
        "extendedKeyUsage=serverAuth\n"
    )
    run("openssl", "x509", "-req", "-in", "fixture.csr", "-CA", "minica.pem",
        "-CAkey", "minica.key", "-set_serial", f"0x{secrets.token_hex(8)}", "-days", "30",
        "-extfile", "fixture.ext", "-out", "fixture.pem", cwd=acme)  # fmt: skip
    (acme / "pebble" / "pebble.json").write_text(
        pebble_config("test/certs/localhost/cert.pem", "test/certs/localhost/key.pem", 7776000)
    )
    # Short enough that a certificate is due for renewal as soon as it is issued.
    (acme / "pebble-short" / "pebble.json").write_text(
        pebble_config("/config/fixture.pem", "/config/fixture.key", 600)
    )
    for name in ("fixture.pem", "fixture.key"):
        shutil.copy(acme / name, acme / "pebble-short")
    for name in ("fixture.pem", "fixture.key", "minica.pem"):
        shutil.copy(acme / name, acme / "proxy")
    shutil.copy(REPOSITORY / "disposable" / "fault_proxy.py", acme / "proxy")
    return acme


# Running


@dataclass
class Outcome:
    item: Item
    passed: bool
    ran: int
    seconds: float
    log: Path
    reason: str = ""


@dataclass
class Release:
    name: str
    items: list[Item]
    lanes: int
    outcomes: list[Outcome] = field(default_factory=list)
    error: str = ""
    baseline: Baseline | None = None

    @property
    def passed(self) -> bool:
        return (
            not self.error
            and len(self.outcomes) == len(self.items)
            and all(outcome.passed for outcome in self.outcomes)
        )


class Runner:
    def __init__(self, keys: Keys, work: Path, output: Output, *, keep_failed: bool) -> None:
        self.keys = keys
        self.work = work
        self.output = output
        self.keep_failed = keep_failed
        self.lock = threading.Lock()
        self.processes: set[subprocess.Popen[bytes]] = set()
        self.lanes: list[Lane] = []

    def release(self, release: Release, fixtures: Path) -> None:
        try:
            release.baseline = baseline(release.name, self.keys, self.output)
            self.output.say(release.name, f"Disposable server:\n{release.baseline.revisions}")
            work = queue.SimpleQueue[Item]()
            for candidate in longest_first(release.items):
                work.put(candidate)
            with ThreadPoolExecutor(release.lanes) as lanes:
                futures = [
                    lanes.submit(self.lane, release, index, work, fixtures)
                    for index in range(release.lanes)
                ]
                for future in futures:
                    future.result()
        except Exception as exc:
            release.error = f"{type(exc).__name__}: {exc}"
            self.output.say(release.name, f"Stopped: {release.error}")
            stopping.set()

    def lane(
        self, release: Release, index: int, work: queue.SimpleQueue[Item], fixtures: Path
    ) -> None:
        if release.baseline is None:
            return
        lane = Lane(release.name, index, release.baseline, self.keys, fixtures, self.output)
        with self.lock:
            self.lanes.append(lane)
        lane.start()
        with ThreadPoolExecutor(1) as booter:
            upcoming: Future[Server] | None = None
            while not stopping.is_set():
                try:
                    candidate = work.get_nowait()
                except queue.Empty:
                    break
                server = upcoming.result() if upcoming else lane.boot()
                upcoming = booter.submit(lane.boot) if not work.empty() else None
                outcome = self.execute(lane, server, candidate)
                with self.lock:
                    release.outcomes.append(outcome)
                if outcome.passed or not self.keep_failed:
                    server.remove()
                else:
                    self.output.say(release.name, f"Kept {server.name} on {lane.network}.")
            if upcoming:
                upcoming.result().remove()
        if not (self.keep_failed and any(not o.passed for o in release.outcomes)):
            lane.remove()

    def execute(self, lane: Lane, server: Server, candidate: Item) -> Outcome:
        log = self.work / "logs" / lane.release / f"{server.name}.log"
        log.parent.mkdir(parents=True, exist_ok=True)
        environment = os.environ | lane.environment(server, self.work)
        if candidate.browser:
            environment["BARECTL_TEST_DATABASE"] = str(self.work / f"{server.name}.sqlite3")
            tags = ["--tag", BROWSER_TAG]
        else:
            environment["BARECTL_TEST_DATABASE"] = ""
            tags = ["--tag", SSH_TAG, "--exclude-tag", BROWSER_TAG]
        command = [sys.executable, "manage.py", "test", *tags, "--verbosity", "2",
                   "--testrunner", "disposable.testrunner.NativeRunner"]  # fmt: skip
        started = time.monotonic()
        with log.open("wb") as stream:
            process = subprocess.Popen(  # noqa: S603 - this repository's own test command
                [*command, *candidate.labels],
                cwd=REPOSITORY,
                env=environment,
                stdout=stream,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            with self.lock:
                self.processes.add(process)
            try:
                returncode = process.wait(timeout=ITEM_LIMIT)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                returncode = process.wait()
            finally:
                with self.lock:
                    self.processes.discard(process)
        seconds = time.monotonic() - started
        outcome = judge(candidate, log, returncode, seconds)
        verdict = "ok  " if outcome.passed else "FAIL"
        self.output.say(
            lane.release,
            f"{verdict} {outcome.ran:>3} tests {seconds:6.1f}s {candidate.label}"
            + (f" — {outcome.reason}" if outcome.reason else ""),
        )
        return outcome

    def interrupt(self) -> None:
        stopping.set()
        with self.lock:
            for process in self.processes:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGTERM)

    def clean(self) -> None:
        names = docker("ps", "-a", "--format", "{{.Names}}").split()
        for lane in self.lanes:
            for name in names:
                if name.startswith(f"{lane.name}-server-"):
                    quietly("rm", "-f", name)
            lane.remove()


def judge(candidate: Item, log: Path, returncode: int | None, seconds: float) -> Outcome:
    text = log.read_text(encoding="utf-8", errors="replace")
    ran = sum(int(match) for match in RAN.findall(text))
    verdicts = VERDICT.findall(text)[-1:]
    reason = ""
    if stopping.is_set() and returncode != 0:
        reason = "stopped"
    elif returncode is None or returncode < 0:
        reason = f"killed after {seconds:.0f} s"
    elif ran != len(candidate.tests):
        reason = f"expected {len(candidate.tests)} tests, ran {ran}"
    elif returncode != 0 or verdicts != ["OK"]:
        reason = f"exit {returncode}"
    return Outcome(candidate, not reason, ran, seconds, log, reason)


def failures(text: str) -> str:
    """The failure and error reports of a ``manage.py test`` log, or its tail."""
    start = text.find("\n======")
    return text[start + 1 :] if start >= 0 else "\n".join(text.splitlines()[-60:])


def record_durations(releases: list[Release], path: Path) -> None:
    durations = read_durations(path)
    for release in releases:
        for outcome in release.outcomes:
            share = outcome.seconds / len(outcome.item.tests)
            for test in outcome.item.tests:
                if outcome.passed:
                    durations[test] = round(share, 1)
                elif outcome.reason == "stopped":
                    # A stopped item took at least this long.
                    durations[test] = round(max(durations.get(test, 0.0), share), 1)
    path.write_text(json.dumps(dict(sorted(durations.items())), indent=1) + "\n")


def default_lanes(releases: int) -> int:
    configured = os.environ.get("BARECTL_NATIVE_LANES")
    if configured:
        return max(1, int(configured))
    info = docker("info", "--format", "{{.NCPU}} {{.MemTotal}}").split()
    cpus, memory = int(info[0]), int(info[1]) / 2**30
    # More lanes than this slow every test past Barectl's own command timeouts.
    total = max(1, min(round(cpus * 1.25), math.floor(memory / LANE_MEMORY_GIB)))
    return max(1, total // releases)


def arguments(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="run-tests.sh", description=__doc__)
    parser.add_argument("labels", nargs="*", help="test modules, classes or methods")
    parser.add_argument("--release", action="append", choices=RELEASES)
    parser.add_argument("--shard", help="I/N: run only the I-th of N partitions")
    parser.add_argument("--lanes", type=int, help="servers per release at once")
    parser.add_argument("--keep-failed", action="store_true", help="keep failed servers")
    parser.add_argument(
        "--time-limit", type=float, metavar="SECONDS", help="stop and fail after SECONDS"
    )
    parser.add_argument("--list", action="store_true", help="print the plan and stop")
    parser.add_argument(
        "--update-durations", action="store_true", help=f"record durations in {DURATIONS.name}"
    )
    return parser.parse_args(argv)


def selected_releases(options: argparse.Namespace) -> list[str]:
    if options.release:
        return list(dict.fromkeys(options.release))
    configured = os.environ.get("BARECTL_DISPOSABLE_RELEASE", "").split()
    unknown = [release for release in configured if release not in RELEASES]
    if unknown:
        raise SystemExit(f"Unsupported release {' '.join(unknown)}; choose 24.04 or 26.04.")
    return configured or list(RELEASES)


def main(argv: Sequence[str] | None = None) -> int:
    options = arguments(sys.argv[1:] if argv is None else argv)
    output = Output(sys.stdout)
    names = selected_releases(options)
    partition = partition_of(options.shard)
    lanes = options.lanes or default_lanes(len(names))
    local = cache_directory() / "durations.json"
    items = select(options.labels, lanes, partition, local)
    if options.list:
        for candidate in longest_first(items):
            print(f"{candidate.estimate:7.1f}s {len(candidate.tests):>3} {candidate.label}")  # noqa: T201
        return 0
    complete = not options.labels and partition is None
    releases = [Release(name, items, min(lanes, max(1, len(items)))) for name in names]
    output.say(
        "plan",
        f"{len(items)} items, {sum(len(i.tests) for i in items)} tests per release, "
        f"{releases[0].lanes} lanes per release",
    )
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="barectl-native-") as directory:
        work = Path(directory)
        keys = controller_keys(cache_directory())
        runner = Runner(keys, work, output, keep_failed=options.keep_failed)
        execute(releases, options.time_limit, runner)
        summarize(releases, output, time.monotonic() - started)
        record_durations(releases, local)
        if options.update_durations and complete:
            record_durations(releases, DURATIONS)
        write_results(releases, partition, complete=complete)
        keep_logs(work, output)
    return 0 if all(release.passed for release in releases) else 1


def partition_of(value: str | None) -> tuple[int, int] | None:
    if not value:
        return None
    index, _, count = value.partition("/")
    partition = (int(index), int(count))
    if not 1 <= partition[0] <= partition[1]:
        raise SystemExit("--shard takes I/N with 1 <= I <= N.")
    return partition


def select(
    labels: Sequence[str], lanes: int, partition: tuple[int, int] | None, local: Path
) -> list[Item]:
    # A CI shard reads only the committed durations, so every shard computes the same plan.
    durations = read_durations(DURATIONS) if partition else read_durations(DURATIONS, local)
    # Split classes against every lane of every shard, so all shards agree on the items.
    spread = lanes * (partition[1] if partition else 1)
    items = [
        *plan(discover(labels, browser=False), durations, browser=False, lanes=spread),
        *plan(discover(labels, browser=True), durations, browser=True, lanes=spread),
    ]
    return shard(items, *partition) if partition else items


def execute(releases: list[Release], limit: float | None, runner: Runner) -> None:
    previous = signal.signal(signal.SIGTERM, lambda *_: runner.interrupt())
    threads: list[threading.Thread] = []
    try:
        fixtures = acme_fixtures(runner.work)
        threads = [
            threading.Thread(target=runner.release, args=(release, fixtures))
            for release in releases
        ]
        for thread in threads:
            thread.start()
        deadline = time.monotonic() + limit if limit else math.inf
        while any(thread.is_alive() for thread in threads):
            if time.monotonic() > deadline and not stopping.is_set():
                runner.output.say("limit", f"{limit:.0f} s reached; stopping.")
                runner.interrupt()
            for thread in threads:
                thread.join(timeout=1)
    except KeyboardInterrupt:
        runner.interrupt()
        for thread in threads:
            thread.join()
    finally:
        signal.signal(signal.SIGTERM, previous)
        if not runner.keep_failed:
            runner.clean()


def summarize(releases: list[Release], output: Output, seconds: float) -> None:
    for release in releases:
        for outcome in release.outcomes:
            if not outcome.passed:
                text = outcome.log.read_text(encoding="utf-8", errors="replace")
                output.say(release.name, f"{'=' * 70}\n{outcome.item.label}: {outcome.reason}")
                output.say(release.name, failures(text))
    print(f"Disposable-server tests after {seconds:.0f} seconds:")  # noqa: T201
    for release in releases:
        ran = sum(outcome.ran for outcome in release.outcomes)
        expected = sum(len(item.tests) for item in release.items)
        if release.passed and release.baseline:
            state = f"passed on {release.baseline.architecture}"
        else:
            failed = sum(1 for outcome in release.outcomes if not outcome.passed)
            state = f"failed ({failed} items failed{', ' + release.error if release.error else ''})"
        print(f"  Ubuntu {release.name}: {state}, {ran} of {expected} tests ran")  # noqa: T201


def write_results(
    releases: list[Release], partition: tuple[int, int] | None, *, complete: bool
) -> None:
    """Passing releases for native-check.sh: a full run, or one shard of a CI matrix."""
    directory = os.environ.get("BARECTL_DISPOSABLE_RESULTS")
    if not directory or not (complete or partition):
        return
    for release in releases:
        if not release.passed or release.baseline is None:
            continue
        name = (
            release.name
            if partition is None
            else f"{release.name}.shard-{partition[0]}-of-{partition[1]}"
        )
        (Path(directory) / name).write_text(release.baseline.architecture + "\n")


def keep_logs(work: Path, output: Output) -> None:
    """Every item's log, kept after the run in ``BARECTL_DISPOSABLE_LOGS`` or the cache."""
    destination = Path(os.environ.get("BARECTL_DISPOSABLE_LOGS") or cache_directory() / "logs")
    if (work / "logs").exists():
        shutil.rmtree(destination, ignore_errors=True)
        shutil.copytree(work / "logs", destination)
        output.say("logs", str(destination))


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
        return port


if __name__ == "__main__":
    sys.exit(main())
