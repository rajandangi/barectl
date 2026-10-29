"""Run the native lifecycle scenarios across lanes (docs/quality.md#native-layer).

The runner boots one L0 snapshot image and drives ``manage.py test`` scenario classes
through it on a lane. A lane's server joins only an ``--internal`` network, so it reaches
nothing but the lane's local mirror; the harness reaches its SSH through the lane's
forwarder. Non-exclusive scenarios share one server in sequence, each with its own name
prefix and a residue check; a failed scenario or residue check discards the server. Items
are killed at 180 s, the build stops at 900 s naming what did not finish, and the summary
reports the total against the 10-minute target. The scheduled breadth scenarios
(``--breadth``) are separate: a reboot, a long scheduler run and the 1/2/4 GiB memory classes
never add to the merge build (docs/quality.md#the-scheduled-breadth-job).
"""

import argparse
import contextlib
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
from collections.abc import Iterable, Iterator, Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import TextIO

from . import images, mirror, quarantine, shard_times
from .docker import DockerError, docker, quietly
from .machine import Machine

REPOSITORY = Path(__file__).resolve().parent.parent
SCRIPTS = REPOSITORY / "disposable"
SCENARIO_TAG = "scenario"
RELEASE = "26.04"
# "over 3 minutes" (docs/adr/0033-prove-real-behavior-in-two-test-layers.md).
ITEM_LIMIT = 180.0
BUILD_LIMIT = 900.0
TARGET = 300.0
# lanes = min(floor(CPUs / 1.75), floor(VM GiB / 0.5)) — spike P3, docs/quality.md.
LANE_CPUS = 1.75
LANE_GIB = 0.5
# A real name no mirror serves: a lane that resolves it is not egress-denied.
EGRESS_PROBE = "example.com"
# The lane's fixture servers (docs/quality.md#native-layer). Docker's embedded resolver
# answers these aliases, so they never reach the lane's NXDOMAIN resolver and the egress
# check stays honest. The managed server clones from the Git host and Caddy trusts the
# ACME host through acme_ca/acme_ca_root.
FIXTURE_ACME_HOST = "pebble"
FIXTURE_ACME_DOMAIN = "site.fixture.test"
# A second name the server answers, so a scenario may run two HTTPS sites on one lane.
FIXTURE_SECOND_DOMAIN = "wordpress.fixture.test"
FIXTURE_GIT_HOST = "git"
RAN = re.compile(r"^Ran (\d+) tests? in ", re.MULTILINE)
VERDICT = re.compile(r"^(OK|FAILED)\b.*$", re.MULTILINE)

stopping = threading.Event()


class ScenarioError(Exception):
    """The harness could not prepare a lane; the build stops."""


# Selection


@dataclass(frozen=True)
class Scenario:
    label: str
    tests: tuple[str, ...]
    layer: str
    exclusive: bool
    prefix: str
    records: tuple[str, ...]
    egress_control: bool = False
    breadth: bool = False
    memory_gib: int = 0


def setup_django() -> None:
    import django

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    django.setup()


def tests_of(suite: unittest.TestSuite | unittest.TestCase) -> Iterator[unittest.TestCase]:
    if isinstance(suite, unittest.TestCase):
        yield suite
        return
    for member in suite:
        yield from tests_of(member)


def discover(
    labels: Sequence[str] | None = None,
    *,
    include_quarantined: bool = False,
    only_quarantined: bool = False,
    egress_control: bool = False,
    validators: bool = False,
    preparations: bool = False,
    breadth: bool = False,
) -> list[Scenario]:
    from django.test.runner import DiscoverRunner

    setup_django()
    selector = DiscoverRunner(tags=[SCENARIO_TAG], verbosity=0)
    suite = selector.build_suite(list(labels) if labels else None)
    by_class: dict[type[unittest.TestCase], list[str]] = {}
    for test in tests_of(suite):
        by_class.setdefault(type(test), []).append(test.id())
    scenarios = [
        _scenario(cls, tests)
        for cls, tests in by_class.items()
        if _wanted(
            cls,
            include_quarantined=include_quarantined,
            only_quarantined=only_quarantined,
            egress_control=egress_control,
            validators=validators,
            preparations=preparations,
            breadth=breadth,
        )
    ]
    return sorted(scenarios, key=lambda scenario: scenario.label)


def _wanted(
    cls: type[unittest.TestCase],
    *,
    include_quarantined: bool,
    only_quarantined: bool,
    egress_control: bool,
    validators: bool = False,
    preparations: bool = False,
    breadth: bool = False,
) -> bool:
    if bool(getattr(cls, "preparation", False)) != preparations:
        return False
    if bool(getattr(cls, "validator", False)) != validators:
        return False
    if bool(getattr(cls, "egress_control", False)) != egress_control:
        return False
    # The scheduled breadth job is selected only by ``--breadth``; the merge build never
    # pays for a reboot, a long scheduler run or a memory-class boot (docs/quality.md).
    if bool(getattr(cls, "breadth", False)) != breadth:
        return False
    marked = quarantine.marker_of(cls) is not None
    if only_quarantined:
        return marked
    return include_quarantined or not marked


def _scenario(cls: type[unittest.TestCase], tests: list[str]) -> Scenario:
    layer = getattr(cls, "layer", None)
    if layer not in {"L0", "L1", "L2", "L3", "L4", "L5", "L0-standing", "L0-24.04"}:
        raise ScenarioError(f"{cls.__name__} declares no known layer ({layer!r}).")
    return Scenario(
        label=f"{cls.__module__}.{cls.__qualname__}",
        tests=tuple(tests),
        layer=str(layer),
        exclusive=bool(getattr(cls, "exclusive", False)),
        prefix=str(getattr(cls, "prefix", "")),
        records=tuple(getattr(cls, "records", ())),
        egress_control=bool(getattr(cls, "egress_control", False)),
        breadth=bool(getattr(cls, "breadth", False)),
        memory_gib=int(getattr(cls, "memory_gib", 0) or 0),
    )


# Residue and teardown (Phase A has no site removal; docs/quality.md#native-layer)


def teardown_command(prefix: str) -> str:
    """Remove a scenario's prefixed resources, waiting for workers before ``userdel``."""
    quoted = shlex.quote(prefix)
    return f"""
prefix={quoted}
automation_units=$(systemctl list-units --all --plain --no-legend \
    'barectl-site-'$prefix'*' | cut -d' ' -f1)
for unit in $automation_units; do
    systemctl unmask --runtime "$unit" 2>/dev/null || true
    systemctl stop "$unit" 2>/dev/null || true
    systemctl --no-reload disable "$unit" 2>/dev/null || true
done
automation_slices=$(systemctl list-units --all --plain --no-legend \
    'barectl-site-'$prefix'*.slice' | cut -d' ' -f1)
for slice in $automation_slices; do
    systemctl stop "$slice" 2>/dev/null || true
done
rm -f /etc/systemd/system/barectl-site-"$prefix"*.service \
    /etc/systemd/system/barectl-site-"$prefix"*.timer \
    /etc/systemd/system/barectl-site-"$prefix"*.slice 2>/dev/null
rm -f /run/systemd/system/barectl-site-"$prefix"*.service \
    /run/systemd/system/barectl-site-"$prefix"*.timer \
    /run/systemd/system/barectl-site-"$prefix"*.slice 2>/dev/null
rm -rf /run/systemd/system/barectl-site-"$prefix"*".service.d" \
    /run/systemd/system/barectl-site-"$prefix"*".timer.d" 2>/dev/null
systemctl daemon-reload 2>/dev/null || true
for config in /etc/haproxy/sites/"$prefix"*.cfg; do
    [ -e "$config" ] || continue
    site=$(basename "$config" .cfg)
    systemctl stop "haproxy-site@$site.service" || exit 1
    systemctl --no-reload disable "haproxy-site@$site.service" || exit 1
    for runtime in php84 php85; do
        systemctl stop "php-fpm-site-$runtime@$site.service" || exit 1
        systemctl --no-reload disable "php-fpm-site-$runtime@$site.service" || exit 1
    done
    rm -rf "/etc/php-fpm/sites/$site" "/var/lib/php-fpm/sites/$site"
    rm -f "$config" "/var/lib/haproxy/sites/$site.state"
done
for config in /etc/valkey/"$prefix"*.conf; do
    [ -e "$config" ] || continue
    site=$(basename "$config" .conf)
    systemctl stop "valkey-server@$site.service" || exit 1
    systemctl --no-reload disable "valkey-server@$site.service" || exit 1
    rm -rf "/etc/systemd/system/valkey-server@$site.service.d" \
        "/var/lib/valkey/$site" "/run/valkey/$site"
    rm -f "$config"
done
systemctl daemon-reload || exit 1
for pool in /etc/php/*/fpm/pool.d/"$prefix"*.conf /etc/php-fpm/*/pools/"$prefix"*.conf; do
    [ -e "$pool" ] || continue
    version=$(basename "$(dirname "$(dirname "$pool")")")
    rm -f "$pool"
    systemctl reload "php-fpm@$version" 2>/dev/null || true
done
for account in $(getent passwd | cut -d: -f1 | grep -E "^[sp]$prefix"); do
    for _ in $(seq 100); do
        pgrep -u "$account" >/dev/null 2>&1 || break
        sleep 0.1
    done
    userdel "$account" 2>/dev/null || true
done
rm -rf /var/www/"$prefix"* 2>/dev/null
rm -f /etc/caddy/sites/"$prefix"*.caddy 2>/dev/null
rm -f /etc/logrotate.d/barectl-site-"$prefix"* 2>/dev/null
systemctl reload caddy 2>/dev/null || true
true
""".strip()


def residue_command(prefix: str) -> str:
    """Report any resource a scenario should have removed, or ``OK``."""
    quoted = shlex.quote(prefix)
    return f"""
prefix={quoted}
problems=""
for account in $(getent passwd | cut -d: -f1 | grep -E "^[sp]$prefix"); do
    problems="$problems account:$account"
done
for path in /etc/haproxy/sites/"$prefix"*.cfg /var/lib/haproxy/sites/"$prefix"*.state \
    /etc/php-fpm/sites/"$prefix"* /var/lib/php-fpm/sites/"$prefix"*; do
    [ -e "$path" ] && problems="$problems serving:$path"
done
for path in /var/www/"$prefix"*; do
    [ -e "$path" ] && problems="$problems dir:$path"
done
for path in /etc/caddy/sites/"$prefix"*.caddy; do
    [ -e "$path" ] && problems="$problems site:$path"
done
for path in /etc/logrotate.d/barectl-site-"$prefix"*; do
    [ -e "$path" ] && problems="$problems rotation:$path"
done
for path in /etc/php/*/fpm/pool.d/"$prefix"*.conf /etc/php-fpm/*/pools/"$prefix"*.conf; do
    [ -e "$path" ] && problems="$problems pool:$path"
done
for path in /etc/valkey/"$prefix"*.conf /var/lib/valkey/"$prefix"* \
    /run/valkey/"$prefix"* /etc/systemd/system/valkey-server@"$prefix"*.service.d; do
    [ -e "$path" ] && problems="$problems cache:$path"
done
for unit in $(systemctl list-units --type=service --no-legend --plain 'valkey-server@*' \
    | cut -d' ' -f1); do
    case "$unit" in
        "valkey-server@$prefix"*) problems="$problems cache-unit:$unit" ;;
    esac
done
for path in /etc/systemd/system/barectl-site-"$prefix"*.service \
    /etc/systemd/system/barectl-site-"$prefix"*.timer \
    /etc/systemd/system/barectl-site-"$prefix"*.slice \
    /run/systemd/system/barectl-site-"$prefix"*.service \
    /run/systemd/system/barectl-site-"$prefix"*.timer \
    /run/systemd/system/barectl-site-"$prefix"*.slice \
    /run/systemd/system/barectl-site-"$prefix"*.service.d \
    /run/systemd/system/barectl-site-"$prefix"*.timer.d; do
    [ -e "$path" ] && problems="$problems automation:$path"
done
automation_units=$(systemctl list-units --all --plain --no-legend \
    'barectl-site-'$prefix'*' | cut -d' ' -f1)
for unit in $automation_units; do
    problems="$problems automation-unit:$unit"
done
if command -v caddy >/dev/null 2>&1 && [ -f /etc/caddy/Caddyfile ]; then
    caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1 \
        || problems="$problems caddy-invalid"
fi
services=$(systemctl list-units --type=service --no-legend --plain 'php-fpm@*' \
    | cut -d' ' -f1)
for service in $services; do
    systemctl is-active --quiet "$service" || problems="$problems inactive:$service"
done
if command -v flock >/dev/null 2>&1 && [ -e /run/barectl/lock ]; then
    flock -n /run/barectl/lock true 2>/dev/null || problems="$problems lock-held"
fi
[ -z "$problems" ] && echo OK || echo "$problems"
""".strip()


# Lanes


class Output:
    def __init__(self, stream: TextIO) -> None:
        self.stream = stream
        self.lock = threading.Lock()

    def say(self, text: str) -> None:
        with self.lock:
            for line in text.rstrip("\n").splitlines() or [""]:
                self.stream.write(f"[native] {line}\n")
            self.stream.flush()


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def controller_key(directory: Path) -> Path:
    key = directory / "id"
    if not key.exists():
        subprocess.run(  # noqa: S603 - fixed key generation
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],  # noqa: S607
            capture_output=True,
            check=True,
            timeout=60,
        )
    return key


@dataclass
class Lane:
    index: int
    image: str
    key: Path
    root: Path
    work: Path
    output: Output
    fixture: str = ""
    name: str = ""
    network: str = ""
    hosts: tuple[str, ...] = ()
    containers: list[str] = field(default_factory=list)
    server: Machine | None = None
    server_layer: str = ""
    server_memory_gib: int = 0
    port: int = 0
    dns: str = ""
    git_key: Path | None = None
    acme_root: Path | None = None

    def start(self) -> None:
        self.name = f"barectl-native-lane-{os.getpid()}-{secrets.token_hex(3)}-{self.index}"
        self.network = self.name
        docker("network", "create", "--internal", self.network)
        manifest = mirror.load()
        self.hosts = manifest.hosts()
        certificate, key = mirror.mirror_certificate(self.hosts)
        self._start_mirror(manifest, certificate, key)
        self._start_dns()
        if self.fixture:
            self._start_pebble()
            self._start_git()

    def _start_pebble(self) -> None:
        binary, certificate, key, self.acme_root = mirror.pebble_files(mirror.host_architecture())
        config = self.work / f"pebble-{self.index}.json"
        config.write_text(
            json.dumps(
                {
                    "pebble": {
                        "listenAddress": "0.0.0.0:14000",
                        "managementListenAddress": "0.0.0.0:15000",
                        "certificate": "/certs/cert.pem",
                        "privateKey": "/certs/key.pem",
                        "httpPort": 80,
                        "tlsPort": 443,
                        "ocspResponderURL": "",
                        "externalAccountBindingRequired": False,
                    }
                }
            ),
            encoding="utf-8",
        )
        name = f"{self.name}-pebble"
        self.containers.append(name)
        docker(
            "run", "-d", "--name", name, "--network", self.network,
            "--network-alias", FIXTURE_ACME_HOST,
            "-v", f"{binary}:/usr/local/bin/pebble:ro",
            "-v", f"{config}:/pebble-config.json:ro",
            "-v", f"{certificate}:/certs/cert.pem:ro",
            "-v", f"{key}:/certs/key.pem:ro",
            "-e", "PEBBLE_VA_NOSLEEP=1",
            self.image, "/usr/local/bin/pebble",
            "-config", "/pebble-config.json", "-dnsserver", "127.0.0.11:53",
        )  # fmt: skip

    def _start_git(self) -> None:
        directory = self.work / f"git-{self.index}"
        directory.mkdir(parents=True, exist_ok=True)
        self.git_key = directory / "id"
        if not self.git_key.exists():
            subprocess.run(  # noqa: S603 - fixed key generation
                ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.git_key)],  # noqa: S607
                capture_output=True,
                check=True,
                timeout=60,
            )  # fmt: skip
        authorized = directory / "authorized_keys"
        authorized.write_text(Path(f"{self.git_key}.pub").read_text(encoding="utf-8"))
        certificate, key = mirror.mirror_certificate([FIXTURE_GIT_HOST])
        name = f"{self.name}-git"
        self.containers.append(name)
        docker(
            "run", "-d", "--name", name, "--network", self.network,
            "--network-alias", FIXTURE_GIT_HOST,
            "-v", f"{certificate}:/tls/git.crt:ro",
            "-v", f"{key}:/tls/git.key:ro",
            "-v", f"{authorized}:/keys/authorized_keys:ro",
            "-v", f"{SCRIPTS}:/native:ro",
            self.fixture, "sh", "/native/native_mirror/git_serve.sh",
        )  # fmt: skip

    def _start_mirror(self, manifest: mirror.Manifest, certificate: Path, key: Path) -> None:
        name = f"{self.name}-mirror"
        self.containers.append(name)
        arguments = ["run", "-d", "--name", name, "--network", self.network]
        for host in self.hosts:
            arguments += ["--network-alias", host]
        for source, target in (
            (self.root, "/mirror-root"),
            (certificate, "/mirror.crt"),
            (key, "/mirror.key"),
            (SCRIPTS, "/native"),
        ):
            arguments += ["-v", f"{source}:{target}:ro"]
        arguments += [
            "--entrypoint", "python3", self.image,
            "/native/native_mirror/serve.py",
            "--root", "/mirror-root", "--certificate", "/mirror.crt", "--key", "/mirror.key",
        ]  # fmt: skip
        for host in self.hosts:
            arguments += ["--host", host]
        docker(*arguments)

    def _start_dns(self) -> None:
        self.dns = f"{self.name}-dns"
        self.containers.append(self.dns)
        docker(
            "run", "-d", "--name", self.dns, "--network", self.network,
            "-v", f"{SCRIPTS}:/native:ro", "--entrypoint", "python3", self.image,
            "/native/native_mirror/dns.py", "--log", "/run/queries.log",
        )  # fmt: skip

    def _dns_address(self) -> str:
        pattern = '{{(index .NetworkSettings.Networks "' + self.network + '").IPAddress}}'
        return docker("inspect", "-f", pattern, self.dns).strip()

    def boot_server(self, layer: str, memory_gib: int = 0) -> Machine:
        extra = [
            "--dns",
            self._dns_address(),
            "--network-alias",
            FIXTURE_ACME_DOMAIN,
            "--network-alias",
            FIXTURE_SECOND_DOMAIN,
        ]
        if memory_gib:
            # A memory-cgroup-limited container, not a 1/2/4 GiB host: the kernel and the
            # page cache are shared with the Docker VM (docs/phase-c-qualification.md).
            extra += [f"--memory={memory_gib}g", f"--memory-swap={memory_gib}g"]
        self.server = Machine.boot(images.ensure(layer), network=self.network, extra=extra)
        self.server_layer = layer
        self.server_memory_gib = memory_gib
        public = Path(f"{self.key}.pub").read_text(encoding="utf-8")
        self.server.exec(
            "install -d -m 700 /root/.ssh && "
            f"printf %s {shlex.quote(public)} >/root/.ssh/authorized_keys && "
            "chmod 600 /root/.ssh/authorized_keys"
        )
        self._start_forwarder(self.server.address(self.network))
        return self.server

    def _start_forwarder(self, target: str) -> None:
        name = f"{self.name}-forward"
        self.containers.append(name)
        self.port = free_port()
        docker(
            "run", "-d", "--name", name, "--network", "bridge",
            "-p", f"127.0.0.1:{self.port}:2200",
            "-v", f"{SCRIPTS}:/native:ro", "--entrypoint", "python3", self.image,
            "/native/native_mirror/forward.py", "--listen", "2200",
            "--target", f"{target}:22",
        )  # fmt: skip
        docker("network", "connect", self.network, name)

    def discard_server(self) -> None:
        if self.server is not None:
            self.server.remove()
            self.server = None
        self._remove(f"{self.name}-forward")

    def environment(
        self, scenario: Scenario, server: Machine, record: str, *, quarantined: bool
    ) -> dict[str, str]:
        known_hosts = self.work / f"{server.name}.known_hosts"
        host_key = server.exec("cut -d' ' -f1-2 /etc/ssh/ssh_host_ed25519_key.pub").strip()
        known_hosts.write_text(f"[127.0.0.1]:{self.port} {host_key}\n", encoding="utf-8")
        return os.environ | {
            "BARECTL_SSH_TEST_HOST": "127.0.0.1",
            "BARECTL_SSH_TEST_PORT": str(self.port),
            "BARECTL_SSH_TEST_USER": "root",
            "BARECTL_SSH_TEST_KEY": str(self.key),
            "BARECTL_SSH_TEST_KNOWN_HOSTS": str(known_hosts),
            "BARECTL_SSH_TEST_CONTAINER": server.name,
            "BARECTL_SCENARIO_PREFIX": scenario.prefix,
            "BARECTL_SCENARIO_RECORD": record,
            "BARECTL_SCENARIO_ARCH": server.exec("uname -m").strip(),
            "BARECTL_SCENARIO_RELEASE": "24.04" if scenario.layer == "L0-24.04" else RELEASE,
            quarantine.RUN_ENV: "1" if quarantined else "",
            "BARECTL_FIXTURE_GIT_KEY": str(self.git_key or ""),
            "BARECTL_FIXTURE_GIT_HOST": FIXTURE_GIT_HOST,
            "BARECTL_FIXTURE_ACME_HOST": FIXTURE_ACME_HOST,
            "BARECTL_FIXTURE_ACME_DOMAIN": FIXTURE_ACME_DOMAIN,
            "BARECTL_FIXTURE_ACME_ROOT": str(self.acme_root or ""),
        }

    def dns_queries(self) -> list[str]:
        with contextlib.suppress(DockerError):
            text = docker("exec", self.dns, "cat", "/run/queries.log")
            return [line.strip() for line in text.splitlines() if line.strip()]
        return []

    def _remove(self, name: str) -> None:
        quietly("rm", "-f", name)
        if name in self.containers:
            self.containers.remove(name)

    def remove(self) -> None:
        self.discard_server()
        for name in list(self.containers):
            quietly("rm", "-f", name)
        self.containers.clear()
        if self.network:
            quietly("network", "rm", self.network)


# Running


@dataclass
class Outcome:
    scenario: Scenario
    passed: bool
    ran: int
    seconds: float
    log: Path
    reason: str = ""


def unaliased(asked: Iterable[str], allowed: Iterable[str]) -> list[str]:
    """The names a server asked for that no mirror serves, in order, deduplicated.

    A resolver may append a search domain to an aliased name, so a name that begins with an
    alias and a dot is the same host, not an escape. A service-discovery name that ends in
    an alias after only ``_service``/``_proto`` labels (as apt's HTTPS method asks) is a
    query about the same host, not a different one.
    """
    # The lane aliases the fixture ACME name on the server itself, so a search-suffixed
    # query for it is a known lane host rather than an escape.
    names = (*allowed, FIXTURE_ACME_DOMAIN, FIXTURE_SECOND_DOMAIN)
    return sorted({name for name in asked if not _mirror_host(name, names)})


def _mirror_host(name: str, names: tuple[str, ...]) -> bool:
    for alias in names:
        if name == alias or name.startswith(f"{alias}."):
            return True
        if name.endswith(f".{alias}"):
            head = name[: -(len(alias) + 1)]
            if head and all(label.startswith("_") for label in head.split(".")):
                return True
    return False


def judge(scenario: Scenario, log: Path, returncode: int | None, seconds: float) -> Outcome:
    text = log.read_text(encoding="utf-8", errors="replace")
    ran = sum(int(match) for match in RAN.findall(text))
    verdicts = VERDICT.findall(text)[-1:]
    reason = ""
    if stopping.is_set() and returncode != 0:
        reason = "stopped"
    elif returncode is None or returncode < 0:
        reason = "over 3 minutes"
    elif ran != len(scenario.tests):
        reason = f"expected {len(scenario.tests)} tests, ran {ran}"
    elif returncode != 0 or verdicts != ["OK"]:
        reason = f"exit {returncode}"
    return Outcome(scenario, not reason, ran, seconds, log, reason)


class Runner:
    def __init__(
        self,
        output: Output,
        work: Path,
        *,
        record: str,
        keep_failed: bool,
        quarantined: bool,
        fixture_image: str = "",
    ) -> None:
        self.output = output
        self.work = work
        self.record = record or ""
        self.keep_failed = keep_failed
        self.quarantined = quarantined
        self.fixture_image = fixture_image
        self.lock = threading.Lock()
        self.processes: set[subprocess.Popen[bytes]] = set()
        self.lanes: list[Lane] = []
        self.outcomes: list[Outcome] = []

    def lane(self, index: int, image: str, key: Path, units: queue.SimpleQueue[_Unit]) -> None:
        lane = Lane(
            index, image, key, mirror.cache_root(), self.work, self.output,
            fixture=self.fixture_image,
        )  # fmt: skip
        with self.lock:
            self.lanes.append(lane)
        try:
            lane.start()
            while not stopping.is_set():
                try:
                    unit = units.get_nowait()
                except queue.Empty:
                    break
                lane.discard_server()
                for scenario in unit.scenarios:
                    if stopping.is_set():
                        break
                    self._run_scenario(lane, scenario)
        except Exception as error:
            self.output.say(f"lane {index} stopped: {type(error).__name__}: {error}")
            stopping.set()
        finally:
            lane.remove()

    def _run_scenario(self, lane: Lane, scenario: Scenario) -> None:
        if (
            lane.server is None
            or lane.server_layer != scenario.layer
            or lane.server_memory_gib != scenario.memory_gib
        ):
            lane.discard_server()
            lane.boot_server(scenario.layer, scenario.memory_gib)
        server = lane.server
        if server is None:
            raise ScenarioError("the lane has no server to run a scenario on.")
        outcome = self._execute(lane, server, scenario)
        if not outcome.passed:
            self._diagnose(server, scenario)
        residue_ok = True
        if not self.record and scenario.prefix:
            residue_ok = self._residue(server, scenario, outcome)
        if (not outcome.passed or not residue_ok) and not self.keep_failed:
            lane.discard_server()

    def _diagnose(self, server: Machine, scenario: Scenario) -> None:
        """Keep the native state a failed item leaves behind (docs/quality.md#native-layer)."""
        name = scenario.label.rsplit(".", 1)[-1]
        path = self.work / "logs" / f"{server.name}-{name}-diagnostics.txt"
        command = """
            echo '== units =='
            systemctl show -p Id -p LoadState -p ActiveState -p SubState -p InvocationID \
                -p MainPID -p ExecStart -p UnitFileState -p RefuseManualStart \
                php-fpm@php84.service php-fpm@php85.service 2>&1 || true
            echo '== automation units =='
            systemctl list-units --all --no-legend 'barectl-site-*' 2>&1 || true
            systemctl list-timers --all --no-legend 'barectl-site-*' 2>&1 || true
            echo '== journals =='
            journalctl --no-pager -n 80 2>&1 | grep -E 'barectl-site|php-fpm|haproxy' || true
            echo '== directories =='
            ls -ld /var/www /var/www/* /run/php-fpm/php84 /run/php-fpm/php85 2>&1 | head -60
        """
        try:
            text = server.exec(command, timeout=60)
        except DockerError as error:
            text = f"The diagnostics could not be read: {type(error).__name__}: {error}\n"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        self.output.say(f"diagnostics: {path}")

    def _execute(self, lane: Lane, server: Machine, scenario: Scenario) -> Outcome:
        log = self.work / "logs" / f"{server.name}-{scenario.label.rsplit('.', 1)[-1]}.log"
        log.parent.mkdir(parents=True, exist_ok=True)
        environment = lane.environment(scenario, server, self.record, quarantined=self.quarantined)
        command = [
            sys.executable, "manage.py", "test", "--tag", SCENARIO_TAG,
            "--verbosity", "2", scenario.label,
        ]  # fmt: skip
        before = set(lane.dns_queries())
        started = time.monotonic()
        with log.open("wb") as stream:
            process = subprocess.Popen(  # noqa: S603 - this repository's own test command
                command, cwd=REPOSITORY, env=environment,
                stdout=stream, stderr=subprocess.STDOUT, start_new_session=True,
            )  # fmt: skip
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
        outcome = judge(scenario, log, returncode, seconds)
        asked = unaliased(set(lane.dns_queries()) - before, lane.hosts)
        if asked and outcome.passed:
            outcome = Outcome(
                scenario, False, outcome.ran, seconds, log,
                "asked for " + ", ".join(asked),
            )  # fmt: skip
        with self.lock:
            self.outcomes.append(outcome)
        verdict = "ok  " if outcome.passed else "FAIL"
        self.output.say(
            f"{verdict} {outcome.ran:>3} tests {seconds:6.1f}s {scenario.label}"
            + (f" — {outcome.reason}" if outcome.reason else "")
        )
        return outcome

    def _residue(self, server: Machine, scenario: Scenario, outcome: Outcome) -> bool:
        try:
            server.exec(teardown_command(scenario.prefix), timeout=120)
            result = server.exec(residue_command(scenario.prefix), timeout=120).strip()
        except DockerError as error:
            self.output.say(f"residue check failed to run: {error}")
            return False
        if result != "OK":
            self.output.say(f"FAIL residue after {scenario.label}: {result}")
            return False
        return True

    def interrupt(self) -> None:
        stopping.set()
        with self.lock:
            for process in self.processes:
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    os.killpg(process.pid, signal.SIGTERM)


@dataclass
class _Unit:
    layer: str
    scenarios: list[Scenario]


def plan(scenarios: list[Scenario], lanes: int) -> list[_Unit]:
    """Non-exclusive scenarios share a lane server; exclusive ones get their own unit."""
    units: list[_Unit] = [
        _Unit(scenario.layer, [scenario]) for scenario in scenarios if scenario.exclusive
    ]
    by_layer: dict[str, list[Scenario]] = {}
    for scenario in scenarios:
        if not scenario.exclusive:
            by_layer.setdefault(scenario.layer, []).append(scenario)
    for layer, group in by_layer.items():
        batches = min(max(lanes, 1), len(group))
        units.extend(_Unit(layer, group[index::batches]) for index in range(batches))
    return units


def default_lanes() -> int:
    configured = os.environ.get("BARECTL_NATIVE_LANES")
    if configured:
        return max(1, int(configured))
    info = docker("info", "--format", "{{.NCPU}} {{.MemTotal}}").split()
    cpus = int(info[0])
    memory = int(info[1]) / 2**30
    return max(1, min(math.floor(cpus / LANE_CPUS), math.floor(memory / LANE_GIB)))


def write_results(outcomes: Sequence[Outcome], work: Path) -> None:
    logs = work / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    (logs / "summary.json").write_text(
        json.dumps(
            [
                {
                    "scenario": outcome.scenario.label,
                    "passed": outcome.passed,
                    "seconds": round(outcome.seconds, 1),
                    "reason": outcome.reason,
                }
                for outcome in outcomes
            ],
            indent=1,
        )
        + "\n",
        encoding="utf-8",
    )


def keep_logs(work: Path, output: Output) -> None:
    source = work / "logs"
    if not source.exists():
        return
    destination = Path(
        os.environ.get("BARECTL_DISPOSABLE_LOGS")
        or Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
        / "barectl"
        / "native"
        / "scenario-logs"
    )
    shutil.rmtree(destination, ignore_errors=True)
    shutil.copytree(source, destination)
    output.say(str(destination))


def summarize(
    outcomes: Sequence[Outcome],
    planned: Sequence[Scenario],
    seconds: float,
    output: Output,
    *,
    validators: bool = False,
) -> None:
    for outcome in outcomes:
        if not outcome.passed:
            text = outcome.log.read_text(encoding="utf-8", errors="replace")
            output.say(f"{'=' * 60}\n{outcome.scenario.label}: {outcome.reason}")
            output.say("\n".join(text.splitlines()[-60:]))
    finished = {outcome.scenario.label for outcome in outcomes}
    unfinished = [scenario.label for scenario in planned if scenario.label not in finished]
    if unfinished:
        output.say("Unfinished scenarios: " + ", ".join(unfinished))
    passed = sum(1 for outcome in outcomes if outcome.passed)
    label = "Fast validators" if validators else "Native scenarios"
    target = 60 if validators else TARGET
    print(f"{label}: {passed} of {len(planned)} passed in {seconds:.0f} s")  # noqa: T201
    print(f"  against the {target:.0f} s target and {BUILD_LIMIT:.0f} s limit.")  # noqa: T201


def arguments(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="run-scenarios.sh", description=__doc__)
    parser.add_argument("labels", nargs="*", help="scenario modules or classes")
    parser.add_argument("--lanes", type=int, help="lane servers at once")
    parser.add_argument("--time-limit", type=float, default=BUILD_LIMIT, metavar="SECONDS")
    parser.add_argument("--record", metavar="STATE", help="record a scenario's transcript")
    parser.add_argument(
        "--list-records",
        action="store_true",
        help="print every transcript state a scenario records and stop",
    )
    parser.add_argument("--keep-failed", action="store_true", help="keep failed servers")
    parser.add_argument("--list", action="store_true", help="print the plan and stop")
    parser.add_argument(
        "--validators", action="store_true", help="run the fast snapshot validators"
    )
    parser.add_argument(
        "--breadth",
        action="store_true",
        help="run the scheduled breadth scenarios (reboot, long ticks, memory classes)",
    )
    parser.add_argument("--include-quarantined", action="store_true", help="also run quarantined")
    parser.add_argument("--quarantined", action="store_true", help="run only quarantined")
    parser.add_argument(
        "--check-egress",
        action="store_true",
        help="prove an unaliased lookup fails the item, then stop",
    )
    parser.add_argument("--shard", help="I/N: run only the I-th of N partitions")
    options = parser.parse_args(argv)
    if options.validators and (options.record or options.shard or options.check_egress):
        parser.error(
            "--validators is a single-container stage without shard, record or egress selection"
        )
    return options


def _shard(scenarios: Sequence[Scenario], value: str) -> list[Scenario]:
    """The scenarios of one shard (docs/quality.md#limits)."""
    index, _, count = value.partition("/")
    position, total = int(index), int(count)
    if not 1 <= position <= total:
        raise SystemExit("--shard takes I/N with 1 <= I <= N.")
    groups = shard_times.Record.load().partition([item.label for item in scenarios], total)
    chosen = {scenario.label: scenario for scenario in scenarios}
    return [chosen[label] for label in groups[position - 1]]


def prepare_layers(
    runner: Runner,
    scenarios: list[Scenario],
    image: str,
    key: Path,
    limit: float,
    output: Output,
) -> None:
    """Prepare each missing snapshot a scenario needs, layer by layer.

    L1 is the real S1 foundation; L2 is the prepared-sites layer built by the product's own
    Create site change on top of L1. Both are prepared through the real flow and reused
    from the keyed cache.
    """
    layers = {scenario.layer for scenario in scenarios}
    requirements = []
    if layers & {"L1", "L2", "L3", "L4", "L5"}:
        requirements.append(("L1", "disposable.test_foundation.HostFoundation"))
    if layers & {"L2", "L3", "L4"}:
        requirements.append(("L2", "disposable.test_prepared_sites.PrepareSites"))
    if layers & {"L3", "L4"}:
        requirements.append(("L3", "disposable.test_prepared_wordpress.PrepareWordPress"))
    if "L4" in layers:
        requirements.append(("L4", "disposable.test_prepared_wordpress.PrepareWordPressCache"))
    if "L5" in layers:
        requirements.append(("L5", "disposable.test_prepared_laravel.PrepareLaravel"))
    for layer, label in requirements:
        if images.load(layer):
            continue
        _prepare(runner, label, layer, image, key, limit, output)


def _prepare(
    runner: Runner, label: str, layer: str, image: str, key: Path, limit: float, output: Output
) -> None:
    preparation = next(iter(discover([label], preparations=True)), None) or next(
        iter(discover([label])), None
    )
    if preparation is None:
        raise ScenarioError(f"No scenario prepares the {layer} snapshot.")
    output.say(f"Preparing the missing {layer} snapshot through {preparation.label}.")
    execute(runner, plan([preparation], 1), image, key, 1, limit, output)
    outcome = runner.outcomes[-1] if runner.outcomes else None
    if outcome is None or not outcome.passed:
        summarize(runner.outcomes or [], [preparation], outcome.seconds if outcome else 0, output)
        write_results(runner.outcomes, runner.work)
        keep_logs(runner.work, output)
        raise SystemExit(1)
    if not images.exists(images.tag(layer)):
        raise ScenarioError(f"{preparation.label} did not commit the {layer} snapshot.")
    runner.outcomes.clear()


def _breadth_lanes(lanes: int, options: argparse.Namespace) -> int:
    """Two lanes for the breadth job: a memory class boots its own limited container."""
    if options.breadth and not options.lanes:
        return min(lanes, 2)
    return lanes


def main(argv: Sequence[str] | None = None) -> int:  # noqa: C901
    options = arguments(sys.argv[1:] if argv is None else argv)
    output = Output(sys.stdout)
    scenarios = discover(
        options.labels,
        only_quarantined=options.quarantined,
        egress_control=options.check_egress,
        validators=options.validators,
        breadth=options.breadth,
    )
    if options.list_records:
        for state in sorted({state for scenario in scenarios for state in scenario.records}):
            print(state)  # noqa: T201
        return 0
    if options.record:
        scenarios = [scenario for scenario in scenarios if options.record in scenario.records]
        if not scenarios:
            raise SystemExit(f"No scenario records {options.record}.")
    if options.quarantined and not scenarios:
        print("Native scenarios: none are quarantined.")  # noqa: T201
        return 0
    if not scenarios:
        raise SystemExit("No scenario tests were found.")
    if options.list:
        for scenario in scenarios:
            print(f"{scenario.layer} exclusive={scenario.exclusive} {scenario.label}")  # noqa: T201
        return 0
    if options.shard and not options.check_egress:
        scenarios = _shard(scenarios, options.shard)
        if not scenarios:
            print("Native scenarios: no scenarios in this shard.")  # noqa: T201
            return 0
    if options.validators:
        # Two validator lanes keep the six classes under the joint-fast target; each lane
        # owns its container, so a manager reload in one cannot break another.
        lanes = 2
    elif options.record or options.check_egress:
        lanes = 1
    else:
        lanes = options.lanes or default_lanes()
    lanes = _breadth_lanes(lanes, options)
    with tempfile.TemporaryDirectory(prefix="barectl-scenarios-") as directory:
        work = Path(directory)
        image = images.ensure()
        fixture_image = images.ensure("fixture")
        images.store("fixture")
        key = controller_key(work)
        runner = Runner(
            output, work, record=options.record, keep_failed=options.keep_failed,
            quarantined=options.quarantined, fixture_image=fixture_image,
        )  # fmt: skip
        started = time.monotonic()
        prepare_layers(runner, scenarios, image, key, options.time_limit, output)
        completed = {outcome.scenario.label for outcome in runner.outcomes}
        units = plan([scenario for scenario in scenarios if scenario.label not in completed], lanes)
        remaining = max(0.0, options.time_limit - (time.monotonic() - started))
        execute(runner, units, image, key, lanes, remaining, output)
        seconds = time.monotonic() - started
        summarize(runner.outcomes, scenarios, seconds, output, validators=options.validators)
        write_results(runner.outcomes, work)
        keep_logs(work, output)
        images.store("L1")
        images.store("L2")
        images.store("L3")
        images.store("L4")
        if options.check_egress:
            return _egress_control(runner.outcomes, output)
    finished = {outcome.scenario.label for outcome in runner.outcomes}
    complete = all(scenario.label in finished for scenario in scenarios)
    return 0 if complete and all(o.passed for o in runner.outcomes) else 1


def _egress_control(outcomes: Sequence[Outcome], output: Output) -> int:
    """The egress control passes only when an unaliased lookup failed the item by name."""
    for outcome in outcomes:
        text = ""
        with contextlib.suppress(OSError):
            text = outcome.log.read_text(encoding="utf-8", errors="replace")
        if not outcome.passed and (EGRESS_PROBE in outcome.reason or EGRESS_PROBE in text):
            output.say(f"egress control: the runner refused {EGRESS_PROBE}, as asked.")
            return 0
    output.say(f"egress control: a lookup of {EGRESS_PROBE} did not fail the item.")
    return 1


def execute(
    runner: Runner,
    units: list[_Unit],
    image: str,
    key: Path,
    lanes: int,
    limit: float,
    output: Output,
) -> None:
    previous = signal.signal(signal.SIGTERM, lambda *_: runner.interrupt())
    work: queue.SimpleQueue[_Unit] = queue.SimpleQueue()
    for unit in units:
        work.put(unit)
    try:
        with ThreadPoolExecutor(lanes) as pool:
            futures = [pool.submit(runner.lane, index, image, key, work) for index in range(lanes)]
            deadline = time.monotonic() + limit
            while any(not future.done() for future in futures):
                if time.monotonic() > deadline and not stopping.is_set():
                    output.say(f"{limit:.0f} s reached; stopping.")
                    runner.interrupt()
                for future in futures:
                    _wait(future)
    except KeyboardInterrupt:
        runner.interrupt()
    finally:
        signal.signal(signal.SIGTERM, previous)
        if not runner.keep_failed:
            for lane in runner.lanes:
                lane.remove()


def _wait(future: Future[None]) -> None:
    with contextlib.suppress(Exception):
        future.result(timeout=1)


if __name__ == "__main__":
    sys.exit(main())
