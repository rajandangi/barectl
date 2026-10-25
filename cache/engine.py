"""Install Valkey through the engine's four-member seam (docs/target-architecture.md#valkey).

One reviewed APT transaction installs Ubuntu's ``valkey-server`` at the version and size
the review names (docs/adr/0007-admit-exact-package-transactions-with-an-inline-apt-guard.md).
The body then stops and masks the distribution's shared unit, and restarts the running
PHP masters and site proxies whose loaded execution evidence a package transaction's
``daemon-reload`` clears (#428). Per-site instances belong to #392/#393.
"""

import hashlib
import importlib.resources
from dataclasses import dataclass
from typing import Final

from bootstrap.standing import Standing
from databases.packages import (
    PackageAction,
    Simulation,
    actions_of,
    check_package,
    check_version,
    guard,
    parse_simulation,
    parse_sizes,
    simulate_command,
    size_command,
    valid_digest,
)
from discovery.root_read import run_root
from discovery.snapshot import CollectedSnapshot
from discovery.ssh import RemoteShell
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import PreparationInputs
from operations.models import ChangeReview

from . import observation

SLUG: Final = "install_valkey"
LABEL: Final = "Install Valkey"
ROOTS: Final = (observation.PACKAGE,)
STAGES: Final = ("preflight", "install", "mask", "recover", "verify")

_DEB_ARCH: Final = {"x86_64": "amd64", "aarch64": "arm64"}
# The foundation's provisional admission, as the database engine kind applies it.
MIN_DISK_BYTES: Final = 2 * 1024**3
MIN_MEMORY_KIB: Final = 512 * 1024

_RESOURCES: Final = importlib.resources.files("cache.bodies")
BODY_BYTES: Final = (
    _RESOURCES.joinpath("install.sh")
    .read_text()
    .replace("# VALKEY_FUNCTIONS", observation.body_functions())
    .rstrip("\n")
    .encode()
)
BODY_SHA256: Final = hashlib.sha256(BODY_BYTES).hexdigest()


@dataclass(frozen=True)
class ValkeyEvidence:
    standing: str
    machine: str
    deb_arch: str
    boot_id: str
    uptime_centiseconds: int | None
    precondition_digest: str
    apt: str
    dpkg: str
    systemd: str
    held: tuple[str, ...]
    disk_bytes: int | None
    memory_kib: int | None
    installed: observation.ValkeyObservation | None
    outside: tuple[str, ...]
    simulation: Simulation | None
    simulation_error: str
    download_bytes: int | None = None
    installed_bytes: int | None = None
    size_problems: tuple[str, ...] = ()


def read_command() -> str:
    """The fixed root read that names the platform, clock and reviewed precondition."""
    parts = [
        "printf 'boot\\t%s\\n' \"$(cat /proc/sys/kernel/random/boot_id)\"",
        "printf 'uptime\\t%s\\n' \"$(cut -d' ' -f1 /proc/uptime | tr -d .)\"",
        "printf 'apt\\t%s\\n' \"$(apt --version)\"",
        "printf 'dpkg\\t%s\\n' \"$(dpkg --version | head -1)\"",
        "printf 'systemd\\t%s\\n' \"$(systemctl --version | head -1)\"",
        "printf 'holds\\t%s\\n' \"$(apt-mark showhold | tr '\\n' ',')\"",
        "printf 'disk\\t%s\\n' \"$(df -B1 --output=avail / | tail -1)\"",
        "printf 'memory\\t%s\\n' \"$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)\"",
        f"printf 'digest\\t%s\\n' \"$({observation.digest_command()} | cut -d' ' -f1)\"",
    ]
    return "; ".join(parts)


def _values(shell: RemoteShell) -> dict[str, str]:
    result = run_root(shell, read_command())
    if result.exit_status != 0 or result.truncated:
        return {}
    allowed = {"boot", "uptime", "apt", "dpkg", "systemd", "holds", "disk", "memory", "digest"}
    values: dict[str, str] = {}
    for line in result.stdout.splitlines():
        name, separator, value = line.partition("\t")
        if not separator or name not in allowed or name in values:
            return {}
        values[name] = value
    return values


def _collect(shell: RemoteShell) -> CollectedSnapshot:
    from discovery.observations import collect

    return collect(shell, sites=False)


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> ValkeyEvidence:
    observed = _collect(shell)
    values = _values(shell)
    machine = observed.architecture.value or ""
    deb_arch = _DEB_ARCH.get(machine, "")
    simulation: Simulation | None = None
    simulation_error = ""
    download_bytes: int | None = None
    installed_bytes: int | None = None
    size_problems: tuple[str, ...] = ()
    if deb_arch:
        result = run_root(shell, simulate_command(ROOTS))
        if result.exit_status == 0 and not result.truncated:
            try:
                simulation = parse_simulation(result.stdout)
            except ValueError:
                simulation_error = "APT's simulation is not in a supported form."
        else:
            simulation_error = "APT could not resolve the installation."
        if simulation is not None and any(
            transition.action == "Inst" for transition in simulation.transitions
        ):
            sizes = run_root(shell, size_command(ROOTS))
            if sizes.exit_status == 0 and not sizes.truncated:
                download_bytes, installed_bytes, size_problems = parse_sizes(sizes.stdout)
            else:
                size_problems = ("APT could not report the transaction's download size.",)
    return ValkeyEvidence(
        standing=observed.standing.standing.value if observed.standing else "",
        machine=machine,
        deb_arch=deb_arch,
        boot_id=values.get("boot", ""),
        uptime_centiseconds=(int(values["uptime"]) if values.get("uptime", "").isdigit() else None),
        precondition_digest=values.get("digest", ""),
        apt=values.get("apt", ""),
        dpkg=values.get("dpkg", ""),
        systemd=values.get("systemd", ""),
        held=tuple(part for part in values.get("holds", "").split(",") if part),
        disk_bytes=int(values["disk"]) if values.get("disk", "").isdigit() else None,
        memory_kib=int(values["memory"]) if values.get("memory", "").isdigit() else None,
        installed=observation.installed(observed),
        outside=observation.outside_supported(observed),
        simulation=simulation,
        simulation_error=simulation_error,
        download_bytes=download_bytes,
        installed_bytes=installed_bytes,
        size_problems=size_problems,
    )


def platform_reasons(evidence: ValkeyEvidence) -> list[str]:
    reasons: list[str] = []
    if evidence.standing != Standing.TARGET_STACK.value:
        reasons.append("Set up and verify the host foundation before installing Valkey.")
    if not evidence.deb_arch:
        reasons.append("The server's architecture is not one Barectl supports.")
    if evidence.apt and not evidence.apt.startswith("apt 3.2."):
        reasons.append("The server is not the supported Ubuntu 26.04 platform.")
    if evidence.dpkg and "version 1.23." not in evidence.dpkg:
        reasons.append("The server is not the supported Ubuntu 26.04 platform.")
    if evidence.systemd and not evidence.systemd.startswith("systemd 259 "):
        reasons.append("The server is not the supported Ubuntu 26.04 platform.")
    if evidence.disk_bytes is not None and evidence.disk_bytes < MIN_DISK_BYTES:
        reasons.append("The server lacks the free disk a reviewed Valkey install needs.")
    if evidence.memory_kib is not None and evidence.memory_kib < MIN_MEMORY_KIB:
        reasons.append("The server lacks the free memory a reviewed Valkey install needs.")
    if not valid_digest(evidence.precondition_digest) or not evidence.boot_id:
        reasons.append("The server's package evidence could not be read.")
    return reasons


def _transaction(
    evidence: ValkeyEvidence,
) -> tuple[Simulation | None, tuple[PackageAction, ...], list[str]]:
    """The reviewed APT transaction, or the refusals that keep it from being one."""
    refusals: list[str] = []
    simulation = evidence.simulation
    if evidence.simulation_error:
        refusals.append(evidence.simulation_error)
        return None, (), refusals
    if simulation is None:
        return None, (), refusals
    refusals.extend(simulation.problems)
    if (
        not any(
            transition.action == "Inst" and transition.package == observation.PACKAGE
            for transition in simulation.transitions
        )
        and evidence.installed is None
    ):
        refusals.append(
            "APT's simulation does not install valkey-server. Check the package indexes, "
            "then prepare again."
        )
    held = {name.split(":", 1)[0] for name in evidence.held}
    refusals.extend(
        f"{transition.package} is held with apt-mark hold. Release the hold through "
        "ordinary administration, then prepare again."
        for transition in simulation.transitions
        if transition.package in held
    )
    try:
        actions = actions_of(simulation.transitions, evidence.deb_arch)
    except ValueError as error:
        refusals.append(f"{error} This reduced transaction only installs missing packages.")
        return simulation, (), refusals
    return simulation, actions, refusals


def _size(size_bytes: int | None) -> str:
    if size_bytes is None:
        return "Not reported."
    if size_bytes < 1000:
        return f"{size_bytes} B"
    for unit, factor in (("GB", 1000**3), ("MB", 1000**2), ("kB", 1000)):
        if size_bytes >= factor:
            return f"{size_bytes / factor:.1f} {unit}"
    return "0 B"


def _install_document(
    evidence: ValkeyEvidence, simulation: Simulation, actions: tuple[PackageAction, ...]
) -> tuple[dict[str, object], tuple[DeclaredEffect, ...]]:
    version = next(
        (
            transition.version
            for transition in simulation.transitions
            if transition.action == "Inst" and transition.package == observation.PACKAGE
        ),
        "",
    )
    packages = [
        [transition.package, transition.version, transition.architecture]
        for transition in simulation.transitions
        if transition.action == "Inst"
    ]
    roots = [[observation.PACKAGE, version]]
    download = _size(evidence.download_bytes)
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": BODY_SHA256,
        "architecture": evidence.machine,
        "deb_arch": evidence.deb_arch,
        "precondition_digest": evidence.precondition_digest,
        "roots": roots,
        "versioned": observation.PACKAGE,
        "engine_version": version,
        "packages": packages,
        "actions": [
            [action.unpack, action.package, action.version, action.architecture]
            for action in actions
        ],
        "download_bytes": evidence.download_bytes,
        "installed_bytes": evidence.installed_bytes,
        "details": [
            {
                "label": "Package transaction",
                "value": f"{observation.PACKAGE} {version}",
            },
            {"label": "Download size", "value": download},
            {
                "label": "Disk space after install",
                "value": _size(evidence.installed_bytes),
            },
            {
                "label": "Every installed package",
                "value": "\n".join(
                    f"{name} {package_version} ({arch})" for name, package_version, arch in packages
                )
                or "Nothing to install.",
            },
            {
                "label": "Network destinations",
                "value": "The server's configured Ubuntu archive only; Barectl adds no source.",
            },
            {
                "label": "Service",
                "value": (
                    f"{observation.UNIT} is stopped and masked, so no shared cache instance "
                    "runs and nothing listens on port 6379."
                ),
            },
            {
                "label": "Restarted after install",
                "value": (
                    "The running PHP masters and site proxies, so discovery still verifies "
                    "their loaded state (#428)."
                ),
            },
        ],
    }
    effects = (
        DeclaredEffect(
            Scope.SERVER,
            (
                f"Install {observation.LABEL} ({observation.PACKAGE} {version}, {download} "
                "download) from the Ubuntu archive, stop and mask the distribution's shared "
                "service, and restart the running PHP masters and site proxies."
            ),
        ),
    )
    return document, effects


def review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, ValkeyEvidence):
        raise ValueError("A Valkey install needs native evidence.")
    refusals = [*platform_reasons(evidence), *evidence.outside]
    current = evidence.installed
    if current is not None:
        if not current.version:
            refusals.append("Valkey's installed version could not be read. Prepare again.")
        elif not current.masked or not current.inactive:
            refusals.append(
                "Valkey is installed but its distribution service is not stopped and masked. "
                "Stop and mask valkey-server.service through ordinary administration, then "
                "prepare again."
            )
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": BODY_SHA256,
        "architecture": evidence.machine,
        "deb_arch": evidence.deb_arch,
    }
    effects: tuple[DeclaredEffect, ...] = ()
    simulation, actions, transaction_refusals = _transaction(evidence)
    refusals.extend(transaction_refusals)
    if actions:
        refusals.extend(evidence.size_problems)
    if actions and evidence.download_bytes is None and not evidence.size_problems:
        refusals.append(
            "APT did not report the transaction's download size. Check the package "
            "indexes, then prepare again."
        )
    note = ""
    if simulation is not None and actions and not refusals:
        document, effects = _install_document(evidence, simulation, actions)
    elif not refusals and current is not None:
        note = (
            f"{LABEL} {current.version} is already installed, and its default service is "
            "stopped and masked."
        )
    return ReviewDraft(
        kind=SLUG,
        intent=f"Install {LABEL}.",
        effects=effects,
        stages=STAGES,
        postconditions=(
            (
                "Valkey is installed at the reviewed version, and the distribution's shared "
                "service is stopped and masked."
            ),
            "Nothing listens on TCP port 6379.",
            (
                "Every running PHP master and site proxy was restarted after the package "
                "database changed, so discovery still verifies them."
            ),
            "Discovery reconstructs Valkey and its version from the server alone.",
        ),
        refusals=tuple(refusals),
        boot_id=evidence.boot_id,
        uptime_centiseconds=evidence.uptime_centiseconds,
        document={**document, "note": note},
    )


def body(document: dict[str, object], context: BodyContext) -> NativeBody:
    if document.get("version") != 1 or document.get("body_sha256") != BODY_SHA256:
        raise ValueError("Unsupported Valkey review.")
    if document.get("deb_arch") not in set(_DEB_ARCH.values()):
        raise ValueError("Unsupported Valkey architecture.")
    digest = document.get("precondition_digest")
    if not isinstance(digest, str) or not valid_digest(digest):
        raise ValueError("The Valkey precondition digest is invalid.")
    roots = document.get("roots")
    actions = document.get("actions")
    versioned = document.get("versioned")
    version = document.get("engine_version")
    if (
        not isinstance(roots, list)
        or len(roots) != 1
        or not isinstance(actions, list)
        or not actions
        or versioned != observation.PACKAGE
        or not isinstance(version, str)
        or not version
    ):
        raise ValueError("The Valkey review is not a valid transaction.")
    entry = roots[0]
    if (
        not isinstance(entry, list)
        or len(entry) != 2
        or not all(isinstance(value, str) for value in entry)
        or entry[0] != observation.PACKAGE
    ):
        raise ValueError("The Valkey review names invalid roots.")
    check_package(entry[0])
    if check_version(entry[1]) != version:
        raise ValueError("The Valkey review names a version outside its transaction.")
    approved: list[PackageAction] = []
    for action in actions:
        if not isinstance(action, list) or len(action) != 4 or type(action[0]) is not bool:
            raise ValueError("The Valkey review names invalid actions.")
        approved.append(PackageAction(action[0], str(action[1]), str(action[2]), str(action[3])))
    try:
        guard_text = guard(tuple(approved))
    except ValueError as error:
        raise ValueError("The Valkey review is not a valid transaction.") from error
    return NativeBody(
        BODY_BYTES,
        (digest, f"{entry[0]}={entry[1]}", guard_text, versioned, version),
    )


def verify(shell: RemoteShell, review: ChangeReview) -> bool | None:
    body(review.document, BodyContext("", "", 0))
    observed = _collect(shell)
    if observed.standing is None:
        return None
    current = observation.observation_of(observed)
    version = str(review.document.get("engine_version", ""))
    if (
        current is None
        or not current.present
        or current.version != version
        or not current.managed
        or not current.masked
        or not current.inactive
    ):
        return False
    result = run_root(shell, observation.verification_command(version))
    return result.exit_status == 0 and not result.truncated


INSTALL: Final = ChangeKind(
    slug=SLUG,
    label=LABEL,
    inspect=inspect,
    review=review,
    body=body,
    verify=verify,
    refresh_discovery=True,
)
