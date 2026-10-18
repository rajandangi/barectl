"""Install and remove a database engine through the engine's four-member seam.

docs/target-architecture.md#stack, the phase specification's database engine bullet, and
ADRs 0007, 0010 and 0013. One engine per server: the review resolves APT's own transaction
and names every package and version, the native body installs exactly those under the
inline apt-daily guard and refuses when the resolved set differs, and the engine is hardened
to the socket and account shape the phase specification sets.
"""

import hashlib
import importlib.resources
from dataclasses import dataclass
from typing import Final

from bootstrap.standing import Standing
from discovery.root_read import run_root
from discovery.snapshot import CollectedSnapshot
from discovery.ssh import RemoteShell
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import InputShape, PreparationInputs
from operations.models import ChangeReview

from . import observation
from .packages import (
    PackageAction,
    Simulation,
    actions_of,
    check_package,
    guard,
    parse_simulation,
    simulate_command,
    valid_digest,
)

SLUG: Final = "install_database_engine"
LABEL: Final = "Install database engine"
REMOVE_SLUG: Final = "remove_database_engine"
REMOVE_LABEL: Final = "Remove database engine"
ENGINE_CHOICES: Final = observation.ENGINES
STAGES: Final = ("preflight", "install", "start", "harden", "verify")
REMOVE_STAGES: Final = ("preflight", "remove", "verify")

_DEB_ARCH: Final = {"x86_64": "amd64", "aarch64": "arm64"}
# The phase specification's headroom, matching the foundation's provisional admission.
MIN_DISK_BYTES: Final = 2 * 1024**3
MIN_MEMORY_KIB: Final = 512 * 1024

_RESOURCES: Final = importlib.resources.files("databases.bodies")
BODY_BYTES: Final = (
    _RESOURCES.joinpath("install.sh")
    .read_text()
    .replace("# ENGINE_DIGESTS\n# ENGINE_HARDENING\n# ENGINE_VERIFY", observation.body_functions())
    .rstrip("\n")
    .encode()
)
BODY_SHA256: Final = hashlib.sha256(BODY_BYTES).hexdigest()
REMOVE_BYTES: Final = (
    _RESOURCES.joinpath("remove.sh")
    .read_text()
    .replace("# ENGINE_DIGESTS\n# ENGINE_VERIFY", observation.body_functions())
    .rstrip("\n")
    .encode()
)
REMOVE_SHA256: Final = hashlib.sha256(REMOVE_BYTES).hexdigest()


@dataclass(frozen=True)
class EngineEvidence:
    engine: str
    git: bool
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
    git_installed: bool
    installed: tuple[observation.EngineObservation, ...]
    outside: tuple[str, ...]
    simulation: Simulation | None
    simulation_error: str
    usage: tuple[str, ...]
    usage_readable: bool

    def current(self, engine: str | None = None) -> observation.EngineObservation | None:
        return next(
            (item for item in self.installed if item.engine == (engine or self.engine)), None
        )

    def root_satisfied(self, root: str) -> bool:
        if root == observation.GIT_ROOT:
            return self.git_installed
        current = self.current()
        return current is not None and any(package.name == root for package in current.packages)


@dataclass(frozen=True)
class RemovalEvidence:
    engine: str
    standing: str
    boot_id: str
    uptime_centiseconds: int | None
    precondition_digest: str
    installed: tuple[observation.EngineObservation, ...]
    usage: tuple[str, ...]
    usage_readable: bool

    def current(self) -> observation.EngineObservation | None:
        return next((item for item in self.installed if item.engine == self.engine), None)


def roots_for(engine: str, *, git: bool) -> tuple[str, ...]:
    spec = observation.specs().get(engine)
    if spec is None:
        raise ValueError("Unknown database engine.")
    return (spec.root, *((observation.GIT_ROOT,) if git else ()))


def read_command(engine: str) -> str:
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
        "printf 'git\\t%s\\n' \"$(dpkg-query -W -f='${db:Status-Status}' git 2>/dev/null)\"",
        (f"printf 'digest\\t%s\\n' \"$({observation.digest_command(engine)} | cut -d' ' -f1)\""),
    ]
    return "; ".join(parts)


def _values(shell: RemoteShell, engine: str) -> dict[str, str]:
    result = run_root(shell, read_command(engine))
    if result.exit_status != 0 or result.truncated:
        return {}
    values: dict[str, str] = {}
    allowed = {
        "boot",
        "uptime",
        "apt",
        "dpkg",
        "systemd",
        "holds",
        "disk",
        "memory",
        "git",
        "digest",
    }
    for line in result.stdout.splitlines():
        name, separator, value = line.partition("\t")
        if not separator or name not in allowed or name in values:
            return {}
        values[name] = value
    return values


def _collect(shell: RemoteShell) -> CollectedSnapshot:
    from discovery.observations import collect

    return collect(shell, sites=False)


def _usage(shell: RemoteShell, engine: str) -> tuple[tuple[str, ...], bool]:
    command = observation.usage_command(engine)
    if command is None:
        return (), True
    result = run_root(shell, command)
    if result.exit_status != 0 or result.truncated:
        return (), False
    return observation.parse_usage(engine, result.stdout), True


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> EngineEvidence:
    engine = inputs.selection
    if engine not in ENGINE_CHOICES:
        raise ValueError("Choose MariaDB or PostgreSQL.")
    observed = _collect(shell)
    values = _values(shell, engine)
    machine = observed.architecture.value or ""
    deb_arch = _DEB_ARCH.get(machine, "")
    simulation: Simulation | None = None
    simulation_error = ""
    if deb_arch:
        result = run_root(shell, simulate_command(roots_for(engine, git=inputs.git)))
        if result.exit_status == 0 and not result.truncated:
            try:
                simulation = parse_simulation(result.stdout)
            except ValueError:
                simulation_error = "APT's simulation is not in a supported form."
        else:
            simulation_error = "APT could not resolve the installation."
    usage, usage_readable = _usage(shell, engine)
    return EngineEvidence(
        engine=engine,
        git=inputs.git,
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
        git_installed=values.get("git", "") == "installed",
        installed=observation.installed_engines(observed),
        outside=observation.outside_supported_engines(observed),
        simulation=simulation,
        simulation_error=simulation_error,
        usage=usage,
        usage_readable=usage_readable,
    )


def platform_reasons(evidence: EngineEvidence) -> list[str]:
    reasons: list[str] = []
    if evidence.standing != Standing.TARGET_STACK.value:
        reasons.append("Set up and verify the host foundation before installing a database engine.")
    if not evidence.deb_arch:
        reasons.append("The server's architecture is not one Barectl supports.")
    if evidence.apt and not evidence.apt.startswith("apt 3.2."):
        reasons.append("The server is not the supported Ubuntu 26.04 platform.")
    if evidence.dpkg and "version 1.23." not in evidence.dpkg:
        reasons.append("The server is not the supported Ubuntu 26.04 platform.")
    if evidence.systemd and not evidence.systemd.startswith("systemd 259 "):
        reasons.append("The server is not the supported Ubuntu 26.04 platform.")
    if evidence.disk_bytes is not None and evidence.disk_bytes < MIN_DISK_BYTES:
        reasons.append("The server lacks the free disk a reviewed database install needs.")
    if evidence.memory_kib is not None and evidence.memory_kib < MIN_MEMORY_KIB:
        reasons.append("The server lacks the free memory a reviewed database install needs.")
    if not valid_digest(evidence.precondition_digest) or not evidence.boot_id:
        reasons.append("The server's package evidence could not be read.")
    return reasons


def _unsatisfied(evidence: EngineEvidence) -> tuple[str, ...]:
    requested = roots_for(evidence.engine, git=evidence.git)
    return tuple(root for root in requested if not evidence.root_satisfied(root))


def _unpacked(evidence: EngineEvidence) -> set[str]:
    if evidence.simulation is None:
        return set()
    return {t.package for t in evidence.simulation.transitions if t.action == "Inst"}


def _transaction(
    evidence: EngineEvidence,
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
    unpacked = _unpacked(evidence)
    refusals.extend(
        f"APT's simulation does not install {root}. Check the package indexes, then prepare again."
        for root in _unsatisfied(evidence)
        if root not in unpacked
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


def _install_document(
    evidence: EngineEvidence, simulation: Simulation, actions: tuple[PackageAction, ...]
) -> tuple[dict[str, object], tuple[DeclaredEffect, ...]]:
    engine = evidence.engine
    spec = observation.specs()[engine]
    roots: list[list[str]] = []
    for root in roots_for(engine, git=evidence.git):
        version = next(
            (t.version for t in simulation.transitions if t.package == root),
            "",
        )
        if not version and evidence.root_satisfied(root):
            version = _installed_version(evidence, root)
        roots.append([root, version])
    version = next(
        (t.version for t in simulation.transitions if t.package == spec.versioned),
        "",
    )
    packages = [
        [t.package, t.version, t.architecture] for t in simulation.transitions if t.action == "Inst"
    ]
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": BODY_SHA256,
        "engine": engine,
        "git": evidence.git,
        "architecture": evidence.machine,
        "deb_arch": evidence.deb_arch,
        "precondition_digest": evidence.precondition_digest,
        "roots": roots,
        "versioned": spec.versioned,
        "engine_version": version,
        "packages": packages,
        "actions": [
            [action.unpack, action.package, action.version, action.architecture]
            for action in actions
        ],
        "hardening": list(observation.hardening_steps(engine)),
        "details": _details(evidence, roots, packages),
    }
    names = ", ".join(f"{name} {version}" for name, version in roots)
    effects = (
        DeclaredEffect(
            Scope.SERVER,
            f"Install {spec.label} from the Ubuntu archive ({names}) and harden it to "
            "its local socket and non-anonymous accounts.",
        ),
    )
    return document, effects


def review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, EngineEvidence):
        raise ValueError("A database engine install needs native evidence.")
    engine = evidence.engine
    spec = observation.specs()[engine]
    refusals = [*platform_reasons(evidence), *evidence.outside]
    installed_other = next((item for item in evidence.installed if item.engine != engine), None)
    if installed_other is not None:
        refusals.append(
            f"This server already runs {installed_other.label}. Barectl manages one database "
            "engine per server; remove it through ordinary administration, then prepare again."
        )
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": BODY_SHA256,
        "engine": engine,
        "git": evidence.git,
        "architecture": evidence.machine,
        "deb_arch": evidence.deb_arch,
    }
    effects: tuple[DeclaredEffect, ...] = ()
    simulation, actions, transaction_refusals = _transaction(evidence)
    refusals.extend(transaction_refusals)
    note = ""
    if simulation is not None and actions and not refusals:
        document, effects = _install_document(evidence, simulation, actions)
    elif not refusals:
        existing = evidence.current()
        note = (
            f"{spec.label} {existing.version} is already installed."
            if existing is not None
            else f"{spec.label} is already installed."
        )
    return ReviewDraft(
        kind=SLUG,
        intent=f"Install {spec.label}.",
        effects=effects,
        stages=STAGES,
        postconditions=(
            (
                f"{spec.label} is installed at the reviewed version, enabled and running, "
                "and its hardening holds."
            ),
            "Discovery reconstructs the engine and its version from the server alone.",
        ),
        refusals=tuple(refusals),
        boot_id=evidence.boot_id,
        uptime_centiseconds=evidence.uptime_centiseconds,
        document={**document, "note": note},
    )


def _installed_version(evidence: EngineEvidence, root: str) -> str:
    for engine in evidence.installed:
        for package in engine.packages:
            if package.name == root:
                return package.version
    return ""


def _details(
    evidence: EngineEvidence, roots: list[list[str]], packages: list[list[str]]
) -> list[dict[str, str]]:
    spec = observation.specs()[evidence.engine]
    return [
        {
            "label": "Package transaction",
            "value": "; ".join(f"{name} {version}" for name, version in roots),
        },
        {
            "label": "Every installed package",
            "value": "\n".join(f"{name} {version} ({arch})" for name, version, arch in packages)
            or "Nothing to install.",
        },
        {
            "label": "Network destinations",
            "value": "The server's configured Ubuntu archive only; Barectl adds no source.",
        },
        {
            "label": "Hardening",
            "value": "\n".join(observation.hardening_steps(evidence.engine)),
        },
        {"label": "Service", "value": "; ".join(spec.units)},
        {
            "label": "Listeners",
            "value": (
                f"Local socket {spec.socket}; no TCP listener on port {spec.port}."
                if evidence.engine == observation.MARIADB
                else f"Loopback only on port {spec.port}; no public listener."
            ),
        },
        {
            "label": "Databases held",
            "value": (
                "None."
                if not evidence.usage
                else f"{len(evidence.usage)}: " + ", ".join(evidence.usage)
            ),
        },
    ]


def body(document: dict[str, object], context: BodyContext) -> NativeBody:
    engine = document.get("engine")
    if (
        document.get("version") != 1
        or document.get("body_sha256") != BODY_SHA256
        or not isinstance(engine, str)
        or engine not in ENGINE_CHOICES
    ):
        raise ValueError("Unsupported database engine review.")
    if document.get("deb_arch") not in set(_DEB_ARCH.values()):
        raise ValueError("Unsupported database engine architecture.")
    digest = document.get("precondition_digest")
    if not isinstance(digest, str) or not valid_digest(digest):
        raise ValueError("The database engine precondition digest is invalid.")
    roots = document.get("roots")
    actions = document.get("actions")
    versioned = document.get("versioned")
    version = document.get("engine_version")
    if (
        not isinstance(roots, list)
        or not roots
        or not isinstance(actions, list)
        or not actions
        or not isinstance(versioned, str)
        or not isinstance(version, str)
        or not version
    ):
        raise ValueError("The database engine review is not a valid transaction.")
    requested: list[str] = []
    for entry in roots:
        if (
            not isinstance(entry, list)
            or len(entry) != 2
            or not all(isinstance(value, str) for value in entry)
        ):
            raise ValueError("The database engine review names invalid roots.")
        check_package(entry[0])
        requested.append(f"{entry[0]}={entry[1]}")
    approved: list[PackageAction] = []
    for action in actions:
        if not isinstance(action, list) or len(action) != 4 or type(action[0]) is not bool:
            raise ValueError("The database engine review names invalid actions.")
        approved.append(PackageAction(action[0], str(action[1]), str(action[2]), str(action[3])))
    try:
        guard_text = guard(tuple(approved))
    except ValueError as error:
        raise ValueError("The database engine review is not a valid transaction.") from error
    return NativeBody(
        BODY_BYTES,
        (engine, digest, " ".join(requested), guard_text, versioned, version),
    )


def verify(shell: RemoteShell, review: ChangeReview) -> bool | None:
    body(review.document, BodyContext("", "", 0))
    engine = str(review.document["engine"])
    observed = _collect(shell)
    if observed.standing is None:
        return None
    current = observation.observation_of(observed, engine)
    version = str(review.document.get("engine_version", ""))
    if current is None or not current.present or current.version != version:
        return False
    if not current.managed:
        return False
    hardening = run_root(shell, observation.verification_command(engine))
    if hardening.exit_status != 0 or hardening.truncated:
        return False
    if review.document.get("git"):
        git = run_root(shell, "dpkg-query -W -f='${db:Status-Status}' git 2>/dev/null")
        if git.exit_status != 0 or git.stdout.strip() != "installed":
            return False
    return True


def inspect_removal(shell: RemoteShell, inputs: PreparationInputs) -> RemovalEvidence:
    engine = inputs.selection
    if engine not in ENGINE_CHOICES:
        raise ValueError("Choose MariaDB or PostgreSQL.")
    observed = _collect(shell)
    values = _values(shell, engine)
    usage, usage_readable = _usage(shell, engine)
    return RemovalEvidence(
        engine=engine,
        standing=observed.standing.standing.value if observed.standing else "",
        boot_id=values.get("boot", ""),
        uptime_centiseconds=(int(values["uptime"]) if values.get("uptime", "").isdigit() else None),
        precondition_digest=values.get("digest", ""),
        installed=observation.installed_engines(observed),
        usage=usage,
        usage_readable=usage_readable,
    )


def review_removal(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, RemovalEvidence):
        raise ValueError("A database engine removal needs native evidence.")
    engine = evidence.engine
    spec = observation.specs()[engine]
    current = evidence.current()
    refusals: list[str] = []
    if evidence.standing != Standing.TARGET_STACK.value:
        refusals.append("Set up and verify the host foundation before removing a database engine.")
    if not evidence.boot_id:
        refusals.append("The server's clock could not be read.")
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": REMOVE_SHA256,
        "engine": engine,
    }
    effects: tuple[DeclaredEffect, ...] = ()
    note = ""
    if current is None:
        note = f"{spec.label} is not installed."
    elif not evidence.usage_readable:
        refusals.append(
            f"The databases {spec.label} holds could not be read, so Barectl will not remove it."
        )
    elif evidence.usage:
        refusals.append(
            f"{spec.label} holds {len(evidence.usage)} database(s): "
            + ", ".join(evidence.usage)
            + ". Barectl refuses to remove a database engine while any site uses it. "
            "Remove the sites and their databases first."
        )
    elif not valid_digest(evidence.precondition_digest):
        refusals.append("The server's package evidence could not be read.")
    if not refusals and current is not None:
        packages = list(observation.removal_packages(current))
        document.update(
            precondition_digest=evidence.precondition_digest,
            packages=packages,
            details=[
                {"label": "Packages removed", "value": "\n".join(packages)},
                {
                    "label": "Data",
                    "value": (
                        "The engine's data directories and configuration files are kept. "
                        "Barectl removes packages only; purge data through ordinary "
                        "administration."
                    ),
                },
            ],
        )
        effects = (
            DeclaredEffect(
                Scope.SERVER,
                f"Remove {spec.label} and stop its service. Its databases and data are kept.",
            ),
        )
    return ReviewDraft(
        kind=REMOVE_SLUG,
        intent=f"Remove {spec.label}.",
        effects=effects,
        stages=REMOVE_STAGES,
        postconditions=(f"{spec.label} is no longer installed.",),
        refusals=tuple(refusals),
        boot_id=evidence.boot_id,
        uptime_centiseconds=evidence.uptime_centiseconds,
        document={**document, "note": note},
    )


def removal_body(document: dict[str, object], context: BodyContext) -> NativeBody:
    engine = document.get("engine")
    if (
        document.get("version") != 1
        or document.get("body_sha256") != REMOVE_SHA256
        or not isinstance(engine, str)
        or engine not in ENGINE_CHOICES
    ):
        raise ValueError("Unsupported database engine removal.")
    digest = document.get("precondition_digest")
    packages = document.get("packages")
    if not isinstance(digest, str) or not valid_digest(digest):
        raise ValueError("The database engine removal digest is invalid.")
    if (
        not isinstance(packages, list)
        or not packages
        or not all(isinstance(name, str) for name in packages)
    ):
        raise ValueError("The database engine removal names no packages.")
    for name in packages:
        check_package(name)
    return NativeBody(REMOVE_BYTES, (engine, digest, " ".join(packages)))


def verify_removal(shell: RemoteShell, review: ChangeReview) -> bool | None:
    removal_body(review.document, BodyContext("", "", 0))
    engine = str(review.document["engine"])
    observed = _collect(shell)
    if observed.standing is None:
        return None
    return observation.observation_of(observed, engine) is None


INSTALL: Final = ChangeKind(
    slug=SLUG,
    label=LABEL,
    inspect=inspect,
    review=review,
    body=body,
    verify=verify,
    refresh_discovery=True,
    input_choices=ENGINE_CHOICES,
    input_shape=InputShape.DATABASE_ENGINE,
)
REMOVE: Final = ChangeKind(
    slug=REMOVE_SLUG,
    label=REMOVE_LABEL,
    inspect=inspect_removal,
    review=review_removal,
    body=removal_body,
    verify=verify_removal,
    refresh_discovery=True,
    input_choices=ENGINE_CHOICES,
)
