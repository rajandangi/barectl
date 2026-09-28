"""The eligibility policy: turn a preparation's evidence into a plan's proposal or refusals.

``review`` is a pure function of the action and the evidence. A plan is eligible only when
no refusal applies; a refusal explains what blocks it and what ordinary administration
resolves it, without Barectl changing anything. The rules follow the v0.2 contract:
Ubuntu 24.04 with systemd, dpkg and APT; authenticated noble, noble-updates and
noble-security archives only; no change to an installed package; only distribution-default
web-stack configuration and units; no unknown APT hooks; and complete evidence. A healthy,
already satisfied profile is a plan with no changes, whatever newer versions the archive
offers, and an otherwise conforming profile whose service is stopped or disabled proposes
explicit enable and start effects.
"""

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, field

from . import profiles
from .evidence import (
    AptEvidence,
    ConfigTree,
    Evidence,
    FileDigest,
    Listener,
    PackageEvidence,
    PackageState,
    Platform,
    Transition,
    TreeEntry,
    UnitState,
    WebEvidence,
)
from .models import Action, PackageTransition, PlanEffect, PlanEvidence, PlanRefusal, Privilege
from .profiles import Profile, TreeSpec

Reason = PlanRefusal.Reason
Effect = PlanEffect.Kind
EvidenceKind = PlanEvidence.Kind
# At most this many paths are named in one refusal; the rest are counted.
_LISTED_PATHS = 5
_TRANSITIONING = frozenset({"activating", "deactivating", "reloading", "refreshing"})
_FALSE = frozenset({"", "0", "false", "no", "off", "without"})


@dataclass(frozen=True)
class RootDraft:
    name: str
    version: str
    installed: bool


@dataclass(frozen=True)
class TransitionDraft:
    step: PackageTransition.Step
    package: str
    architecture: str
    version: str
    origins: tuple[str, ...]


@dataclass(frozen=True)
class EvidenceDraft:
    kind: PlanEvidence.Kind
    fingerprint: str
    summary: str


@dataclass
class Draft:
    """A plan before it is saved: the decision, its reasons and its proposal."""

    action: Action
    intent: str
    platform: Platform | None
    refusals: list[tuple[PlanRefusal.Reason, str]] = field(default_factory=list)
    roots: list[RootDraft] = field(default_factory=list)
    transitions: list[TransitionDraft] = field(default_factory=list)
    effects: list[tuple[PlanEffect.Kind, str]] = field(default_factory=list)
    postconditions: list[str] = field(default_factory=list)
    evidence: list[EvidenceDraft] = field(default_factory=list)

    @property
    def eligible(self) -> bool:
        return not self.refusals

    @property
    def no_changes(self) -> bool:
        return self.eligible and any(kind == Effect.NO_CHANGES for kind, _ in self.effects)

    def refuse(self, reason: PlanRefusal.Reason, text: str) -> None:
        if (reason, text) not in self.refusals:
            self.refusals.append((reason, text))

    def fingerprint(self, kind: PlanEvidence.Kind, lines: Iterable[str], summary: str) -> None:
        digest = hashlib.sha256("\n".join(lines).encode()).hexdigest()
        self.evidence.append(EvidenceDraft(kind, digest, summary[:300]))


def review(action: Action, evidence: Evidence) -> Draft:
    """Decide ``action``'s plan from ``evidence``."""
    intent = (
        profiles.METADATA_REFRESH_INTENT
        if action == Action.METADATA_REFRESH
        else profiles.PROFILES[action].intent
    )
    draft = Draft(action, intent, evidence.platform)
    for gap in evidence.gaps:
        draft.refuse(Reason.INCOMPLETE, gap)
    _check_platform(draft, evidence.platform)
    _check_apt(draft, evidence.apt, package_plan=action != Action.METADATA_REFRESH)
    if action == Action.METADATA_REFRESH:
        if draft.eligible and evidence.apt is not None:
            _refresh_effects(draft, evidence.apt)
        return draft
    profile = profiles.PROFILES[action]
    _check_profile(draft, profile, evidence)
    return draft


# Platform and privilege -----------------------------------------------------------------


def _check_platform(draft: Draft, platform: Platform | None) -> None:
    if platform is None:
        draft.refuse(Reason.INCOMPLETE, "Barectl could not establish the server's platform.")
        return
    os = platform.os
    if (os.id, os.version_id) != profiles.SUPPORTED_OS:
        name = os.pretty_name or "an operating system Barectl could not identify"
        draft.refuse(
            Reason.UNSUPPORTED_PLATFORM,
            f"The server runs {name}. Bootstrap supports Ubuntu 24.04 only.",
        )
    if not platform.systemd:
        draft.refuse(
            Reason.UNSUPPORTED_PLATFORM,
            "systemd is not the running system manager. Bootstrap needs systemd.",
        )
    if platform.architecture and platform.architecture not in profiles.ARCHITECTURES:
        draft.refuse(
            Reason.UNSUPPORTED_PLATFORM,
            f"The {platform.architecture} architecture is not supported; bootstrap supports "
            "amd64 and arm64.",
        )
    if not {"apt", "dpkg", "systemd"} <= set(platform.tools):
        draft.refuse(
            Reason.UNSUPPORTED_PLATFORM,
            "dpkg does not list the apt, dpkg and systemd packages, which bootstrap needs.",
        )
    if not platform.boot_id or platform.uptime_centiseconds is None:
        draft.refuse(
            Reason.INCOMPLETE,
            "Without the boot identity and uptime, the plan cannot be bound to an admission "
            "deadline.",
        )
    if platform.privilege == Privilege.UNAVAILABLE:
        draft.refuse(
            Reason.PRIVILEGE,
            "The SSH user is not root, and sudo -n -l does not authorize "
            f"{profiles.APPLY_ENTRYPOINT} without a password. Applying needs root or an existing "
            "noninteractive sudo authorization; Barectl never installs one or asks for a "
            "password. Barectl accounts and permissions do not grant Linux privileges.",
        )
    draft.fingerprint(
        EvidenceKind.PLATFORM,
        [
            os.id,
            os.version_id,
            os.pretty_name,
            platform.architecture,
            str(platform.systemd),
            platform.boot_id,
            *(f"{name} {version}" for name, version in sorted(platform.tools.items())),
        ],
        f"{os.pretty_name or 'Unidentified'}, {platform.architecture or 'unknown architecture'}"
        f", apt {platform.tools.get('apt', 'unknown')}, boot {platform.boot_id or 'unknown'}",
    )
    draft.fingerprint(
        EvidenceKind.PRIVILEGE,
        [platform.privilege, str(platform.listener_privilege)],
        _privilege_summary(platform),
    )


def _privilege_summary(platform: Platform) -> str:
    match platform.privilege:
        case Privilege.ROOT:
            return "The SSH user is root."
        case Privilege.SUDO:
            listeners = " and the listener query" if platform.listener_privilege else ""
            return f"Noninteractive sudo is authorized for {profiles.APPLY_ENTRYPOINT}{listeners}."
        case Privilege.UNAVAILABLE:
            return "Neither root nor noninteractive sudo is available."


# APT --------------------------------------------------------------------------------------


def _check_apt(draft: Draft, apt: AptEvidence | None, *, package_plan: bool) -> None:
    if apt is None:
        draft.refuse(Reason.INCOMPLETE, "Barectl could not read the APT configuration.")
        return
    hooks = _check_hooks(draft, apt)
    _check_options(draft, apt)
    for path in apt.source_overrides:
        draft.refuse(
            Reason.PACKAGE_SOURCE,
            f"{path} sets a repository option that disables or weakens authentication, such "
            "as trusted=yes. Bootstrap uses authenticated sources only.",
        )
    if package_plan:
        _check_indexes(draft, apt)
    elif not apt.targets:
        draft.refuse(Reason.APT_CONFIGURATION, "APT has no package sources configured.")
    sources = [f"{f.path} {f.digest}" for f in apt.files if _is_source(f)]
    preferences = [f"{f.path} {f.digest}" for f in apt.files if _is_preference(f)]
    other = [
        f"{f.path} {f.digest}" for f in apt.files if not _is_source(f) and not _is_preference(f)
    ]
    draft.fingerprint(
        EvidenceKind.APT_CONFIGURATION,
        [*(f"{entry.key} {entry.value}" for entry in apt.config), *other],
        f"{len(apt.config)} effective settings and {len(other)} configuration files.",
    )
    owners = sorted(set(hooks.values()))
    draft.fingerprint(
        EvidenceKind.APT_HOOKS,
        [f"{name} {value}" for name, value in hooks],
        f"{len(hooks)} hooks from {', '.join(owners)}." if hooks else "No APT hooks.",
    )
    draft.fingerprint(EvidenceKind.APT_SOURCES, sources, f"{len(sources)} source files.")
    draft.fingerprint(
        EvidenceKind.APT_PREFERENCES, preferences, f"{len(preferences)} preference files."
    )
    trusted = sum(1 for target in apt.targets if target.trusted)
    draft.fingerprint(
        EvidenceKind.PACKAGE_INDEXES,
        [
            *("|".join(map(str, target)) for target in apt.targets),
            *(f"{f.path} {f.digest}" for f in apt.releases),
        ],
        f"{len(apt.targets)} package indexes, {trusted} authenticated; "
        f"{len(apt.releases)} Release files.",
    )


def _is_source(digest: FileDigest) -> bool:
    return digest.path.startswith("/etc/apt/sources.list")


def _is_preference(digest: FileDigest) -> bool:
    return digest.path.startswith("/etc/apt/preferences")


def _check_hooks(draft: Draft, apt: AptEvidence) -> dict[tuple[str, str], str]:
    """Refuse unknown hooks; return the admitted ones with the package installing each."""
    admitted: dict[tuple[str, str], str] = {}
    for entry in apt.config:
        if not profiles.HOOK_KEY.search(entry.name) or not entry.value:
            continue
        owner = profiles.DISTRIBUTION_HOOKS.get((entry.name, entry.value))
        if owner is None:
            draft.refuse(
                Reason.APT_HOOK,
                f"The APT configuration sets {entry.key.removesuffix('::')} to a command "
                "Barectl has not qualified. Hooks run as root during package changes; remove "
                "it, or restore the distribution's hook, then prepare again.",
            )
        else:
            admitted[entry.name, entry.value] = owner
    return admitted


def _check_options(draft: Draft, apt: AptEvidence) -> None:
    for entry in apt.config:
        name = entry.name
        changed = (
            (name in profiles.AUTHENTICATION_OPTIONS and entry.value.lower() not in _FALSE)
            or (name in profiles.REQUIRED_OPTIONS and entry.value.lower() in _FALSE)
            or (name in profiles.FIXED_OPTIONS and entry.value != profiles.FIXED_OPTIONS[name])
            or (name in profiles.EMPTY_LISTS and entry.value != "")
        )
        if changed:
            draft.refuse(
                Reason.APT_CONFIGURATION,
                f"The APT configuration changes {entry.key.removesuffix('::')}, which affects "
                "authentication, package selection or dpkg. Restore the distribution's "
                "setting, then prepare again.",
            )


def _check_indexes(draft: Draft, apt: AptEvidence) -> None:
    architecture = draft.platform.architecture if draft.platform else ""
    for suite in profiles.REQUIRED_SUITES:
        found = any(
            target.origin == "Ubuntu"
            and target.codename == "noble"
            and target.suite == suite
            and target.component == "main"
            and target.architecture == architecture
            and target.trusted
            for target in apt.targets
        )
        if not found:
            draft.refuse(
                Reason.PACKAGE_METADATA,
                f"No authenticated Ubuntu package index for {suite} main is available. "
                "Refresh the package metadata, with a reviewed metadata refresh or ordinary "
                "administration, then prepare again.",
            )


def _refresh_effects(draft: Draft, apt: AptEvidence) -> None:
    sites = sorted({target.site for target in apt.targets if target.site})
    draft.effects.append(
        (
            Effect.INDEX_UPDATE,
            (
                f"apt-get update downloads the package indexes of the configured sources "
                f"({', '.join(sites)}) and accepts only authenticated indexes. No package is "
                "installed, upgraded or removed."
            ),
        )
    )
    owners = sorted(
        {
            owner
            for (name, value), owner in profiles.DISTRIBUTION_HOOKS.items()
            if name.startswith("apt::update::")
            and any(entry.name == name and entry.value == value for entry in apt.config)
        }
    )
    if owners:
        effects = "; ".join(f"{owner} {profiles.HOOK_EFFECTS[owner]}" for owner in owners)
        draft.effects.append(
            (Effect.UPDATE_HOOKS, f"APT runs the distribution's update hooks: {effects}.")
        )
    draft.effects.append(
        (
            Effect.INVALIDATES_PLANS,
            (
                "Completing the refresh invalidates earlier package plans for this server; "
                "prepare them again afterwards."
            ),
        )
    )
    draft.effects.append(
        (Effect.NO_ROLLBACK, "Barectl does not restore the previous indexes afterwards.")
    )
    draft.postconditions.extend(
        [
            "apt-get update finishes without errors or warnings, so no index failed partially.",
            "The noble, noble-updates and noble-security indexes are authenticated Ubuntu indexes.",
            "No package is installed, upgraded or removed.",
        ]
    )


# Package profiles ---------------------------------------------------------------------


def _check_profile(draft: Draft, profile: Profile, evidence: Evidence) -> None:
    packages, web = evidence.packages, evidence.web
    if packages is None or web is None:
        draft.refuse(Reason.INCOMPLETE, "Barectl could not read the package and service evidence.")
        return
    states = {state.name: state for state in packages.states}
    missing = _check_roots(draft, profile, states)
    _check_package_health(draft, profile, packages, states)
    if missing and packages.simulation is not None:
        _check_simulation(draft, profile, packages, missing)
    installed = {name for name, state in states.items() if state.installed}
    starts = _check_units(draft, profile, web.units, installed)
    _check_trees(draft, profile, web, installed)
    running = any(unit.active_state == "active" for unit in web.units)
    if profile.port is not None:
        _check_listeners(draft, profile, web.listeners or (), running=running and not missing)
    _fingerprint_packages(draft, profile, packages)
    _fingerprint_web(draft, web)
    if draft.eligible:
        _profile_effects(draft, profile, packages, starts)


def _check_roots(draft: Draft, profile: Profile, states: dict[str, PackageState]) -> list[str]:
    missing: list[str] = []
    for root in profile.roots:
        state = states.get(root)
        if state is not None and state.installed:
            draft.roots.append(RootDraft(root, state.version, installed=True))
        elif state is None or state.absent:
            missing.append(root)
    return missing


def _check_package_health(
    draft: Draft,
    profile: Profile,
    packages: PackageEvidence,
    states: dict[str, PackageState],
) -> None:
    if packages.audit.strip():
        draft.refuse(
            Reason.PACKAGE_HEALTH,
            "dpkg --audit reports packages that are not fully installed or configured. "
            "Complete or repair them with dpkg and apt, then prepare again.",
        )
    for name in profile.packages:
        state = states.get(name)
        if state is None or state.installed or state.absent:
            continue
        if state.status[1] == "c":
            draft.refuse(
                Reason.LEFTOVER,
                f"{name} was removed, but its configuration files remain (dpkg state "
                f"{state.status}). Purge or reinstall it through ordinary administration, "
                "then prepare again.",
            )
        else:
            draft.refuse(
                Reason.PACKAGE_HEALTH,
                f"{name} is in dpkg state {state.status}, not installed and configured. "
                "Complete or repair it with dpkg and apt, then prepare again.",
            )


def _check_simulation(
    draft: Draft,
    profile: Profile,
    packages: PackageEvidence,
    missing: list[str],
) -> None:
    simulation = packages.simulation
    if simulation is None:
        return
    for problem in simulation.problems:
        draft.refuse(
            Reason.SIMULATION,
            f"{problem} Check the package sources and indexes, then prepare again.",
        )
    held = {hold.split(":", 1)[0] for hold in packages.holds}
    for transition in simulation.transitions:
        _check_transition(draft, transition, held)
    _check_pairs(draft, simulation.transitions)
    unpacked = {t.package: t for t in simulation.transitions if t.action == "Inst"}
    for root in missing:
        found = unpacked.get(root)
        if found is None:
            draft.refuse(
                Reason.SIMULATION,
                f"APT's simulation does not install {root}. Check the package indexes, "
                "then prepare again.",
            )
        else:
            draft.roots.append(RootDraft(root, found.version, installed=False))
    order = {name: index for index, name in enumerate(profile.roots)}
    draft.roots.sort(key=lambda root: order[root.name])


def _check_transition(draft: Draft, transition: Transition, held: set[str]) -> None:
    name = transition.package
    if transition.action in {"Remv", "Purg"}:
        draft.refuse(
            Reason.INSTALLED_PACKAGE_CHANGE,
            f"Installing would remove {name} {transition.previous}. Bootstrap never removes "
            "packages.",
        )
        return
    if transition.action == "Inst" and transition.previous:
        draft.refuse(
            Reason.INSTALLED_PACKAGE_CHANGE,
            f"Installing would change the installed package {name} from "
            f"{transition.previous} to {transition.version}. Bootstrap never upgrades, "
            "downgrades or reinstalls installed packages; update the server through ordinary "
            "maintenance, then prepare again.",
        )
    if not transition.origins or not set(transition.origins) <= profiles.ALLOWED_ORIGINS:
        archives = ", ".join(transition.origins) or "an unidentified archive"
        draft.refuse(
            Reason.PACKAGE_SOURCE,
            f"{name} {transition.version} would come from {archives}. Bootstrap installs "
            "only from the Ubuntu 24.04 noble, noble-updates and noble-security archives.",
        )
    architecture = draft.platform.architecture if draft.platform else ""
    if transition.architecture not in {architecture, "all"}:
        draft.refuse(
            Reason.SIMULATION,
            f"{name} would be installed for the {transition.architecture} architecture, not "
            "the server's.",
        )
    if name in held:
        draft.refuse(
            Reason.HELD_PACKAGE,
            f"{name} is held with apt-mark hold. Bootstrap does not change held packages; "
            "release the hold through ordinary administration, then prepare again.",
        )
    if transition.action == "Inst":
        draft.transitions.append(
            TransitionDraft(
                PackageTransition.Step.INSTALL,
                name,
                transition.architecture,
                transition.version,
                transition.origins,
            )
        )
    else:
        draft.transitions.append(
            TransitionDraft(
                PackageTransition.Step.CONFIGURE,
                name,
                transition.architecture,
                transition.version,
                transition.origins,
            )
        )


def _check_pairs(draft: Draft, transitions: tuple[Transition, ...]) -> None:
    """Each unpacked package is configured at the same version, and nothing else is."""
    unpacks = {(t.package, t.version) for t in transitions if t.action == "Inst"}
    configures = {(t.package, t.version) for t in transitions if t.action == "Conf"}
    for package, version in sorted(configures - unpacks):
        draft.refuse(
            Reason.SIMULATION,
            f"APT would configure {package} {version} without installing it, which completes "
            "an earlier, unfinished installation. Repair it with dpkg, then prepare again.",
        )
    for package, version in sorted(unpacks - configures):
        draft.refuse(
            Reason.SIMULATION,
            f"APT would unpack {package} {version} without configuring it.",
        )


def _check_units(
    draft: Draft, profile: Profile, units: tuple[UnitState, ...], installed: set[str]
) -> list[PlanEffect.Kind]:
    """Refuse units that are not the distribution's; return the enable and start effects."""
    effects: list[PlanEffect.Kind] = []
    for unit in units:
        if profile.roots[0] not in installed:
            _check_absent_unit(draft, unit)
            continue
        problem = _unit_problem(unit)
        if problem:
            draft.refuse(Reason.SERVICE_UNIT, f"{unit.name} {problem}")
            continue
        if unit.unit_file_state == "disabled":
            effects.append(Effect.SERVICE_ENABLE)
        if unit.active_state == "inactive":
            effects.append(Effect.SERVICE_START)
    return effects


def _unit_problem(unit: UnitState) -> str:
    """Why an installed profile's unit is not the distribution's healthy unit, if it is not."""
    if unit.load_state == "masked":
        return "is masked. Unmask it through ordinary administration, then prepare again."
    if unit.load_state != "loaded":
        return f"is not loaded (systemd reports {unit.load_state or 'nothing'})."
    if unit.drop_in_paths:
        return (
            f"has drop-in overrides ({', '.join(unit.drop_in_paths[:_LISTED_PATHS])}). "
            "Bootstrap supports only the distribution's unit."
        )
    if unit.fragment_path != f"/usr/lib/systemd/system/{unit.name}":
        return (
            f"is defined by {unit.fragment_path or 'no unit file'}, not the distribution's "
            "unit file."
        )
    if unit.active_state == "failed":
        return (
            "has failed. Inspect it with systemctl status and journalctl, repair it, then "
            "prepare again."
        )
    if unit.active_state in _TRANSITIONING:
        return f"is {unit.active_state}. Prepare again once it settles."
    if unit.active_state not in {"active", "inactive"}:
        return f"reports the unsupported state {unit.active_state}."
    if unit.unit_file_state not in {"enabled", "disabled"}:
        return f"has the unsupported enablement state {unit.unit_file_state or 'none'}."
    return ""


def _check_absent_unit(draft: Draft, unit: UnitState) -> None:
    if unit.load_state == "not-found":
        return
    if unit.load_state == "masked":
        draft.refuse(
            Reason.SERVICE_UNIT,
            f"{unit.name} is masked, so the package could not start it. Unmask it through "
            "ordinary administration, then prepare again.",
        )
        return
    draft.refuse(
        Reason.LEFTOVER,
        f"{unit.name} exists although its package is not installed. Bootstrap does not adopt "
        "existing units; remove it, then prepare again.",
    )


def _check_trees(draft: Draft, profile: Profile, web: WebEvidence, installed: set[str]) -> None:
    for spec, tree in zip(profile.trees, web.trees, strict=True):
        if spec.owner not in installed:
            if tree.exists:
                draft.refuse(
                    Reason.LEFTOVER,
                    f"{spec.root} exists although {spec.owner} is not installed. Barectl does "
                    "not adopt or overwrite existing configuration; remove it or restore the "
                    "package through ordinary administration, then prepare again.",
                )
            continue
        _verify_tree(draft, spec, tree, web)


def _verify_tree(draft: Draft, spec: TreeSpec, tree: ConfigTree, web: WebEvidence) -> None:
    """Every entry is an unmodified distribution file, a default link, or a directory."""
    under = f"{spec.root}/"
    conffiles = {
        item.path: item.md5
        for item in web.conffiles
        if not item.obsolete and item.path.startswith(under)
    }
    defaults = dict(conffiles)
    defaults.update({path: md5 for path, md5 in web.ucf.items() if path.startswith(under)})
    customized: list[str] = []
    unreadable: list[str] = []
    for entry in tree.entries:
        problem = _entry_problem(entry, spec, tree, defaults)
        if problem is _UNREADABLE:
            unreadable.append(entry.path)
        elif problem:
            customized.append(f"{entry.path} ({problem})")
    files = {entry.path for entry in tree.entries if entry.kind == "f"}
    customized.extend(
        f"{path} (a distribution default that is missing)"
        for path in sorted(set(conffiles) - files)
    )
    if not tree.exists:
        customized.append(f"{spec.root} (missing)")
    if customized:
        draft.refuse(
            Reason.CUSTOMIZED,
            f"The configuration under {spec.root} is not the distribution's default: "
            f"{_listed(customized)}. Bootstrap does not adopt or overwrite custom "
            "configuration.",
        )
    if unreadable:
        draft.refuse(
            Reason.INCOMPLETE,
            f"The SSH user cannot read {_listed(unreadable)}, so Barectl cannot confirm "
            "they are the distribution's defaults.",
        )


_UNREADABLE = "unreadable"


def _entry_problem(
    entry: TreeEntry, spec: TreeSpec, tree: ConfigTree, defaults: dict[str, str]
) -> str:
    """Why an entry is not part of the distribution's configuration; empty when it is."""
    if entry.kind == "d":
        return ""
    if entry.kind == "l":
        return "" if spec.links(entry.path, entry.target) else "a link Barectl does not recognize"
    if entry.kind != "f":
        return "a special file"
    digest = tree.digests.get(entry.path)
    if entry.path not in defaults:
        return "not part of the distribution's configuration"
    if digest is None:
        return _UNREADABLE
    if digest != defaults[entry.path]:
        return "changed from the distribution's default"
    return ""


def _listed(items: list[str]) -> str:
    shown = "; ".join(items[:_LISTED_PATHS])
    more = len(items) - _LISTED_PATHS
    return f"{shown}; and {more} more" if more > 0 else shown


def _check_listeners(
    draft: Draft, profile: Profile, listeners: tuple[Listener, ...], *, running: bool
) -> None:
    others = [
        listener
        for listener in listeners
        if not running or (listener.processes is not None and set(listener.processes) != {"nginx"})
    ]
    if others:
        addresses = ", ".join(listener.address for listener in others)
        draft.refuse(
            Reason.LISTENER,
            f"Another service listens on port {profile.port} ({addresses}), so the "
            "distribution's default site could not start. Stop or reconfigure it, then "
            "prepare again.",
        )
    attributed = all(listener.processes is not None for listener in listeners)
    owners = sorted({name for item in listeners for name in item.processes or ()})
    summary = (
        f"No listener on port {profile.port}."
        if not listeners
        else f"{len(listeners)} listeners on port {profile.port}"
        + (f" ({', '.join(owners)})." if attributed and owners else ", owners not attributed.")
    )
    draft.fingerprint(
        EvidenceKind.LISTENERS,
        [f"{item.address} {','.join(item.processes or ())}" for item in listeners],
        summary,
    )


def _fingerprint_packages(draft: Draft, profile: Profile, packages: PackageEvidence) -> None:
    states = sorted(packages.states)
    relevant = {state.name for state in states}
    draft.fingerprint(
        EvidenceKind.DPKG_STATUS,
        [packages.audit, *("\t".join(state) for state in states)],
        f"{len(states)} relevant packages; "
        + (
            "dpkg --audit reports nothing."
            if not packages.audit.strip()
            else "dpkg --audit reports problems."
        ),
    )
    draft.fingerprint(
        EvidenceKind.PACKAGE_HOLDS,
        sorted(packages.holds),
        f"{len(packages.holds)} held packages.",
    )
    automatic = sorted(name for name in packages.automatic if name.split(":")[0] in relevant)
    draft.fingerprint(
        EvidenceKind.AUTO_MARKS,
        automatic,
        f"{len(automatic)} of the relevant packages are marked automatically installed.",
    )
    if packages.simulation is not None:
        draft.fingerprint(
            EvidenceKind.SIMULATION,
            [
                "|".join((t.action, t.package, t.previous, t.version, t.architecture, *t.origins))
                for t in packages.simulation.transitions
            ],
            f"{len(packages.simulation.transitions)} package actions for "
            f"{', '.join(profile.roots)}.",
        )


def _fingerprint_web(draft: Draft, web: WebEvidence) -> None:
    lines = [
        f"{tree.root} {entry.kind} {entry.path} {entry.target} {tree.digests.get(entry.path, '')}"
        for tree in web.trees
        for entry in tree.entries
    ]
    roots = ", ".join(tree.root for tree in web.trees if tree.exists) or "no directories"
    draft.fingerprint(
        EvidenceKind.WEB_CONFIGURATION,
        [*lines, *(f"{c.path} {c.md5} {c.obsolete}" for c in web.conffiles)],
        f"{len(lines)} entries under {roots}.",
    )
    draft.fingerprint(
        EvidenceKind.SERVICE_UNITS,
        [
            " ".join(
                (
                    unit.name,
                    unit.load_state,
                    unit.active_state,
                    unit.sub_state,
                    unit.unit_file_state,
                    unit.fragment_path,
                    *unit.drop_in_paths,
                )
            )
            for unit in web.units
        ],
        "; ".join(
            f"{unit.name} {unit.load_state}, {unit.active_state}, {unit.unit_file_state or '—'}"
            for unit in web.units
        ),
    )


# Effects ------------------------------------------------------------------------------------


def _profile_effects(
    draft: Draft, profile: Profile, packages: PackageEvidence, starts: list[PlanEffect.Kind]
) -> None:
    unit = profile.units[0]
    restart = any(state.name == "needrestart" and state.installed for state in packages.states)
    if draft.transitions:
        _install_effects(draft, profile, unit, needrestart=restart)
        return
    if not starts:
        draft.effects.append(
            (
                Effect.NO_CHANGES,
                (
                    "No changes. The profile is installed, healthy and uses the distribution's "
                    "default configuration. Newer versions in the archive are not installed; "
                    "upgrades are ordinary maintenance outside bootstrap."
                ),
            )
        )
        return
    if Effect.SERVICE_ENABLE in starts:
        draft.effects.append((Effect.SERVICE_ENABLE, f"Enables {unit} so that it starts at boot."))
    if Effect.SERVICE_START in starts:
        draft.effects.append((Effect.SERVICE_START, f"Starts {unit}."))
        draft.effects.append(_exposure(profile))
    draft.postconditions.extend(_service_postconditions(profile, unit))


def _install_effects(draft: Draft, profile: Profile, unit: str, *, needrestart: bool) -> None:
    installs = [t for t in draft.transitions if t.step == PackageTransition.Step.INSTALL]
    roots = ", ".join(root.name for root in draft.roots if not root.installed)
    draft.effects.append(
        (
            Effect.PACKAGES,
            (
                f"Installs {len(installs)} packages at the exact versions listed, from the Ubuntu "
                f"24.04 archives. APT marks {roots} as manually installed and the other new "
                "packages as automatically installed; packages installed before keep their marks."
            ),
        )
    )
    draft.effects.append(
        (
            Effect.MAINTAINER_START,
            (
                f"The package maintainer scripts enable and start {unit} while dpkg runs, before "
                "Barectl validates the result."
            ),
        )
    )
    draft.effects.append(_exposure(profile))
    if needrestart:
        draft.effects.append(
            (
                Effect.NEEDRESTART,
                (
                    "needrestart runs after dpkg. With Ubuntu 24.04's default configuration it "
                    "restarts services that use outdated libraries without asking."
                ),
            )
        )
    draft.effects.append(
        (
            Effect.NO_ROLLBACK,
            (
                "Barectl does not roll back. An interrupted or failed installation can leave "
                "packages unpacked or unconfigured, to recover with apt and dpkg."
            ),
        )
    )
    draft.postconditions.append(
        "Each listed package is installed at its listed version, and dpkg --audit reports nothing."
    )
    draft.postconditions.extend(_service_postconditions(profile, unit))
    draft.postconditions.append(
        "Packages installed before keep their automatic or manual installation marks."
    )


def _exposure(profile: Profile) -> tuple[PlanEffect.Kind, str]:
    if profile.port is not None:
        return (
            Effect.HTTP_LISTENER,
            (
                f"The distribution's default site serves HTTP on port {profile.port} on every "
                "IPv4 and IPv6 address. Check the server's firewall policy before applying; "
                "Barectl does not change it."
            ),
        )
    return (
        Effect.LOCAL_SOCKET,
        (
            "The distribution's default www pool listens on the local socket "
            "/run/php/php8.3-fpm.sock and opens no network port. No site, route, pool, database, "
            "certificate or application user is created."
        ),
    )


def _service_postconditions(profile: Profile, unit: str) -> list[str]:
    if profile.action == Action.NGINX:
        return [
            "nginx -t accepts the configuration.",
            f"{unit} is enabled and active.",
            f"Port {profile.port} accepts connections on IPv4 and IPv6.",
            "Discovery observes Nginx with the default site file.",
        ]
    return [
        "php-fpm8.3 -t accepts the configuration, and php8.3 runs the installed CLI.",
        f"{unit} is enabled and active.",
        "/run/php/php8.3-fpm.sock exists.",
        "Discovery observes PHP-FPM 8.3 with the www pool.",
    ]
