"""docs/ssh-connections.md#plan-preparation"""

import hashlib
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import cmp_to_key

from . import native, php_supply, profiles, releases
from .evidence import (
    AptEvidence,
    ConfigTree,
    ConfiguredSource,
    Evidence,
    FileDigest,
    IndexTarget,
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
from .profiles import Profile, TreeSpec, enablements, unit_file
from .releases import Release
from .versions import compare

Reason = PlanRefusal.Reason
Effect = PlanEffect.Kind
EvidenceKind = PlanEvidence.Kind
# At most this many paths are named in one refusal; the rest are counted.
_LISTED_PATHS = 5
_TRANSITIONING = frozenset({"activating", "deactivating", "reloading", "refreshing"})
_FALSE = frozenset({"", "0", "false", "no", "off", "without"})
_NO_RULES: Mapping[str, TreeRule] = {}


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
    # The supported release the server runs, whose policy the plan follows.
    release: Release | None
    refusals: list[tuple[PlanRefusal.Reason, str]] = field(default_factory=list)
    roots: list[RootDraft] = field(default_factory=list)
    transitions: list[TransitionDraft] = field(default_factory=list)
    effects: list[tuple[PlanEffect.Kind, str]] = field(default_factory=list)
    postconditions: list[str] = field(default_factory=list)
    evidence: list[EvidenceDraft] = field(default_factory=list)
    # The finished bootstrap units a cleanup clears, as preparation observed them.
    units: list[native.UnitEvidence] = field(default_factory=list)
    php_version: str = ""
    php_supply: str = "ubuntu"
    php_source_admitted: bool = False

    @property
    def eligible(self) -> bool:
        return not self.refusals

    @property
    def revision(self) -> int:
        """The revision of the definitions the plan was reviewed against."""
        return profiles.PROFILE_REVISION

    @property
    def no_changes(self) -> bool:
        return self.eligible and any(kind == Effect.NO_CHANGES for kind, _ in self.effects)

    def refuse(self, reason: PlanRefusal.Reason, text: str) -> None:
        if (reason, text) not in self.refusals:
            self.refusals.append((reason, text))

    def fingerprint(self, kind: PlanEvidence.Kind, lines: Iterable[str], summary: str) -> None:
        digest = hashlib.sha256("\n".join(lines).encode()).hexdigest()
        self.evidence.append(EvidenceDraft(kind, digest, summary[:300]))


type TreeRule = Callable[[Draft, TreeSpec, ConfigTree], None]


def review(
    action: Action,
    evidence: Evidence,
    current: frozenset[str] = frozenset(),
    *,
    tree_rules: Mapping[str, TreeRule] = _NO_RULES,
    version: str | None = None,
    supply: str = "ubuntu",
) -> Draft:
    """``current`` names the units of this installation's runs that are not finished; a
    cleanup never clears them. ``tree_rules`` judge the trees whose spec names a rule
    (docs/databases.md#site-aware-readiness).
    """
    platform = evidence.platform
    release = releases.of(platform.os) if platform is not None else None
    draft = Draft(action, _intent(action, release), platform, release)
    if release is not None and (action == Action.PHP or action in profiles.BRANCH_ACTIONS):
        try:
            selected = profiles.profile(release, action, version=version, supply=supply)
        except ValueError:
            draft.refuse(Reason.UNSUPPORTED_VERSION, "The requested PHP selection is unavailable.")
            return draft
        draft.php_version = version or ""
        draft.php_supply = supply
        draft.intent = selected.intent
        if not php_supply.supported(selected.php_version, datetime.now(UTC).date()):
            draft.refuse(
                Reason.UNSUPPORTED_VERSION, "This PHP branch has passed its security cutoff."
            )
        if platform is not None and not php_supply.qualified(
            release, platform.architecture, selected.php_version, selected.php_supply
        ):
            draft.refuse(
                Reason.UNSUPPORTED_VERSION,
                "This PHP branch, source and architecture have not completed native qualification.",
            )
    _source_evidence(draft, evidence)
    # An unsupported platform leads: evidence gaps on it are usually its consequence.
    check_platform(draft, platform)
    for gap in evidence.gaps:
        draft.refuse(Reason.INCOMPLETE, gap)
    if release is None:
        # Nothing else was read: no release policy applies to judge it by.
        return draft
    if action == Action.CLEAR_RESULTS:
        _review_cleanup(draft, evidence.units, current)
        return draft
    _check_apt(draft, release, evidence.apt, package_plan=action != Action.METADATA_REFRESH)
    if action == Action.METADATA_REFRESH:
        if draft.eligible and evidence.apt is not None:
            _refresh_effects(draft, release, evidence.apt)
        return draft
    _check_profile(
        draft,
        profiles.profile(release, action, version=version, supply=supply),
        evidence,
        tree_rules,
    )
    return draft


def _source_evidence(draft: Draft, evidence: Evidence) -> None:
    if evidence.php_source is not None:
        draft.php_source_admitted = evidence.php_source.admitted
        for refusal in evidence.php_source.refusals:
            draft.refuse(Reason.PACKAGE_SOURCE, refusal)
        if evidence.php_source.digest:
            draft.evidence.append(
                EvidenceDraft(
                    PlanEvidence.Kind.PHP_SOURCE_REVALIDATION,
                    evidence.php_source.digest,
                    "Approved PHP source, signing key, selection and index authentication.",
                )
            )


def _intent(action: Action, release: Release | None) -> str:
    match action:
        case Action.METADATA_REFRESH:
            return profiles.METADATA_REFRESH_INTENT
        case Action.CLEAR_RESULTS:
            return profiles.CLEAR_RESULTS_INTENT
        case _ if release is not None:
            return profiles.profile(release, action).intent
        case Action.NGINX:
            return "Install the distribution-default Nginx web server from Ubuntu packages."
        case Action.MARIADB:
            return "Install the distribution MariaDB server from Ubuntu packages."
        case _:
            return "Install the distribution-default PHP FPM and CLI from Ubuntu packages."


# Platform and privilege -----------------------------------------------------------------


def check_platform(draft: Draft, platform: Platform | None) -> None:
    if platform is None:
        draft.refuse(Reason.INCOMPLETE, "Barectl could not establish the server's platform.")
        return
    os = platform.os
    if draft.release is None:
        name = os.pretty_name or "an operating system Barectl could not identify"
        draft.refuse(
            Reason.UNSUPPORTED_PLATFORM,
            f"The server runs {name}. Bootstrap supports {releases.named()} only.",
        )
    else:
        _check_tools(draft, draft.release, platform)
    if not platform.systemd:
        draft.refuse(
            Reason.UNSUPPORTED_PLATFORM,
            "systemd is not the running system manager. Bootstrap needs systemd.",
        )
    if platform.architecture and platform.architecture not in releases.ARCHITECTURES:
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
        [platform.privilege, str(platform.listener_privilege), str(platform.listener_port)],
        _privilege_summary(platform),
    )


def _check_tools(draft: Draft, release: Release, platform: Platform) -> None:
    """Refuse an APT or systemd outside the series the release was qualified with."""
    for package, series in (("apt", release.apt), ("systemd", release.systemd)):
        version = platform.tools.get(package)
        if version is None or release.qualifies(package, version):
            continue
        draft.refuse(
            Reason.UNSUPPORTED_PLATFORM,
            f"The server has {package} {version}. On {release.name}, bootstrap is qualified "
            f"with {package} {series} only, whose behaviour package admission and native "
            "execution rely on. Install the release's own package through ordinary "
            "maintenance, then prepare again.",
        )


def _privilege_summary(platform: Platform) -> str:
    match platform.privilege:
        case Privilege.ROOT:
            return "The SSH user is root."
        case Privilege.SUDO:
            listeners = (
                f" and the listener query on port {platform.listener_port}"
                if platform.listener_privilege
                else ""
            )
            return f"Noninteractive sudo is authorized for {profiles.APPLY_ENTRYPOINT}{listeners}."
        case Privilege.UNAVAILABLE:
            return "Neither root nor noninteractive sudo is available."


# APT --------------------------------------------------------------------------------------


def _check_apt(
    draft: Draft, release: Release, apt: AptEvidence | None, *, package_plan: bool
) -> None:
    if apt is None:
        draft.refuse(
            Reason.INCOMPLETE,
            "Without the APT evidence Barectl could not read, it cannot review the package "
            "sources, hooks and APT configuration.",
        )
        return
    hooks = _check_hooks(draft, release, apt)
    _check_options(draft, apt)
    for path in apt.source_overrides:
        if path == php_supply.SOURCE_FILE and draft.php_source_admitted:
            continue
        draft.refuse(
            Reason.PACKAGE_SOURCE,
            f"{path} sets a repository option that disables or weakens authentication, such "
            "as trusted=yes. Bootstrap uses authenticated sources only.",
        )
    if not package_plan and not apt.sources:
        draft.refuse(Reason.APT_CONFIGURATION, "APT has no package sources configured.")
    if package_plan:
        _check_source_media(draft, apt)
        _check_third_party_authentication(draft, release, apt)
    sources = [f"{f.path} {f.digest}" for f in apt.files if _is_source(f)]
    sources += ["|".join(source) for source in apt.sources]
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
    source_files = sum(1 for f in apt.files if _is_source(f))
    draft.fingerprint(
        EvidenceKind.APT_SOURCES,
        sources,
        f"{source_files} source files configuring {len(apt.sources)} package indexes.",
    )
    draft.fingerprint(
        EvidenceKind.APT_PREFERENCES, preferences, f"{len(preferences)} preference files."
    )
    if apt.changed_while_read:
        draft.refuse(
            Reason.INCOMPLETE,
            "The APT configuration changed while Barectl read it. Prepare again once it is "
            "settled.",
        )
    elif not apt.digest:
        draft.refuse(
            Reason.INCOMPLETE,
            "Barectl could not compute the APT digest that applying rechecks on the server.",
        )
    else:
        # Kept as read: the apply payload compares the server's own digest with it.
        draft.evidence.append(
            EvidenceDraft(
                EvidenceKind.APT_REVALIDATION,
                apt.digest,
                "Effective APT configuration, files under /etc/apt and configured sources, "
                "rechecked on the server under the mutation lock before applying.",
            )
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


def _check_source_media(draft: Draft, apt: AptEvidence) -> None:
    """docs/adr/0007-admit-exact-package-transactions-with-an-inline-apt-guard.md#installation"""
    local = sorted(
        {source.site for source in apt.sources if source.site.split(":", 1)[0] not in _NETWORK}
    )
    if local:
        draft.refuse(
            Reason.PACKAGE_SOURCE,
            f"APT is configured with removable media or local sources ({', '.join(local)}). "
            "Bootstrap installs only packages downloaded from network archives; remove these "
            "sources through ordinary administration, then prepare again.",
        )


_NETWORK = frozenset({"http", "https"})


def _check_third_party_authentication(draft: Draft, release: Release, apt: AptEvidence) -> None:
    unauthenticated = _grouped(
        target for target in apt.targets if not target.trusted and not release.owns(target)
    )
    if unauthenticated:
        draft.refuse(
            Reason.PACKAGE_SOURCE,
            f"APT has unauthenticated package indexes from {', '.join(unauthenticated)}. "
            "Bootstrap installs only while every source is authenticated; sign the source or "
            "remove it through ordinary administration, then prepare again.",
        )


def _third_party(release: Release, apt: AptEvidence) -> list[str]:
    """The downloaded indexes that are not the release's own archive, grouped by source."""
    return _grouped(target for target in apt.targets if not release.owns(target))


def _grouped(targets: Iterable[IndexTarget]) -> list[str]:
    return _named_sources(
        ConfiguredSource(target.site, target.release, target.component) for target in targets
    )


def _named_sources(sources: Iterable[ConfiguredSource]) -> list[str]:
    components: dict[tuple[str, str], set[str]] = {}
    for source in sources:
        components.setdefault((source.site, source.suite), set()).add(source.component)
    return [
        f"{site} {suite} ({', '.join(sorted(names))})"
        for (site, suite), names in sorted(components.items())
    ]


def _is_source(digest: FileDigest) -> bool:
    return digest.path.startswith("/etc/apt/sources.list")


def _is_preference(digest: FileDigest) -> bool:
    return digest.path.startswith("/etc/apt/preferences")


def _check_hooks(draft: Draft, release: Release, apt: AptEvidence) -> dict[tuple[str, str], str]:
    """Refuse unknown hooks; return the admitted ones with the package installing each."""
    admitted: dict[tuple[str, str], str] = {}
    for entry in apt.config:
        if not profiles.HOOK_KEY.search(entry.name) or not entry.value:
            continue
        owner = release.hooks.get((entry.name, entry.value))
        if owner is None:
            draft.refuse(
                Reason.APT_HOOK,
                f"The APT configuration sets {entry.key.removesuffix('::')} to a command "
                f"Barectl has not qualified on {release.name}. Hooks run as root during "
                "package changes; remove it, or restore the distribution's hook, then prepare "
                "again.",
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


def _check_indexes(
    draft: Draft, release: Release, apt: AptEvidence, components: tuple[str, ...]
) -> None:
    architecture = draft.platform.architecture if draft.platform else ""
    for suite in release.suites:
        for component in components:
            found = any(
                target.origin == "Ubuntu"
                and target.codename == release.codename
                and target.suite == suite
                and target.component == component
                and target.architecture == architecture
                and target.trusted
                for target in apt.targets
            )
            if not found:
                draft.refuse(
                    Reason.PACKAGE_METADATA,
                    f"No authenticated Ubuntu package index for {suite} {component} is "
                    "available. Refresh the package metadata, with a reviewed metadata refresh "
                    "or ordinary administration, then prepare again.",
                )
    validity = apt.validity
    if validity is None:
        # Reading it failed, which is already a refusal for incomplete evidence.
        return
    for file in validity.releases:
        until = file.valid_until
        if until is None or until > validity.now:
            continue
        if file.origin == "Ubuntu" and file.suite in release.suites:
            draft.refuse(
                Reason.PACKAGE_METADATA,
                f"The Ubuntu Release file for {file.suite} expired at "
                f"{until.astimezone(UTC):%Y-%m-%d %H:%M} UTC by the server's clock, so its "
                "indexes are not current evidence. Refresh the package metadata, with a "
                "reviewed metadata refresh or ordinary administration, then prepare again.",
            )


def _refresh_effects(draft: Draft, release: Release, apt: AptEvidence) -> None:
    sites = sorted({source.site for source in apt.sources if source.site})
    downloaded = {(t.site, t.release, t.component) for t in apt.targets}
    pending = _named_sources(
        source
        for source in apt.sources
        if (source.site, source.suite, source.component) not in downloaded
    )
    later = (
        f" APT has no indexes of {'; '.join(pending)} yet; package plans identify them by "
        "their Release files after the update."
        if pending
        else ""
    )
    draft.effects.append(
        (
            Effect.INDEX_UPDATE,
            (
                f"apt-get update downloads the package indexes of the configured sources "
                f"({', '.join(sites)}) and accepts only authenticated indexes. No package is "
                f"installed, upgraded or removed.{later}"
            ),
        )
    )
    third_party = _third_party(release, apt)
    if third_party:
        draft.effects.append(
            (
                Effect.THIRD_PARTY_SOURCES,
                (
                    f"The update also covers sources other than {release.name}'s own archive: "
                    f"{'; '.join(third_party)}. Each must authenticate and update without "
                    "errors, or the refresh fails. A package plan is refused while any of them "
                    "offers one of its packages."
                ),
            )
        )
    owners = sorted(
        {
            owner
            for (name, value), owner in release.hooks.items()
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
            f"The {_suites(release)} indexes are authenticated Ubuntu indexes.",
            "No package is installed, upgraded or removed.",
        ]
    )


def _suites(release: Release) -> str:
    first, updates, security = release.suites
    return f"{first}, {updates} and {security}"


# Clearing finished runs ---------------------------------------------------------------


def _review_cleanup(
    draft: Draft, units: tuple[native.UnitEvidence, ...] | None, current: frozenset[str]
) -> None:
    """docs/ssh-connections.md#clearing-finished-bootstrap-runs"""
    if units is None:
        draft.refuse(Reason.INCOMPLETE, "Barectl could not read the retained bootstrap units.")
        return
    draft.fingerprint(
        EvidenceKind.RETAINED_UNITS,
        sorted(
            f"{unit.unit} {unit.invocation_id} {unit.active_state}/{unit.sub_state} "
            f"{unit.result} {unit.exec_main_status} {unit.populated}"
            for unit in units
        ),
        f"{len(units)} bootstrap units retained",
    )
    running = [unit for unit in units if not unit.terminal]
    ours = [unit for unit in units if unit.terminal and unit.unit in current]
    unidentified = [
        unit
        for unit in units
        if unit.terminal and unit.unit not in current and not unit.invocation_id
    ]
    finished = [
        unit for unit in units if unit.terminal and unit.unit not in current and unit.invocation_id
    ]
    draft.units = sorted(finished, key=lambda unit: unit.unit)[: native.CLEANUP_BATCH]
    left = len(finished) - len(draft.units)
    if not draft.units:
        draft.effects.append(
            (Effect.NO_CHANGES, "The server retains no finished bootstrap run to clear.")
        )
    else:
        exited = sum(1 for unit in draft.units if unit.active_state == "active")
        failed = len(draft.units) - exited
        draft.effects.append(
            (
                Effect.CLEAR_UNITS,
                (
                    f"Barectl clears {len(draft.units)} finished bootstrap runs from systemd: "
                    f"systemctl stop for {exited} successful units kept after exit, and "
                    f"systemctl reset-failed for {failed} others. Under the mutation lock it "
                    "first rechecks that each still shows the reviewed invocation, has finished "
                    "and has no processes, and clears none if any changed. Units already gone "
                    "are skipped."
                ),
            )
        )
        draft.effects.append(
            (
                Effect.NATIVE_EVIDENCE,
                (
                    "systemd forgets these units' states and exit results. Their journal "
                    "entries stay as long as the server's journal retention keeps them. Another "
                    "Barectl installation that still needs one of them to check a run's outcome "
                    "can then only close that run as outcome unknown. Barectl's own records of "
                    "its runs are kept."
                ),
            )
        )
    kept = []
    if running:
        kept.append(f"{len(running)} still running or with processes left")
    if ours:
        kept.append(f"{len(ours)} whose runs this installation is still establishing")
    if unidentified:
        kept.append(f"{len(unidentified)} without an invocation to recheck")
    if left:
        kept.append(f"{left} beyond the {native.CLEANUP_BATCH} one cleanup clears")
    if kept:
        draft.effects.append(
            (Effect.KEPT_UNITS, f"Left in place: {'; '.join(kept)}. Cleanup never stops them.")
        )
    if draft.units:
        draft.effects.append(
            (
                Effect.NO_ROLLBACK,
                (
                    "Clearing cannot be undone. The cleanup's own unit is kept as a finished "
                    "run that a later cleanup can clear."
                ),
            )
        )
        draft.postconditions.append("systemd retains none of the listed units.")


# Package profiles ---------------------------------------------------------------------


def _check_profile(
    draft: Draft, profile: Profile, evidence: Evidence, tree_rules: Mapping[str, TreeRule]
) -> None:
    packages, web = evidence.packages, evidence.web
    if packages is None or web is None:
        draft.refuse(Reason.INCOMPLETE, "Barectl could not read the package and service evidence.")
        return
    states = {state.name: state for state in packages.states}
    _check_php_supply(draft, evidence.apt, packages)
    missing = _check_roots(draft, profile, states)
    _check_package_health(draft, profile, packages, states)
    _check_prerequisites(draft, profile, packages, states)
    # Only an installation needs current indexes; a satisfied profile installs nothing.
    if missing and evidence.apt is not None and draft.release is not None:
        _check_indexes(draft, draft.release, evidence.apt, profile.components)
    if missing and packages.simulation is not None:
        _check_simulation(draft, profile, packages, missing)
        if evidence.apt is not None and draft.release is not None:
            _check_offers(draft, draft.release, evidence.apt, packages, profile.components)
    if profile.readiness and evidence.apt is not None and draft.release is not None:
        _check_installed_origin(draft, draft.release, evidence.apt, packages, profile.components)
    installed = {name for name, state in states.items() if state.installed}
    _check_releases(draft, profile, packages, web)
    _check_conflicts(draft, packages)
    starts = _check_units(draft, profile, web.units, installed)
    _check_trees(draft, profile, web, installed, tree_rules)
    if profile.modules:
        _check_modules(draft, profile, web, installed)
    serving = profile.service_package in installed
    _check_paths(draft, profile, web, installed=serving)
    _check_configuration(draft, profile, web, installed=serving)
    if profile.readiness and serving:
        _check_readiness(draft, profile, web)
    _check_exposure(
        draft, profile, web, complete=not missing, serving=profile.service_package in installed
    )
    _fingerprint_packages(draft, profile, packages)
    _fingerprint_web(draft, web)
    _revalidation(draft, evidence)
    if draft.eligible:
        _profile_effects(draft, profile, packages, starts)
        if draft.transitions and evidence.apt is not None and draft.release is not None:
            _third_party_effect(draft, draft.release, evidence.apt)


def _check_exposure(
    draft: Draft, profile: Profile, web: WebEvidence, *, complete: bool, serving: bool
) -> None:
    """The port and socket listeners. ``complete`` when no root package is missing, and
    ``serving`` when the first root, which provides the service, is installed."""
    running = any(
        unit.name == profile.serving_unit and unit.active_state == "active" for unit in web.units
    )
    listened: list[tuple[list[str], str]] = []
    if profile.port is not None:
        listened.append(
            _check_listeners(draft, profile, web.listeners or (), running=running and complete)
        )
    if profile.socket is not None:
        listened.append(
            _check_socket(draft, profile, profile.socket, web.sockets, serving=running and serving)
        )
    if listened:
        draft.fingerprint(
            EvidenceKind.LISTENERS,
            [line for lines, _ in listened for line in lines],
            " ".join(summary for _, summary in listened),
        )


def _revalidation(draft: Draft, evidence: Evidence) -> None:
    """Keep the package digest the apply payload recomputes, or refuse without it."""
    if evidence.package_changed_while_read:
        draft.refuse(
            Reason.INCOMPLETE,
            "Packages, services or configuration changed while Barectl read them. Prepare "
            "again once they are settled.",
        )
    elif not evidence.package_digest:
        draft.refuse(
            Reason.INCOMPLETE,
            "Barectl could not compute the package digest that applying rechecks on the server.",
        )
    else:
        # Kept as read: the apply payload compares the server's own digest with it.
        draft.evidence.append(
            EvidenceDraft(
                EvidenceKind.PACKAGE_REVALIDATION,
                evidence.package_digest,
                "dpkg's status, automatic marks, Release files, APT's simulation, service "
                "units, configuration and listeners, rechecked on the server under the "
                "mutation lock before applying.",
            )
        )


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
    release = draft.release
    allowed = release.origins if release is not None else frozenset()
    if (
        release is not None
        and draft.php_supply == "sury"
        and draft.php_source_admitted
        and name in php_supply.allowed_packages()
    ):
        allowed = frozenset({release.codename})
    if not transition.origins or not set(transition.origins) <= allowed:
        archives = ", ".join(transition.origins) or "an unidentified archive"
        own = f"{release.name} {_suites(release)}" if release else "server's own Ubuntu release"
        draft.refuse(
            Reason.PACKAGE_SOURCE,
            f"{name} {transition.version} would come from {archives}. Bootstrap installs "
            f"only from the {own} archives.",
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


def _check_offers(
    draft: Draft,
    release: Release,
    apt: AptEvidence,
    packages: PackageEvidence,
    components: tuple[str, ...],
) -> None:
    """docs/adr/0008-review-each-ubuntu-release-by-its-own-policy.md#hosting-providers-images"""
    targets = {(t.site, t.release, t.component, t.architecture): t for t in apt.targets}
    others: dict[str, list[str]] = {}
    owned: set[tuple[str, str]] = set()
    elsewhere: dict[tuple[str, str], set[str]] = {}
    suppliers = _offer_instances(apt, packages)
    for offer in packages.offers:
        target = targets.get((offer.site, offer.release, offer.component, offer.architecture))
        source_php = (
            draft.php_supply == "sury"
            and draft.php_source_admitted
            and offer.package in php_supply.allowed_packages()
        )
        if target is not None and _sury_target(draft, target) and source_php:
            owned.add((offer.package, offer.version))
            continue
        if target is not None and release.owns(target):
            if source_php:
                continue
            if offer.component in components:
                owned.add((offer.package, offer.version))
            else:
                elsewhere.setdefault((offer.package, offer.version), set()).add(offer.component)
            continue
        source = f"{offer.site} {offer.release}/{offer.component}"
        others.setdefault(source, []).append(f"{offer.package} {offer.version}")
    transitions = packages.simulation.transitions if packages.simulation else ()
    _check_ambiguities(
        draft,
        suppliers,
        {(t.package, t.version) for t in transitions if t.action == "Inst"},
    )
    for source, versions in sorted(others.items()):
        draft.refuse(
            Reason.PACKAGE_SOURCE,
            f"{source}, which Barectl does not identify as {release.name}'s own archive, "
            f"offers {_listed(versions)}; this plan installs these packages from "
            f"{release.name}'s archive. Bootstrap installs only while no other source offers "
            "any of the plan's packages, at any version, so that "
            "APT cannot take one from it. Remove or disable that source through ordinary "
            "administration, then prepare again.",
        )
    for transition in transitions:
        offered = (transition.package, transition.version)
        if transition.action != "Inst" or offered in owned:
            continue
        if offered in elsewhere:
            draft.refuse(
                Reason.PACKAGE_SOURCE,
                f"{release.name}'s archive offers {transition.package} {transition.version} "
                f"only from its {', '.join(sorted(elsewhere[offered]))} component; this profile "
                f"installs only from {' and '.join(components)}.",
            )
        else:
            draft.refuse(
                Reason.SIMULATION,
                f"APT does not list {transition.package} {transition.version} among the "
                f"versions {release.name}'s own archive offers. Check the package sources and "
                "indexes, then prepare again.",
            )


def _check_ambiguities(
    draft: Draft,
    suppliers: dict[tuple[str, str], set[str]],
    selected: set[tuple[str, str]],
) -> None:
    if draft.php_supply != "sury":
        return
    for (package, version), sources in suppliers.items():
        if (package, version) in selected and len(sources) > 1:
            draft.refuse(
                Reason.PACKAGE_SOURCE,
                f"{package} {version} is offered by multiple source instances. Exact-version "
                "source ambiguity prevents authenticated archive selection.",
            )


def _offer_instances(
    apt: AptEvidence, packages: PackageEvidence
) -> dict[tuple[str, str], set[str]]:
    targets = {(t.site, t.release, t.component, t.architecture) for t in apt.targets}
    instances: dict[tuple[str, str], set[str]] = {}
    for offer in packages.offers:
        if offer[2:] in targets:
            instances.setdefault((offer.package, offer.version), set()).add("|".join(offer[2:]))
    return instances


def _check_php_supply(draft: Draft, apt: AptEvidence | None, packages: PackageEvidence) -> None:
    if draft.php_supply != "sury" or apt is None:
        return
    targets = {(t.site, t.release, t.component, t.architecture): t for t in apt.targets}
    own = {
        (offer.package, offer.version)
        for offer in packages.offers
        if (target := targets.get((offer.site, offer.release, offer.component, offer.architecture)))
        is not None
        and _sury_target(draft, target)
    }
    for state in packages.states:
        if not state.name.startswith("php") or state.absent:
            continue
        if (
            not state.installed
            or state.name not in php_supply.allowed_packages()
            or (state.name, state.version) not in own
        ):
            draft.refuse(
                Reason.PACKAGE_SOURCE,
                f"Installed or residual {state.name} cannot be authenticated as an exact "
                "approved PHP-supply package. Bootstrap never converts an existing PHP supply.",
            )
    _check_ambiguities(
        draft,
        _offer_instances(apt, packages),
        {(state.name, state.version) for state in packages.states if state.installed},
    )


def _sury_target(draft: Draft, target: IndexTarget) -> bool:
    release, platform = draft.release, draft.platform
    return (
        draft.php_source_admitted
        and release is not None
        and platform is not None
        and target.site == php_supply.SOURCE_URL.rstrip("/")
        and target.origin == "deb.sury.org"
        and target.suite == target.codename == target.release == release.codename
        and target.component == "main"
        and target.architecture in {platform.architecture, "all"}
        and target.trusted
    )


def _check_installed_origin(
    draft: Draft,
    release: Release,
    apt: AptEvidence,
    packages: PackageEvidence,
    components: tuple[str, ...],
) -> None:
    """docs/bootstrap.md#mariadb: an established database engine is the release's own."""
    targets = {(t.site, t.release, t.component, t.architecture): t for t in apt.targets}
    owned = {
        (offer.package, offer.version)
        for offer in packages.offers
        if offer.component in components
        and (
            target := targets.get((offer.site, offer.release, offer.component, offer.architecture))
        )
        is not None
        and release.owns(target)
    }
    for root in draft.roots:
        if not root.installed or (root.name, root.version) in owned:
            continue
        # docs/bootstrap.md#mariadb: a superseded update of the release's own.
        newer = [
            version
            for package, version in owned
            if "ubuntu" in root.version
            and package == root.name
            and compare(version, root.version) > 0
        ]
        if newer:
            draft.refuse(
                Reason.PACKAGE_SOURCE,
                f"{root.name} {root.version} is installed, but it is no longer offered by "
                f"{release.name}'s archive, which offers "
                f"{max(newer, key=cmp_to_key(compare))}. Upgrade it with ordinary "
                f"administration, such as sudo apt-get install --only-upgrade {root.name}, "
                "then prepare again.",
            )
        else:
            draft.refuse(
                Reason.PACKAGE_SOURCE,
                f"{root.name} {root.version} is installed, but {release.name}'s own archive "
                f"does not offer that version from its {' or '.join(components)} component, "
                "so it may come from another repository, such as the upstream project's. "
                "Bootstrap does not adopt a database engine from another archive; its "
                "versions follow other rules than the release's.",
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
        if profile.service_package not in installed:
            _check_absent_unit(draft, unit)
            continue
        problem = _unit_problem(unit, profile.drop_ins, managed=profile.managed_units)
        if problem:
            draft.refuse(Reason.SERVICE_UNIT, f"{unit.name} {problem}")
            continue
        if not profile.managed_units:
            continue
        stopped = unit.unit_file_state == "disabled" or unit.active_state == "inactive"
        if stopped and not profile.startable:
            draft.refuse(
                Reason.SERVICE_UNIT,
                f"{unit.name} is not active and enabled ({unit.active_state}, "
                f"{unit.unit_file_state}). {profile.stopped}",
            )
            continue
        if unit.unit_file_state == "disabled":
            effects.append(Effect.SERVICE_ENABLE)
        if unit.active_state == "inactive":
            effects.append(Effect.SERVICE_START)
    return effects


def _unit_problem(
    unit: UnitState, drop_ins: frozenset[str] = frozenset(), *, managed: bool = True
) -> str:
    """Why an installed profile's unit is not the distribution's healthy unit, if it is not.

    ``drop_ins`` are those another action verifies; an unmanaged unit may also be static.
    """
    if unit.load_state == "masked":
        return "is masked. Unmask it through ordinary administration, then prepare again."
    if unit.load_state != "loaded":
        return f"is not loaded (systemd reports {unit.load_state or 'nothing'})."
    foreign = [path for path in unit.drop_in_paths if path not in drop_ins]
    if foreign:
        return (
            f"has drop-in overrides ({', '.join(foreign[:_LISTED_PATHS])}). "
            "Bootstrap supports only the distribution's unit."
        )
    if unit.fragment_path != unit_file(unit.name):
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
    if unit.unit_file_state not in enablements(unit.name) | (
        frozenset({"static"}) if not managed else frozenset()
    ):
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


def _check_trees(
    draft: Draft,
    profile: Profile,
    web: WebEvidence,
    installed: set[str],
    rules: Mapping[str, TreeRule],
) -> None:
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
        if spec.rule:
            rule = rules.get(spec.rule)
            if rule is None:
                draft.refuse(
                    Reason.INCOMPLETE,
                    f"Barectl has no rule to judge {spec.root} by, so it cannot review it.",
                )
            else:
                rule(draft, spec, tree)
            continue
        _verify_tree(draft, spec, tree, web, installed)


def _check_prerequisites(
    draft: Draft, profile: Profile, packages: PackageEvidence, states: dict[str, PackageState]
) -> None:
    """The packages the profile builds on, installed at a version the root is offered at."""
    if packages.unpinned and profile.pinned is not None:
        _refuse_unpinned(draft, profile.pinned, packages.unpinned)
    missing = [
        name for name in profile.prerequisites if name not in states or not states[name].installed
    ]
    if missing:
        draft.refuse(Reason.PREREQUISITE, profile.prerequisite)


def _refuse_unpinned(draft: Draft, pinned: tuple[tuple[str, ...], str], version: str) -> None:
    """docs/databases.md#installed-php-versions"""
    roots, package = pinned
    release = draft.release.name if draft.release else "the release"
    prefix = package.removesuffix("common")
    upgrade = (
        f"Upgrade PHP through ordinary administration, such as sudo apt-get install "
        f"--only-upgrade {prefix}common {prefix}cli {prefix}fpm, then prepare again."
    )
    if len(roots) == 1:
        draft.refuse(
            Reason.INSTALLED_PACKAGE_CHANGE,
            f"{package} {version} is installed, and {roots[0]} depends on exactly that "
            f"version, but no configured source offers {roots[0]} {version}: {release}'s "
            "archive keeps only its newest updates. Installing it would upgrade PHP, which a "
            f"driver plan never does. {upgrade}",
        )
        return
    draft.refuse(
        Reason.INSTALLED_PACKAGE_CHANGE,
        f"{package} {version} is installed, and {', '.join(roots)} depend on exactly that "
        f"version, but no configured source offers all of them at {version}: {release}'s "
        f"archive keeps only its newest updates. Installing them would upgrade PHP, which an "
        f"extension plan never does. {upgrade}",
    )


def _check_modules(draft: Draft, profile: Profile, web: WebEvidence, installed: set[str]) -> None:
    """The modules of the installed roots are linked from every SAPI and loaded by PHP-FPM and
    the CLI, and the build loads the profile's built-ins (docs/wordpress.md#php-runtime)."""
    owners = profile.module_roots or (profile.roots[0],) * len(profile.modules)
    pairs = list(zip(profile.modules, owners, strict=True))
    enabled = [module for module, owner in pairs if owner in installed]
    packages = sorted({owner for _, owner in pairs if owner in installed})
    links = {
        entry.path: entry.target
        for tree in web.trees
        for entry in tree.entries
        if entry.kind == "l"
    }
    mods = next(spec.root for spec in profile.trees if spec.root.endswith("/mods-available"))
    sapis = [spec.root for spec in profile.trees if not spec.root.endswith("/mods-available")]
    unlinked = [
        f"{sapi}/conf.d/{link}.ini"
        for sapi in sapis
        for link, module in enabled
        if links.get(f"{sapi}/conf.d/{link}.ini") != f"{mods}/{module}.ini"
    ]
    loaded = {line.strip().casefold() for line in web.modules.splitlines()}
    cli = {line.strip().casefold() for line in web.cli_modules.splitlines()}
    unloaded = [
        f"{module} (not loaded)" for _, module in enabled if module.casefold() not in loaded
    ]
    if profile.cli_module_list:
        unloaded += [
            f"{module} (not loaded by the CLI)"
            for _, module in enabled
            if module.casefold() not in cli
        ]
    if unlinked or unloaded:
        modules = " ".join(module for _, module in enabled)
        plural = len(packages) > 1
        draft.refuse(
            Reason.CUSTOMIZED,
            f"{', '.join(packages)} {'are' if plural else 'is'} installed, but "
            f"{'their' if plural else 'its'} modules are not enabled as the package enables "
            f"them: {_listed([*unlinked, *unloaded])}. Enable them through ordinary "
            f"administration, such as sudo phpenmod {modules}, then prepare again.",
        )
    absent = [
        f"{module} ({where})"
        for module in profile.builtins
        for where, listed in (("PHP-FPM", loaded), ("the CLI", cli))
        if module.casefold() not in listed
    ]
    if absent:
        draft.refuse(
            Reason.CUSTOMIZED,
            f"PHP {profile.php_version} does not load {_listed(absent)}. These capabilities "
            "come from the PHP build and php-common, which an extension plan never installs "
            "or repairs. Restore them through ordinary administration, then prepare again.",
        )


def _verify_tree(
    draft: Draft, spec: TreeSpec, tree: ConfigTree, web: WebEvidence, installed: set[str]
) -> None:
    """Every entry is an unmodified distribution file, a default link, or a directory."""
    under = f"{spec.root}/"
    conffiles = {
        item.path: item.md5
        for item in web.conffiles
        if not item.obsolete and item.path.startswith(under)
    }
    defaults = dict(conffiles)
    defaults.update({path: md5 for path, md5 in web.ucf.items() if path.startswith(under)})
    generated = {
        path: md5 for path, (package, md5) in spec.generated.items() if package in installed
    }
    customized: list[str] = []
    unreadable: list[str] = []
    for entry in tree.entries:
        problem = _entry_problem(entry, spec, tree, defaults, generated)
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
    entry: TreeEntry,
    spec: TreeSpec,
    tree: ConfigTree,
    defaults: dict[str, str],
    generated: dict[str, str | None],
) -> str:
    """Why an entry is not part of the distribution's configuration; empty when it is."""
    if entry.kind == "d":
        return ""
    if entry.kind == "l":
        return "" if spec.links(entry.path, entry.target) else "a link Barectl does not recognize"
    if entry.kind != "f":
        return "a special file"
    digest = tree.digests.get(entry.path)
    if entry.path in generated:
        # Only root may read some; contents are compared when readable and known.
        expected = generated[entry.path]
        if digest is not None and expected is not None and digest != expected:
            return "changed from what the package's maintainer script writes"
        return ""
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
) -> tuple[list[str], str]:
    """Refuse other services on the port; return the listeners' evidence and summary."""
    others = [
        listener
        for listener in listeners
        if not running
        or (listener.processes is not None and set(listener.processes) != {profile.process})
    ]
    if others:
        addresses = ", ".join(listener.address for listener in others)
        draft.refuse(
            Reason.LISTENER,
            f"Another service listens on port {profile.port} ({addresses}), so {profile.serves} "
            "could not start. Stop or reconfigure it, then prepare again.",
        )
    elif running and profile.exclusive:
        found = {listener.address for listener in listeners}
        if not found or not found <= profile.addresses:
            draft.refuse(
                Reason.LISTENER,
                f"{profile.serves_capitalized} listens on port "
                f"{profile.port} at {', '.join(sorted(found)) or 'no address'}, not only at "
                f"{' or '.join(sorted(profile.addresses))} as the distribution's configuration "
                "binds it. Bootstrap supports only the distribution's local listener; restore "
                "it through ordinary administration, then prepare again.",
            )
    attributed = all(listener.processes is not None for listener in listeners)
    owners = sorted({name for item in listeners for name in item.processes or ()})
    summary = (
        f"No listener on port {profile.port}."
        if not listeners
        else f"{len(listeners)} listeners on port {profile.port}"
        + (f" ({', '.join(owners)})." if attributed and owners else ", owners not attributed.")
    )
    return [f"{item.address} {','.join(item.processes or ())}" for item in listeners], summary


def _check_releases(
    draft: Draft, profile: Profile, packages: PackageEvidence, web: WebEvidence
) -> None:
    """Refuse the software's other releases, and entries beside the profile's directories."""
    releases = profile.releases
    if releases is None:
        return
    others = [
        f"{state.name} ({'configuration files left' if state.status[1] == 'c' else state.status})"
        if not state.installed
        else f"{state.name} {state.version}"
        for state in sorted(packages.releases)
    ]
    if others:
        draft.refuse(
            Reason.UNSUPPORTED_VERSION,
            f"Packages of another release are on the server: {_listed(others)}. This profile "
            f"supports only {releases.name} and does not install beside another release; "
            "remove or purge them through ordinary administration, then prepare again.",
        )
    for directory, allowed in profile.layout.items():
        extra = sorted(set(web.layout.get(directory, ())) - allowed)
        if not extra:
            continue
        paths = _listed([f"{directory}/{name}" for name in extra])
        if directory == releases.directory:
            draft.refuse(
                Reason.UNSUPPORTED_VERSION,
                f"{directory} holds configuration besides {releases.name}'s: {paths}. This "
                f"profile supports only {releases.name}; remove other releases' configuration "
                "through ordinary administration, then prepare again.",
            )
        else:
            draft.refuse(
                Reason.CUSTOMIZED,
                f"{directory} holds entries that are not part of the profile: {paths}, such as "
                f"{releases.example}. Bootstrap does not adopt or overwrite "
                "custom configuration.",
            )


def _check_socket(
    draft: Draft, profile: Profile, socket: str, sockets: tuple[str, ...], *, serving: bool
) -> tuple[list[str], str]:
    """The service's socket: only the running service listens there, and it does. Return
    the socket's evidence and summary."""
    unit = profile.serving_unit
    listening = socket in sockets
    if listening and not serving:
        draft.refuse(
            Reason.LISTENER,
            f"Another process listens on {socket}, where {profile.serves} listens, while "
            f"{unit} is not running. Stop or reconfigure it, then prepare again.",
        )
    elif serving and not listening:
        draft.refuse(
            Reason.LISTENER,
            f"{unit} is active, but nothing listens on {socket}, where {profile.serves} "
            "listens. Inspect it with systemctl status and journalctl, then prepare again.",
        )
    return sorted(sockets), (
        f"A local socket listens on {socket}." if listening else f"Nothing listens on {socket}."
    )


def _package_text(state: PackageState) -> str:
    if state.installed:
        return f"{state.name} {state.version}"
    left = "configuration files left" if state.status[1] == "c" else f"dpkg state {state.status}"
    return f"{state.name} ({left})"


def _check_conflicts(draft: Draft, packages: PackageEvidence) -> None:
    """docs/bootstrap.md#mariadb"""
    found = [_package_text(state) for state in sorted(packages.conflicts)]
    if found:
        draft.refuse(
            Reason.CONFLICT,
            f"Another database server's packages are on the server: {_listed(found)}. "
            "Bootstrap never installs beside, replaces, migrates or removes an existing "
            "database installation; remove or purge it through ordinary administration, "
            "keeping any data you need, then prepare again.",
        )


def _check_paths(draft: Draft, profile: Profile, web: WebEvidence, *, installed: bool) -> None:
    """docs/bootstrap.md#mariadb: data an installation would not account for."""
    spec = profile.data
    unaccounted = [path for path in profile.forbidden if web.data.get(path)]
    if spec is not None and not installed:
        unaccounted += [path for path in (spec.directory, *spec.remnants) if web.data.get(path)]
    for directory, allowed in spec.listings if spec is not None else ():
        unaccounted += [
            f"{directory}/{name}"
            for name in sorted(set(web.layout.get(directory, ())) - allowed)
            if not name.startswith(".")
        ]
    if unaccounted:
        draft.refuse(
            Reason.LEFTOVER,
            "Data or option files exist that the installed packages do not account for: "
            f"{_listed(unaccounted)}. Bootstrap never adopts, erases or migrates database "
            "data or configuration; move or remove them through ordinary administration, "
            "keeping any data you need, then prepare again.",
        )
    if not profile.paths:
        return
    draft.fingerprint(
        EvidenceKind.DATA_PATHS,
        [f"{path} {kind}" for path, kind in sorted(web.data.items())],
        f"{sum(1 for kind in web.data.values() if kind)} of {len(web.data)} paths exist.",
    )
    if spec is None or not installed:
        return
    expected = {
        spec.directory: f"directory {spec.owner}",
        spec.marker: f"{spec.marker_type} {spec.owner}",
    }
    if any(web.data.get(path) != kind for path, kind in expected.items()):
        draft.refuse(
            Reason.CUSTOMIZED,
            f"{spec.directory} is not the initialized data directory the distribution's "
            f"package creates: a directory owned by {spec.owner} holding {spec.marker}. "
            "Bootstrap does not initialize, repair or adopt a data directory; repair it "
            "through ordinary administration, then prepare again.",
        )


def _check_configuration(
    draft: Draft, profile: Profile, web: WebEvidence, *, installed: bool
) -> None:
    """docs/bootstrap.md#mariadb: the option files the server actually reads."""
    wanted = profile.alternative
    if wanted is not None:
        found = web.alternative
        if installed and web.resolved != wanted.value:
            draft.refuse(
                Reason.CUSTOMIZED,
                f"{wanted.link} resolves to {web.resolved or 'nothing'}, not "
                f"{wanted.value}, so the server does not read the distribution's "
                f"configuration. Restore the {wanted.name} alternative with "
                f"update-alternatives --auto {wanted.name}, then prepare again.",
            )
        elif not installed and found is not None and found.status != "auto":
            draft.refuse(
                Reason.CUSTOMIZED,
                f"The {wanted.name} alternative is set manually to {found.value}. Bootstrap "
                f"installs only while it is absent or automatic; run update-alternatives "
                f"--auto {wanted.name} through ordinary administration, then prepare again.",
            )
    defaults = profile.defaults
    if defaults is not None and installed and web.defaults != defaults.expected:
        draft.refuse(
            Reason.CUSTOMIZED,
            f"{defaults.command} does not report the distribution's options, so an option "
            "file the review does not recognize changes the server. Restore the "
            "distribution's configuration through ordinary administration, then prepare again.",
        )


def _check_readiness(draft: Draft, profile: Profile, web: WebEvidence) -> None:
    """docs/bootstrap.md#mariadb: an installed engine is established only when its
    administrative check, run with privilege, shows the distribution's form."""
    readiness = web.readiness
    command = profile.check.command
    draft.fingerprint(
        EvidenceKind.ADMINISTRATION,
        [readiness.state, str(readiness.exit_status), readiness.output],
        {
            "read": "The administrative check ran with privilege.",
            "stopped": "The service does not run; applying checks administration.",
            "unprivileged": "The administrative check could not run with privilege.",
        }.get(readiness.state, "Unknown"),
    )
    if readiness.state == "unprivileged":
        draft.refuse(
            Reason.ADMINISTRATION,
            f"{profile.serves_capitalized} is installed, but its administrative socket "
            "readiness is unverified: the SSH user is not root, and sudo -n -l does not "
            f"authorize {command} without a password. Run the review as root, or authorize "
            "that exact read-only command, then prepare again.",
        )
    elif readiness.state == "read" and (
        readiness.exit_status != 0 or readiness.output != profile.check.expected
    ):
        draft.refuse(Reason.ADMINISTRATION, profile.readiness_failure)


def _fingerprint_packages(draft: Draft, profile: Profile, packages: PackageEvidence) -> None:
    states = sorted(packages.states)
    relevant = {state.name for state in states}
    draft.fingerprint(
        EvidenceKind.DPKG_STATUS,
        [
            packages.audit,
            *("\t".join(state) for state in states),
            *("\t".join(state) for state in sorted(packages.releases)),
        ],
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
                *(
                    "|".join((t.action, t.package, t.previous, t.version, t.architecture))
                    + "|".join(("", *t.origins))
                    for t in packages.simulation.transitions
                ),
                *("|".join(offer) for offer in packages.offers),
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
    lines += [
        f"{directory} {name}" for directory, names in sorted(web.layout.items()) for name in names
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
    unit = profile.units[0] if profile.units else ""
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
        if profile.exposure is not None:
            draft.effects.append(profile.exposure)
    draft.postconditions.extend(profile.postconditions)


def _install_effects(draft: Draft, profile: Profile, unit: str, *, needrestart: bool) -> None:
    release = draft.release.name if draft.release else "Ubuntu"
    installs = [t for t in draft.transitions if t.step == PackageTransition.Step.INSTALL]
    roots = ", ".join(root.name for root in draft.roots if not root.installed)
    archives = profile.archives or f"{release} archives"
    draft.effects.append(
        (
            Effect.PACKAGES,
            (
                f"Installs {len(installs)} packages at the exact versions listed, from the "
                f"{archives}. Barectl names only {roots} to APT, at the reviewed versions, "
                "so APT marks only those as manually installed and the other new packages as "
                "automatically installed; packages installed before keep their marks. No "
                "recommended or suggested package is added, and APT keeps the downloaded "
                "archives in /var/cache/apt/archives."
            ),
        )
    )
    draft.effects.append(
        (
            Effect.PACKAGE_GUARD,
            (
                "After APT downloads the archives, debconf preconfigures them from their "
                "templates, as the distribution's hook does on every installation. Then, "
                "under APT's dpkg lock and before dpkg changes any package, Barectl's inline "
                "guard compares APT's actual actions with the list above and stops the "
                "installation if anything differs. It cannot undo what debconf recorded."
            ),
        )
    )
    draft.effects.append(
        (Effect.SERVICE_INHIBITION, profile.maintainer_start)
        if profile.maintainer_start
        else (
            Effect.MAINTAINER_START,
            profile.maintainer
            or (
                f"The package maintainer scripts enable and start {unit} while dpkg runs, before "
                "Barectl validates the result."
            ),
        )
    )
    if profile.data is not None:
        draft.effects.append((Effect.DATA_DIRECTORY, profile.data.effect))
    if profile.exposure is not None:
        draft.effects.append(profile.exposure)
    if needrestart:
        draft.effects.append(
            (
                Effect.NEEDRESTART,
                (
                    f"needrestart runs after dpkg. With {release}'s default configuration it "
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
    draft.postconditions.extend(profile.postconditions)
    draft.postconditions.append(
        "Packages installed before keep their automatic or manual installation marks."
    )


def _third_party_effect(draft: Draft, release: Release, apt: AptEvidence) -> None:
    sources = _third_party(release, apt)
    if not sources:
        return
    draft.effects.append(
        (
            Effect.THIRD_PARTY_SOURCES,
            (
                f"APT also has package indexes from sources other than {release.name}'s own "
                f"archive: {'; '.join(sources)}. None of them offers any package of this plan, "
                "at any version."
            ),
        )
    )
