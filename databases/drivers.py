"""PHP database driver plans (docs/databases.md#php-database-drivers).

A driver is a bootstrap package profile whose PHP-FPM tree may hold Barectl's site pools:
bootstrap reviews and applies the package transaction, and this module supplies the site
grammar that judges that tree and the pools a reload restarts.
"""

import dataclasses
from dataclasses import dataclass

from bootstrap import inspection as bootstrap_inspection
from bootstrap import profiles, releases
from bootstrap.apply import EVIDENCE_FAILURE, current_units
from bootstrap.evidence import ConfigTree
from bootstrap.models import (
    Action,
    ConfigurationPlan,
    PlanEffect,
    PlanEvidence,
    PlanRefusal,
    Privilege,
)
from bootstrap.profiles import SITE_CONVENTION, TreeSpec
from bootstrap.review import Draft, EvidenceDraft
from bootstrap.review import review as bootstrap_review
from discovery.ssh import RemoteShell
from operations.lifecycle import OperationRefused
from sites import inspection as site_inspection
from sites import native as site_native
from sites.admission import complete, recognize_trees
from sites.convention import SitePaths
from sites.inspection import SiteEvidence

Reason = PlanRefusal.Reason
Effect = PlanEffect.Kind
_LISTED = 5


@dataclass(frozen=True)
class Pool:
    name: str
    user: str
    socket: str
    default: bool


@dataclass
class DriverDraft(Draft):
    # Every pool the reload restarts, the distribution's first.
    pools: tuple[Pool, ...] = ()
    # The selected site, when the plan is for one: its account IDs, convention revision.
    site_uid: int = 0
    site_gid: int = 0
    site_revision: int = 0
    # What PHP-FPM and the CLI list as loaded when preparation read them.
    fpm_modules: frozenset[str] | None = None
    cli_modules: frozenset[str] | None = None


@dataclass(frozen=True)
class _Selected:
    """The selected site's native PHP selection and the evidence that binds the plan to it."""

    php_version: str
    php_supply: str
    uid: int
    gid: int
    revision: int
    context: list[EvidenceDraft]


def _select_site(shell: RemoteShell, action: Action, identifier: str) -> _Selected | DriverDraft:
    site = site_inspection.inspect(shell, identifier, "0" * 32)
    refused = DriverDraft(
        action, "Inspect the selected site's PHP driver.", site.platform, site.release
    )
    recognized = complete(refused, site, identifier, "0" * 32)
    paths = site.paths
    if (
        recognized is None
        or not refused.eligible
        or paths is None
        or site.gaps
        or not site.read_privilege
    ):
        refused.refuse(
            Reason.INCOMPLETE,
            "The selected site's PHP branch and supply could not be read. Prepare again.",
        )
        return refused
    fields = (site.accounts.user if site.accounts else "").split(":")
    if len(fields) < 4 or not fields[2].isdigit() or not fields[3].isdigit():
        refused.refuse(
            Reason.INCOMPLETE,
            "The selected site's user and group could not be read. Prepare again.",
        )
        return refused
    return _Selected(
        paths.php,
        site.php_supply,
        int(fields[2]),
        int(fields[3]),
        recognized.revision,
        [item for item in refused.evidence if item.kind == PlanEvidence.Kind.SITE_REVALIDATION],
    )


def prepare(
    shell: RemoteShell,
    action: Action,
    *,
    php_version: str = "",
    php_supply: str = "ubuntu",
    identifier: str = "",
) -> DriverDraft:
    context: list[EvidenceDraft] = []
    uid = gid = revision = 0
    if identifier:
        selected = _select_site(shell, action, identifier)
        if isinstance(selected, DriverDraft):
            return selected
        php_version, php_supply = selected.php_version, selected.php_supply
        uid, gid, revision, context = (
            selected.uid,
            selected.gid,
            selected.revision,
            selected.context,
        )
    evidence = bootstrap_inspection.inspect(
        shell, action, version=php_version or None, supply=php_supply
    )
    platform = evidence.platform
    release = releases.of(platform.os) if platform is not None else None
    trees: SiteEvidence | None = None
    if platform is not None and release is not None and platform.privilege != Privilege.UNAVAILABLE:
        trees = site_inspection.inspect_trees(shell, platform, release, php_version=php_version)
    judged = _SiteConvention(trees)
    draft = bootstrap_review(
        action,
        evidence,
        current_units(),
        tree_rules={SITE_CONVENTION: judged},
        version=php_version or None,
        supply=php_supply,
    )
    driver = DriverDraft(
        **{item.name: getattr(draft, item.name) for item in dataclasses.fields(Draft)}
    )
    driver.evidence.extend(context)
    driver.site_uid, driver.site_gid, driver.site_revision = uid, gid, revision
    if evidence.web is not None and (evidence.web.modules or evidence.web.cli_modules):
        driver.fpm_modules = _listed_modules(evidence.web.modules)
        driver.cli_modules = _listed_modules(evidence.web.cli_modules)
    if identifier:
        driver.intent += (
            f" The native PHP selection of site {identifier} is rechecked before any change."
        )
    if trees is not None:
        driver.refusals.extend(
            (Reason.INCOMPLETE, gap)
            for gap in trees.gaps
            if (Reason.INCOMPLETE, gap) not in driver.refusals
        )
    if release is None:
        return driver
    profile = profiles.profile(release, action, version=php_version or None, supply=php_supply)
    if driver.eligible:
        driver.pools = judged.pools(profile.php_version)
        if driver.transitions:
            _effects(driver, profile, profile.php_version)
    return driver


def _listed_modules(text: str) -> frozenset[str]:
    return frozenset(line.strip().casefold() for line in text.splitlines() if line.strip())


@dataclass
class _SiteConvention:
    """The tree rule: the distribution's files and links, and Barectl's site pools."""

    trees: SiteEvidence | None
    recognized: dict[str, int] = dataclasses.field(default_factory=dict)

    def __call__(self, draft: Draft, spec: TreeSpec, tree: ConfigTree) -> None:
        trees = self.trees
        if trees is None or not trees.read_privilege:
            draft.refuse(
                Reason.PRIVILEGE,
                f"Barectl needs root, or noninteractive sudo authorized for its fixed read-only "
                f"scripts, to read {spec.root} and the site pools in it as root. Barectl never "
                "installs a sudo policy or asks for a password.",
            )
            return
        found = recognize_trees(trees)
        if found is None or trees.tree is None or trees.md5 is None:
            draft.refuse(
                Reason.INCOMPLETE,
                f"Barectl could not read {spec.root} as root, so it cannot tell which pools "
                "the driver's reload restarts.",
            )
            return
        under = f"{spec.root}/"
        read = {item.path for item in trees.tree if item.path.startswith(under)}
        listed = {entry.path for entry in tree.entries if entry.path.startswith(under)}
        if read != listed:
            draft.refuse(
                Reason.INCOMPLETE,
                f"{spec.root} changed while Barectl read it. Prepare again.",
            )
            return
        unsupported = [item for item in found.unsupported if item.startswith(under)]
        if unsupported:
            shown = "; ".join(unsupported[:_LISTED])
            more = len(unsupported) - _LISTED
            draft.refuse(
                Reason.CUSTOMIZED,
                f"The configuration under {spec.root} holds entries that are neither the "
                f"distribution's nor Barectl's site pools: {shown}"
                f"{f'; and {more} more' if more > 0 else ''}. A driver's reload would load "
                "them into every pool; Barectl does not adopt custom configuration.",
            )
        self.recognized = {
            name: found.pool_revisions[name]
            for name in found.pools
            if found.pool_versions[name] == spec.root.split("/")[3]
        }
        entries = sorted(
            f"{item.kind} {item.mode:o} {item.uid} {item.gid} {item.path} {item.target} "
            f"{trees.md5.get(item.path, '')}"
            for item in trees.tree
            if item.path.startswith(under)
        )
        pools = ", ".join(["www", *(f"{name} (s{name})" for name in sorted(self.recognized))])
        draft.fingerprint(
            PlanEvidence.Kind.FPM_CLOSURE,
            entries,
            f"{len(entries)} entries under {spec.root}; recognized pools: {pools}.",
        )

    def pools(self, php: str) -> tuple[Pool, ...]:
        default = Pool("www", "www-data", f"/run/php/php{php}-fpm.sock", default=True)
        sites = tuple(
            Pool(
                name,
                (paths := SitePaths(name, php, revision=self.recognized[name])).user,
                paths.socket,
                default=False,
            )
            for name in sorted(self.recognized)
        )
        return (default, *sites)


def _effects(draft: DriverDraft, profile: profiles.Profile, php: str) -> None:
    unit = profile.reload
    pools = "; ".join(f"{pool.name} as {pool.user} on {pool.socket}" for pool in draft.pools)
    draft.effects.append(
        (
            Effect.SERVICE_RELOAD,
            (
                f"After php-fpm{php} -t accepts the configuration, Barectl reloads {unit} and "
                f"waits for every pool's socket to listen again. The reload restarts the workers "
                f"of every pool: {pools}. Requests a worker is serving when it restarts can "
                "fail. A failed check stops the run before the reload."
            ),
        )
    )
    if profile.action in profiles.DRIVER_ACTIONS:
        modules = ", ".join(module for _, module in profile.modules)
        draft.effects.append(
            (
                Effect.DRIVER_MODULES,
                (
                    f"The modules {modules} load in every PHP-FPM pool and in the CLI. This "
                    "action installs only this driver; it is not general extension management."
                ),
            )
        )
    draft.effects += [
        (
            Effect.INVALIDATES_PLANS,
            (
                "The PHP configuration changes, so earlier site and database plans no longer "
                "match the server and are refused when applied. Prepare them again after this "
                "plan is applied."
            ),
        ),
    ]
    draft.postconditions.append(
        f"Each reviewed pool listens on its socket: {', '.join(p.socket for p in draft.pools)}."
    )


def site_preconditions(plan: ConfigurationPlan, identifier: str) -> tuple[tuple[str, str], ...]:
    """The selected site's native digest the payload rechecks as root before it changes
    anything, bound to the digest the plan reviewed."""
    pool = plan.driver_pools.filter(name=identifier, default=False).first()
    digest = (
        plan.evidence.filter(kind=PlanEvidence.Kind.SITE_REVALIDATION)
        .values_list("fingerprint", flat=True)
        .first()
    )
    if pool is None or not digest or not plan.php_version:
        raise OperationRefused(EVIDENCE_FAILURE)
    try:
        selected = SitePaths(identifier, plan.php_version, revision=4)
        paths = (
            selected if selected.socket == pool.socket else SitePaths(identifier, plan.php_version)
        )
        if paths.socket != pool.socket:
            raise ValueError("The reviewed site socket differs.")
        return ((site_native.site_digest(paths), digest),)
    except ValueError:
        raise OperationRefused(EVIDENCE_FAILURE) from None
