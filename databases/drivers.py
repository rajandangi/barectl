"""PHP database driver plans (docs/databases.md#php-database-drivers).

A driver is a bootstrap package profile whose PHP-FPM tree may hold Barectl's site pools:
bootstrap reviews and applies the package transaction, and this module supplies the site
grammar that judges that tree and the pools a reload restarts.
"""

import dataclasses
from dataclasses import dataclass

from bootstrap import inspection as bootstrap_inspection
from bootstrap import profiles, releases
from bootstrap.apply import current_units
from bootstrap.evidence import ConfigTree
from bootstrap.models import Action, PlanEffect, PlanEvidence, PlanRefusal, Privilege
from bootstrap.profiles import SITE_CONVENTION, TreeSpec
from bootstrap.review import Draft
from bootstrap.review import review as bootstrap_review
from discovery.ssh import RemoteShell
from sites import inspection as site_inspection
from sites.admission import recognize_trees
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


def prepare(shell: RemoteShell, action: Action) -> DriverDraft:
    evidence = bootstrap_inspection.inspect(shell, action)
    platform = evidence.platform
    release = releases.of(platform.os) if platform is not None else None
    trees: SiteEvidence | None = None
    if platform is not None and release is not None and platform.privilege != Privilege.UNAVAILABLE:
        trees = site_inspection.inspect_trees(shell, platform, release)
    judged = _SiteConvention(trees)
    draft = bootstrap_review(
        action, evidence, current_units(), tree_rules={SITE_CONVENTION: judged}
    )
    driver = DriverDraft(
        **{item.name: getattr(draft, item.name) for item in dataclasses.fields(Draft)}
    )
    if trees is not None:
        driver.refusals.extend(
            (Reason.INCOMPLETE, gap)
            for gap in trees.gaps
            if (Reason.INCOMPLETE, gap) not in driver.refusals
        )
    if release is None:
        return driver
    profile = profiles.profile(release, action)
    driver.pools = judged.pools(release.php)
    if driver.eligible and driver.transitions:
        _effects(driver, profile)
    return driver


@dataclass
class _SiteConvention:
    """The tree rule: the distribution's files and links, and Barectl's site pools."""

    trees: SiteEvidence | None
    recognized: set[str] = dataclasses.field(default_factory=set)

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
        self.recognized = set(found.pools)
        entries = sorted(
            f"{item.kind} {item.mode:o} {item.uid} {item.gid} {item.path} {item.target} "
            f"{trees.md5.get(item.path, '')}"
            for item in trees.tree
            if item.path.startswith(under)
        )
        pools = ", ".join(["www", *(f"{name} (s{name})" for name in sorted(found.pools))])
        draft.fingerprint(
            PlanEvidence.Kind.FPM_CLOSURE,
            entries,
            f"{len(entries)} entries under {spec.root}; recognized pools: {pools}.",
        )

    def pools(self, php: str) -> tuple[Pool, ...]:
        default = Pool("www", "www-data", f"/run/php/php{php}-fpm.sock", default=True)
        sites = tuple(
            Pool(name, (paths := SitePaths(name, php)).user, paths.socket, default=False)
            for name in sorted(self.recognized)
        )
        return (default, *sites)


def _effects(draft: DriverDraft, profile: profiles.Profile) -> None:
    unit = profile.reload
    php = unit.removeprefix("php").removesuffix("-fpm.service")
    pools = "; ".join(f"{pool.name} as {pool.user} on {pool.socket}" for pool in draft.pools)
    modules = ", ".join(module for _, module in profile.modules)
    draft.effects += [
        (
            Effect.SERVICE_RELOAD,
            (
                f"After php-fpm{php} -t accepts the configuration, Barectl reloads {unit} and "
                f"waits for every pool's socket to listen again. The reload restarts the workers "
                f"of every pool: {pools}. Requests a worker is serving when it restarts can "
                "fail. A failed check stops the run before the reload."
            ),
        ),
        (
            Effect.DRIVER_MODULES,
            (
                f"The modules {modules} load in every PHP-FPM pool and in the CLI. This action "
                "installs only this driver; it is not general extension management."
            ),
        ),
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
