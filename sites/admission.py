"""Site admission: the supported grammar, collisions and the reviewed effects.

docs/sites.md#admission. Separate from the stock Nginx and PHP profiles' admission, which
still refuses any tree that holds a site (bootstrap.review).
"""

from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from typing import override

from bootstrap import native as bootstrap_native
from bootstrap import profiles
from bootstrap.models import ADMISSION_CENTISECONDS, Action, PlanEffect, PlanEvidence, PlanRefusal
from bootstrap.releases import Release
from bootstrap.review import Draft, EvidenceDraft, check_platform
from discovery.models import FileType
from discovery.observations.sites import FileFacts

from . import names as site_names
from . import native
from .convention import (
    CONVENTION_REVISION,
    NOLOGIN,
    SITES_AVAILABLE,
    SITES_ENABLED,
    TLS_DEFAULT_PATH,
    WEB_USER,
    RecognizedSite,
    SitePaths,
    Stage,
    is_tls_default,
    recognize_pool,
    recognize_site,
    render_placeholder,
    render_pool,
    render_probe,
    render_site,
)
from .inspection import PathState, SiteEvidence, TreeItem

Reason = PlanRefusal.Reason
Effect = PlanEffect.Kind
Kind = PlanEvidence.Kind
_LISTED = 5
# docs/sites.md#account-allocation: the only /etc/default/useradd settings the explicit
# useradd command makes irrelevant or that match its flags.
_USERADD_SETTINGS = frozenset({"SHELL", "SKEL", "HOME", "GROUP"})
_NSSWITCH = frozenset({("files",), ("files", "systemd")})
DEFAULT_RANGE = (1000, 60000)
# How a satisfied site's file is described by its stage.
_ROUTE = {
    Stage.HTTP: "",
    Stage.CHALLENGE: " with its HTTP-01 challenge route and webroot",
    Stage.HTTPS: " with its HTTP-01 challenge route, webroot and HTTPS server block",
    Stage.REDIRECT: (
        " with its HTTP-01 challenge route, webroot, HTTPS server block and HTTP redirect"
    ),
}


@dataclass(frozen=True)
class DirectoryDraft:
    path: str
    owner: str
    group: str
    mode: str


@dataclass(frozen=True)
class AccountDraft:
    user: str
    home: str
    command: str
    uid_range: tuple[int, int]
    gid_range: tuple[int, int]
    free_uids: int
    free_gids: int
    predicted_uid: int | None
    predicted_gid: int | None
    subordinate_ids: bool


@dataclass
class SiteDraft(Draft):
    identifier: str = ""
    names: tuple[str, ...] = ()
    paths: SitePaths | None = None
    ipv6: bool = False
    token: str = ""
    files: list[native.GeneratedFile] = field(default_factory=list)
    directories: list[DirectoryDraft] = field(default_factory=list)
    account: AccountDraft | None = None
    payload_bytes: int | None = None
    retained: frozenset[str] = frozenset()

    @property
    @override
    def revision(self) -> int:
        return CONVENTION_REVISION


def intent(identifier: str, names: Iterable[str]) -> str:
    return f"Create the HTTP PHP site {identifier} for {', '.join(names)}."[:200]


useradd = native.useradd


def review(
    identifier: str,
    requested: tuple[str, ...],
    token: str,
    evidence: SiteEvidence,
    *,
    certificates_expected: bool = False,
    allow_finish: bool = True,
) -> SiteDraft:
    """``certificates_expected`` skips the certificate-path collision refusal: a TLS review
    of a site that may already own its lineage (docs/tls.md#issuance)."""
    platform, release = evidence.platform, evidence.release
    draft = SiteDraft(
        Action.SITE_HTTP,
        intent(identifier, requested),
        platform,
        release,
        identifier=identifier,
        names=requested,
        token=token,
    )
    check_platform(draft, platform)
    for gap in evidence.gaps:
        draft.refuse(Reason.INCOMPLETE, gap)
    paths = evidence.paths
    if release is None or paths is None:
        return draft
    draft.paths = paths
    try:
        site_names.request(identifier, " ".join(requested))
    except site_names.InvalidInput as invalid:
        draft.refuse(Reason.INCOMPLETE, f"The stored request is not valid: {invalid}")
        return draft
    if not evidence.read_privilege:
        draft.refuse(
            Reason.PRIVILEGE,
            PRIVILEGE,
        )
        return draft
    _Admission(
        draft,
        evidence,
        paths,
        certificates_expected=certificates_expected,
        allow_finish=allow_finish,
    ).run()
    return draft


PRIVILEGE = (
    "The SSH user is not root, and sudo -n -l does not authorize Barectl's fixed read-only "
    "inspection commands without a password. Site preparation reads the complete Nginx and "
    "PHP-FPM configuration as root, as applying later checks it; the permission to prepare "
    "site plans is the explicit authority for that privileged read. Barectl never installs a "
    "sudo policy or asks for a password."
)


def complete(
    draft: Draft,
    evidence: SiteEvidence,
    identifier: str,
    token: str,
    *,
    certificates_expected: bool | None = None,
) -> RecognizedSite | None:
    """The one complete convention site a TLS review stands on (docs/tls.md#readiness).

    Records site admission's refusals on ``draft`` and returns the recognized site only when
    it is complete, so readiness and challenge admission ask the same question once. A site
    that already routes its challenges owns its certificate lineage
    (``certificates_expected=None``)."""
    check_platform(draft, evidence.platform)
    for gap in evidence.gaps:
        draft.refuse(Reason.INCOMPLETE, gap)
    paths = evidence.paths
    if evidence.release is None or paths is None:
        return None
    if not evidence.read_privilege:
        draft.refuse(Reason.PRIVILEGE, PRIVILEGE)
        return None
    text = evidence.contents.get(paths.source)
    site = recognize_site(identifier, text) if text is not None else None
    if site is None:
        draft.refuse(
            Reason.NOT_FOLLOWING,
            f"The site {identifier} does not follow the convention: {paths.source} is not a "
            "site file of the convention. Barectl manages only a site that follows the "
            "convention exactly; create the site first.",
        )
        return None
    expected = (
        site.stage.routes_challenges if certificates_expected is None else certificates_expected
    )
    checked = review(
        identifier,
        site.names,
        token,
        evidence,
        certificates_expected=expected,
        allow_finish=False,
    )
    _merge_into(draft, checked)
    if not checked.eligible or not checked.no_changes:
        return None
    return site


def _merge_into(draft: Draft, checked: Draft) -> None:
    for reason, text in checked.refusals:
        draft.refuse(reason, text)
    kinds = {item.kind for item in draft.evidence}
    for item in checked.evidence:
        if item.kind not in kinds:
            kinds.add(item.kind)
            draft.evidence.append(item)


@dataclass(frozen=True)
class _Resource:
    name: str
    exists: bool
    # Exists with the attributes the convention gives it.
    conforms: bool


@dataclass
class _Admission:
    draft: SiteDraft
    evidence: SiteEvidence
    paths: SitePaths
    certificates_expected: bool = False
    allow_finish: bool = True
    # The convention files recognized under the trees, by identifier.
    sites: dict[str, RecognizedSite] = field(default_factory=dict)
    pools: set[str] = field(default_factory=set)
    links: set[str] = field(default_factory=set)
    ipv6: bool = False

    def refuse(self, reason: PlanRefusal.Reason, text: str) -> None:
        self.draft.refuse(reason, text)

    def run(self) -> None:
        evidence = self.evidence
        self._packages()
        self._units()
        self._tree()
        self._ancestors()
        ipv6 = self._listeners()
        self._accounts_policy()
        self._fingerprints()
        self._revalidation()
        if evidence.states is None or evidence.accounts is None or evidence.tree is None:
            return
        self._names()
        if not self._existing(self._site_state(ipv6)):
            return
        self.draft.ipv6 = ipv6
        if self.draft.eligible:
            self._changes()

    # Packages and services -----------------------------------------------------------

    def _packages(self) -> None:
        evidence, php = self.evidence, self.paths.php
        states = {state.name: state for state in evidence.packages or ()}
        if evidence.packages is None:
            return
        missing = [
            name
            for name in (
                "nginx",
                "nginx-common",
                f"php{php}-fpm",
                f"php{php}-cli",
                f"php{php}-common",
            )
            if name not in states or not states[name].installed
        ]
        if missing:
            self.refuse(
                Reason.PREREQUISITE,
                f"{', '.join(missing)} {'is' if len(missing) == 1 else 'are'} not installed and "
                "configured. Apply the Nginx and PHP bootstrap profiles first, then prepare "
                "again.",
            )
        others = [
            f"{state.name} {state.version or state.status}"
            for state in evidence.other_releases or ()
        ]
        if others:
            self.refuse(
                Reason.UNSUPPORTED_VERSION,
                f"Packages of another PHP release are on the server: {_listed(others)}. Sites "
                f"use only PHP {php}, the release's default.",
            )

    def _units(self) -> None:
        for unit in self.evidence.units or ():
            problem = _unit_problem(unit.load_state, unit.active_state, unit.sub_state)
            if not problem and unit.unit_file_state != "enabled":
                problem = "is not enabled."
            if not problem and unit.drop_in_paths:
                problem = f"has drop-in overrides ({', '.join(unit.drop_in_paths[:_LISTED])})."
            if not problem and unit.fragment_path != f"/usr/lib/systemd/system/{unit.name}":
                problem = "is not defined by the distribution's unit file."
            if problem:
                self.refuse(
                    Reason.SERVICE_UNIT,
                    f"{unit.name} {problem} A site needs the distribution's unit, enabled and "
                    "running.",
                )

    # The configuration trees -------------------------------------------------------------

    def _tree(self) -> None:
        recognized = recognize_trees(self.evidence)
        if recognized is None:
            return
        self.sites, self.pools, self.links = recognized.sites, recognized.pools, recognized.links
        tree = self.evidence.tree or ()
        self._required(tree)
        problems = [
            entry
            for entry in recognized.unsupported
            if entry.split(" (", 1)[0] not in recognized.foreign
        ]
        if problems:
            self.refuse(
                Reason.UNSUPPORTED_LAYOUT,
                "The Nginx or PHP-FPM configuration holds entries outside the supported site "
                f"grammar: {_listed(problems)}. Site creation admits only the "
                "distribution's unmodified files and links and files that match Barectl's site "
                "templates exactly; it does not adopt custom configuration.",
            )

    def _required(self, tree: tuple[TreeItem, ...]) -> None:
        present = {item.path for item in tree}
        if f"{SITES_ENABLED}/default" not in present:
            self.refuse(
                Reason.PREREQUISITE,
                f"The distribution's default site is not enabled ({SITES_ENABLED}/default). It "
                "must answer requests for names no site declares; restore it, then prepare again.",
            )
        posix = f"/etc/php/{self.paths.php}/fpm/conf.d/20-posix.ini"
        if posix not in present:
            self.refuse(
                Reason.PREREQUISITE,
                f"PHP-FPM does not load the posix extension ({posix}), which the temporary "
                "serving probe uses to report its identity. Enable it with phpenmod posix, then "
                "prepare again.",
            )

    def _ancestors(self) -> None:
        states = self.evidence.states
        if states is None:
            return
        problems = []
        for path in native.ancestors(self.paths):
            state = states[path]
            owner_name = WEB_USER if path == "/run/php" else "root"
            if state.kind != "d" or state.owner != owner_name or state.mode & 0o022:
                problems.append(
                    f"{path} must be a directory owned by {owner_name} that only its owner can "
                    f"write; it is {_describe(state)}"
                )
        if problems:
            self.refuse(
                Reason.UNSUPPORTED_LAYOUT,
                f"Unsafe parent directories: {_listed(problems)}. Barectl writes site files only "
                "below root-controlled directories.",
            )

    def _listeners(self) -> bool:
        listeners = self.evidence.listeners
        if listeners is None:
            return False
        addresses = {listener.address for listener in listeners}
        others = [
            listener.address
            for listener in listeners
            if listener.processes is None or set(listener.processes) != {"nginx"}
        ]
        if others:
            self.refuse(
                Reason.LISTENER,
                f"Another process listens on port 80 ({', '.join(others)}). Only Nginx may, "
                "so that requests for the site's names reach it.",
            )
        if "0.0.0.0" not in addresses:  # noqa: S104 - a reported address, not a bind
            self.refuse(
                Reason.LISTENER,
                "Nginx does not listen on port 80 on every IPv4 address, as the distribution's "
                "default site does. Restore it, then prepare again.",
            )
        return "[::]" in addresses

    # Accounts and allocation -------------------------------------------------------------

    def _accounts_policy(self) -> None:
        accounts, policy = self.evidence.accounts, self.evidence.policy
        if accounts is not None and not (accounts.web_user and accounts.web_group):
            self.refuse(
                Reason.PREREQUISITE,
                f"The {WEB_USER} user or group does not exist; Nginx and the site's socket need "
                "them.",
            )
        if policy is None or accounts is None:
            return
        for database in ("passwd", "group"):
            sources = policy.nsswitch.get(database, ())
            if sources not in _NSSWITCH:
                self.refuse(
                    Reason.UNSUPPORTED_LAYOUT,
                    f"/etc/nsswitch.conf resolves {database} through "
                    f"{' '.join(sources) or 'nothing'}. Site accounts are supported only with "
                    "the local files, with or without systemd, so that useradd's result is what "
                    "the server resolves.",
                )
        extra = sorted(
            key
            for key, value in policy.useradd.items()
            if key not in _USERADD_SETTINGS and not (key == "CREATE_MAIL_SPOOL" and value == "no")
        )
        if extra:
            self.refuse(
                Reason.UNSUPPORTED_LAYOUT,
                f"/etc/default/useradd sets {', '.join(extra)}, which would change the site "
                "account beyond the reviewed flags. Remove the setting, then prepare again.",
            )
        uid_range = _range(policy.login_defs, "UID", self)
        gid_range = _range(policy.login_defs, "GID", self)
        free_uids = _free(uid_range, accounts.uids)
        free_gids = _free(gid_range, accounts.gids)
        if not accounts.user and (not free_uids or not free_gids):
            self.refuse(
                Reason.PREREQUISITE,
                f"No normal account ID is free between {uid_range[0]} and {uid_range[1]}, or no "
                f"group ID between {gid_range[0]} and {gid_range[1]}.",
            )
        subordinate = policy.subordinate and policy.login_defs.get("SUB_UID_COUNT", "1") != "0"
        uid = _predict(uid_range, accounts.uids)
        gid = (
            uid
            if uid is not None and uid not in accounts.gids
            else _predict(gid_range, accounts.gids)
        )
        self.draft.account = AccountDraft(
            user=self.paths.user,
            home=self.paths.boundary,
            command=useradd(self.paths),
            uid_range=uid_range,
            gid_range=gid_range,
            free_uids=free_uids,
            free_gids=free_gids,
            predicted_uid=uid,
            predicted_gid=gid,
            subordinate_ids=subordinate,
        )

    # Names of other sites, and the site's own state --------------------------------------

    def _names(self) -> None:
        """Refuse a requested domain that another site or enabled file already declares."""
        identifier = self.paths.identifier
        requested = set(self.draft.names)
        for other, site in sorted(self.sites.items()):
            if other == identifier:
                continue
            shared = sorted(requested & set(site.names))
            if shared:
                self.refuse(
                    Reason.NOT_FOLLOWING,
                    f"The site {other} already declares {', '.join(shared)} "
                    f"({SITES_AVAILABLE}/{other}.conf). A name belongs to one site.",
                )
        for path, names in sorted(self.evidence.foreign.items()):
            base = path.rpartition("/")[2].removesuffix(".conf")
            if base == identifier or base in self.sites:
                continue
            shared = sorted(requested & {name.lower() for name in names})
            if shared:
                self.refuse(
                    Reason.NOT_FOLLOWING,
                    f"{path} already declares {', '.join(shared)}. A name belongs to one site.",
                )
        self._certificate_paths()

    def _certificate_paths(self) -> None:
        """docs/sites.md#admission: a certificate lineage is never adopted."""
        if self.certificates_expected:
            return
        states = self.evidence.states or {}
        existing = self.sites.get(self.paths.identifier)
        challenge = existing is not None and existing.stage.routes_challenges
        # A site serving challenges owns its webroot; _site_state checks it.
        own = self.paths.webroot if challenge else ""
        taken = [path for path in self.paths.certificates if states[path].present and path != own]
        if taken:
            self.refuse(
                Reason.COLLISION,
                f"Certificate paths reserved for the site {self.paths.identifier} already "
                f"exist: {_listed(taken)}. Barectl does not adopt an existing certificate "
                "lineage.",
            )

    def _existing(self, resources: list[_Resource]) -> bool:
        """One rule over the site's own resources (docs/sites.md#existing-resources).

        ``True`` when the site has missing resources and every existing resource is exact.
        """
        paths = self.paths
        present = [item for item in resources if item.exists]
        if not present:
            return True
        foreign = [item.name for item in present if not item.conforms]
        if foreign:
            self._refuse_resources("already exist and do not follow the site convention", foreign)
            return False
        missing = [item.name for item in resources if not item.exists]
        if missing:
            if not self.allow_finish:
                self.refuse(
                    Reason.NOT_FOLLOWING,
                    f"The site {paths.identifier} is partly applied; resources are absent: "
                    f"{_listed(missing)}. TLS needs a complete site that follows the convention. "
                    "Finish the HTTP site or restore its exact resources before reviewing TLS.",
                )
                return False
            site = self.sites.get(paths.identifier)
            if site is not None and site.stage != Stage.HTTP:
                self.refuse(
                    Reason.PREREQUISITE,
                    "This partly applied site already has a challenge or HTTPS configuration. "
                    "HTTP site finish cannot reconstruct missing TLS resources; restore the "
                    "existing resources through ordinary administration and review TLS separately.",
                )
                return False
            application = (
                (paths.placeholder,)
                if self.evidence.states is not None and self.evidence.states[paths.public].present
                else ()
            )
            self.draft.retained = frozenset([item.name for item in present] + list(application))
            self.draft.intent = (
                f"Finish the HTTP PHP site {paths.identifier} for {', '.join(self.draft.names)}."
            )[:200]
            if self.evidence.accounts is not None and self.evidence.accounts.user:
                uid, gid = _ids(self.evidence.accounts.user)
                if self.draft.account is not None:
                    self.draft.account = replace(
                        self.draft.account, command="", predicted_uid=uid, predicted_gid=gid
                    )
            return True
        site = self.sites.get(paths.identifier)
        if site is not None and self.draft.eligible:
            self.draft.effects.append(
                (
                    Effect.NO_CHANGES,
                    (
                        f"No changes. The site {paths.identifier} already matches the "
                        "convention with exactly these names: its account, directories, pool, "
                        f"Nginx file{_ROUTE[site.stage]}, link and socket. This is a layout "
                        "match, not a claim that the site serves requests; application content "
                        "is not compared."
                    ),
                )
            )
        return False

    def _refuse_resources(self, problem: str, resources: list[str]) -> None:
        """docs/sites.md#existing-resources: Barectl never tells an operator to remove a
        resource it cannot prove belongs to this site."""
        self.refuse(
            Reason.NOT_FOLLOWING,
            f"Resources that the identifier {self.paths.identifier} derives {problem}: "
            f"{_listed(resources)}. Barectl does not change or remove existing resources "
            "that differ; bring the site into the convention (docs/site-conventions.md) "
            "or remove what is not in use through ordinary administration, then prepare again.",
        )

    def _site_state(self, ipv6: bool) -> list[_Resource]:
        """Each of the site's resources: whether it exists and follows the convention."""
        self.ipv6 = ipv6
        paths, accounts = self.paths, self.evidence.accounts
        states = self.evidence.states or {}
        if accounts is None:
            return []
        resources: list[_Resource] = []

        def record(name: str, exists: bool, conforms: bool) -> None:
            resources.append(_Resource(name, exists, conforms))

        user = paths.user
        uid, gid = _ids(accounts.user)
        home = paths.boundary
        range_ok = (
            self.draft.account is not None
            and uid is not None
            and (self.draft.account.uid_range[0] <= uid <= self.draft.account.uid_range[1])
        )
        record(
            f"user {user}",
            bool(accounts.user),
            accounts.user == f"{user}:x:{uid}:{gid}::{home}:{NOLOGIN}"
            and range_ok
            and accounts.groups == str(gid)
            and accounts.password_locked is True,
        )
        record(
            f"group {user}",
            bool(accounts.group),
            bool(accounts.user)
            and accounts.group == f"{user}:x:{gid}:"
            and self.draft.account is not None
            and gid is not None
            and self.draft.account.gid_range[0] <= gid <= self.draft.account.gid_range[1],
        )
        for path, owner, group, mode in (
            (paths.boundary, "root", "root", 0o755),
            (paths.public, user, WEB_USER, 0o750),
            (paths.private, user, user, 0o700),
        ):
            state = states[path]
            record(
                path,
                state.present,
                (state.kind, state.owner, state.group, state.mode) == ("d", owner, group, mode),
            )
        site = self.sites.get(paths.identifier)
        record(
            paths.source,
            states[paths.source].present,
            site is not None
            and set(site.names) == set(self.draft.names)
            and site.ipv6 == self.ipv6,
        )
        record(paths.link, states[paths.link].present, paths.identifier in self.links)
        if site is not None and site.stage.routes_challenges:
            webroot = states[paths.webroot]
            record(
                paths.webroot,
                webroot.present,
                (webroot.kind, webroot.owner, webroot.group, webroot.mode)
                == ("d", "root", WEB_USER, 0o750),
            )
        record(paths.pool, states[paths.pool].present, paths.identifier in self.pools)
        socket = states[paths.socket]
        record(
            paths.socket,
            socket.present or bool(self.evidence.socket_listening),
            (socket.kind, socket.owner, socket.group, socket.mode)
            == ("s", WEB_USER, WEB_USER, 0o600)
            and bool(self.evidence.socket_listening),
        )
        return resources

    # Evidence --------------------------------------------------------------------------

    def _fingerprints(self) -> None:
        draft, evidence = self.draft, self.evidence
        tree = evidence.tree or ()
        md5 = evidence.md5 or {}
        lines = {
            i.path: f"{i.kind} {i.mode:o} {i.uid} {i.gid} {i.links} {i.path} {i.target} "
            f"{md5.get(i.path, '')}"
            for i in tree
        }
        nginx = [line for path, line in lines.items() if path.startswith("/etc/nginx")]
        fpm = [line for path, line in lines.items() if path.startswith("/etc/php")]
        draft.fingerprint(
            Kind.NGINX_CLOSURE,
            nginx,
            f"{len(nginx)} entries under /etc/nginx; {len(self.sites)} recognized site files.",
        )
        draft.fingerprint(
            Kind.FPM_CLOSURE,
            fpm,
            f"{len(fpm)} entries under /etc/php/{self.paths.php}; {len(self.pools)} recognized "
            "site pools.",
        )
        accounts = evidence.accounts
        if accounts is not None:
            draft.fingerprint(
                Kind.ACCOUNTS,
                [
                    accounts.user,
                    accounts.group,
                    accounts.groups,
                    str(sorted(accounts.uids)),
                    str(sorted(accounts.gids)),
                ],
                f"{len(accounts.uids)} user IDs and {len(accounts.gids)} group IDs; "
                f"{self.paths.user} {'exists' if accounts.user else 'does not exist'}.",
            )
        if evidence.policy is not None:
            policy = evidence.policy
            draft.fingerprint(
                Kind.ALLOCATION,
                [
                    *(f"{k} {v}" for k, v in sorted(policy.login_defs.items())),
                    *(f"{k}={v}" for k, v in sorted(policy.useradd.items())),
                    *(f"{k}: {' '.join(v)}" for k, v in sorted(policy.nsswitch.items())),
                    str(policy.subordinate),
                ],
                "/etc/login.defs, /etc/default/useradd and the passwd and group sources of "
                "/etc/nsswitch.conf.",
            )
        if evidence.states is not None:
            draft.fingerprint(
                Kind.SITE_PATHS,
                [
                    f"{s.path} {s.kind} {s.mode:o} {s.uid} {s.gid} {s.links}"
                    for s in evidence.states.values()
                ],
                f"{sum(1 for s in evidence.states.values() if s.present)} of "
                f"{len(evidence.states)} site paths and parent directories exist.",
            )
        if evidence.listeners is not None:
            draft.fingerprint(
                Kind.LISTENERS,
                sorted(f"{i.address} {','.join(i.processes or ())}" for i in evidence.listeners),
                f"{len(evidence.listeners)} listeners on port 80"
                + (
                    f" ({', '.join(sorted({i.address for i in evidence.listeners}))})."
                    if evidence.listeners
                    else "."
                ),
            )
        if evidence.units is not None:
            draft.fingerprint(
                Kind.SERVICE_UNITS,
                [
                    f"{u.name} {u.load_state} {u.active_state} {u.sub_state} {u.unit_file_state} "
                    f"{u.fragment_path} {' '.join(u.drop_in_paths)}"
                    for u in evidence.units
                ],
                "; ".join(
                    f"{u.name} {u.active_state}/{u.sub_state}, {u.unit_file_state}"
                    for u in evidence.units
                ),
            )
        if evidence.packages is not None:
            draft.fingerprint(
                Kind.DPKG_STATUS,
                ["\t".join(state) for state in sorted(evidence.packages)],
                "; ".join(f"{s.name} {s.version}" for s in evidence.packages if s.installed)
                or "None of the site's packages is installed.",
            )

    def _revalidation(self) -> None:
        evidence = self.evidence
        if evidence.changed_while_read:
            self.refuse(
                Reason.INCOMPLETE,
                "The configuration, accounts, services or listeners changed while Barectl read "
                "them. Prepare again once they are settled.",
            )
        elif not evidence.digest:
            self.refuse(
                Reason.INCOMPLETE,
                "Barectl could not compute the site evidence digest that applying rechecks.",
            )
        else:
            self.draft.evidence.append(
                EvidenceDraft(
                    Kind.SITE_REVALIDATION,
                    evidence.digest,
                    "The Nginx and PHP-FPM trees, /var/www, accounts, allocation policy, parent "
                    "directories, certificate names, services, packages and listeners, "
                    "rechecked as root under the mutation lock before applying.",
                )
            )

    # The proposal ------------------------------------------------------------------------

    def _changes(self) -> None:
        draft, paths = self.draft, self.paths
        user, identifier = paths.user, paths.identifier
        probe = paths.probe(draft.token)
        draft.directories = [
            DirectoryDraft(paths.boundary, "root", "root", "0755"),
            DirectoryDraft(paths.public, user, WEB_USER, "0750"),
            DirectoryDraft(paths.private, user, user, "0700"),
        ]
        draft.files = [
            native.GeneratedFile(
                "nginx_source",
                paths.source,
                "file",
                "root",
                "root",
                "0644",
                content=self.evidence.contents.get(paths.source)
                or render_site(identifier, draft.names, ipv6=draft.ipv6),
            ),
            native.GeneratedFile(
                "nginx_link", paths.link, "symlink", "root", "root", "", link_target=paths.source
            ),
            native.GeneratedFile(
                "pool", paths.pool, "file", "root", "root", "0644", content=render_pool(identifier)
            ),
            native.GeneratedFile(
                "placeholder",
                paths.placeholder,
                "file",
                user,
                WEB_USER,
                "0640",
                content=render_placeholder(identifier),
            ),
            native.GeneratedFile(
                "probe",
                probe,
                "file",
                "root",
                user,
                "0640",
                content=render_probe(draft.token),
                temporary=True,
            ),
        ]
        draft.directories = [item for item in draft.directories if item.path not in draft.retained]
        self._payload()
        if not draft.eligible:
            return
        self._effects()

    def _payload(self) -> None:
        draft, paths = self.draft, self.paths
        platform, account = draft.platform, draft.account
        digest = self.evidence.digest
        if (
            platform is None
            or platform.uptime_centiseconds is None
            or account is None
            or not digest
        ):
            return
        files = {item.role: item for item in draft.files}
        change = native.SiteChange(
            paths=paths,
            names=draft.names,
            ipv6=draft.ipv6,
            token=draft.token,
            digest=digest,
            uid_range=account.uid_range,
            gid_range=account.gid_range,
            placeholder=files["placeholder"],
            probe=files["probe"],
            pool=files["pool"],
            site=files["nginx_source"],
            create=frozenset(
                [item.path for item in draft.files if item.path not in draft.retained]
                + [item.path for item in draft.directories]
            ),
            existing_uid=account.predicted_uid if not account.command else None,
            existing_gid=account.predicted_gid if not account.command else None,
        )
        payload = native.site_payload(
            bootstrap_native.new_unit_name(),
            platform.boot_id,
            platform.uptime_centiseconds + ADMISSION_CENTISECONDS,
            change,
        )
        draft.payload_bytes = len(payload.encode())
        if draft.payload_bytes > bootstrap_native.MAX_PAYLOAD:
            self.refuse(
                Reason.PAYLOAD_TOO_LARGE,
                f"Applying this site would need {draft.payload_bytes} bytes, more than the "
                f"{bootstrap_native.MAX_PAYLOAD} bytes Barectl submits in one run. Barectl never "
                "splits a reviewed action; request fewer or shorter names.",
            )

    def _effects(self) -> None:
        draft, paths = self.draft, self.paths
        account = draft.account
        if account is None:
            return
        user, php = paths.user, paths.php
        low, high = account.uid_range
        group_low, group_high = account.gid_range
        predicted = ""
        if account.predicted_uid is not None:
            predicted = (
                f" The allocator would likely choose UID {account.predicted_uid} and GID "
                f"{account.predicted_gid}, which is not guaranteed: another account may take "
                "them first, and applying binds the actual IDs before any file ownership."
            )
        subordinate = ""
        if account.subordinate_ids:
            subordinate = (
                " useradd also allocates subordinate user and group ID ranges in /etc/subuid "
                "and /etc/subgid, as /etc/login.defs configures."
            )
        families = "IPv4 and IPv6" if draft.ipv6 else "IPv4"
        texts = {
            Effect.SITE_ACCOUNT: (
                f"Runs {account.command} under its own lock. It creates the user {user} and its "
                f"private group {user} with a normal UID from {low} to {high} "
                f"({account.free_uids} free) and a GID from {group_low} to {group_high} "
                f"({account.free_gids} free), home {paths.boundary}, shell {NOLOGIN}, a locked "
                "password and no supplementary groups, sudo rights or SSH keys. No home "
                f"directory, skeleton files or mail spool are created.{subordinate}{predicted}"
            ),
            Effect.SITE_DIRECTORIES: (
                f"Creates {paths.boundary} (root:root 0755, the site boundary and the account's "
                f"home), {paths.public} ({user}:{WEB_USER} 0750, the document root) and "
                f"{paths.private} ({user}:{user} 0700, outside the document root)."
            ),
            Effect.SITE_FILES: (
                "Publishes each file listed below with its exact bytes, owner and mode, and the "
                "enablement link, each staged in its own directory and linked into place only "
                "while the destination is still absent. Every destination is absent now, so no "
                "file is replaced and no backup is made."
            ),
            Effect.SERVICE_RELOAD: (
                f"After php-fpm{php} -t accepts the complete configuration, reloads "
                f"{paths.fpm_service}; the reload restarts the worker processes of every pool, "
                "including the distribution's www pool and other sites. After nginx -t accepts "
                "the configuration, reloads nginx.service, whose old workers finish their "
                "requests. A failed check is never followed by a reload."
            ),
            Effect.HTTP_ROUTING: (
                f"Nginx serves {', '.join(draft.names)} on port 80 over {families} from "
                f"{paths.public}: existing files, index.php or index.html, 404 otherwise, with "
                "dotfiles refused and no directory listing. PHP scripts that exist run in the "
                f"pool {paths.identifier} as {user} through {paths.socket}, which only www-data "
                "may connect to, with no PATH_INFO. Requests for other names still reach the "
                "distribution's default site. No firewall, DNS or TLS change is made."
            ),
            Effect.ACCEPTANCE_PROBE: (
                f"Writes the temporary probe {paths.probe(draft.token)} (root:{user} 0640), "
                "requests each name over each reviewed address family and the probe once, and "
                "then removes the probe, whose bytes must still match. It prints only its token "
                "and the PHP process's user and group IDs. A probe that cannot be removed makes "
                "the verification incomplete."
            ),
            Effect.ISOLATION_LIMITS: (
                f"The pool runs as {user} with pm = ondemand, at most 5 processes and a 10 "
                "second idle timeout, a small starting profile rather than capacity sizing. "
                "Separate users are an ordinary local access boundary, not container isolation; "
                "Nginx workers can read every site's public files. No database catalog was read "
                "and no database is created."
            ),
            Effect.NO_ROLLBACK: (
                "The account, directories, files and reloads are not one transaction. After the "
                "first change a failure is partial completion: Barectl never removes the "
                "account, directories or content automatically, and a new review shows what "
                "exists."
            ),
        }
        if draft.retained:
            if not account.command:
                texts.pop(Effect.SITE_ACCOUNT)
            if draft.directories:
                texts[Effect.SITE_DIRECTORIES] = "Creates only the absent directories listed below."
            else:
                texts.pop(Effect.SITE_DIRECTORIES)
            texts[Effect.SITE_FILES] = (
                "Publishes only the absent files and link listed below, with no replacement. "
                "Existing exact resources and the site's account IDs are revalidated and kept. "
                "Content stages stay in the root-owned site boundary before publication."
            )
        draft.effects.extend(texts.items())
        draft.postconditions.extend(
            [
                f"{user} and its group exist with the reviewed attributes and IDs in range.",
                "Each directory and file has its reviewed owner, mode and bytes.",
                f"php-fpm{php} -t and nginx -t accept the configuration; both services are active.",
                f"{paths.socket} is a socket owned by www-data with mode 0600.",
                (
                    f"Each name returns the placeholder, and the probe reports {user}'s IDs."
                    if paths.placeholder not in draft.retained
                    else (
                        f"Each name routes the temporary probe through the pool as {user}; "
                        "existing application content is kept."
                    )
                ),
                "The probe no longer exists.",
            ]
        )


@dataclass
class TreeRecognition:
    """What the site grammar recognizes under the Nginx and PHP-FPM trees
    (docs/sites.md#admission)."""

    # The convention files and enablement links, by identifier.
    sites: dict[str, RecognizedSite] = field(default_factory=dict)
    pools: set[str] = field(default_factory=set)
    links: set[str] = field(default_factory=set)
    # Each entry outside the grammar, with why.
    unsupported: list[str] = field(default_factory=list)
    # The other sites' and pools' files, tolerated for creating a different site.
    foreign: set[str] = field(default_factory=set)


def recognize_trees(evidence: SiteEvidence) -> TreeRecognition | None:
    """``None`` when the trees, their digests or the packages' defaults were not read."""
    tree, md5, release = evidence.tree, evidence.md5, evidence.release
    if tree is None or md5 is None or evidence.conffiles is None or evidence.ucf is None:
        return None
    if release is None:
        return None
    php = release.php
    roots = ("/etc/nginx", f"/etc/php/{php}/fpm", f"/etc/php/{php}/mods-available")
    under = tuple(f"{root}/" for root in roots)
    defaults = {
        item.path: item.md5
        for item in evidence.conffiles
        if not item.obsolete and item.path.startswith(under)
    }
    defaults.update(
        {path: digest for path, digest in evidence.ucf.items() if path.startswith(under)}
    )
    grammar = _Grammar(evidence, release, php, md5, defaults)
    found = grammar.found
    found.unsupported += [
        f"{path} (larger than {native.MAX_FILE} bytes)" for path in evidence.oversized
    ]
    devices = {item.path: item.device for item in tree if item.path in roots}
    found.unsupported += [
        f"{item.path} (on another filesystem than {root})"
        for item in tree
        for root in roots
        if item.path.startswith(f"{root}/") and item.device != devices.get(root)
    ]
    for item in tree:
        if item.kind == "f":
            grammar.recognize(item)
    files = {item.path for item in tree if item.kind == "f"}
    modules = files & set(defaults)
    found.unsupported += [
        f"{item.path} ({problem})" for item in tree if (problem := grammar.problem(item, modules))
    ]
    found.unsupported += [
        f"{path} (a distribution default that is missing)" for path in sorted(set(defaults) - files)
    ]
    return found


@dataclass
class _Grammar:
    evidence: SiteEvidence
    release: Release
    php: str
    md5: dict[str, str]
    defaults: dict[str, str]
    found: TreeRecognition = field(default_factory=TreeRecognition)

    def recognize(self, item: TreeItem) -> None:
        path = item.path
        directory, _, name = path.rpartition("/")
        metadata = item.uid == 0 and not item.mode & 0o022 and item.links == 1
        unsupported = self.found.unsupported
        if path in self.defaults:
            digest = self.md5.get(path)
            if digest is None:
                unsupported.append(f"{path} (unreadable)")
            elif digest != self.defaults[path]:
                unsupported.append(f"{path} (changed from the distribution's default)")
            elif not metadata:
                unsupported.append(f"{path} (writable by someone besides root, or hard-linked)")
            return
        identifier = name.removesuffix(".conf")
        text = self.evidence.contents.get(path) if name.endswith(".conf") else None
        convention = item.uid == 0 and item.gid == 0 and item.mode == 0o644 and item.links == 1
        if directory == SITES_AVAILABLE:
            # Any file here is a site file. One that does not match the convention is
            # another site's, tolerated for creating a different site (docs/adr/0015).
            recognized = recognize_site(identifier, text) if text is not None else None
            if recognized is not None and convention:
                self.found.sites[identifier] = recognized
            else:
                self.found.foreign.add(path)
            return
        pool = directory == f"/etc/php/{self.php}/fpm/pool.d" and text is not None
        if pool and text is not None and recognize_pool(identifier, text) and convention:
            self.found.pools.add(identifier)
            return
        if path == TLS_DEFAULT_PATH and is_tls_default(text, _facts(item)):
            return
        if directory == f"/etc/php/{self.php}/fpm/pool.d":
            self.found.foreign.add(path)
        unsupported.append(f"{path} (not a distribution file or an exact site template)")

    def problem(self, item: TreeItem, modules: set[str]) -> str:
        """``modules`` holds the distribution's module files present in the tree, the only
        targets a SAPI's conf.d link may name."""
        if item.kind == "d":
            return (
                "a directory someone besides root can write"
                if item.uid or item.mode & 0o022
                else ""
            )
        if item.kind == "f":
            return ""
        if item.kind != "l":
            return "a special file"
        if profiles.profile(self.release, Action.PHP).trees[0].links(item.path, item.target):
            return "" if item.target in modules else "a link to no distribution module file"
        known = profiles.profile(self.release, Action.NGINX).trees[0].links(
            item.path, item.target
        ) or self._convention_link(item)
        if known:
            return ""
        # An enabled site file that is not a link Barectl recognizes is another site's
        # enablement, tolerated for creating a different site (docs/adr/0015).
        if item.path.startswith(f"{SITES_ENABLED}/"):
            self.found.foreign.add(item.path)
            return ""
        return "a link Barectl does not recognize"

    def _convention_link(self, item: TreeItem) -> bool:
        directory, _, name = item.path.rpartition("/")
        identifier = name.removesuffix(".conf")
        recognized = (
            directory == SITES_ENABLED
            and name.endswith(".conf")
            and identifier in self.found.sites
            and item.target in SitePaths(identifier, self.php).link_targets
            and item.uid == 0
        )
        if recognized:
            self.found.links.add(identifier)
        return recognized


def _facts(item: TreeItem) -> FileFacts:
    file_type = FileType.FILE if item.kind == "f" else FileType.OTHER
    return FileFacts(file_type, item.uid, item.gid, item.mode, item.links)


def _unit_problem(load: str, active: str, sub: str) -> str:
    if load != "loaded":
        return f"is not loaded (systemd reports {load or 'nothing'})."
    if (active, sub) != ("active", "running"):
        return f"is {active}/{sub}, not active and running."
    return ""


def _ids(record: str) -> tuple[int | None, int | None]:
    parts = record.split(":")
    if len(parts) == 7 and parts[2].isdigit() and parts[3].isdigit():
        return int(parts[2]), int(parts[3])
    return None, None


def _range(settings: dict[str, str], prefix: str, admission: _Admission) -> tuple[int, int]:
    low = settings.get(f"{prefix}_MIN", str(DEFAULT_RANGE[0]))
    high = settings.get(f"{prefix}_MAX", str(DEFAULT_RANGE[1]))
    if not (low.isdigit() and high.isdigit()) or not 0 < int(low) <= int(high) < 2**31:
        admission.refuse(
            Reason.UNSUPPORTED_LAYOUT,
            f"/etc/login.defs sets {prefix}_MIN {low} and {prefix}_MAX {high}, which Barectl "
            "does not recognize as a range of normal accounts.",
        )
        return DEFAULT_RANGE
    return int(low), int(high)


def _free(bounds: tuple[int, int], used: frozenset[int]) -> int:
    low, high = bounds
    return high - low + 1 - sum(1 for value in used if low <= value <= high)


def _predict(bounds: tuple[int, int], used: frozenset[int]) -> int | None:
    """useradd's choice: after the highest ID used in range, else the lowest free one."""
    low, high = bounds
    taken = sorted(value for value in used if low <= value <= high)
    if not taken:
        return low
    if taken[-1] < high:
        return taken[-1] + 1
    candidate = low
    for value in taken:
        if value != candidate:
            return candidate
        candidate += 1
    return None


def _describe(state: PathState) -> str:
    if not state.present:
        return "missing."
    kinds = {"d": "a directory", "l": "a symbolic link", "f": "a file", "s": "a socket"}
    kind = kinds.get(state.kind, "another type of file")
    return f"{kind} owned by UID {state.uid} with mode {state.mode:04o}."


def _listed(items: list[str]) -> str:
    shown = "; ".join(items[:_LISTED])
    more = len(items) - _LISTED
    return f"{shown}; and {more} more" if more > 0 else shown
