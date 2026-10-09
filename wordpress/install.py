"""The WordPress installation review: its admission, refusals and proposed effects.

docs/wordpress.md#installation-review. Preparation changes nothing and starts no
application code. It stands on the existing workflows' own evidence, each judged by the
module that owns it: the complete convention site and its covered HTTPS lineage, the
satisfied MariaDB binding, the selected CLI and pool capabilities and the authenticated
WP-CLI. It adds only what is new: the site's public and private trees and its database
must hold nothing, the toolchain and capacity must exist, and the official archive must
still be what the review pins.
"""

import hashlib
import secrets
from collections.abc import Callable
from typing import override

from bootstrap import native as bootstrap_native
from bootstrap.evidence import Platform
from bootstrap.models import (
    ADMISSION_CENTISECONDS,
    Action,
    PlanEffect,
    PlanEvidence,
    PlanPreparation,
    PlanRefusal,
)
from bootstrap.releases import Release
from bootstrap.releases import of as releases_of
from bootstrap.review import Draft, EvidenceDraft
from databases import admission as binding_admission
from discovery.models import DatabaseEngine
from discovery.ssh import RemoteShell
from operations.lifecycle import OperationRefused
from sites import admission as site_admission
from sites import inspection as site_inspection
from sites.convention import (
    Application,
    RecognizedSite,
    SitePaths,
    Stage,
    recognize_site,
    render_placeholder,
    render_site,
)
from sites.names import IDENTIFIER
from tls import activation as tls_activation
from tls import readiness

from . import convention, core_native, inputs, install_native, runtime, setup, setup_native
from .models import InstallationRequest, InstallationReview, PlanWordpressInstall, RuntimeCapability
from .runtime import CapabilityDraft

Reason = PlanRefusal.Reason
Effect = PlanEffect.Kind
Kind = PlanEvidence.Kind
# The revision of the installation definitions a plan was reviewed against.
PROFILE_REVISION = 1
_LISTED = 3

MISSING_REQUEST = (
    "The WordPress installation request of this preparation is not recorded, so Barectl read "
    "nothing from the server."
)
INVALID_REQUEST = (
    "The recorded WordPress installation request is not valid, so Barectl read nothing from "
    "the server: {0} Prepare a new review."
)
NOT_COMPLETE = (
    "The site {0} is not complete as the site convention requires, so WordPress is not "
    "installed on it. Complete the site first (its review in the site's Overview or the "
    "server's Advanced section proposes what is missing)."
)
ROUTED = (
    "The site file of {0} already routes {1}, so this is not a first installation. Barectl "
    "never converts or adopts an existing application; inspect it through ordinary "
    "administration."
)
NO_HTTPS = (
    "The site {0} does not serve HTTPS with the HTTP redirect yet (its site file is in the "
    "{1} form). WordPress installs on a complete HTTPS site: activate the site's HTTPS first."
)
UNCOVERED = (
    "{0} is not one of the names the site {1} serves and its certificate covers "
    "({2}). Choose one of those names as the canonical HTTPS name."
)
UNQUALIFIED = (
    "WordPress {0} with PHP {1} from {2} packages on Ubuntu {3} ({4}) has not completed "
    "Barectl's qualification. Only the release's own PHP branch from Ubuntu packages, on "
    "amd64 or arm64, is qualified; Barectl does not change the site's PHP selection."
)
CHANGED_WHILE_READ = "{0} changed while Barectl read it. Prepare again once it is settled."


class InstallDraft(readiness.TlsSiteDraft):
    """An installation review before it is saved."""

    def __init__(
        self,
        identifier: str,
        token: str,
        wanted: inputs.Metadata,
        platform: Platform | None = None,
        release: Release | None = None,
        action: Action = Action.WORDPRESS_INSTALL,
    ) -> None:
        super().__init__(
            action,
            intent(identifier, wanted.canonical_name),
            platform,
            release,
        )
        self.identifier = identifier
        self.token = token
        self.wanted = wanted
        self.paths: SitePaths | None = None
        self.uid = 0
        self.gid = 0
        self.preimage = ""
        self.gate_content = ""
        self.ready_content = ""
        self.placeholder_sha256 = ""
        self.placeholder_present = False
        self.loader_sha256 = ""
        self.tool_path = setup_native.PHAR
        self.runtime_lines: list[str] = []
        self.capabilities: list[CapabilityDraft] = []
        self.free_bytes = 0
        self.engine_other = False
        self.body_sha256 = ""
        self.payload_bytes: int | None = None

    @property
    @override
    def revision(self) -> int:
        return PROFILE_REVISION

    @property
    def ready(self) -> bool:
        """Whether the review is complete enough to save its typed rows."""
        return self.eligible and bool(self.gate_content and self.ready_content)


def intent(identifier: str, name: str) -> str:
    return (
        f"Install WordPress {core_native.VERSION} on the site {identifier} at https://{name}/, "
        "using the authenticated WP-CLI."
    )[:200]


def digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def wanted_of(request: InstallationRequest) -> inputs.Metadata:
    return inputs.Metadata(
        request.canonical_name, request.title, request.admin_login, request.admin_email
    )


def prepare(preparation: PlanPreparation, shell: RemoteShell) -> InstallDraft:
    request = InstallationRequest.objects.filter(preparation=preparation).first()
    if request is None:
        raise OperationRefused(MISSING_REQUEST)
    wanted = wanted_of(request)
    found = inputs.problems(wanted)
    if not IDENTIFIER.fullmatch(request.identifier):
        found.append("The site identifier is not valid.")
    if found:
        raise OperationRefused(INVALID_REQUEST.format(" ".join(found)))
    identifier = request.identifier
    token = secrets.token_hex(16)
    site = site_inspection.inspect(shell, identifier, token)
    release = releases_of(site.platform.os) if site.platform is not None else None
    draft = InstallDraft(identifier, token, wanted, site.platform, release)
    recognized = site_admission.complete(draft, site, identifier, token)
    if recognized is None:
        if draft.eligible:
            draft.refuse(Reason.PREREQUISITE, NOT_COMPLETE.format(identifier))
        return draft
    paths = site.paths
    if paths is None or site.release is None or site.platform is None:
        draft.refuse(Reason.INCOMPLETE, "Barectl could not read the site's native layout.")
        return draft
    _record_site(draft, site, paths, recognized)
    _site(draft, site.platform.architecture, recognized.application, recognized.stage)
    if recognized.stage.activated:
        tls_activation.lineage(draft, shell, identifier)
    _binding(draft, shell, site)
    _runtime(draft, shell)
    _tool(draft, shell)
    _application(draft, shell)
    _supply(draft, shell)
    if draft.eligible:
        _candidates(draft, recognized.ipv6, recognized.php_version)
    if draft.ready:
        _effects(draft)
        row = PlanWordpressInstall(**install_fields(draft))
        _payload(draft, row, install_native.staged_payload)
    return draft


# The site ----


def _record_site(
    draft: InstallDraft,
    site: site_inspection.SiteEvidence,
    paths: SitePaths,
    recognized: RecognizedSite,
) -> None:
    draft.paths = paths
    draft.names, draft.ipv6 = recognized.names, recognized.ipv6
    draft.php_version, draft.php_supply = paths.php, site.php_supply
    draft.site_revision = paths.revision
    draft.preimage = site.contents.get(paths.source) or ""
    fields = (site.accounts.user if site.accounts else "").split(":")
    if len(fields) >= 4 and fields[2].isdigit() and fields[3].isdigit():
        draft.uid, draft.gid = int(fields[2]), int(fields[3])
    else:
        draft.refuse(Reason.INCOMPLETE, "The site user and group could not be read.")


def _site(draft: InstallDraft, architecture: str, application: Application, stage: Stage) -> None:
    identifier, wanted = draft.identifier, draft.wanted
    if application.wordpress:
        draft.refuse(
            Reason.EXISTING_APPLICATION,
            ROUTED.format(identifier, "WordPress through its provisioning gate or ready form"),
        )
    if stage != Stage.REDIRECT:
        draft.refuse(Reason.PREREQUISITE, NO_HTTPS.format(identifier, stage.value))
    if wanted.canonical_name not in draft.names:
        draft.refuse(
            Reason.PREREQUISITE,
            UNCOVERED.format(wanted.canonical_name, identifier, ", ".join(draft.names)),
        )
    _qualified(draft, architecture)


def _qualified(draft: InstallDraft, architecture: str) -> None:
    """Only the release's own PHP branch from Ubuntu packages, on amd64 or arm64, is
    qualified for the pinned WordPress."""
    release = draft.release
    if release is not None and (
        draft.php_supply != "ubuntu"
        or draft.php_version != release.php
        or architecture not in {"amd64", "arm64"}
    ):
        draft.refuse(
            Reason.UNSUPPORTED_VERSION,
            UNQUALIFIED.format(
                core_native.VERSION,
                draft.php_version,
                draft.php_supply,
                release.version,
                architecture,
            ),
        )


def _site_digest(draft: Draft) -> str:
    return next(
        (item.fingerprint for item in draft.evidence if item.kind == Kind.SITE_REVALIDATION), ""
    )


def _merge(draft: InstallDraft, other: Draft, kinds: set[PlanEvidence.Kind]) -> None:
    present = {item.kind for item in draft.evidence}
    for item in other.evidence:
        if item.kind in kinds and item.kind not in present:
            draft.evidence.append(item)
            present.add(item.kind)


def _same_site(draft: InstallDraft, other: Draft, what: str) -> None:
    mine, theirs = _site_digest(draft), _site_digest(other)
    if mine and theirs and mine != theirs:
        draft.refuse(Reason.INCOMPLETE, CHANGED_WHILE_READ.format(f"The site {what}"))


# The database binding ----


def _binding(draft: InstallDraft, shell: RemoteShell, site: site_inspection.SiteEvidence) -> None:
    identifier = draft.identifier
    reviewed = binding_admission.review(
        shell, site, identifier, DatabaseEngine.MARIADB, draft.token
    )
    if reviewed.no_changes:
        _same_site(draft, reviewed, "binding read")
        _merge(draft, reviewed, {Kind.PACKAGE_REVALIDATION, Kind.DRIVER, Kind.CATALOG})
        draft.engine_other = reviewed.other_engine
        return
    if any(reason == Reason.EXISTING_BINDING for reason, _ in reviewed.refusals) or (
        _bound_to_postgresql(draft, shell, site)
    ):
        draft.refuse(
            Reason.UNSUPPORTED_ENGINE,
            f"PostgreSQL holds the site {identifier}'s database binding. WordPress needs the "
            "site's MariaDB binding, and Barectl converts no engine, moves no data and adds no "
            "PostgreSQL adapter.",
        )
        return
    problems = "; ".join(text for _, text in reviewed.refusals[:_LISTED])
    draft.refuse(
        Reason.PREREQUISITE,
        f"The site {identifier} has no satisfied MariaDB binding: "
        f"{problems or 'its binding review proposes changes.'} Prepare and apply the site's "
        "MariaDB database first; this review binds nothing.",
    )


def _bound_to_postgresql(
    draft: InstallDraft, shell: RemoteShell, site: site_inspection.SiteEvidence
) -> bool:
    """Whether the site has a satisfied PostgreSQL binding, for a server on which MariaDB is
    not established and so could not show it."""
    other = binding_admission.review(
        shell, site, draft.identifier, DatabaseEngine.POSTGRESQL, draft.token
    )
    return other.no_changes


# The runtime and the tool ----


def _runtime(draft: InstallDraft, shell: RemoteShell) -> None:
    reviewed = runtime.prepare(shell, draft.identifier)
    _same_site(draft, reviewed, "runtime read")
    if not reviewed.eligible:
        problems = "; ".join(text for _, text in reviewed.refusals[:_LISTED])
        draft.refuse(
            Reason.PREREQUISITE,
            f"The selected PHP runtime cannot be established for WordPress: {problems}",
        )
        return
    missing = [
        item.label
        for item in reviewed.capabilities
        if item.state != RuntimeCapability.State.ENABLED
    ] or (["every baseline capability"] if not reviewed.capabilities else [])
    if missing or not reviewed.no_changes:
        draft.refuse(
            Reason.PREREQUISITE,
            f"The selected CLI and the site's PHP-FPM do not both load the WordPress baseline "
            f"({', '.join(missing) or 'its packages are not installed'}). Prepare and apply the "
            "site's WordPress PHP runtime plan first; this review installs no package.",
        )
        return
    draft.capabilities = list(reviewed.capabilities)
    draft.runtime_lines = sorted(
        f"{item.name} {int(item.cli)} {int(item.fpm)}" for item in draft.capabilities
    )
    draft.fingerprint(
        Kind.WORDPRESS_RUNTIME,
        draft.runtime_lines,
        f"PHP {draft.php_version}: every baseline capability loads in the selected CLI and "
        "the site's PHP-FPM as of this read; the run proves the pool itself with a private probe.",
    )


def _tool(draft: InstallDraft, shell: RemoteShell) -> None:
    reviewed = setup.prepare(shell)
    if reviewed.observed.get("phar") == "absent":
        draft.refuse(
            Reason.PREREQUISITE,
            f"The authenticated WP-CLI {setup_native.VERSION} is not installed at "
            f"{setup_native.PHAR}. Prepare and apply the server's WP-CLI setup plan first; "
            "this review installs no tool.",
        )
        return
    if not reviewed.eligible or not reviewed.installed:
        problems = "; ".join(text for _, text in reviewed.refusals[:_LISTED])
        draft.refuse(
            Reason.PREREQUISITE,
            f"The WP-CLI tool cannot be verified: {problems or 'it is not installed.'}",
        )
        return
    _merge(draft, reviewed, {Kind.WPCLI_REVALIDATION})


# The application's files and database ----


def _read(draft: InstallDraft, shell: RemoteShell, argv: list[str], what: str) -> str | None:
    text = readiness.root_read(draft, shell, argv)
    if text is None and draft.eligible:
        draft.refuse(Reason.INCOMPLETE, f"Barectl could not read {what}. Prepare again.")
    return text


def _application(draft: InstallDraft, shell: RemoteShell) -> None:
    identifier = draft.identifier
    first = _read(
        draft, shell, core_native.files_argv(identifier), "the site's public and private trees"
    )
    database = _read(
        draft, shell, core_native.database_argv(identifier), "the site database's catalog"
    )
    again = _read(
        draft, shell, core_native.files_argv(identifier), "the site's public and private trees"
    )
    if first is None or database is None or again is None:
        return
    if first != again:
        draft.refuse(
            Reason.INCOMPLETE, CHANGED_WHILE_READ.format("The site's public or private tree")
        )
        return
    try:
        files = core_native.parse_files(first)
        catalog = core_native.parse_database(database)
    except core_native.Unreadable as unreadable:
        draft.refuse(Reason.INCOMPLETE, str(unreadable))
        return
    draft.placeholder_sha256 = digest(render_placeholder(identifier))
    _files(draft, files)
    _database(draft, catalog)
    if draft.eligible:
        # The digest of the read's exact output, as the same script piped to sha256sum
        # computes it under the lock.
        draft.evidence += [
            EvidenceDraft(
                Kind.WORDPRESS_FILES,
                digest(first),
                "The site directory's entries, with the public tree holding only the exact "
                "placeholder and the private directory empty, rechecked under the lock.",
            ),
            EvidenceDraft(
                Kind.WORDPRESS_DATABASE,
                digest(database),
                f"The database s{identifier} exists and holds no table, routine, event or "
                "trigger, rechecked under the lock.",
            ),
        ]


def _files(draft: InstallDraft, files: core_native.FileState) -> None:
    identifier = draft.identifier
    if not files.complete:
        draft.refuse(
            Reason.INCOMPLETE,
            f"Barectl could not list the site {identifier}'s directories completely.",
        )
        return
    kept = {"public", "private"}
    foreign = sorted(entry.path for entry in files.site if entry.path not in kept)
    if foreign:
        draft.refuse(
            Reason.COLLISION,
            f"/var/www/{identifier} holds {', '.join(foreign[:_LISTED])}, which the site "
            "convention does not create. Barectl adopts and removes nothing; correct it "
            "through ordinary administration.",
        )
    for entry in files.site:
        if entry.path in kept and entry.kind != "d":
            draft.refuse(
                Reason.UNSUPPORTED_LAYOUT,
                f"/var/www/{identifier}/{entry.path} is not a directory.",
            )
    _public(draft, files)
    private = [entry.path for entry in files.private]
    if private:
        draft.refuse(
            Reason.EXISTING_APPLICATION,
            f"The private directory of {identifier} holds {', '.join(private[:_LISTED])}"
            f"{' (a private WordPress configuration)' if 'wp-config.php' in private else ''}. "
            "Barectl never adopts or replaces private files.",
        )


def _public(draft: InstallDraft, files: core_native.FileState) -> None:
    identifier = draft.identifier
    others = [entry for entry in files.public if entry.path != "index.html"]
    if others:
        names = [entry.path.split("/")[0] for entry in others]
        application = sorted(set(names) & core_native.APPLICATION_NAMES)
        draft.refuse(
            Reason.EXISTING_APPLICATION,
            (
                f"The public tree of {identifier} holds WordPress files "
                f"({', '.join(application)}). "
                if application
                else f"The public tree of {identifier} holds content other than the site "
                f"placeholder ({', '.join(sorted(set(names))[:_LISTED])}). "
            )
            + "Barectl never overwrites, adopts, converts or deletes existing content; "
            "inspect it through ordinary administration.",
        )
    placeholder = next((entry for entry in files.public if entry.path == "index.html"), None)
    if placeholder is None:
        return
    if placeholder.kind != "f" or placeholder.links != 1:
        draft.refuse(
            Reason.UNSUPPORTED_LAYOUT,
            f"The public index.html of {identifier} is not a single regular file.",
        )
    elif files.placeholder_sha256 != digest(render_placeholder(identifier)):
        draft.refuse(
            Reason.EXISTING_APPLICATION,
            f"The public index.html of {identifier} is not the exact known placeholder, so it "
            "may be application content. Barectl replaces only the exact placeholder.",
        )
    else:
        draft.placeholder_present = True


def _database(draft: InstallDraft, catalog: core_native.DatabaseState) -> None:
    identifier = draft.identifier
    if not catalog.exists:
        draft.refuse(
            Reason.PREREQUISITE,
            f"The database s{identifier} does not exist, so there is no satisfied binding to "
            "install into.",
        )
    elif not catalog.empty:
        held = (
            f"{catalog.tables} table(s)"
            f"{' (' + ', '.join(catalog.names) + ')' if catalog.names else ''}, "
            f"{catalog.routines} routine(s), {catalog.events} event(s) and "
            f"{catalog.triggers} trigger(s)"
        )
        draft.refuse(
            Reason.EXISTING_APPLICATION,
            f"The database s{identifier} is not empty: it holds {held}. Core installation "
            "runs only into a wholly empty database, and Barectl converts, drops and replays "
            "nothing; a partial WordPress schema needs ordinary administration.",
        )


# Supply ----


def _supply(draft: InstallDraft, shell: RemoteShell) -> None:
    text = _read(draft, shell, core_native.supply_argv(), "the toolchain, capacity and archive")
    if text is None:
        return
    try:
        supply = core_native.parse_supply(text)
    except core_native.Unreadable as unreadable:
        draft.refuse(Reason.INCOMPLETE, str(unreadable))
        return
    missing = sorted(name for name, found in supply.tools.items() if not found)
    if missing:
        draft.refuse(
            Reason.PREREQUISITE,
            f"The server lacks /usr/bin/{', /usr/bin/'.join(missing)}, which the run needs "
            "to bound and verify the archive. Install them through ordinary administration; "
            "Barectl installs no package here.",
        )
    draft.free_bytes = supply.free_bytes
    if supply.free_bytes < core_native.REQUIRED_FREE_BYTES:
        draft.refuse(
            Reason.PREREQUISITE,
            f"/var/www has {supply.free_bytes} bytes free, fewer than the "
            f"{core_native.REQUIRED_FREE_BYTES} bytes the archive and a staged and a published "
            "tree can need within the reviewed limits.",
        )
    if supply.tools.get("curl"):
        if supply.archive_status != 200:
            draft.refuse(
                Reason.PREREQUISITE,
                f"The server cannot reach {core_native.ARCHIVE_URL} over trusted HTTPS "
                f"(status {supply.archive_status or 'none'}). Fix the server's network, "
                "resolver or CA store through ordinary administration.",
            )
        elif supply.archive_bytes != core_native.ARCHIVE_BYTES:
            draft.refuse(
                Reason.INCOMPLETE,
                f"{core_native.ARCHIVE_URL} announces {supply.archive_bytes or 'no'} bytes, "
                f"not the reviewed {core_native.ARCHIVE_BYTES}. A different archive is refused "
                "until Barectl's reviewed pin changes.",
            )


# Candidates and effects ----


def _candidates(draft: InstallDraft, ipv6: bool, php_version: str) -> None:
    identifier, names, canonical = draft.identifier, draft.names, draft.wanted.canonical_name
    candidates = {
        application: render_site(
            identifier,
            names,
            ipv6=ipv6,
            stage=Stage.REDIRECT,
            php_version=php_version,
            application=application,
            canonical=canonical,
        )
        for application in (Application.WORDPRESS_GATE, Application.WORDPRESS)
    }
    for application, text in candidates.items():
        found = recognize_site(identifier, text)
        if found is None or found.application != application or found.canonical_name != canonical:
            draft.refuse(Reason.INCOMPLETE, "Barectl could not build the reviewed routing forms.")
            return
    draft.gate_content = candidates[Application.WORDPRESS_GATE]
    draft.ready_content = candidates[Application.WORDPRESS]
    draft.loader_sha256 = digest(convention.render_loader(identifier))


def install_fields(draft: InstallDraft) -> dict[str, object]:
    """The installation review's fields, from a draft that is ready to be saved."""
    paths = draft.paths
    if paths is None:
        raise ValueError("The installation review has no site paths.")
    identifier, wanted = draft.identifier, draft.wanted
    return {
        "identifier": identifier,
        "php_version": draft.php_version,
        "php_supply": draft.php_supply,
        "site_revision": draft.site_revision,
        "site_user": paths.user,
        "uid": draft.uid,
        "gid": draft.gid,
        "socket": paths.socket,
        "ipv6": draft.ipv6,
        "names": " ".join(draft.names),
        "canonical_name": wanted.canonical_name,
        "url": f"https://{wanted.canonical_name}",
        "title": wanted.title,
        "admin_login": wanted.admin_login,
        "admin_email": wanted.admin_email,
        "certificate_sha256": draft.certificate,
        "certificate_not_after": draft.not_after,
        "tool_version": setup_native.VERSION,
        "tool_path": setup_native.PHAR,
        "tool_sha256": setup_native.SHA256,
        "core_version": core_native.VERSION,
        "core_locale": core_native.LOCALE,
        "archive_url": core_native.ARCHIVE_URL,
        "archive_bytes": core_native.ARCHIVE_BYTES,
        "archive_sha256": core_native.ARCHIVE_SHA256,
        "max_archive_bytes": core_native.MAX_ARCHIVE_BYTES,
        "max_tree_bytes": core_native.MAX_TREE_BYTES,
        "max_entries": core_native.MAX_ENTRIES,
        "max_file_bytes": core_native.MAX_FILE_BYTES,
        "memory_max_bytes": core_native.MEMORY_MAX_BYTES,
        "runtime_limit_seconds": core_native.RUNTIME_LIMIT_SECONDS,
        "preimage_sha256": digest(draft.preimage),
        "gate_sha256": digest(draft.gate_content),
        "gate_content": draft.gate_content,
        "ready_sha256": digest(draft.ready_content),
        "ready_content": draft.ready_content,
        "placeholder_sha256": draft.placeholder_sha256,
        "placeholder_present": draft.placeholder_present,
        "loader_sha256": draft.loader_sha256,
        "public_root": convention.public_root(identifier),
        "private_configuration": convention.private_configuration_path(identifier),
        "database_name": f"s{identifier}",
        "engine_other": draft.engine_other,
        "body_sha256": draft.body_sha256,
        "payload_bytes": draft.payload_bytes,
    }


def password_command(identifier: str, php_version: str, name: str, login: str) -> str:
    """The first-login terminal step: the selected CLI, as the site user, prompting for the
    password on stdin (docs/adr/0018-generate-wordpress-secrets-on-the-server.md)."""
    return (
        f"sudo -u s{identifier} /usr/bin/php{php_version} {setup_native.PHAR} "
        f"--path={convention.public_root(identifier)} --url=https://{name} "
        f"user update {login} --prompt=user_pass --skip-email"
    )


def _evidence(draft: InstallDraft) -> install_native.Evidence | None:
    digests = {item.kind: item.fingerprint for item in draft.evidence}
    try:
        return install_native.Evidence(
            site=digests[Kind.SITE_REVALIDATION],
            lineage=digests[Kind.LINEAGE_REVALIDATION],
            package=digests[Kind.PACKAGE_REVALIDATION],
            driver=digests[Kind.DRIVER],
            catalog=digests[Kind.CATALOG],
            wpcli=digests[Kind.WPCLI_REVALIDATION],
            files=digests[Kind.WORDPRESS_FILES],
            database=digests[Kind.WORDPRESS_DATABASE],
        )
    except KeyError:
        return None


def _payload[R: InstallationReview](
    draft: InstallDraft,
    row: R,
    build: Callable[[str, str, int, R, install_native.Evidence, str], tuple[str, str]],
) -> None:
    """Build the payload applying would submit, exactly as applying builds it, and refuse a
    review whose payload would not fit one run rather than split it."""
    platform, release = draft.platform, draft.release
    evidence = _evidence(draft)
    if platform is None or platform.uptime_centiseconds is None or release is None or not evidence:
        draft.refuse(Reason.INCOMPLETE, "Barectl could not build the reviewed payload.")
        return
    try:
        text, body = build(
            bootstrap_native.new_unit_name(),
            platform.boot_id,
            platform.uptime_centiseconds + ADMISSION_CENTISECONDS,
            row,
            evidence,
            release.version,
        )
    except ValueError:
        draft.refuse(Reason.INCOMPLETE, "Barectl could not build the reviewed payload.")
        return
    draft.body_sha256 = digest(body)
    draft.payload_bytes = len(text.encode())
    if draft.payload_bytes > bootstrap_native.MAX_PAYLOAD:
        draft.refuse(
            Reason.PAYLOAD_TOO_LARGE,
            f"Applying this review would submit {draft.payload_bytes} bytes, more than the "
            f"{bootstrap_native.MAX_PAYLOAD} bytes Barectl submits in one run. Barectl never "
            "splits a reviewed action.",
        )


def _effects(draft: InstallDraft) -> None:
    identifier, wanted, php = draft.identifier, draft.wanted, draft.php_version
    name = wanted.canonical_name
    root = convention.public_root(identifier)
    private = convention.private_configuration_path(identifier)
    aliases = [item for item in draft.names if item != name]
    placeholder = (
        f"replacing only the exact placeholder index.html (SHA-256 {draft.placeholder_sha256}) "
        "and no other file."
        if draft.placeholder_present
        else "into a public tree that is empty and replacing no file."
    )
    draft.effects += [
        (
            Effect.APP_ARTIFACTS,
            (
                f"Runs the authenticated WP-CLI {setup_native.VERSION} at {setup_native.PHAR} "
                f"(SHA-256 {setup_native.SHA256}) as the site user s{identifier} with "
                f"/usr/bin/php{php}, a controlled environment and a private temporary "
                "directory, never as root and never with --allow-root. "
                f"`core download` fetches only {core_native.ARCHIVE_URL} with --no-extract: "
                f"{core_native.ARCHIVE_BYTES} bytes, SHA-256 {core_native.ARCHIVE_SHA256}. Native "
                "sha256sum must match before native tar admits regular files and directories "
                "under the sole wordpress/ prefix, with no links, devices or traversal. "
                f"`core verify-checksums` then checks {core_native.VERSION}/{core_native.LOCALE}. "
                "No latest version is resolved, and nothing downloaded executes before the "
                "archive and tree checks pass."
            ),
        ),
        (
            Effect.APP_FILES,
            (
                f"Publishes the release files and wp-content into {root} (directories 0755, "
                f"files 0644, owned by s{identifier}), {placeholder} The fixed "
                f"public loader {root}/wp-config.php (s{identifier}:www-data 0640, SHA-256 "
                f"{draft.loader_sha256}) requires {private}, which holds the passwordless "
                f"socket configuration for database s{identifier} (DB_HOST "
                f"{convention.DB_HOST}, empty DB_PASSWORD, prefix {convention.TABLE_PREFIX}) "
                f"and eight salts generated on the server (s{identifier}:s{identifier} 0600). "
                "Files are published without following links or recursively changing existing "
                "ownership, only where the destination is absent or the placeholder."
            ),
        ),
        (
            Effect.APP_SCHEMA,
            (
                f"`core install` creates the twelve WordPress core tables with prefix "
                f"{convention.TABLE_PREFIX} in the empty database s{identifier} through the "
                f"local socket as s{identifier}, with site URL and home https://{name}, title "
                f'"{wanted.title}", administrator login {wanted.admin_login} and email '
                f"{wanted.admin_email}, and --skip-email. Nothing is installed into a database "
                "that holds any table."
            ),
        ),
        (
            Effect.APP_NETWORK,
            (
                "The server, not the controller, makes the outbound HTTPS requests: the "
                f"archive from {core_native.ARCHIVE_URL}, and WP-CLI's core checksum catalog "
                "from wordpress.org. This review made one HEAD request for the archive's size "
                "and downloaded nothing. Public checksums are integrity evidence, not a "
                "signature or a malware scan."
            ),
        ),
        (
            Effect.APP_EXPOSURE,
            (
                f"Before any application file or table exists, the site file is replaced by "
                f"the provisioning gate (SHA-256 {digest(draft.gate_content)}): application and "
                "PHP paths answer 503, /wp-admin/install.php is blocked and the HTTP-01 "
                "challenge route is kept. After schema, options, integrity and private "
                "CLI and pool access verify while gated, the site file becomes the ready form "
                f"(SHA-256 {digest(draft.ready_content)}) serving WordPress at https://{name}/"
                + (
                    f", with {', '.join(aliases)} redirecting there over HTTP and HTTPS. "
                    if aliases
                    else ". "
                )
                + f"The current site file (SHA-256 {digest(draft.preimage)}) is kept as a "
                "root-only recovery preimage and nginx -t must accept each form before its "
                "reload. If serving verification fails, Barectl restores the gate only while "
                "the current bytes still equal this ready form; if it cannot prove that, it "
                "reports the potentially exposed state. Application files and tables are "
                "never erased."
            ),
        ),
        (
            Effect.APP_ACCOUNT,
            (
                f"Creates the administrator {wanted.admin_login} <{wanted.admin_email}>. Its "
                f"initial password is generated on the server as s{identifier}, fed directly to "
                "WP-CLI's documented prompt and discarded; it is never shown, recorded, sent by "
                "email or placed in a command line, environment, unit text, journal or this "
                "page. Installation is therefore followed by a required terminal step, "
                '"Administrator password setup required": '
                f"{password_command(identifier, php, name, wanted.admin_login)}"
            ),
        ),
        (
            Effect.APP_LIMITS,
            (
                "Applying is one finite transient systemd unit under the shared native "
                "mutation lock: it refuses when the server restarted after review, when the "
                "admission deadline passed, when another change or certificate renewal holds "
                "the lock, or when any reviewed evidence changed, before changing anything. "
                f"It runs at most {core_native.RUNTIME_LIMIT_SECONDS // 60} minutes, with a "
                f"{core_native.MAX_ARCHIVE_BYTES // 2**20} MiB archive limit, a "
                f"{core_native.MAX_TREE_BYTES // 2**20} MiB / {core_native.MAX_ENTRIES} entry "
                f"extracted tree, {core_native.MAX_FILE_BYTES // 2**20} MiB per file and "
                f"{core_native.MEMORY_MAX_BYTES // 2**20} MiB of memory; a larger archive is "
                "refused. The web server, cron and WordPress's own updater stay outside the lock."
            ),
        ),
        (
            Effect.NO_ROLLBACK,
            (
                "Installation is not transactional. After a failure Barectl keeps the files, "
                "tables, salts and accounts it created and keeps the gate; it drops no database, "
                "removes no content and never replays core installation into partial tables. "
                "Ordinary administration recovers a partial installation."
            ),
        ),
    ]
    draft.postconditions += [
        (
            f"Database s{identifier} holds exactly the twelve core tables and canonical siteurl "
            f"and home options of https://{name}."
        ),
        (
            "The release files match the pinned archive and core integrity verifies for "
            f"{core_native.VERSION}/{core_native.LOCALE}."
        ),
        (
            "WP-CLI and a private FastCGI request through the site's pool both reach the "
            f"application as s{identifier} while the site is gated."
        ),
        (
            f"After the ready form is published, https://{name}/ and its login answer, and the "
            "public configuration, uploaded PHP and private paths are denied."
        ),
        "The administrator exists without a usable password until the terminal step is done.",
    ]
