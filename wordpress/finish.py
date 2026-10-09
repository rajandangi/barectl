"""The WordPress Finish review: eligible missing work of a partial installation.

docs/wordpress.md#finishing-a-partial-installation. Preparation changes nothing and starts no
application code. It reconstructs eligibility from the server alone, with no record of any
earlier request or run: the site file must be the exact provisioning gate, every existing
release file must equal the pinned archive, an existing private configuration must be the
supported grammar, and the database must be wholly empty or hold exactly the installed core
schema. It stands on the same site, certificate, binding, runtime and WP-CLI workflows the
installation review does, and adds only the reads and decisions of what exists.
"""

import secrets
from typing import override

from bootstrap.evidence import Platform
from bootstrap.models import Action, PlanEffect, PlanEvidence, PlanPreparation, PlanRefusal
from bootstrap.releases import Release
from bootstrap.releases import of as releases_of
from bootstrap.review import EvidenceDraft
from discovery.ssh import RemoteShell
from operations.lifecycle import OperationRefused
from sites import admission as site_admission
from sites import inspection as site_inspection
from sites.convention import Application, RecognizedSite, Stage, render_placeholder
from sites.names import IDENTIFIER
from tls import activation as tls_activation

from . import convention, core_native, finish_native, inputs, install, setup_native
from .install import InstallDraft, digest
from .models import FinishRequest, PlanWordpressFinish

Reason = PlanRefusal.Reason
Effect = PlanEffect.Kind
Kind = PlanEvidence.Kind
_LISTED = 5
PROFILE_REVISION = 1
# Ubuntu's fixed www-data group, which owns the public loader beside the site user.
WWW_DATA_GID = 33

MISSING_REQUEST = (
    "The WordPress Finish request of this preparation is not recorded, so Barectl read nothing "
    "from the server."
)
NOT_GATED = (
    "The site file of {0} is not the exact WordPress provisioning gate ({1}), so there is no "
    "installation stopped behind a gate for Barectl to finish. Finish never converts or adopts "
    "an existing application: if WordPress was never installed here, prepare an installation "
    "review; otherwise inspect the server through ordinary administration."
)
FOREIGN_SITE = (
    "/var/www/{0} holds {1}, which the site convention does not create. A leftover .wp-* "
    "directory is the staging area of a killed run and is safe to remove once no unit uses "
    "it. Barectl adopts and removes nothing; correct it through ordinary administration."
)
TOO_MANY = (
    "The public tree of {0} holds more than {1} entries, far more than a WordPress release "
    "does. Barectl never adopts or deletes existing content; inspect it through ordinary "
    "administration."
)
EDITED = (
    "The release files of {0} differ from the pinned WordPress {1} archive ({2}). Barectl "
    "compares them with a copy of the same pinned archive and never replaces an existing "
    "file, so it finishes nothing on top of edited or ambiguous files; correct them through "
    "ordinary administration."
)
FOREIGN_FILES = (
    "The public tree of {0} holds {1}, which is neither a WordPress release file nor the "
    "site's loader or placeholder. Barectl never adopts, overwrites or deletes existing "
    "content; inspect it through ordinary administration."
)
CONTENT_MISSING = (
    "The database of {0} already holds the installation, but its wp-content directory is "
    "missing. wp-content is the operator's content once WordPress is installed, so Barectl "
    "does not recreate it from the archive; restore it through ordinary administration."
)
PARTIAL_TABLES = (
    "The database s{0} holds {1}, which is not exactly the complete WordPress core schema with "
    "the canonical options of {2}. Barectl never replays core installation into partial "
    "tables, repairs a schema or drops anything; a partial or altered schema needs ordinary "
    "administration."
)
OPTIONS_DIFFER = (
    "The database s{0} holds the complete core schema, but its siteurl and home options are "
    "not {1}, the address the site file routes. Barectl changes no option; correct it through "
    "ordinary administration."
)
NEEDS_METADATA = (
    "The database s{0} is wholly empty, so finishing runs core installation once and needs "
    "the site title and administrator: {1} Prepare a new review with them."
)
LOADER_OTHER = (
    "The public wp-config.php of {0} is not the fixed loader. Barectl never replaces an "
    "existing application file; inspect it through ordinary administration."
)
CONFIGURATION_OTHER = (
    "The private WordPress configuration of {0} is {1}. Barectl rotates no salt and replaces "
    "no existing file; correct it through ordinary administration."
)
PRIVATE_FILES = (
    "The private directory of {0} holds {1}. Barectl never adopts or replaces private files "
    "other than the supported WordPress configuration."
)
FILE_ATTRIBUTES = "{0} must be a regular file owned by {1} with mode {2} and one link."
PLACEHOLDER_OTHER = (
    "The public index.html of {0} is not the exact known placeholder, so it may be "
    "application content. Barectl replaces only the exact placeholder."
)


class FinishDraft(InstallDraft):
    """A Finish review before it is saved."""

    def __init__(
        self,
        identifier: str,
        token: str,
        request: FinishRequest,
        platform: Platform | None = None,
        release: Release | None = None,
    ) -> None:
        super().__init__(
            identifier,
            token,
            inputs.Metadata("", request.title, request.admin_login, request.admin_email),
            platform,
            release,
            action=Action.WORDPRESS_FINISH,
        )
        self.intent = intent(identifier)
        self.absent_names = ""
        self.compares = False
        self.comparison_sha256 = ""
        self.strict_content = False
        self.creates_loader = False
        self.creates_configuration = False
        self.runs_install = False
        self.configuration_sha256 = ""
        self.kept: list[str] = []

    @property
    @override
    def revision(self) -> int:
        return PROFILE_REVISION


def intent(identifier: str) -> str:
    return (
        f"Finish the WordPress {core_native.VERSION} installation of the site {identifier}: "
        "create only the missing verified resources and publish the ready routing."
    )[:200]


def prepare(preparation: PlanPreparation, shell: RemoteShell) -> FinishDraft:
    request = FinishRequest.objects.filter(preparation=preparation).first()
    if request is None:
        raise OperationRefused(MISSING_REQUEST)
    if not IDENTIFIER.fullmatch(request.identifier):
        raise OperationRefused(install.INVALID_REQUEST.format("The site identifier is not valid."))
    found = inputs.account_problems(
        inputs.AccountMetadata(request.title, request.admin_login, request.admin_email)
    )
    if found:
        raise OperationRefused(install.INVALID_REQUEST.format(" ".join(found)))
    identifier = request.identifier
    token = secrets.token_hex(16)
    site = site_inspection.inspect(shell, identifier, token)
    release = releases_of(site.platform.os) if site.platform is not None else None
    draft = FinishDraft(identifier, token, request, site.platform, release)
    recognized = site_admission.complete(draft, site, identifier, token)
    if recognized is None:
        if draft.eligible:
            draft.refuse(Reason.PREREQUISITE, install.NOT_COMPLETE.format(identifier))
        return draft
    paths = site.paths
    if paths is None or site.release is None or site.platform is None:
        draft.refuse(Reason.INCOMPLETE, "Barectl could not read the site's native layout.")
        return draft
    install._record_site(draft, site, paths, recognized)
    _routing(draft, site.platform.architecture, recognized)
    if recognized.stage.activated:
        tls_activation.lineage(draft, shell, identifier)
    install._binding(draft, shell, site)
    install._runtime(draft, shell)
    install._tool(draft, shell)
    if draft.eligible:
        _resources(draft, shell)
    install._supply(draft, shell)
    _proposal(draft, recognized)
    return draft


def _proposal(draft: FinishDraft, recognized: RecognizedSite) -> None:
    """The exact routing forms, the proposed effects and the payload they bind."""
    if draft.eligible:
        install._candidates(draft, recognized.ipv6, recognized.php_version)
        if draft.gate_content != draft.preimage:
            draft.refuse(Reason.INCOMPLETE, "Barectl could not build the reviewed routing forms.")
    if draft.ready:
        _effects(draft)
        row = PlanWordpressFinish(**finish_fields(draft))
        install._payload(draft, row, finish_native.staged_payload)


# The site file ----


def _routing(draft: FinishDraft, architecture: str, recognized: RecognizedSite) -> None:
    """The site file must already be the exact gate of HTTPS with its HTTP redirect; the
    canonical name is the one it routes."""
    identifier = draft.identifier
    draft.intent = intent(identifier)
    draft.wanted = inputs.Metadata(
        recognized.canonical_name,
        draft.wanted.title,
        draft.wanted.admin_login,
        draft.wanted.admin_email,
    )
    if (
        recognized.application is not Application.WORDPRESS_GATE
        or recognized.stage != Stage.REDIRECT
    ):
        form = (
            "ready WordPress routing"
            if recognized.application is Application.WORDPRESS
            else f"{recognized.application.value} {recognized.stage.value}"
        )
        draft.refuse(Reason.EXISTING_APPLICATION, NOT_GATED.format(identifier, f"its {form}"))
    install._qualified(draft, architecture)


# The application's files and database ----


def _resources(draft: FinishDraft, shell: RemoteShell) -> None:
    identifier = draft.identifier
    first = install._read(
        draft, shell, finish_native.layout_argv(identifier), "the site's trees and configuration"
    )
    database = install._read(
        draft, shell, finish_native.database_state_argv(identifier), "the site database's catalog"
    )
    again = install._read(
        draft, shell, finish_native.layout_argv(identifier), "the site's trees and configuration"
    )
    if first is None or database is None or again is None:
        return
    if first != again:
        draft.refuse(
            Reason.INCOMPLETE,
            install.CHANGED_WHILE_READ.format("The site's public or private tree"),
        )
        return
    try:
        layout = finish_native.parse_layout(first)
        facts = finish_native.parse_database(database, identifier)
    except finish_native.Unreadable as unreadable:
        draft.refuse(Reason.INCOMPLETE, str(unreadable))
        return
    draft.placeholder_sha256 = digest(render_placeholder(identifier))
    _tree(draft, layout)
    _database(draft, facts)
    if not draft.eligible:
        return
    _release(draft, shell, layout)
    _loader(draft, layout)
    _configuration(draft, layout)
    if draft.eligible:
        draft.evidence += [
            EvidenceDraft(
                Kind.WORDPRESS_FILES,
                digest(first),
                "The site directory's entries, the top level of the public and private trees, "
                "the placeholder, the loader and the private configuration's grammar and "
                "digest, rechecked under the lock.",
            ),
            EvidenceDraft(
                Kind.WORDPRESS_DATABASE,
                digest(database),
                f"The database s{identifier}'s object counts, core schema summary and "
                "canonical options, rechecked under the lock.",
            ),
        ]


def _tree(draft: FinishDraft, layout: finish_native.Layout) -> None:
    identifier, files = draft.identifier, layout.files
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
            Reason.COLLISION, FOREIGN_SITE.format(identifier, ", ".join(foreign[:_LISTED]))
        )
    for entry in files.site:
        if entry.path in kept and entry.kind != "d":
            draft.refuse(
                Reason.UNSUPPORTED_LAYOUT, f"/var/www/{identifier}/{entry.path} is not a directory."
            )
    if len(files.public) > core_native.MAX_LISTED:
        draft.refuse(
            Reason.EXISTING_APPLICATION, TOO_MANY.format(identifier, core_native.MAX_LISTED)
        )
    private = [entry.path for entry in files.private if entry.path != "wp-config.php"]
    if private:
        draft.refuse(
            Reason.EXISTING_APPLICATION,
            PRIVATE_FILES.format(identifier, ", ".join(private[:_LISTED])),
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
        draft.refuse(Reason.EXISTING_APPLICATION, PLACEHOLDER_OTHER.format(identifier))
    else:
        draft.placeholder_present = True


def _database(draft: FinishDraft, facts: finish_native.DatabaseFacts) -> None:
    identifier, counts = draft.identifier, facts.counts
    if not counts.exists:
        draft.refuse(
            Reason.PREREQUISITE,
            f"The database s{identifier} does not exist, so there is no satisfied binding to "
            "finish into.",
        )
        return
    if counts.empty:
        draft.runs_install = True
        draft.strict_content = True
        problems = inputs.problems(draft.wanted)
        if problems:
            draft.refuse(Reason.PREREQUISITE, NEEDS_METADATA.format(identifier, " ".join(problems)))
        return
    url = f"https://{draft.wanted.canonical_name}"
    if not facts.installed:
        held = (
            f"{counts.tables} table(s)"
            f"{' (' + ', '.join(counts.names) + ')' if counts.names else ''}, "
            f"{counts.routines} routine(s), {counts.events} event(s) and {counts.triggers} "
            f"trigger(s)"
        )
        draft.refuse(Reason.EXISTING_APPLICATION, PARTIAL_TABLES.format(identifier, held, url))
    elif any(facts.options.get(name) != url for name in convention.SITE_OPTIONS):
        draft.refuse(Reason.EXISTING_APPLICATION, OPTIONS_DIFFER.format(identifier, url))
    else:
        draft.wanted = inputs.Metadata(draft.wanted.canonical_name, "", "", "")


def _release(draft: FinishDraft, shell: RemoteShell, layout: finish_native.Layout) -> None:
    """Compare every existing release entry with the pinned archive, read once into memory."""
    identifier = draft.identifier
    entries = [
        entry.path
        for entry in layout.files.public
        if entry.path not in {"index.html", "wp-config.php"}
    ]
    draft.compares = bool(entries)
    if not draft.compares:
        return
    text = install._read(
        draft,
        shell,
        finish_native.stream_argv(identifier, draft.uid, strict=draft.strict_content),
        "the pinned archive to compare it with the published release files",
    )
    if text is None:
        return
    try:
        comparison = finish_native.parse_comparison(text)
    except finish_native.Unreadable as unreadable:
        draft.refuse(Reason.INCOMPLETE, str(unreadable))
        return
    if comparison.foreign:
        draft.refuse(
            Reason.EXISTING_APPLICATION,
            FOREIGN_FILES.format(identifier, ", ".join(comparison.foreign[:_LISTED])),
        )
    differing = sorted(name for name, state in comparison.tops.items() if state == "differs")
    if differing:
        paths = [difference.path for difference in comparison.differences[:_LISTED]]
        draft.refuse(
            Reason.EXISTING_APPLICATION,
            EDITED.format(identifier, core_native.VERSION, ", ".join(paths or differing)),
        )
    absent = sorted(name for name, state in comparison.tops.items() if state == "absent")
    if not draft.strict_content and comparison.tops.get("wp-content") == "absent":
        draft.refuse(Reason.EXISTING_APPLICATION, CONTENT_MISSING.format(identifier))
    draft.absent_names = " ".join(absent)[:800]
    draft.kept = sorted(
        name for name, state in comparison.tops.items() if state in {"same", "content"}
    )
    draft.comparison_sha256 = finish_native.comparison_digest(text)


def _attributes(
    layout: finish_native.Layout, directory: str, uid: int, gid: int, mode: int
) -> bool:
    """Whether the directory's wp-config.php is a single regular file with these attributes."""
    entries = layout.files.public if directory == "public" else layout.files.private
    entry = next((item for item in entries if item.path == "wp-config.php"), None)
    return entry is not None and (entry.kind, entry.uid, entry.gid, entry.mode, entry.links) == (
        "f",
        uid,
        gid,
        f"{mode:o}",
        1,
    )


def _loader(draft: FinishDraft, layout: finish_native.Layout) -> None:
    identifier, state = draft.identifier, layout.inspection.loader
    if state == "absent":
        draft.creates_loader = True
    elif state == "exact":
        if not _attributes(layout, "public", draft.uid, WWW_DATA_GID, 0o640):
            draft.refuse(
                Reason.UNSUPPORTED_LAYOUT,
                FILE_ATTRIBUTES.format(
                    f"{convention.public_root(identifier)}/wp-config.php",
                    f"s{identifier}:www-data",
                    "0640",
                ),
            )
    elif state == "denied":
        draft.refuse(Reason.INCOMPLETE, "Barectl could not read the public wp-config.php.")
    else:
        draft.refuse(Reason.EXISTING_APPLICATION, LOADER_OTHER.format(identifier))


def _configuration(draft: FinishDraft, layout: finish_native.Layout) -> None:
    identifier, found = draft.identifier, layout.inspection
    if found.configuration == "absent":
        draft.creates_configuration = True
    elif found.configuration == "supported":
        draft.configuration_sha256 = found.configuration_digest
        if not _attributes(layout, "private", draft.uid, draft.gid, 0o600):
            draft.refuse(
                Reason.UNSUPPORTED_LAYOUT,
                FILE_ATTRIBUTES.format(
                    convention.private_configuration_path(identifier),
                    f"s{identifier}:s{identifier}",
                    "0600",
                ),
            )
    elif found.configuration == "denied":
        draft.refuse(Reason.INCOMPLETE, "Barectl could not read the private configuration.")
    else:
        what = (
            f"not the supported grammar (the first refused line is {found.line})"
            if found.line
            else "not a plain regular file in the supported grammar"
        )
        draft.refuse(Reason.EXISTING_APPLICATION, CONFIGURATION_OTHER.format(identifier, what))


# Fields and effects ----


def finish_fields(draft: FinishDraft) -> dict[str, object]:
    """The Finish review's fields, from a draft that is ready to be saved."""
    return {
        **install.install_fields(draft),
        "absent_names": draft.absent_names,
        "compares": draft.compares,
        "comparison_sha256": draft.comparison_sha256,
        "strict_content": draft.strict_content,
        "creates_loader": draft.creates_loader,
        "creates_configuration": draft.creates_configuration,
        "runs_install": draft.runs_install,
        "configuration_sha256": draft.configuration_sha256,
    }


def _effects(draft: FinishDraft) -> None:
    identifier, wanted = draft.identifier, draft.wanted
    name, php = wanted.canonical_name, draft.php_version
    root = convention.public_root(identifier)
    private = convention.private_configuration_path(identifier)
    aliases = [item for item in draft.names if item != name]
    publishing = (
        f"publishes the release entries the public root lacks ({draft.absent_names}) from the "
        "staged copy"
        if draft.absent_names
        else (
            "publishes the whole release from the staged copy into the empty public tree"
            if not draft.compares
            else "publishes no release entry, because every one exists and equals the archive"
        )
    )
    kept = (
        f" It keeps the existing, identical entries ({', '.join(draft.kept)})."
        if draft.kept
        else ""
    )
    placeholder = (
        f" It replaces only the exact placeholder index.html (SHA-256 {draft.placeholder_sha256})."
        if draft.placeholder_present
        else ""
    )
    loader = (
        f"creates the fixed loader {root}/wp-config.php (SHA-256 {draft.loader_sha256})"
        if draft.creates_loader
        else "keeps the existing exact loader"
    )
    configuration = (
        f"creates {private} with eight new salts generated on the server, because none exists"
        if draft.creates_configuration
        else (
            f"keeps the existing supported {private} (SHA-256 {draft.configuration_sha256}) "
            "and rotates no salt"
        )
    )
    draft.effects += [
        (
            Effect.APP_ARTIFACTS,
            (
                f"Runs the authenticated WP-CLI {setup_native.VERSION} at {setup_native.PHAR} "
                f"(SHA-256 {setup_native.SHA256}) as the site user s{identifier} with "
                f"/usr/bin/php{php}, a controlled environment and a private temporary "
                f"directory, never as root. `core download` fetches only {core_native.ARCHIVE_URL} "
                f"with --no-extract: {core_native.ARCHIVE_BYTES} bytes, SHA-256 "
                f"{core_native.ARCHIVE_SHA256}, checked and extracted into a private staging "
                "tree exactly as an installation does, and `core verify-checksums` must pass "
                f"for {core_native.VERSION}/{core_native.LOCALE} before anything is published. "
                "This review read the same archive once into memory, without writing it, to "
                "compare the existing release files"
                + (f" (comparison SHA-256 {draft.comparison_sha256})." if draft.compares else ".")
            ),
        ),
        (
            Effect.APP_FILES,
            (
                f"Under the lock the run {publishing}.{kept}{placeholder} It {loader} and "
                f"{configuration}. Files are published only where the destination is absent, "
                "without following links or changing existing ownership. Existing files are "
                "compared with the staged copy and are never replaced."
            ),
        ),
        (
            Effect.APP_SCHEMA,
            (
                (
                    f"The database s{identifier} is wholly empty, so `core install` runs once "
                    f'with site URL and home https://{name}, title "{wanted.title}", '
                    f"administrator {wanted.admin_login} <{wanted.admin_email}> and "
                    "--skip-email, creating the twelve core tables."
                )
                if draft.runs_install
                else (
                    f"The database s{identifier} already holds exactly the core schema and "
                    f"the canonical options of https://{name}. Core installation is not run: "
                    "no table, option or account is created, changed or reset."
                )
            ),
        ),
        (
            Effect.APP_NETWORK,
            (
                "The server, not the controller, makes the outbound HTTPS requests: the "
                f"archive from {core_native.ARCHIVE_URL} (once for this review's comparison, "
                "again for the run) and WP-CLI's core checksum catalog from wordpress.org. "
                "Public checksums are integrity evidence, not a signature or a malware scan."
            ),
        ),
        (
            Effect.APP_EXPOSURE,
            (
                "The site file already is the provisioning gate "
                f"(SHA-256 {digest(draft.gate_content)}): "
                "application and PHP paths answer 503, /wp-admin/install.php is blocked and "
                "the HTTP-01 challenge route is kept. The run verifies that HTTPS serves the "
                "gate before it publishes anything, keeps the gate as a root-only recovery "
                "preimage, and after schema, options, integrity and private CLI and pool access "
                "verify while gated replaces it with the ready form "
                f"(SHA-256 {digest(draft.ready_content)}) serving WordPress at https://{name}/"
                + (
                    f", with {', '.join(aliases)} redirecting there over HTTP and HTTPS. "
                    if aliases
                    else ". "
                )
                + "If serving verification fails, Barectl restores the gate only while the "
                "current bytes still equal this ready form; if it cannot prove that, it "
                "reports the potentially exposed state. Application files and tables are "
                "never erased."
            ),
        ),
        (
            Effect.APP_ACCOUNT,
            (
                (
                    f"Creates the administrator {wanted.admin_login} <{wanted.admin_email}>. "
                    f"Its initial password is generated on the server as s{identifier}, fed "
                    "directly to WP-CLI's documented prompt and discarded; it is never shown, "
                    "recorded, sent by email or placed in a command line, environment, unit "
                    "text, journal or this page. Finishing is therefore followed by a "
                    'required terminal step, "Administrator password setup required": '
                    f"{install.password_command(identifier, php, name, wanted.admin_login)}"
                )
                if draft.runs_install
                else (
                    "Creates, resets and changes no account. The existing administrators keep "
                    "their passwords, and no password step follows."
                )
            ),
        ),
        (
            Effect.APP_LIMITS,
            (
                "Applying is one finite transient systemd unit under the shared native "
                "mutation lock: it refuses when the server restarted after review, when the "
                "admission deadline passed, when another change or certificate renewal holds "
                "the lock, or when any reviewed evidence changed (including the comparison of "
                "the existing files), before changing anything. It runs at most "
                f"{core_native.RUNTIME_LIMIT_SECONDS // 60} minutes within the installation's "
                "archive, tree, file and memory limits. The web server, cron and "
                "WordPress's own updater stay outside the lock."
            ),
        ),
        (
            Effect.NO_ROLLBACK,
            (
                "Finishing is not transactional. After a failure Barectl keeps every file, "
                "table, salt and account it or an earlier run created and keeps the gate; it "
                "drops no database, removes no content, rotates no salt, resets no "
                "administrator and never replays core installation into partial tables."
            ),
        ),
    ]
    draft.postconditions += [
        (
            f"Database s{identifier} holds the complete core schema and the canonical siteurl "
            f"and home options of https://{name}"
            + (", with exactly the twelve core tables." if draft.runs_install else ".")
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
        (
            "The administrator exists without a usable password until the terminal step is done."
            if draft.runs_install
            else "No account was created or changed."
        ),
    ]
