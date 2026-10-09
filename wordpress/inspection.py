"""The WordPress inspection review: its admission, refusals and proposed effects.

docs/wordpress.md#inspecting-wordpress. Preparation changes nothing and starts no application
code: it reads the installed application's native files, catalog names and extension
directories as root, then binds the review to that evidence. Applying the review is what runs
WP-CLI, and it first rechecks every digest under the mutation lock.
"""

import hashlib
import secrets
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
from discovery.models import CoreQualification
from discovery.ssh import RemoteShell
from operations.lifecycle import OperationRefused
from sites import admission as site_admission
from sites import inspection as site_inspection
from sites.convention import Application, SitePaths, Stage
from sites.names import IDENTIFIER
from tls import readiness

from . import convention, execution, inspection_native, runtime, setup, setup_native
from .inspection_models import InspectionRequest, Operation, PlanWordpressInspection
from .models import RuntimeCapability

Reason = PlanRefusal.Reason
Effect = PlanEffect.Kind
Kind = PlanEvidence.Kind
# The revision of the inspection definitions a plan was reviewed against.
PROFILE_REVISION = 1
_LISTED = 3
_NAMES_SHOWN = 12

MISSING_REQUEST = (
    "The WordPress inspection request of this preparation is not recorded, so Barectl read "
    "nothing from the server."
)
INVALID_REQUEST = (
    "The recorded WordPress inspection request is not valid, so Barectl read nothing from the "
    "server. Prepare a new review."
)
CHANGED_WHILE_READ = "{0} changed while Barectl read it. Prepare again once it is settled."
UNQUALIFIED = (
    "WordPress with PHP {0} from {1} packages on Ubuntu {2} ({3}) has not completed Barectl's "
    "qualification. Only the release's own PHP branch from Ubuntu packages, on amd64 or arm64, "
    "is qualified, so Barectl runs no application code on this site."
)


class InspectionDraft(readiness.TlsSiteDraft):
    """An inspection review before it is saved."""

    def __init__(
        self,
        identifier: str,
        token: str,
        operation: str,
        platform: Platform | None = None,
        release: Release | None = None,
    ) -> None:
        super().__init__(Action.WORDPRESS_INSPECT, intent(identifier, operation), platform, release)
        self.identifier = identifier
        self.token = token
        self.operation = operation
        self.paths: SitePaths | None = None
        self.uid = 0
        self.gid = 0
        self.canonical_name = ""
        self.core_version = ""
        self.qualified = False
        self.configuration_sha256 = ""
        self.inventory = inspection_native.Inventory([], [], [], [], [])
        self.body_sha256 = ""
        self.payload_bytes: int | None = None

    @property
    @override
    def revision(self) -> int:
        return PROFILE_REVISION

    @property
    def ready(self) -> bool:
        """Whether the review is complete enough to save its typed row."""
        return self.eligible and bool(self.canonical_name and self.core_version)


def intent(identifier: str, operation: str) -> str:
    label = {
        Operation.INSPECT: "Inspect WordPress",
        Operation.CORE: "Verify the WordPress core checksums",
        Operation.PLUGINS: "Verify the repository plugin checksums",
    }.get(Operation(operation), "Inspect WordPress")
    return f"{label} on the site {identifier} by running the authenticated WP-CLI."[:200]


def digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def prepare(preparation: PlanPreparation, shell: RemoteShell) -> InspectionDraft:
    request = InspectionRequest.objects.filter(preparation=preparation).first()
    if request is None:
        raise OperationRefused(MISSING_REQUEST)
    if not IDENTIFIER.fullmatch(request.identifier) or request.operation not in set(Operation):
        raise OperationRefused(INVALID_REQUEST)
    identifier = request.identifier
    token = secrets.token_hex(16)
    site = site_inspection.inspect(shell, identifier, token)
    release = releases_of(site.platform.os) if site.platform is not None else None
    draft = InspectionDraft(identifier, token, request.operation, site.platform, release)
    recognized = site_admission.complete(draft, site, identifier, token)
    if recognized is None:
        if draft.eligible:
            draft.refuse(
                Reason.PREREQUISITE,
                f"The site {identifier} is not complete as the site convention requires, so "
                "nothing is inspected on it. Complete the site first.",
            )
        return draft
    paths = site.paths
    if paths is None or site.release is None or site.platform is None:
        draft.refuse(Reason.INCOMPLETE, "Barectl could not read the site's native layout.")
        return draft
    draft.paths = paths
    draft.names, draft.ipv6 = recognized.names, recognized.ipv6
    draft.php_version, draft.php_supply = paths.php, site.php_supply
    draft.site_revision = paths.revision
    fields = (site.accounts.user if site.accounts else "").split(":")
    if len(fields) >= 4 and fields[2].isdigit() and fields[3].isdigit():
        draft.uid, draft.gid = int(fields[2]), int(fields[3])
    else:
        draft.refuse(Reason.INCOMPLETE, "The site user and group could not be read.")
    _site(draft, site.platform.architecture, recognized.application, recognized.stage)
    draft.canonical_name = recognized.canonical_name
    _runtime(draft, shell)
    _tool(draft, shell)
    _application(draft, shell)
    if draft.ready:
        _effects(draft)
        _payload(draft)
    return draft


def _site(
    draft: InspectionDraft, architecture: str, application: Application, stage: Stage
) -> None:
    identifier = draft.identifier
    release = draft.release
    if application is Application.WORDPRESS_GATE:
        draft.refuse(
            Reason.PREREQUISITE,
            f"The site {identifier} is still behind the WordPress provisioning gate: its "
            "installation did not finish. Nothing is inspected until the application is "
            "installed and served.",
        )
    elif not application.wordpress or stage != Stage.REDIRECT:
        draft.refuse(
            Reason.PREREQUISITE,
            f"The site {identifier} does not serve WordPress over HTTPS (its site file is in "
            "another form), so there is no installed application to inspect.",
        )
    if release is not None and (
        draft.php_supply != "ubuntu"
        or draft.php_version != release.php
        or architecture not in {"amd64", "arm64"}
    ):
        draft.refuse(
            Reason.UNSUPPORTED_VERSION,
            UNQUALIFIED.format(draft.php_version, draft.php_supply, release.version, architecture),
        )


def _site_digest(draft: Draft) -> str:
    return next(
        (item.fingerprint for item in draft.evidence if item.kind == Kind.SITE_REVALIDATION), ""
    )


def _same_site(draft: InspectionDraft, other: Draft, what: str) -> None:
    mine, theirs = _site_digest(draft), _site_digest(other)
    if mine and theirs and mine != theirs:
        draft.refuse(Reason.INCOMPLETE, CHANGED_WHILE_READ.format(f"The site {what}"))


def _runtime(draft: InspectionDraft, shell: RemoteShell) -> None:
    reviewed = runtime.prepare(shell, draft.identifier)
    _same_site(draft, reviewed, "runtime read")
    if not reviewed.eligible:
        problems = "; ".join(text for _, text in reviewed.refusals[:_LISTED])
        draft.refuse(
            Reason.PREREQUISITE,
            f"The selected PHP runtime cannot be established for WordPress: {problems}",
        )
        return
    missing = [item.label for item in reviewed.capabilities if not item.cli] or (
        ["every baseline capability"] if not reviewed.capabilities else []
    )
    unplanned = [
        item.label
        for item in reviewed.capabilities
        if item.state != RuntimeCapability.State.ENABLED
    ]
    if missing or unplanned:
        draft.refuse(
            Reason.PREREQUISITE,
            "The selected PHP CLI does not load the WordPress baseline "
            f"({', '.join(missing or unplanned)}). Prepare and apply the site's WordPress PHP "
            "runtime plan first; an inspection installs no package.",
        )
        return
    draft.fingerprint(
        Kind.WORDPRESS_RUNTIME,
        sorted(f"{item.name} {int(item.cli)} {int(item.fpm)}" for item in reviewed.capabilities),
        f"PHP {draft.php_version}: every baseline capability loads in the selected CLI as of "
        "this read.",
    )


def _tool(draft: InspectionDraft, shell: RemoteShell) -> None:
    reviewed = setup.prepare(shell)
    if not reviewed.eligible or not reviewed.installed:
        problems = "; ".join(text for _, text in reviewed.refusals[:_LISTED])
        draft.refuse(
            Reason.PREREQUISITE,
            f"The authenticated WP-CLI {setup_native.VERSION} is not established at "
            f"{setup_native.PHAR}: {problems or 'it is not installed.'} Prepare and apply the "
            "server's WP-CLI setup plan first; an inspection installs no tool.",
        )
        return
    present = {item.kind for item in draft.evidence}
    for item in reviewed.evidence:
        if item.kind == Kind.WPCLI_REVALIDATION and item.kind not in present:
            draft.evidence.append(item)


def _application(draft: InspectionDraft, shell: RemoteShell) -> None:
    argv = inspection_native.state_argv(draft.identifier)
    first = readiness.root_read(draft, shell, argv)
    second = readiness.root_read(draft, shell, argv)
    if first is None or second is None:
        if draft.eligible:
            draft.refuse(
                Reason.INCOMPLETE, "Barectl could not read the application's state. Prepare again."
            )
        return
    if first != second:
        draft.refuse(Reason.INCOMPLETE, CHANGED_WHILE_READ.format("The application's state"))
        return
    try:
        state = inspection_native.parse_state(first)
    except inspection_native.Unreadable as unreadable:
        draft.refuse(Reason.INCOMPLETE, str(unreadable))
        return
    draft.evidence.append(
        EvidenceDraft(
            Kind.WORDPRESS_STATE,
            digest(first),
            "The loader, private configuration digest, core release, schema signature, canonical "
            "options, extension names and the files WordPress loads by itself, rechecked under "
            "the lock.",
        )
    )
    _core(draft, state)
    _extensions(draft, state)


def _core(draft: InspectionDraft, state: inspection_native.State) -> None:
    config = state.config
    identifier = draft.identifier
    if config is None:
        return
    if config.loader == "absent" and config.configuration == "absent":
        draft.refuse(
            Reason.PREREQUISITE,
            f"WordPress is not installed on the site {identifier}: it has no loader and no "
            "private configuration.",
        )
        return
    if config.loader != "exact" or config.configuration != "supported":
        draft.refuse(
            Reason.UNSUPPORTED_LAYOUT,
            f"The WordPress loader ({config.loader}) or private configuration "
            f"({config.configuration}) of {identifier} is not Barectl's supported form, which "
            "WP-CLI's bootstrap relies on, so no application code runs.",
        )
        return
    qualification = convention.qualification(config.version)
    if qualification not in {CoreQualification.QUALIFIED, CoreQualification.NEWER}:
        draft.refuse(
            Reason.UNSUPPORTED_VERSION,
            f"The core release {config.version} is {qualification.label.lower()} than or "
            f"unrelated to the qualified {convention.CORE_VERSION}; Barectl keeps only passive "
            "evidence for it and runs no application code.",
        )
        return
    if state.packaged:
        draft.refuse(
            Reason.UNSUPPORTED_LAYOUT,
            "The core release carries a language package; only the en_US release is qualified.",
        )
    schema = convention.parse_schema(state.schema, [f"s{identifier}"]) if state.schema else {}
    found = schema.get(f"s{identifier}")
    options = _options(state.options)
    if found is None or not found.complete or found.ambiguous:
        draft.refuse(
            Reason.UNSUPPORTED_LAYOUT,
            "The database does not hold exactly the complete WordPress core schema with "
            f"prefix {convention.TABLE_PREFIX}, which the qualified WP-CLI needs to bootstrap.",
        )
    address = f"https://{draft.canonical_name}"
    if options != {"siteurl": address, "home": address}:
        draft.refuse(
            Reason.UNSUPPORTED_LAYOUT,
            f"The stored siteurl and home are not the site's canonical address {address}, so "
            "the application cannot be targeted unambiguously.",
        )
    draft.core_version = config.version
    draft.qualified = qualification is CoreQualification.QUALIFIED
    draft.configuration_sha256 = config.configuration_digest


def _options(text: str) -> dict[str, str] | None:
    try:
        return convention.parse_options(text)
    except convention.CatalogFormatError:
        return None


def _extensions(draft: InspectionDraft, state: inspection_native.State) -> None:
    found = inspection_native.inventory(state)
    draft.inventory = found
    over = found.count > execution.MAX_ITEMS
    if draft.operation == Operation.INSPECT and over:
        draft.refuse(
            Reason.UNSUPPORTED_LAYOUT,
            f"The application has {found.count} plugins, must-use plugins, drop-ins and "
            f"themes, more than the {execution.MAX_ITEMS} one result may hold. Barectl never "
            "shows a truncated inventory as complete.",
        )
    if draft.operation == Operation.PLUGINS:
        if not found.slugs:
            draft.refuse(
                Reason.PREREQUISITE,
                "No plugin directory with a WordPress.org slug is installed, so there is "
                "nothing to verify against the repository's checksums.",
            )
        elif len(found.slugs) > execution.MAX_ITEMS:
            draft.refuse(
                Reason.UNSUPPORTED_LAYOUT,
                f"More than {execution.MAX_ITEMS} plugin directories are installed; one result "
                "never holds more.",
            )


def _listed(names: list[str]) -> str:
    shown = ", ".join(names[:_NAMES_SHOWN])
    return f"{shown} and {len(names) - _NAMES_SHOWN} more" if len(names) > _NAMES_SHOWN else shown


def inspection_fields(draft: InspectionDraft) -> dict[str, object]:
    """The inspection review's fields, from a draft that is ready to be saved."""
    paths = draft.paths
    if paths is None:
        raise ValueError("The inspection review has no site paths.")
    max_file, memory = inspection_native.limits()
    return {
        "identifier": draft.identifier,
        "php_version": draft.php_version,
        "php_supply": draft.php_supply,
        "site_revision": draft.site_revision,
        "site_user": paths.user,
        "uid": draft.uid,
        "gid": draft.gid,
        "canonical_name": draft.canonical_name,
        "url": f"https://{draft.canonical_name}",
        "operation": draft.operation,
        "tool_version": setup_native.VERSION,
        "tool_path": setup_native.PHAR,
        "tool_sha256": setup_native.SHA256,
        "core_version": draft.core_version,
        "core_locale": "en_US",
        "core_qualified": draft.qualified,
        "configuration_sha256": draft.configuration_sha256,
        "targets": draft.inventory.targets(),
        "max_file_bytes": max_file,
        "memory_max_bytes": memory,
        "runtime_limit_seconds": inspection_native.RUNTIME_LIMIT_SECONDS,
        "command_seconds": inspection_native.COMMAND_SECONDS,
        "budget_seconds": inspection_native.BUDGET_SECONDS,
        "body_sha256": draft.body_sha256,
        "payload_bytes": draft.payload_bytes,
    }


def evidence_of(digests: dict[str, str]) -> inspection_native.Evidence | None:
    try:
        return inspection_native.Evidence(
            site=digests[Kind.SITE_REVALIDATION],
            wpcli=digests[Kind.WPCLI_REVALIDATION],
            state=digests[Kind.WORDPRESS_STATE],
        )
    except KeyError:
        return None


def _payload(draft: InspectionDraft) -> None:
    """Build the payload applying would submit, exactly as applying builds it, and refuse a
    review whose payload would not fit one run rather than split it."""
    platform = draft.platform
    evidence = evidence_of({item.kind: item.fingerprint for item in draft.evidence})
    if platform is None or platform.uptime_centiseconds is None or not evidence:
        draft.refuse(Reason.INCOMPLETE, "Barectl could not build the reviewed payload.")
        return
    row = PlanWordpressInspection(**inspection_fields(draft))
    try:
        text, body = inspection_native.staged(
            bootstrap_native.new_unit_name(),
            platform.boot_id,
            platform.uptime_centiseconds + ADMISSION_CENTISECONDS,
            row,
            evidence,
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


def _effects(draft: InspectionDraft) -> None:
    identifier, name, php = draft.identifier, draft.canonical_name, draft.php_version
    operation = Operation(draft.operation)
    found = draft.inventory
    commands = "; ".join(f"`wp {command}`" for command in inspection_native.COMMANDS[operation])
    loads = inspection_native.RUNS_APPLICATION[operation]
    mu = _listed(found.mu_plugins) or "none installed"
    dropins = _listed(found.dropins) or "none installed"
    if loads:
        disclosure = (
            "These commands load WordPress, so the run executes WordPress core, the private "
            "configuration through the fixed public loader, every must-use plugin "
            f"({mu}) and every drop-in WordPress loads by itself ({dropins}), all as the site "
            "user. --skip-plugins and --skip-themes skip the "
            f"{len(found.plugins)} installed plugin(s) and {len(found.themes)} theme(s) but are "
            "not isolation: they do not stop must-use plugins, drop-ins or WordPress itself, "
            "and WP-CLI still reads the extensions' files."
        )
    else:
        disclosure = (
            "On the pinned WP-CLI this command runs before WordPress loads, so it executes "
            "WP-CLI and its PHP code only: no plugin, theme, must-use plugin or drop-in runs. "
            "That is Barectl's observation of this WP-CLI version, not an upstream guarantee."
        )
    draft.effects += [
        (
            Effect.APP_EXECUTION,
            (
                f"Runs the authenticated WP-CLI {setup_native.VERSION} at {setup_native.PHAR} "
                f"(SHA-256 {setup_native.SHA256}) as the site user s{identifier}, never as root "
                f"and never with --allow-root, with /usr/bin/php{php}, a cleared environment, a "
                "private home, cache and temporary directory, "
                f"--path={convention.public_root(identifier)} "
                f"--url=https://{name}, no WP-CLI packages and no project or global "
                f"configuration file: {commands}. {disclosure} The commands are fixed; "
                "there is no command line, flag or script to supply."
            ),
        ),
        (
            Effect.APP_NETWORK,
            _network(operation, found),
        ),
        (
            Effect.APP_RESULT,
            (
                "Each command's raw output goes to a private file that is removed when the run "
                "ends. A trusted projection run as the site user accepts only the exact output "
                f"forms, at most {execution.MAX_ITEMS} items and {execution.MAX_RECORD // 1024} "
                "KiB, and the unit publishes that one record to the journal; malformed, mixed, "
                "extra or oversized output makes the result unavailable instead of being "
                "truncated or passed through. Barectl retrieves exactly that record by the "
                "unit's name and recorded invocation. If the journal no longer holds it, the "
                "result is unavailable while the run's execution outcome still comes from "
                "systemd. The result is the application's own report as of its time, not a "
                "live-security assessment, and it changes nothing: Barectl repairs, updates, "
                "flushes and edits nothing."
            ),
        ),
        (
            Effect.APP_LIMITS,
            (
                "Applying is one finite transient systemd unit under the shared native mutation "
                "lock: it refuses when the server restarted after review, the admission deadline "
                "passed, another change or certificate renewal holds the lock, or the site, the "
                "tool, the loader and private configuration, the core release, the schema, the "
                "extension names or the must-use and drop-in files changed, before running any "
                "application code. It runs at most "
                f"{inspection_native.RUNTIME_LIMIT_SECONDS // 60} minutes, each command at most "
                f"{inspection_native.COMMAND_SECONDS} seconds with a "
                f"{inspection_native.MAX_FILE_BYTES // 2**20} MiB file limit and "
                f"{inspection_native.MEMORY_MAX_BYTES // 2**20} MiB of memory. The web server, "
                "cron and WordPress's own updater stay outside the lock."
            ),
        ),
    ]
    if not draft.qualified:
        draft.effects.append(
            (
                Effect.APP_LIMITS,
                (
                    f"The installed core release {draft.core_version} is newer than the "
                    f"qualified {convention.CORE_VERSION}. WP-CLI {setup_native.VERSION} is run "
                    "against it for this diagnosis only, as its loader, configuration and schema "
                    "match the qualified forms; Barectl enables no installation, Finish or "
                    "maintenance for it."
                ),
            )
        )
    draft.postconditions += [
        (
            "The run's staging directory is removed and it changed neither the site, WP-CLI nor "
            "the application."
        ),
        (
            f"One validated {execution.MAX_RECORD // 1024} KiB record is retrievable from the "
            "journal, or the result is shown as unavailable with its reason."
        ),
    ]


def _network(operation: str, found: inspection_native.Inventory) -> str:
    if operation == Operation.CORE:
        return (
            "The server, not the controller, makes one HTTPS request to the WordPress.org core "
            "checksum API for the observed release and locale. Public checksums are integrity "
            "evidence, not a publisher signature or a malware scan. When the catalog cannot be "
            "fetched or parsed the result is unavailable, never a pass or a mismatch."
        )
    if operation == Operation.PLUGINS:
        return (
            f"The server, not the controller, makes one HTTPS request per observed slug "
            f"({len(found.slugs)}) to downloads.wordpress.org/plugin-checksums. A plugin that "
            "is not on WordPress.org, a private or custom package and one without a published "
            "catalog for its version are unavailable, never trusted and never reported corrupt "
            "by inference; a repository plugin whose files differ is a mismatch. WP-CLI does "
            "not detect deleted plugin files. Public checksums are integrity evidence, not a "
            "signature or a malware scan."
        )
    return (
        "The inventory commands request no update information, and Barectl makes no request "
        "itself. A must-use plugin or drop-in may make its own requests; Barectl can neither "
        "prevent nor observe them."
    )
