"""The WordPress maintenance review: its admission, refusals and proposed effects.

docs/wordpress.md#maintaining-wordpress. Preparation changes nothing and starts no application
code: it reads the installed application's native files, catalog names and extension
directories as root, then binds the review to that evidence exactly as the inspection does
(``inspection.observe``). Applying the review is what runs WP-CLI, and it first rechecks every
digest under the mutation lock.
"""

from bootstrap import native as bootstrap_native
from bootstrap.evidence import Platform
from bootstrap.models import (
    ADMISSION_CENTISECONDS,
    Action,
    PlanEffect,
    PlanPreparation,
    PlanRefusal,
)
from bootstrap.releases import Release
from discovery.ssh import RemoteShell
from operations.lifecycle import OperationRefused
from sites.names import IDENTIFIER

from . import convention, execution, inspection, inspection_native, maintenance_native, setup_native
from .maintenance_models import MaintenanceRequest, Operation, PlanWordpressMaintenance

Reason = PlanRefusal.Reason
Effect = PlanEffect.Kind

MISSING_REQUEST = (
    "The WordPress maintenance request of this preparation is not recorded, so Barectl read "
    "nothing from the server."
)
INVALID_REQUEST = (
    "The recorded WordPress maintenance request is not valid, so Barectl read nothing from the "
    "server. Prepare a new review."
)


class MaintenanceDraft(inspection.InspectionDraft):
    """A maintenance review before it is saved."""

    def __init__(
        self,
        identifier: str,
        token: str,
        operation: str,
        platform: Platform | None = None,
        release: Release | None = None,
    ) -> None:
        super().__init__(
            identifier,
            token,
            operation,
            platform,
            release,
            action=Action.WORDPRESS_MAINTAIN,
            description=intent(identifier, operation),
        )


def intent(identifier: str, operation: str) -> str:
    label = {
        Operation.REWRITE: "Flush the WordPress rewrite rules",
        Operation.CACHE: "Flush the WordPress object cache",
    }.get(Operation(operation), "Maintain WordPress")
    return f"{label} on the site {identifier} by running the authenticated WP-CLI."[:200]


def prepare(preparation: PlanPreparation, shell: RemoteShell) -> MaintenanceDraft:
    request = MaintenanceRequest.objects.filter(preparation=preparation).first()
    if request is None:
        raise OperationRefused(MISSING_REQUEST)
    if not IDENTIFIER.fullmatch(request.identifier) or request.operation not in set(Operation):
        raise OperationRefused(INVALID_REQUEST)
    draft = inspection.observe(
        shell, request.identifier, request.operation, MaintenanceDraft, _extensions
    )
    if not isinstance(draft, MaintenanceDraft):
        raise TypeError("Not a maintenance draft.")
    if draft.ready:
        _effects(draft)
        _payload(draft)
    return draft


def _extensions(draft: inspection.InspectionDraft, state: inspection_native.State) -> None:
    found = inspection_native.inventory(state)
    draft.inventory = found
    if draft.core_version and not draft.qualified:
        draft.refuse(
            Reason.UNSUPPORTED_VERSION,
            f"The core release {draft.core_version} is newer than the qualified "
            f"{convention.CORE_VERSION}. Maintenance, unlike a diagnosis, needs the exact "
            f"qualified core and WP-CLI {setup_native.VERSION} pair; Barectl changes nothing "
            "on it and never downgrades.",
        )
    listed = {directory for directory, *_ in state.entries}
    for directory in sorted(listed):
        if (
            sum(1 for entry in state.entries if entry[0] == directory)
            > inspection_native.MAX_LISTED
        ):
            draft.refuse(
                Reason.UNSUPPORTED_LAYOUT,
                f"{directory} lists more than {inspection_native.MAX_LISTED} entries, more than "
                "Barectl binds and rechecks, so the extensions the action would run are not "
                "fully reviewed.",
            )
    if draft.operation == Operation.CACHE:
        _cache_scope(draft, found)


def _cache_scope(draft: inspection.InspectionDraft, found: inspection_native.Inventory) -> None:
    """No persistent cache provider is qualified, so a drop-in WordPress loads by itself leaves
    the flush's scope unverified and refuses it."""
    for name in found.dropins:
        if name == "object-cache.php":
            what = (
                "a persistent object-cache drop-in (object-cache.php), which may be backed by a "
                "store shared with other applications"
            )
        elif name == "advanced-cache.php":
            what = "a page-cache drop-in (advanced-cache.php)"
        elif name == "db.php":
            what = "a replacement database layer (db.php)"
        else:
            what = f"the drop-in {name}"
        draft.refuse(
            Reason.UNSUPPORTED_LAYOUT,
            f"The site has {what}. No persistent cache provider is qualified and a drop-in is "
            "unexpected on a convention site, so the scope of an object-cache flush is "
            "unverified and Barectl refuses it rather than widen it. Remove the drop-in or "
            "manage that cache through ordinary administration.",
        )


def _payload(draft: inspection.InspectionDraft) -> None:
    """Build the payload applying would submit, exactly as applying builds it, and refuse a
    review whose payload would not fit one run rather than split it."""
    platform = draft.platform
    evidence = inspection.evidence_of({item.kind: item.fingerprint for item in draft.evidence})
    if platform is None or platform.uptime_centiseconds is None or not evidence:
        draft.refuse(Reason.INCOMPLETE, "Barectl could not build the reviewed payload.")
        return
    row = PlanWordpressMaintenance(**inspection.inspection_fields(draft))
    try:
        text, body = maintenance_native.staged(
            bootstrap_native.new_unit_name(),
            platform.boot_id,
            platform.uptime_centiseconds + ADMISSION_CENTISECONDS,
            row,
            evidence,
        )
    except ValueError:
        draft.refuse(Reason.INCOMPLETE, "Barectl could not build the reviewed payload.")
        return
    draft.body_sha256 = inspection.digest(body)
    draft.payload_bytes = len(text.encode())
    if draft.payload_bytes > bootstrap_native.MAX_PAYLOAD:
        draft.refuse(
            Reason.PAYLOAD_TOO_LARGE,
            f"Applying this review would submit {draft.payload_bytes} bytes, more than the "
            f"{bootstrap_native.MAX_PAYLOAD} bytes Barectl submits in one run. Barectl never "
            "splits a reviewed action.",
        )


def _effects(draft: inspection.InspectionDraft) -> None:
    identifier, name, php = draft.identifier, draft.canonical_name, draft.php_version
    operation = Operation(draft.operation)
    found = draft.inventory
    mu = inspection.listed(found.mu_plugins) or "none installed"
    dropins = inspection.listed(found.dropins) or "none installed"
    command = maintenance_native.COMMANDS[operation]
    loads = maintenance_native.LOADS_EXTENSIONS[operation]
    plugins = inspection.listed(found.plugins) or "none installed"
    themes = inspection.listed(found.themes) or "none installed"
    if loads:
        hooks = (
            "This action loads WordPress with its ordinary plugins and themes, because the "
            "skip flags would drop the routes they register: it executes WordPress core, the "
            "private configuration through the fixed public loader, the active plugins "
            f"(installed: {plugins}), the active theme (installed: {themes}), every must-use "
            f"plugin ({mu}) and every drop-in WordPress loads by itself ({dropins}), all as "
            "the site user. Their hooks run, including the ones that register routes and "
            "anything else they do on a request, such as reading files, writing to the "
            "database or making network requests, which Barectl can neither prevent nor "
            "observe."
        )
    else:
        hooks = (
            "This action loads WordPress with --skip-plugins and --skip-themes, which skip the "
            f"{len(found.plugins)} installed plugin(s) and {len(found.themes)} theme(s) but are "
            "not isolation: WordPress core, the private configuration through the fixed public "
            f"loader, every must-use plugin ({mu}) and every drop-in WordPress loads by itself "
            f"({dropins}) still run, all as the site user."
        )
    draft.effects += [
        (
            Effect.APP_EXECUTION,
            (
                f"Runs the authenticated WP-CLI {setup_native.VERSION} at {setup_native.PHAR} "
                f"(SHA-256 {setup_native.SHA256}) as the site user s{identifier}, never as root "
                f"and never with --allow-root, with /usr/bin/php{php}, a cleared environment, a "
                "private home, cache and temporary directory, "
                f"--path={convention.public_root(identifier)} --url=https://{name}, no WP-CLI "
                f"packages and no project or global configuration file: `wp {command}`. {hooks} "
                "The command is fixed; there is no command line, flag or script to supply."
            ),
        ),
        (Effect.APP_STATE, _state_effect(operation)),
        (
            Effect.APP_NETWORK,
            (
                "Barectl makes no request itself. WordPress and the code it loads may make "
                "their own requests while they run, which Barectl can neither prevent nor "
                "observe."
            ),
        ),
        (
            Effect.APP_RESULT,
            (
                "The command's raw output goes to a private file that is removed when the run "
                "ends. A trusted projection run as the site user accepts only the command's "
                "exact output forms and the unit publishes one record of at most "
                f"{execution.MAX_RECORD // 1024} KiB to the journal; any other output makes "
                "the result unavailable instead of being passed through, and then Barectl "
                "cannot say whether the flush took effect. A command that fails ends the run as "
                "failed. Barectl retrieves exactly that record by the unit's name and recorded "
                "invocation; if the journal no longer holds it, the result is unavailable "
                "while the run's execution outcome still comes from systemd. Native success "
                "means the command completed; Barectl does not promise every plugin's hook "
                "effects or any performance recovery."
            ),
        ),
        (
            Effect.APP_LIMITS,
            (
                "Applying is one finite transient systemd unit under the shared native "
                "mutation lock: it refuses when the server restarted after review, the "
                "admission deadline passed, another change or certificate renewal holds the "
                "lock, or the site, the tool, the loader and private configuration, the core "
                "release, the schema, the extension names or the must-use and drop-in files "
                "changed, before running any application code. It runs at most "
                f"{maintenance_native.RUNTIME_LIMIT_SECONDS // 60} minutes, the command at "
                f"most {maintenance_native.COMMAND_SECONDS} seconds with a "
                f"{maintenance_native.MAX_FILE_BYTES // 2**20} MiB file limit and "
                f"{maintenance_native.MEMORY_MAX_BYTES // 2**20} MiB of memory. Loading "
                "WordPress costs one command-line PHP process of CPU, memory and database "
                "queries on the server while web requests continue. The web server, cron, "
                "administrators and WordPress's own updater stay outside the lock."
            ),
        ),
    ]
    draft.postconditions += [
        (
            "The run's staging directory is removed and it changed neither the site, Nginx, "
            "WP-CLI nor any application file."
        ),
        (
            f"One validated {execution.MAX_RECORD // 1024} KiB record is retrievable from the "
            "journal, or the result is shown as unavailable with its reason."
        ),
    ]


def _state_effect(operation: Operation) -> str:
    if operation == Operation.REWRITE:
        return (
            "A soft flush (`wp rewrite flush` without --hard) deletes WordPress's stored "
            "`rewrite_rules` option and regenerates it from the routes WordPress core, the "
            "loaded theme and the loaded plugins register in that command-line request, then "
            "stores it again in the site's database; the next web requests use the refreshed "
            "rules, and a request that arrives during the rebuild regenerates them itself. It "
            "never writes .htaccess, never edits the Nginx site file or any other file, and "
            "never reloads Nginx: Nginx keeps passing unknown paths to WordPress's front "
            "controller. With plain permalinks WordPress stores no rules, and the result says "
            "so. A route a plugin registers only under conditions that do not hold in a "
            "command-line request is not stored. Plugin hooks that run during the flush may "
            "change other application data. Page caches are not cleared."
        )
    return (
        "WordPress's default object cache exists only in the memory of one request. This "
        "command clears the cache of its own command-line process, which is empty; it clears "
        "nothing in the requests the web server is serving, no page cache, no browser or CDN "
        "cache and no persistent store. No persistent cache provider is qualified and the "
        "site has no object-cache drop-in, so Barectl does not present this as a live-site "
        "cache repair, and cannot claim any public speed-up or stale-content fix from it."
    )
