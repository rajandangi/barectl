"""Applying a reviewed WordPress installation: its payload, outcome and verification.

docs/wordpress.md#applying-an-installation. The payload gates the site, acquires and
publishes the pinned release, creates the private configuration and the schema and routes
the application on the server; this module binds the run to the reviewed rows and pins,
separates the boundaries at which a run stopped from the refusals that changed nothing, and
reads the installation's native state afterwards. Nothing here ever holds a password or a
salt: they exist only on the server.
"""

from django.utils import timezone

from bootstrap import native as bootstrap_native
from bootstrap.models import (
    ApplyRun,
    ConfigurationPlan,
    Execution,
    PlanEvidence,
    Verification,
)
from bootstrap.native import Limits, UnitEvidence
from discovery.ssh import RemoteShell
from operations.lifecycle import OperationRefused
from sites.convention import CONVENTION_REVISION, Application, Stage, render_site

from . import convention, core_native, first_access, install_native, setup_native
from .first_access_models import FirstAccessDelivery
from .models import InstallationReview, InstallRunResult, PlanWordpressInstall, RunWordpressInstall

Exit = install_native.Exit
Kind = PlanEvidence.Kind
EVIDENCE_FAILURE = (
    "The reviewed WordPress installation is incomplete, or its pins or payload differ from "
    "this version's, so Barectl submitted nothing. Prepare a new review."
)
VERIFY_PRIVILEGE = (
    "The SSH user is not root, and sudo -n -l does not authorize the fixed read-only command "
    "that verifies the installation afterwards, so Barectl submitted nothing."
)
VERIFICATION_FAILED = (
    "The installation ran, but the server does not match the review: {problems} Barectl does "
    "not repair or roll back; inspect the server through ordinary administration "
    "(docs/wordpress.md#recovering-a-partial-installation)."
)
_NOTHING_REMOVED = (
    " Barectl keeps every file, table, salt and account the run created, never replays core "
    "installation and removes nothing automatically; a new review shows what exists "
    "(docs/wordpress.md#recovering-a-partial-installation)."
)
_REFUSALS: dict[int, str] = {
    Exit.TOOLS: (
        "The server lacks a native tool the run needs (curl, tar, sha256sum, python3, gzip, "
        "openssl, mariadb, runuser, Nginx or the site's PHP CLI), so the run stopped before "
        "changing anything. Install it through ordinary administration, then prepare a new "
        "review."
    ),
    Exit.STAGING: (
        "The run's private staging area could not be created, or the server has less free "
        "space than the reviewed limits need, or a WP-CLI configuration file exists above the "
        "site, so the run stopped before changing anything."
    ),
    Exit.DOWNLOAD: (
        "WP-CLI could not download the pinned archive within the reviewed limits "
        f"({core_native.MAX_ARCHIVE_BYTES // 2**20} MiB per file, "
        f"{core_native.MEMORY_MAX_BYTES // 2**20} MiB of memory), so the run stopped before "
        "changing anything. Nothing was installed; prepare a new review after the network "
        "settles."
    ),
    Exit.ARCHIVE: (
        "The downloaded archive is not the reviewed bytes: its size or SHA-256 differs from "
        "the pin, or the download left an unexpected file. The run stopped before changing "
        "anything and no downloaded code ran."
    ),
    Exit.ENTRIES: (
        "The archive holds an entry the reviewed admission refuses (a link, device, unsafe "
        "name or mode, or more entries or bytes than the reviewed limits), so the run stopped "
        "before changing anything and no downloaded code ran."
    ),
    Exit.EXTRACT: (
        "The archive did not extract into the exact tree the review describes, so the run "
        "stopped before changing anything and no downloaded code ran."
    ),
    Exit.CHECKSUMS: (
        "WP-CLI's core checksum verification of the extracted tree failed, so the run stopped "
        "before changing anything and no downloaded code ran."
    ),
}
_GATE_REFUSALS: dict[int, str] = {
    Exit.GATE: (
        "The provisioning gate could not be published, so the site file was left as it was "
        "(or restored from its preimage). No application file or table exists."
    ),
    Exit.GATE_NOT_SERVING: (
        "Nginx accepted the provisioning gate but did not serve it as reviewed (503 for "
        "application paths, the challenge route kept), so Barectl restored the previous site "
        "file and verified nothing was published. No application file or table exists."
    ),
}
_PARTIAL: dict[int, str] = {
    Exit.GATE_NOT_RESTORED: (
        "The provisioning gate could not be proven restored or serving. The site file may be "
        "the gate or the previous form: read /etc/nginx/sites-available and `nginx -T` now. "
        "Application files are not published yet."
    ),
    Exit.PUBLISH: (
        "Publishing the release files stopped. Part of the release may already be in the "
        "public root, still behind the provisioning gate."
    ),
    Exit.PLACEHOLDER: (
        "The placeholder could not be replaced as reviewed. The release files are published "
        "behind the provisioning gate."
    ),
    Exit.LOADER: (
        "The public loader could not be published. The release files are published behind the "
        "provisioning gate; no table exists."
    ),
    Exit.CONFIGURATION: (
        "The private configuration could not be created or did not match its supported "
        "grammar. The release files and the loader are published behind the provisioning "
        "gate; no table exists."
    ),
    Exit.INSTALL: (
        "WP-CLI's core installation failed. The database may hold some WordPress tables, and "
        "the administrator account may or may not exist. The site stays behind the "
        "provisioning gate; core installation is never replayed into partial tables."
    ),
    Exit.SCHEMA: (
        "The database does not hold exactly the complete WordPress core schema and the "
        "canonical options. The site stays behind the provisioning gate."
    ),
    Exit.INTEGRITY: (
        "WP-CLI's core checksum verification of the published tree failed. The site stays "
        "behind the provisioning gate."
    ),
    Exit.ACCESS: (
        "WP-CLI or the site's own PHP-FPM pool could not reach the installed application as "
        "the site user. The site stays behind the provisioning gate."
    ),
    Exit.READY: (
        "The ready routing could not be published, so the provisioning gate was restored. The "
        "application is installed but not served."
    ),
}
_COMMON_REFUSALS: dict[Execution, str] = {
    Execution.LOCK_CONFLICT: (
        "Another change held Barectl's mutation lock on the server, so the run stopped before "
        "changing anything. Prepare a new review after that change finishes."
    ),
    Execution.UNSAFE_LOCK: (
        "The lock directory /run/lock/barectl or its lock file is not a root-owned private "
        "directory with an empty lock file, so the run stopped before changing anything. "
        "Remove it through ordinary administration, then prepare again."
    ),
    Execution.BOOT_CHANGED: (
        "The server restarted after the installation was reviewed, so the run stopped before "
        "changing anything. Prepare a new review."
    ),
    Execution.EXPIRED: (
        "The review's admission deadline had passed on the server's clock when the run "
        "started, so it stopped before changing anything. Prepare a new review."
    ),
    Execution.OTHER_RUN_ACTIVE: (
        "Another Barectl run still had processes on the server, so this run stopped before "
        "changing anything. Prepare a new review after it finishes."
    ),
    Execution.RENEWAL_ACTIVE: (
        "Scheduled certificate renewal still had processes on the server, so the run stopped "
        "before changing anything. Prepare a new review after it finishes."
    ),
    Execution.CAPACITY: (
        "The server kept too many finished runs when this run held the lock, so it stopped "
        "before changing anything. Clear finished runs with a reviewed cleanup, then prepare "
        "again."
    ),
}
_SERVING = (
    "The application is installed, but HTTPS did not serve it as reviewed. Barectl restored "
    "the provisioning gate and verified that application paths answer 503 again."
)
_EXPOSED = (
    "The application is installed, but HTTPS did not serve it as reviewed, and Barectl could "
    "not prove that the provisioning gate is back. The site may be reachable in an "
    "unverified state: read /etc/nginx/sites-available/{site}.conf and `nginx -T` now, and "
    "restore the gate or the previous form through ordinary administration."
)
_REFUSED = {
    **dict.fromkeys(install_native.ARTIFACT_REFUSALS, Execution.ARTIFACT_REFUSED),
    Exit.GATE: Execution.GATE_REFUSED,
    Exit.GATE_NOT_SERVING: Execution.GATE_REFUSED,
}


def execution(evidence: UnitEvidence) -> Execution:
    """The payload's own exit statuses; every other outcome as bootstrap reads it."""
    exited = evidence.exec_main_code == bootstrap_native.CLD_EXITED
    if not (evidence.found and evidence.terminal and exited):
        return evidence.execution
    status = evidence.exec_main_status
    if status in _REFUSED:
        return _REFUSED[status]
    if status in install_native.PARTIAL:
        return Execution.PARTIAL
    if status == Exit.NOT_SERVING:
        return Execution.NOT_SERVING
    if status == Exit.EXPOSED:
        return Execution.EXPOSURE_UNCERTAIN
    return evidence.execution


_TIMED_OUT = (
    "The run reached its {limit} limit and systemd stopped it. It may have changed the server: "
    "its staging directory was cleaned when systemd ended it, and the unit's journal names the "
    "last step."
)
_KILLED = (
    "The run was terminated by a signal before it finished. A staging directory named "
    ".wp-<unit> in the site directory may remain and is safe to remove."
)
_DRIFT = (
    "The site, its certificate, database, tool, files or the payload itself changed after "
    "review, so the run stopped before changing anything. Prepare a new review."
)
_INCOMPLETE = (
    "The run did not complete. It may have changed the server: inspect its unit with "
    "systemctl status and journalctl, the site directory for a leftover .wp-* staging "
    "directory (safe to remove) and the site file."
)


def failure(run: ApplyRun | None, outcome: Execution, exit_status: int | None) -> str:
    code = exit_status if exit_status is not None else -1
    exact = {
        Execution.ARTIFACT_REFUSED: _REFUSALS.get(code, ""),
        Execution.GATE_REFUSED: _GATE_REFUSALS.get(code, ""),
        Execution.DRIFT: _DRIFT,
        **_COMMON_REFUSALS,
    }
    if text := exact.get(outcome, ""):
        return text
    after = {
        Execution.PARTIAL: (
            f"Stopped at exit status {code}: {_PARTIAL[code]}" if code in _PARTIAL else ""
        ),
        Execution.NOT_SERVING: _SERVING,
        Execution.EXPOSURE_UNCERTAIN: _EXPOSED.format(site=_identifier(run)),
        Execution.TIMED_OUT: _TIMED_OUT.format(limit=bootstrap_native.RUNTIME_MAX),
        Execution.KILLED: _KILLED,
        Execution.VALIDATION_FAILED: _INCOMPLETE,
        Execution.FAILED: _INCOMPLETE,
    }.get(outcome, "")
    return f"{after}{_NOTHING_REMOVED}" if after else ""


def _identifier(run: ApplyRun | None) -> str:
    row = RunWordpressInstall.objects.filter(run=run).first() if run is not None else None
    return row.identifier if row is not None else "<site>"


def reviewed_changes(plan: ConfigurationPlan) -> str:
    row = PlanWordpressInstall.objects.filter(plan=plan).first()
    if row is None:
        return ""
    return "\n".join(
        (
            (
                f"Publish the provisioning gate (SHA-256 {row.gate_sha256}) for {row.url}, "
                f"keeping the site file's preimage (SHA-256 {row.preimage_sha256})"
            ),
            (
                f"Download {row.archive_url} ({row.archive_bytes} bytes, SHA-256 "
                f"{row.archive_sha256}) with WP-CLI {row.tool_version} as {row.site_user}"
            ),
            (
                f"Publish WordPress {row.core_version} into {row.public_root}"
                + (", replacing the exact placeholder" if row.placeholder_present else "")
            ),
            f"Create {row.private_configuration} and the loader {row.public_root}/wp-config.php",
            (
                f"Install the core schema in {row.database_name} for administrator "
                f"{row.admin_login} <{row.admin_email}>"
            ),
            f"Publish the ready routing (SHA-256 {row.ready_sha256}) and verify {row.url}/",
        )
    )


def copy_audit(plan: ConfigurationPlan, run: ApplyRun) -> None:
    """Keep the plan's exact review with the run, so the audit outlives the plan."""
    row = PlanWordpressInstall.objects.filter(plan=plan).first()
    if row is None:
        raise OperationRefused(EVIDENCE_FAILURE)
    RunWordpressInstall.objects.create(
        run=run,
        **{field.name: getattr(row, field.name) for field in InstallationReview._meta.local_fields},
    )
    if row.first_access_spki and row.first_access_expires_at is not None:
        FirstAccessDelivery.objects.create(
            run=run,
            requested_by_id=plan.preparation.requested_by_id,
            key_sha256=first_access.key_digest(row.first_access_spki),
            expires_at=row.first_access_expires_at,
            unavailable=True,
        )


def _evidence(plan: ConfigurationPlan) -> install_native.Evidence:
    digests = dict(plan.evidence.values_list("kind", "fingerprint"))
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
        raise OperationRefused(EVIDENCE_FAILURE) from None


def _pinned(row: InstallationReview) -> bool:
    """Whether the review still names exactly this version's pins, limits and routing forms."""
    if row.first_access_spki and (
        row.first_access_expires_at is None or row.first_access_expires_at <= timezone.now()
    ):
        return False
    names = tuple(row.names.split(" "))
    try:
        forms = {
            application: render_site(
                row.identifier,
                names,
                ipv6=row.ipv6,
                stage=Stage.REDIRECT,
                php_version=row.php_version if row.site_revision == CONVENTION_REVISION else "",
                application=application,
                canonical=row.canonical_name,
            )
            for application in (Application.WORDPRESS_GATE, Application.WORDPRESS)
        }
    except ValueError:
        return False
    return (
        row.tool_version == setup_native.VERSION
        and row.tool_path == setup_native.PHAR
        and row.tool_sha256 == setup_native.SHA256
        and row.core_version == core_native.VERSION
        and row.core_locale == core_native.LOCALE
        and row.archive_url == core_native.ARCHIVE_URL
        and row.archive_bytes == core_native.ARCHIVE_BYTES
        and row.archive_sha256 == core_native.ARCHIVE_SHA256
        and row.max_archive_bytes == core_native.MAX_ARCHIVE_BYTES
        and row.max_tree_bytes == core_native.MAX_TREE_BYTES
        and row.max_entries == core_native.MAX_ENTRIES
        and row.max_file_bytes == core_native.MAX_FILE_BYTES
        and row.memory_max_bytes == core_native.MEMORY_MAX_BYTES
        and row.runtime_limit_seconds == core_native.RUNTIME_LIMIT_SECONDS
        and row.gate_content == forms[Application.WORDPRESS_GATE]
        and row.ready_content == forms[Application.WORDPRESS]
        and row.loader_sha256 == install_native.digest(convention.render_loader(row.identifier))
    )


def payload(run: ApplyRun, plan: ConfigurationPlan) -> str:
    row = PlanWordpressInstall.objects.filter(plan=plan).first()
    if row is None or not _pinned(row):
        raise OperationRefused(EVIDENCE_FAILURE)
    try:
        text, body = install_native.staged_payload(
            run.unit_name,
            run.boot_id,
            run.admission_deadline_centiseconds,
            row,
            _evidence(plan),
            run.release,
        )
    except ValueError:
        raise OperationRefused(EVIDENCE_FAILURE) from None
    if install_native.digest(body) != row.body_sha256:
        raise OperationRefused(EVIDENCE_FAILURE)
    return text


def limits(run: ApplyRun) -> Limits:
    row = RunWordpressInstall.objects.filter(run=run).first()
    if row is None or (row.max_file_bytes, row.memory_max_bytes) != (
        core_native.MAX_FILE_BYTES,
        core_native.MEMORY_MAX_BYTES,
    ):
        raise OperationRefused(EVIDENCE_FAILURE)
    return Limits(row.max_file_bytes, row.memory_max_bytes)


def _suffix(run: ApplyRun) -> str:
    return run.unit_name.removeprefix(bootstrap_native.UNIT_PREFIX).removesuffix(".service")


def admit(shell: RemoteShell, run: ApplyRun, *, root: bool) -> None:
    row = RunWordpressInstall.objects.filter(run=run).first()
    if row is None:
        raise OperationRefused(EVIDENCE_FAILURE)
    if root:
        return
    argv = install_native.state(row, _suffix(run))
    if shell.run(bootstrap_native.authorization(argv)).exit_status:
        raise OperationRefused(VERIFY_PRIVILEGE)


def verify(shell: RemoteShell, run: ApplyRun) -> Verification:
    """docs/wordpress.md#applying-an-installation: a fresh read after a successful run."""
    row = RunWordpressInstall.objects.filter(run=run).first()
    root = bootstrap_native.is_root(shell)
    if row is None or root is None:
        return Verification.UNAVAILABLE
    argv = install_native.state(row, _suffix(run))
    if not root and shell.run(bootstrap_native.authorization(argv)).exit_status != 0:
        return Verification.UNAVAILABLE
    result = shell.run(bootstrap_native.privileged(argv, root=root))
    if result.exit_status or result.truncated:
        return Verification.UNAVAILABLE
    try:
        found = install_native.parse_state(result.stdout)
    except install_native.Unreadable:
        return Verification.UNAVAILABLE
    problems = install_native.problems(row, _suffix(run), found)
    if not InstallRunResult.objects.filter(run=run).exists():
        InstallRunResult.objects.create(
            run=run, problems="\n".join(problems), verified_at=timezone.now()
        )
    if not problems and row.first_access_spki and row.first_access_expires_at is not None:
        first_access.capture(
            shell, run, row.identifier, row.first_access_spki, row.first_access_expires_at
        )
    return Verification.FAILED if problems else Verification.PASSED


def audit(run: ApplyRun) -> list[str]:
    result = InstallRunResult.objects.filter(run=run).first()
    if result is None:
        return []
    return [
        f"Verified {timezone.localtime(result.verified_at):%b %-d, %Y, %H:%M:%S %Z}.",
        *result.problems.splitlines(),
    ]


def verification_failure(run: ApplyRun) -> str:
    result = InstallRunResult.objects.filter(run=run).first()
    problems = " ".join((result.problems if result else "").splitlines())
    return VERIFICATION_FAILED.format(problems=problems or "see the server.")
