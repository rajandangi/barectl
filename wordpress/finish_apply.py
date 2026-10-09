"""Applying a reviewed WordPress Finish: its payload, outcome and verification.

docs/wordpress.md#finishing-a-partial-installation. The payload publishes only what the review
found missing, compares and keeps everything that exists, and routes the application on the
server; this module binds the run to the reviewed rows and pins, separates the boundaries at
which a run stopped from the refusals that changed nothing, and reads the application's
native state afterwards with the installation's own verification. Nothing here ever holds a
password or a salt.
"""

import re

from django.utils import timezone

from bootstrap import native as bootstrap_native
from bootstrap.models import ApplyRun, ConfigurationPlan, Execution, Verification
from bootstrap.native import Limits, UnitEvidence
from discovery.ssh import RemoteShell
from operations.lifecycle import OperationRefused

from . import core_native, finish_native, inputs, install_apply, install_native
from .models import FinishReview, InstallRunResult, PlanWordpressFinish, RunWordpressFinish

Exit = finish_native.Exit
_DIGEST = re.compile(r"[0-9a-f]{64}")
EVIDENCE_FAILURE = (
    "The reviewed WordPress Finish is incomplete, or its pins or payload differ from this "
    "version's, so Barectl submitted nothing. Prepare a new review."
)
VERIFICATION_FAILED = (
    "The Finish ran, but the server does not match the review: {problems} Barectl does not "
    "repair or roll back; inspect the server through ordinary administration "
    "(docs/wordpress.md#finishing-a-partial-installation)."
)
_NOTHING_REMOVED = (
    " Barectl keeps every file, table, salt and account that exists, never replays core "
    "installation and removes nothing automatically; a new Finish review shows what exists "
    "(docs/wordpress.md#finishing-a-partial-installation)."
)
_NOT_GATED = (
    "The site file was not the reviewed provisioning gate serving 503 when the run started, or "
    "the gate's recovery preimage could not be kept, so the run stopped before changing "
    "anything. Prepare a new review."
)
_DRIFT = (
    "The site, its certificate, database, tool, existing files or the payload itself changed "
    "after review, so the run stopped before changing anything. Prepare a new review."
)
_EDITED = (
    "An existing release file or directory differs from the pinned WordPress archive's staged "
    "copy (the unit's journal, journalctl -u <unit>, names the first entry), so the run "
    "stopped before changing anything. Barectl replaces no existing file; correct the entry "
    "through ordinary administration, or restore it from your own backup, then prepare a new "
    "review."
)
_PARTIAL: dict[int, str] = {
    Exit.PUBLISH: (
        "Publishing the missing release entries stopped. Some may be published, behind the "
        "provisioning gate; existing entries were not touched."
    ),
    Exit.PLACEHOLDER: (
        "The placeholder could not be replaced as reviewed. The release is published behind "
        "the provisioning gate."
    ),
    Exit.LOADER: (
        "The public loader could not be created. The release is published behind the "
        "provisioning gate; a foreign file at the destination is kept."
    ),
    Exit.CONFIGURATION: (
        "The private configuration could not be created or did not match its supported "
        "grammar. The site stays behind the provisioning gate; a foreign file at the "
        "destination is kept."
    ),
    Exit.INSTALL: (
        "WP-CLI's core installation failed. The database may hold some WordPress tables, and "
        "the administrator account may or may not exist. The site stays behind the "
        "provisioning gate; core installation is never replayed into partial tables."
    ),
    Exit.SCHEMA: (
        "The database does not hold the complete WordPress core schema and the canonical "
        "options. The site stays behind the provisioning gate."
    ),
    Exit.INTEGRITY: (
        "WP-CLI's core checksum verification of the published tree failed. The site stays "
        "behind the provisioning gate."
    ),
    Exit.ACCESS: (
        "WP-CLI or the site's own PHP-FPM pool could not reach the application as the site "
        "user. The site stays behind the provisioning gate."
    ),
    Exit.READY: (
        "The ready routing could not be published, so the provisioning gate was restored. The "
        "application is complete but not served."
    ),
}
_REFUSED = {
    **dict.fromkeys(install_native.ARTIFACT_REFUSALS, Execution.ARTIFACT_REFUSED),
    Exit.NOT_GATED: Execution.NOT_GATED,
    Exit.EDITED: Execution.EDITED_FILES,
}
_SERVING = (
    "The application is complete, but HTTPS did not serve it as reviewed. Barectl restored "
    "the provisioning gate and verified that application paths answer 503 again."
)


def execution(evidence: UnitEvidence) -> Execution:
    """The payload's own exit statuses; every other outcome as bootstrap reads it."""
    exited = evidence.exec_main_code == bootstrap_native.CLD_EXITED
    if not (evidence.found and evidence.terminal and exited):
        return evidence.execution
    status = evidence.exec_main_status
    if status in _REFUSED:
        return _REFUSED[status]
    if status in _PARTIAL:
        return Execution.PARTIAL
    if status == Exit.NOT_SERVING:
        return Execution.NOT_SERVING
    if status == Exit.EXPOSED:
        return Execution.EXPOSURE_UNCERTAIN
    return evidence.execution


def failure(run: ApplyRun | None, outcome: Execution, exit_status: int | None) -> str:
    code = exit_status if exit_status is not None else -1
    exact = {
        Execution.ARTIFACT_REFUSED: install_apply._REFUSALS.get(code, ""),
        Execution.NOT_GATED: _NOT_GATED,
        Execution.EDITED_FILES: _EDITED,
        Execution.DRIFT: _DRIFT,
        **install_apply._COMMON_REFUSALS,
    }
    if text := exact.get(outcome, ""):
        return text
    after = {
        Execution.PARTIAL: (
            f"Stopped at exit status {code}: {_PARTIAL[code]}" if code in _PARTIAL else ""
        ),
        Execution.NOT_SERVING: _SERVING,
        Execution.EXPOSURE_UNCERTAIN: install_apply._EXPOSED.format(site=_identifier(run)),
        Execution.TIMED_OUT: install_apply._TIMED_OUT.format(limit=bootstrap_native.RUNTIME_MAX),
        Execution.KILLED: install_apply._KILLED,
        Execution.VALIDATION_FAILED: install_apply._INCOMPLETE,
        Execution.FAILED: install_apply._INCOMPLETE,
    }.get(outcome, "")
    return f"{after}{_NOTHING_REMOVED}" if after else ""


def _identifier(run: ApplyRun | None) -> str:
    row = RunWordpressFinish.objects.filter(run=run).first() if run is not None else None
    return row.identifier if row is not None else "<site>"


# Audit --------------------------------------------------------------------------------------


def reviewed_changes(plan: ConfigurationPlan) -> str:
    row = PlanWordpressFinish.objects.filter(plan=plan).first()
    if row is None:
        return ""
    if not row.compares:
        publishing = "Publish the whole release into the public tree, which holds no release entry"
    elif row.absent_names:
        publishing = f"Publish the release entries the public root lacks ({row.absent_names})"
    else:
        publishing = "Publish no release entry; every one exists and is compared"
    lines = [
        (
            f"Verify that the provisioning gate (SHA-256 {row.gate_sha256}) serves {row.url} and "
            "keep its bytes as the recovery preimage"
        ),
        (
            f"Download {row.archive_url} ({row.archive_bytes} bytes, SHA-256 "
            f"{row.archive_sha256}) with WP-CLI {row.tool_version} as {row.site_user}"
        ),
        (
            "Compare the existing release files with the staged copy and replace none"
            if row.compares
            else "Find no release entry in the public root"
        ),
        f"{publishing} in {row.public_root}"
        + (", replacing the exact placeholder" if row.placeholder_present else ""),
        (
            f"Create the loader {row.public_root}/wp-config.php"
            if row.creates_loader
            else "Keep the existing loader"
        ),
        (
            f"Create {row.private_configuration} with new salts"
            if row.creates_configuration
            else f"Keep {row.private_configuration} (SHA-256 {row.configuration_sha256})"
        ),
        (
            f"Install the core schema in {row.database_name} for administrator "
            f"{row.admin_login} <{row.admin_email}>"
            if row.runs_install
            else f"Keep the installed core schema in {row.database_name}; run no installation"
        ),
        f"Publish the ready routing (SHA-256 {row.ready_sha256}) and verify {row.url}/",
    ]
    return "\n".join(lines)


def copy_audit(plan: ConfigurationPlan, run: ApplyRun) -> None:
    """Keep the plan's exact review with the run, so the audit outlives the plan."""
    row = PlanWordpressFinish.objects.filter(plan=plan).first()
    if row is None:
        raise OperationRefused(EVIDENCE_FAILURE)
    RunWordpressFinish.objects.create(
        run=run,
        **{field.name: getattr(row, field.name) for field in FinishReview._meta.local_fields},
    )


# Payload ------------------------------------------------------------------------------------


def _consistent(row: FinishReview) -> bool:
    """Whether the review's decisions agree with one another, as preparation records them."""
    kept = bool(_DIGEST.fullmatch(row.configuration_sha256))
    account = not inputs.problems(
        inputs.Metadata(row.canonical_name, row.title, row.admin_login, row.admin_email)
    )
    return (
        row.runs_install == row.strict_content
        and row.creates_configuration != kept
        and (account if row.runs_install else not (row.title or row.admin_login or row.admin_email))
    )


def _evidence(plan: ConfigurationPlan) -> install_native.Evidence:
    try:
        return install_apply._evidence(plan)
    except OperationRefused:
        raise OperationRefused(EVIDENCE_FAILURE) from None


def payload(run: ApplyRun, plan: ConfigurationPlan) -> str:
    row = PlanWordpressFinish.objects.filter(plan=plan).first()
    if row is None or not install_apply._pinned(row) or not _consistent(row):
        raise OperationRefused(EVIDENCE_FAILURE)
    try:
        text, body = finish_native.staged_payload(
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
    row = RunWordpressFinish.objects.filter(run=run).first()
    if row is None or (row.max_file_bytes, row.memory_max_bytes) != (
        core_native.MAX_FILE_BYTES,
        core_native.MEMORY_MAX_BYTES,
    ):
        raise OperationRefused(EVIDENCE_FAILURE)
    return Limits(row.max_file_bytes, row.memory_max_bytes)


def admit(shell: RemoteShell, run: ApplyRun, *, root: bool) -> None:
    row = RunWordpressFinish.objects.filter(run=run).first()
    if row is None:
        raise OperationRefused(EVIDENCE_FAILURE)
    if root:
        return
    argv = install_native.state(row, install_apply._suffix(run))
    if shell.run(bootstrap_native.authorization(argv)).exit_status:
        raise OperationRefused(install_apply.VERIFY_PRIVILEGE)


# Verification -------------------------------------------------------------------------------


def verify(shell: RemoteShell, run: ApplyRun) -> Verification:
    """docs/wordpress.md#finishing-a-partial-installation: a fresh read after a successful
    run, held to the installation's own postconditions. A database that already held the
    installation may hold plugin tables beside the core ones."""
    row = RunWordpressFinish.objects.filter(run=run).first()
    root = bootstrap_native.is_root(shell)
    if row is None or root is None:
        return Verification.UNAVAILABLE
    suffix = install_apply._suffix(run)
    argv = install_native.state(row, suffix)
    if not root and shell.run(bootstrap_native.authorization(argv)).exit_status != 0:
        return Verification.UNAVAILABLE
    result = shell.run(bootstrap_native.privileged(argv, root=root))
    if result.exit_status or result.truncated:
        return Verification.UNAVAILABLE
    try:
        found = install_native.parse_state(result.stdout)
    except install_native.Unreadable:
        return Verification.UNAVAILABLE
    problems = install_native.problems(row, suffix, found, exact_tables=row.runs_install)
    if not InstallRunResult.objects.filter(run=run).exists():
        InstallRunResult.objects.create(
            run=run, problems="\n".join(problems), verified_at=timezone.now()
        )
    return Verification.FAILED if problems else Verification.PASSED


def audit(run: ApplyRun) -> list[str]:
    return install_apply.audit(run)


def verification_failure(run: ApplyRun) -> str:
    result = InstallRunResult.objects.filter(run=run).first()
    problems = " ".join((result.problems if result else "").splitlines())
    return VERIFICATION_FAILED.format(problems=problems or "see the server.")
