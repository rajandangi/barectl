"""Applying a reviewed WP-CLI setup: its payload, outcome and verification.

docs/wordpress.md#applying-a-wp-cli-setup. The payload acquires and authenticates the
pinned artifacts on the server; this module binds the run to the reviewed pins, reads
the installation's native state afterwards, and separates the boundaries at which a
run stopped from the refusals that changed nothing.
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
from bootstrap.native import UnitEvidence
from discovery.ssh import RemoteShell
from operations.lifecycle import OperationRefused

from . import setup_native
from .models import PlanWpcliTool, RunWpcliTool, WpcliRunResult
from .setup import Unreadable, WpcliState, parse_state

Exit = setup_native.Exit
EVIDENCE_FAILURE = (
    "The reviewed WP-CLI setup is incomplete or its pins differ from this version's, so "
    "Barectl submitted nothing. Prepare a new plan."
)
VERIFY_PRIVILEGE = (
    "The SSH user is not root, and sudo -n -l does not authorize the fixed read-only command "
    "that verifies the setup afterwards, so Barectl submitted nothing."
)
VERIFICATION_FAILED = (
    "The setup ran, but the installation does not match the review: {problems} Barectl does "
    "not repair or roll back; inspect the server through ordinary administration "
    "(docs/wordpress.md#recovering-a-partial-tool-setup)."
)
_AFTER = (
    " Barectl never removes another tool's files automatically and never resumes a run; a "
    "new plan shows what exists (docs/wordpress.md#recovering-a-partial-tool-setup)."
)
_BOUNDARY = (
    f"Publishing the artifact stopped; a staged file beside {setup_native.PHAR} may remain "
    "and is safe to remove. Inspect the directory with ls -la "
    f"{setup_native.DIRECTORY}, then prepare a new plan, which installs what is missing."
)
_REFUSALS: dict[int, str] = {
    Exit.TOOLS: (
        "The server does not have /usr/bin/gpg and /usr/bin/curl, so the run stopped before "
        "changing anything. Install them through ordinary administration, then prepare a new "
        "plan."
    ),
    Exit.KEY: (
        "The published signing key did not authenticate as the approved primary identity "
        f"{setup_native.FINGERPRINT}, so the run stopped before changing anything. An "
        "unapproved key rotation refuses; prepare a new plan, and if the key truly changed, "
        "the review must be refreshed first."
    ),
    Exit.SIGNATURE: (
        "The downloaded release artifacts did not authenticate: the signature is invalid, "
        "revoked or expired, its signer is not the approved identity or a bound subkey, or "
        "the artifact's SHA-256 is not the reviewed one. Nothing was installed; prepare a "
        "new plan."
    ),
    Exit.DOWNLOAD: (
        "An official artifact could not be downloaded over HTTPS, so the run stopped before "
        "changing anything. Nothing was installed; prepare a new plan after the network or "
        "the release settles."
    ),
}
_REFUSED = {
    Exit.TOOLS: Execution.TOOL_REFUSED,
    Exit.KEY: Execution.TOOL_REFUSED,
    Exit.SIGNATURE: Execution.TOOL_REFUSED,
    Exit.DOWNLOAD: Execution.TOOL_REFUSED,
}


def execution(evidence: UnitEvidence) -> Execution:
    """The setup payload's own exit codes; every other outcome as bootstrap reads it."""
    exited = evidence.exec_main_code == bootstrap_native.CLD_EXITED
    terminal = evidence.found and evidence.terminal and exited
    if terminal and evidence.exec_main_status in _REFUSED:
        return _REFUSED[evidence.exec_main_status]
    if terminal and evidence.exec_main_status == Exit.FILE:
        return Execution.PARTIAL
    return evidence.execution


def failure(_run: ApplyRun | None, outcome: Execution, exit_status: int | None) -> str:
    if outcome == Execution.PARTIAL and exit_status == Exit.FILE:
        return f"Stopped at exit status {exit_status}: {_BOUNDARY}{_AFTER}"
    if outcome == Execution.TOOL_REFUSED and exit_status in _REFUSALS:
        return _REFUSALS[exit_status]
    if outcome == Execution.TOOL_REFUSED:
        return (
            "The authenticated tool could not be established, so the run stopped before "
            "changing anything. Prepare a new plan."
        )
    if outcome == Execution.SUCCEEDED:
        return ""
    if outcome == Execution.DRIFT:
        return (
            "The WP-CLI installation path or the native tools changed after review, so the "
            "run stopped before changing anything. Prepare a new plan."
        )
    if outcome in {
        Execution.VALIDATION_FAILED,
        Execution.TIMED_OUT,
        Execution.KILLED,
        Execution.FAILED,
    }:
        return (
            "The run did not complete its verified installation. Inspect its unit with "
            f"systemctl status and journalctl; a staged file beside {setup_native.PHAR} and "
            f"the run's private directory under /run may remain and are safe to "
            f"remove.{_AFTER}"
        )
    return ""


# Audit --------------------------------------------------------------------------------------


def reviewed_changes(plan: ConfigurationPlan) -> str:
    tool = PlanWpcliTool.objects.filter(plan=plan).first()
    if tool is None:
        return ""
    lines = [f"Authenticate WP-CLI {tool.version} against primary key {tool.fingerprint}"]
    if tool.creates_directory:
        lines.append(f"Create {setup_native.DIRECTORY}, root:root 0755")
    lines.append(
        f"Publish {tool.path}, root:root 0644, SHA-256 {tool.sha256}, downloaded from "
        f"{tool.phar_url}"
    )
    return "\n".join(lines)


def copy_audit(plan: ConfigurationPlan, run: ApplyRun) -> None:
    tool = PlanWpcliTool.objects.filter(plan=plan).first()
    if tool is None:
        raise OperationRefused(EVIDENCE_FAILURE)
    RunWpcliTool.objects.create(
        run=run,
        version=tool.version,
        phar_url=tool.phar_url,
        signature_url=tool.signature_url,
        key_url=tool.key_url,
        fingerprint=tool.fingerprint,
        sha256=tool.sha256,
        path=tool.path,
        creates_directory=tool.creates_directory,
        exists=tool.exists,
        payload_bytes=tool.payload_bytes,
    )


# Payload ------------------------------------------------------------------------------------


def _fingerprint(plan: ConfigurationPlan) -> str:
    return (
        plan.evidence.filter(kind=PlanEvidence.Kind.WPCLI_REVALIDATION)
        .values_list("fingerprint", flat=True)
        .first()
        or ""
    )


def payload(run: ApplyRun, plan: ConfigurationPlan) -> str:
    tool = PlanWpcliTool.objects.filter(plan=plan).first()
    if (
        tool is None
        or tool.version != setup_native.VERSION
        or tool.phar_url != setup_native.PHAR_URL
        or tool.signature_url != setup_native.SIGNATURE_URL
        or tool.key_url != setup_native.KEY_URL
        or tool.fingerprint != setup_native.FINGERPRINT
        or tool.sha256 != setup_native.SHA256
        or tool.path != setup_native.PHAR
        or tool.exists
    ):
        raise OperationRefused(EVIDENCE_FAILURE)
    digest = _fingerprint(plan)
    if not digest:
        raise OperationRefused(EVIDENCE_FAILURE)
    try:
        return setup_native.setup_payload(
            run.unit_name, run.boot_id, run.admission_deadline_centiseconds, digest=digest
        )
    except ValueError:
        raise OperationRefused(EVIDENCE_FAILURE) from None


def admit(shell: RemoteShell, run: ApplyRun, *, root: bool) -> None:
    if root:
        return
    if shell.run(bootstrap_native.authorization(setup_native.wpcli_state())).exit_status:
        raise OperationRefused(VERIFY_PRIVILEGE)


# Verification -------------------------------------------------------------------------------


def _problems(state: WpcliState) -> list[str]:
    """Each difference from the reviewed setup the read found."""
    problems: list[str] = []
    found = state.paths.get(setup_native.PHAR)
    if found != ("regular file", "root", "root", "644", "1") or (
        state.sha.get(setup_native.PHAR) != setup_native.SHA256
    ):
        problems.append(f"{setup_native.PHAR} does not have its reviewed bytes, owner and mode.")
    directory = state.paths.get(setup_native.DIRECTORY)
    if directory is None or directory[0:4] != ("directory", "root", "root", "755"):
        problems.append(f"{setup_native.DIRECTORY} is not a root:root 0755 directory.")
    staged = [
        entry[4]
        for entry in state.entries
        if entry[4] != setup_native.PHAR and entry[4].rpartition("/")[2].startswith(".")
    ]
    if staged:
        problems.append(f"A staged file remains: {', '.join(staged)}.")
    entries = sorted(entry[4] for entry in state.entries)
    if entries != [setup_native.PHAR]:
        problems.append(f"{setup_native.DIRECTORY} does not hold exactly the reviewed artifact.")
    return problems


def verify(shell: RemoteShell, run: ApplyRun) -> Verification:
    """docs/wordpress.md#applying-a-wp-cli-setup: a fresh read after a successful run."""
    root = bootstrap_native.is_root(shell)
    argv = setup_native.wpcli_state()
    if root is None or (
        not root and shell.run(bootstrap_native.authorization(argv)).exit_status != 0
    ):
        return Verification.UNAVAILABLE
    result = shell.run(bootstrap_native.privileged(argv, root=root))
    if result.exit_status or result.truncated:
        return Verification.UNAVAILABLE
    try:
        state = parse_state(result.stdout)
    except Unreadable:
        return Verification.UNAVAILABLE
    problems = _problems(state)
    if not WpcliRunResult.objects.filter(run=run).exists():
        WpcliRunResult.objects.create(
            run=run, problems="\n".join(problems), verified_at=timezone.now()
        )
    return Verification.FAILED if problems else Verification.PASSED


def audit(run: ApplyRun) -> list[str]:
    result = WpcliRunResult.objects.filter(run=run).first()
    if result is None:
        return []
    return [
        f"Verified {timezone.localtime(result.verified_at):%b %-d, %Y, %H:%M:%S %Z}.",
        *result.problems.splitlines(),
    ]


def verification_failure(run: ApplyRun) -> str:
    result = WpcliRunResult.objects.filter(run=run).first()
    problems = " ".join((result.problems if result else "").splitlines())
    return VERIFICATION_FAILED.format(problems=problems or "see the server.")
