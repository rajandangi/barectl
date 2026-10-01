"""Applying a reviewed renewal setup: its payload, outcome and verification.

docs/tls.md#applying-renewal-setup; the inhibition is recorded in
docs/adr/0013-inhibit-certbot-renewal-until-the-guard-is-verified.md.
"""

from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone

from bootstrap import apply as bootstrap_apply
from bootstrap import native as bootstrap_native
from bootstrap import releases
from bootstrap.evidence import Unreadable as EvidenceUnreadable
from bootstrap.models import (
    Action,
    ApplyRun,
    ConfigurationPlan,
    Execution,
    PackageTransition,
    PlanEvidence,
    Verification,
)
from bootstrap.native import UnitEvidence
from bootstrap.profiles import profile
from discovery.ssh import RemoteShell
from operations.lifecycle import OperationRefused
from sites import apply as site_apply

from . import renewal, setup_native
from .models import PlanRenewalFile, RunRenewalFile, SetupRunResult
from .setup import RenewalState, Unreadable, parse_state

Exit = setup_native.Exit
EVIDENCE_FAILURE = (
    "The reviewed renewal setup is incomplete, or its files differ from the ones this "
    "version of Barectl publishes, so Barectl submitted nothing. Prepare a new plan."
)
VERIFY_PRIVILEGE = (
    "The SSH user is not root, and sudo -n -l does not authorize the fixed read-only command "
    "that verifies the renewal setup afterwards, so Barectl submitted nothing."
)
VERIFICATION_FAILED = (
    "The setup ran, but the server does not match the review: {problems} Barectl does not "
    "repair or roll back; inspect the server through ordinary administration "
    "(docs/tls.md#recovering-a-partial-setup)."
)
_AFTER = (
    " Barectl never removes packages or files automatically and never resumes a run; a new "
    "plan shows what exists (docs/tls.md#recovering-a-partial-setup)."
)
_UNMASK = "systemctl unmask --runtime certbot.timer certbot.service"
_BOUNDARIES = {
    Exit.FILES: (
        "Certbot is installed, but publishing the renewal files stopped. certbot.timer and "
        "certbot.service stay masked at runtime, so nothing renews, and after a restart the "
        "timer stays disabled. Inspect the files with ls -l /usr/local/sbin/barectl-certbot-* "
        f"{renewal.DROP_IN_DIRECTORY}; prepare a new plan, which publishes what is missing."
    ),
    Exit.OVERRIDE: (
        "The renewal files were published, but systemd did not load certbot.service with "
        "exactly the reviewed drop-in, or a script is not valid shell. certbot.timer stays "
        "masked at runtime and disabled. Inspect it with systemctl cat certbot.service and "
        f"systemctl show certbot.service; after correcting it, run {_UNMASK} and prepare a new "
        "plan."
    ),
    Exit.TIMER: (
        "The override was verified, but certbot.timer could not be unmasked, enabled or "
        "started. Inspect it with systemctl status certbot.timer; a new plan enables it."
    ),
}
_REFUSALS: dict[Execution, str] = {
    **site_apply.REFUSALS,
    **{
        outcome: text
        for outcome, text in bootstrap_apply.PACKAGE_FAILURES.items()
        if outcome in Execution.refused_before_changes()
    },
    Execution.INHIBITION_FAILED: (
        "systemd refused to mask certbot.timer and certbot.service at runtime, so the run "
        "removed any mask it had added and stopped before changing anything. Inspect them "
        "with systemctl status, then prepare a new plan."
    ),
    Execution.DRIFT: (
        "The APT configuration, the packages, Certbot's configuration and state, its units "
        "or scheduled tasks changed after review, so the run stopped before changing "
        "anything and removed its runtime masks. Prepare a new plan."
    ),
}
_REFUSALS.pop(Execution.ACCOUNT_BUSY, None)


def execution(evidence: UnitEvidence) -> Execution:
    exited = evidence.exec_main_code == bootstrap_native.CLD_EXITED
    terminal = evidence.found and evidence.terminal and exited
    if terminal and evidence.exec_main_status == Exit.INHIBITION:
        return Execution.INHIBITION_FAILED
    if terminal and evidence.exec_main_status in _BOUNDARIES:
        return Execution.PARTIAL
    return evidence.execution


def failure(_run: ApplyRun | None, outcome: Execution, exit_status: int | None) -> str:
    if outcome in _REFUSALS:
        return _REFUSALS[outcome]
    if outcome == Execution.PARTIAL and exit_status in _BOUNDARIES:
        return f"Stopped at exit status {exit_status}: {_BOUNDARIES[exit_status]}{_AFTER}"
    if outcome == Execution.SUCCEEDED:
        return ""
    package = bootstrap_apply.PACKAGE_FAILURES.get(outcome)
    masked = (
        f" certbot.timer and certbot.service stay masked at runtime until the server restarts "
        f"or {_UNMASK}; the timer stays disabled."
    )
    if package is not None:
        return f"{package}{masked}"
    return f"The run failed. Inspect its unit with systemctl status and journalctl.{masked}"


# Audit --------------------------------------------------------------------------------------


def reviewed_changes(plan: ConfigurationPlan) -> str:
    lines = [
        f"Install {item.package} {item.version} ({item.architecture})"
        for item in plan.transitions.filter(step=PackageTransition.Step.INSTALL)
    ]
    lines.append("Mask certbot.timer and certbot.service at runtime for the run")
    lines += [
        f"Publish {item.path}, root:root {item.mode}, SHA-256 {item.content_sha256}"
        for item in PlanRenewalFile.objects.filter(plan=plan, exists=False)
    ]
    lines += [
        "Verify certbot.service's override, then unmask both units",
        "Enable and start certbot.timer",
    ]
    return "\n".join(lines)


def copy_audit(plan: ConfigurationPlan, run: ApplyRun) -> None:
    RunRenewalFile.objects.bulk_create(
        RunRenewalFile(
            run=run,
            **{
                name: getattr(item, name)
                for name in (
                    "position",
                    "role",
                    "path",
                    "mode",
                    "content",
                    "content_sha256",
                    "exists",
                )
            },
        )
        for item in PlanRenewalFile.objects.filter(plan=plan)
    )


# Payload ------------------------------------------------------------------------------------


def _fingerprint(plan: ConfigurationPlan, kind: PlanEvidence.Kind) -> str:
    return plan.evidence.filter(kind=kind).values_list("fingerprint", flat=True).first() or ""


def payload(run: ApplyRun, plan: ConfigurationPlan) -> str:
    release = releases.RELEASES.get(run.release)
    reviewed = {
        item.path: item.content_sha256 for item in PlanRenewalFile.objects.filter(plan=plan)
    }
    current = {file.path: file.sha256 for file in renewal.files()}
    if release is None or reviewed != current:
        raise OperationRefused(EVIDENCE_FAILURE)
    certbot = profile(release, Action.CERTBOT)
    transitions = list(plan.transitions.all())
    try:
        return setup_native.setup_payload(
            run.unit_name,
            run.boot_id,
            run.admission_deadline_centiseconds,
            apt=_fingerprint(plan, PlanEvidence.Kind.APT_REVALIDATION),
            packages=_fingerprint(plan, PlanEvidence.Kind.PACKAGE_REVALIDATION),
            scope=certbot.revalidation,
            digest=_fingerprint(plan, PlanEvidence.Kind.RENEWAL_REVALIDATION),
            roots=[(root.name, root.version) for root in plan.roots.all() if not root.installed],
            actions=[
                bootstrap_native.PackageAction(
                    item.step == PackageTransition.Step.INSTALL,
                    item.package,
                    item.version,
                    item.architecture,
                )
                for item in transitions
            ],
            check=certbot.check,
        )
    except ValueError, ObjectDoesNotExist:
        raise OperationRefused(EVIDENCE_FAILURE) from None


def admit(shell: RemoteShell, run: ApplyRun, *, root: bool) -> None:
    if root:
        return
    if shell.run(bootstrap_native.authorization(setup_native.renewal_state())).exit_status:
        raise OperationRefused(VERIFY_PRIVILEGE)


# Verification -------------------------------------------------------------------------------


def _problems(run: ApplyRun, state: RenewalState) -> list[str]:
    problems = []
    for item in RunRenewalFile.objects.filter(run=run):
        found = state.paths.get(item.path)
        exact = found == ("regular file", "root", "root", item.mode.lstrip("0"), "1")
        if not exact or state.sha.get(item.path) != item.content_sha256:
            problems.append(f"{item.path} does not have its reviewed bytes, owner and mode.")
    service = state.units.get("certbot.service", {})
    timer = state.units.get("certbot.timer", {})
    override = {
        "FragmentPath": "/usr/lib/systemd/system/certbot.service",
        "DropInPaths": renewal.DROP_IN,
        "SuccessExitStatus": f"{renewal.Outcome.LOCK_HELD} {renewal.Outcome.APPLY_ACTIVE}",
        "TimeoutStartUSec": "30min",
        "TimeoutStopUSec": "1min",
        "KillMode": "control-group",
    }
    argv = f"argv[]=/usr/bin/sh {renewal.WRAPPER} ;"
    if any(service.get(key) != value for key, value in override.items()) or (
        argv not in service.get("ExecStart", "")
    ):
        problems.append("certbot.service does not load exactly the reviewed override.")
    schedule = (
        timer.get("UnitFileState"),
        timer.get("ActiveState"),
        timer.get("DropInPaths"),
        timer.get("RandomizedDelayUSec"),
    )
    if schedule != ("enabled", "active", "", renewal.TIMER_RANDOMIZED_DELAY):
        problems.append(
            "certbot.timer is not enabled and active with the packaged schedule and no drop-in."
        )
    masks = [path for _kind, path, _ in state.systemd if path.startswith("/run/systemd/system/")]
    if masks:
        problems.append(f"Runtime units remain: {', '.join(masks)}.")
    if not {renewal.WRAPPER, renewal.DEPLOY_HOOK} <= state.syntax:
        problems.append("A renewal script is not valid shell.")
    return problems


def verify(shell: RemoteShell, run: ApplyRun) -> Verification:
    """docs/tls.md#applying-renewal-setup: fresh reads after a successful run."""
    root = bootstrap_native.is_root(shell)
    argv = setup_native.renewal_state()
    if root is None or (
        not root and shell.run(bootstrap_native.authorization(argv)).exit_status != 0
    ):
        return Verification.UNAVAILABLE
    result = shell.run(bootstrap_native.privileged(argv, root=root))
    if result.exit_status or result.truncated:
        return Verification.UNAVAILABLE
    release = releases.RELEASES.get(run.release)
    plan = run.plan
    expected = {}
    if plan is not None:
        expected = {
            item.package: item.version
            for item in plan.transitions.filter(step=PackageTransition.Step.INSTALL)
        }
    try:
        state = parse_state(result.stdout)
        installed = bootstrap_apply.packages_installed(shell, expected) if expected else True
    except Unreadable, EvidenceUnreadable:
        return Verification.UNAVAILABLE
    problems = _problems(run, state)
    if not installed:
        problems.insert(
            0, "A reviewed package is not installed at its version, or dpkg reports a problem."
        )
    if release is not None and state.version != f"certbot {release.certbot}":
        problems.append(f"certbot --version reports {state.version or 'nothing'}.")
    if not SetupRunResult.objects.filter(run=run).exists():
        SetupRunResult.objects.create(
            run=run, problems="\n".join(problems), verified_at=timezone.now()
        )
    return Verification.FAILED if problems else Verification.PASSED


def audit(run: ApplyRun) -> list[str]:
    result = SetupRunResult.objects.filter(run=run).first()
    if result is None:
        return []
    return [
        f"Verified {timezone.localtime(result.verified_at):%b %-d, %Y, %H:%M:%S %Z}.",
        *result.problems.splitlines(),
    ]


def verification_failure(run: ApplyRun) -> str:
    result = SetupRunResult.objects.filter(run=run).first()
    problems = " ".join((result.problems if result else "").splitlines())
    return VERIFICATION_FAILED.format(problems=problems or "see the server.")
