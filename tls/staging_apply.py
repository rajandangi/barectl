"""Applying a reviewed staging order: its payload, outcome, verification and audit.

docs/tls.md#staging. Every failure boundary leaves the site's HTTP serving as it was;
verification reads the staged certificate's evidence with fresh eyes and never touches a
production lineage.
"""

import re

from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone

from bootstrap import native as bootstrap_native
from bootstrap.models import ApplyRun, ConfigurationPlan, Execution, PlanEvidence, Verification
from bootstrap.native import UnitEvidence
from discovery.ssh import RemoteShell
from operations.lifecycle import OperationRefused

from . import staging_native
from .models import PlanTlsStaging, RunStaging, StagingRunResult

EVIDENCE_FAILURE = (
    "The reviewed staging plan is incomplete or its site file differs from the convention, "
    "so Barectl submitted nothing. Prepare a new plan."
)
VERIFY_PRIVILEGE = (
    "The SSH user is not root, and sudo -n -l does not authorize the fixed read-only command "
    "that reads the staged certificate, so Barectl submitted nothing. Barectl never installs "
    "a sudo policy or asks for a password."
)
VERIFICATION_FAILED = (
    "The order succeeded, but the staged certificate does not match the review: {problems} "
    "Barectl does not repair or remove anything; inspect the staging state on the server "
    "through ordinary administration."
)
FAILED = "The staging order did not succeed. Working HTTP is unchanged."
DRIFT = (
    "The site's evidence changed before or during the staging order. A staged certificate "
    "may exist. Inspect the isolated staging state and HTTP serving, then prepare again."
)

_FAILURES = {
    staging_native.DNS: staging_native._FAILURES[staging_native.DNS],
    staging_native.AUTHORITY_CAA: staging_native._FAILURES[staging_native.AUTHORITY_CAA],
    staging_native.RATE_LIMITED: staging_native._FAILURES[staging_native.RATE_LIMITED],
    staging_native.ACCOUNT: staging_native._FAILURES[staging_native.ACCOUNT],
    staging_native.ORDER_FAILED: staging_native._FAILURES[staging_native.ORDER_FAILED],
}

# Certbot 2.x issues SAN-only certificates, so the subject line exists but may be empty.
_SUBJECT = re.compile(r"^subject=(.*)$", re.MULTILINE)
_DATES = re.compile(r"^(notBefore|notAfter)=(.+)$", re.MULTILINE)
_NAMES = re.compile(r"DNS:([^,\s]+)")


def execution(evidence: UnitEvidence) -> Execution:
    """The payload's own exit codes; every other outcome as bootstrap reads it."""
    exited = evidence.exec_main_code == bootstrap_native.CLD_EXITED
    terminal = evidence.found and evidence.terminal and exited
    if terminal and evidence.exec_main_status in _FAILURES:
        return Execution.FAILED
    return evidence.execution


def failure(run: ApplyRun, execution: Execution, exit_status: int | None) -> str:
    staging = RunStaging.objects.filter(run=run).first()
    if staging is not None and exit_status in _FAILURES:
        return _FAILURES[exit_status]
    if execution == Execution.DRIFT:
        return DRIFT
    return FAILED


def reviewed_changes(plan: ConfigurationPlan) -> str:
    staging = plan.staging
    return (
        f"Order a staging certificate for {', '.join(staging.name_list)} from "
        f"{staging.authority_name} into {staging_native.config_dir(staging.identifier)}, "
        "never referenced by Nginx"
    )


def copy_audit(plan: ConfigurationPlan, run: ApplyRun) -> None:
    staging = PlanTlsStaging.objects.get(plan=plan)
    RunStaging.objects.create(
        run=run,
        identifier=staging.identifier,
        php_version=staging.php_version,
        names=staging.names,
        webroot=staging.webroot,
        authority=staging.authority,
        authority_name=staging.authority_name,
        email=staging.email,
        cert_name=staging.cert_name,
    )


def payload(run: ApplyRun, plan: ConfigurationPlan) -> str:
    try:
        staging = plan.staging
        digest = (
            plan.evidence.filter(kind=PlanEvidence.Kind.SITE_REVALIDATION)
            .values_list("fingerprint", flat=True)
            .first()
        )
        return staging_native.payload(
            run.unit_name,
            run.boot_id,
            run.admission_deadline_centiseconds,
            identifier=staging.identifier,
            php_version=staging.php_version,
            webroot=staging.webroot,
            names=staging.name_list,
            email=staging.email,
            directory=staging.authority,
            site_digest=digest or "",
        )
    except ObjectDoesNotExist:
        raise OperationRefused(EVIDENCE_FAILURE) from None


def admit(shell: RemoteShell, run: ApplyRun, *, root: bool) -> None:
    staging = RunStaging.objects.filter(run=run).first()
    if staging is None:
        raise OperationRefused(EVIDENCE_FAILURE)
    if root:
        return
    argv = staging_native.lineage_argv(staging.identifier)
    if shell.run(bootstrap_native.authorization(argv)).exit_status != 0:
        raise OperationRefused(VERIFY_PRIVILEGE)


def verify(shell: RemoteShell, run: ApplyRun) -> Verification:
    """docs/tls.md#staging: fresh reads of the staged certificate and the untouched site."""
    staging = RunStaging.objects.filter(run=run).first()
    if staging is None:
        return Verification.UNAVAILABLE
    root = bootstrap_native.is_root(shell)
    argv = staging_native.lineage_argv(staging.identifier)
    if root is None or (
        not root and shell.run(bootstrap_native.authorization(argv)).exit_status != 0
    ):
        return Verification.UNAVAILABLE
    result = shell.run(bootstrap_native.privileged(argv, root=root))
    if result.exit_status != 0 or result.truncated:
        return Verification.UNAVAILABLE
    stdout = result.stdout
    fields = {label: value.strip() for label, value in _DATES.findall(stdout)}
    subject = _SUBJECT.search(stdout)
    problems = []
    if subject is None:
        problems.append("the staged certificate does not exist under the staging configuration.")
    else:
        fields["subject"] = subject[1].strip()
    names = tuple(match[1] for match in _NAMES.finditer(stdout))
    if subject is not None and sorted(names) != sorted(staging.name_list):
        problems.append(f"the staged certificate names {', '.join(names) or 'nothing'}.")
    StagingRunResult.objects.update_or_create(
        run=run,
        defaults={
            "subject": fields.get("subject", ""),
            "not_before": fields.get("notBefore", ""),
            "not_after": fields.get("notAfter", ""),
            "names": "\n".join(names),
            "problems": " ".join(problems),
            "verified_at": timezone.now(),
        },
    )
    return Verification.FAILED if problems else Verification.PASSED


def verification_failure(run: ApplyRun) -> str:
    result = StagingRunResult.objects.filter(run=run).first()
    problems = " ".join((result.problems if result else "").splitlines())
    return VERIFICATION_FAILED.format(problems=problems or "see the server.")


def audit(run: ApplyRun) -> list[str]:
    staging = RunStaging.objects.filter(run=run).first()
    if staging is None:
        return []
    certificate = StagingRunResult.objects.filter(run=run).first()
    dated = (
        f", valid {certificate.not_before} to {certificate.not_after}"
        if certificate and certificate.not_after
        else ""
    )
    return [
        (
            f"Staged a certificate for {', '.join(staging.name_list)} from "
            f"{staging.authority_name}, never referenced by Nginx{dated}"
        )
    ]
