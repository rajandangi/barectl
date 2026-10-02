"""Applying a reviewed production certificate order: its payload, outcome and verification.

docs/tls.md#issuance. Every failure boundary leaves the site's HTTP serving as it was and
never touches Nginx; verification reads the lineage's public identity with fresh eyes and
never reads private-key bytes into Barectl.
"""

import re
from dataclasses import dataclass

from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone

from bootstrap import native as bootstrap_native
from bootstrap.models import ApplyRun, ConfigurationPlan, Execution, PlanEvidence, Verification
from bootstrap.native import UnitEvidence
from discovery.ssh import RemoteShell
from operations.lifecycle import OperationRefused

from . import issuance_native
from .models import IssuanceRunResult, PlanTlsIssuance, RunTlsIssuance

EVIDENCE_FAILURE = (
    "The reviewed production order plan is incomplete or its evidence differs from the "
    "review, so Barectl submitted nothing. Prepare a new plan."
)
VERIFY_PRIVILEGE = (
    "The SSH user is not root, and sudo -n -l does not authorize the fixed read-only command "
    "that reads the issued lineage, so Barectl submitted nothing. Barectl never installs a "
    "sudo policy or asks for a password."
)
FAILED = "The production order did not succeed. Working HTTP is unchanged."
DRIFT = (
    "The site's, the renewal setup's, the readiness reads' or the lineage state changed after "
    "the review, so the order stopped before Certbot ran. Prepare a new production order "
    "plan to review the current state."
)
VERIFICATION_FAILED = (
    "The order succeeded, but the issued certificate does not match the review: {problems} "
    "Barectl does not repair or remove anything; inspect the lineage through ordinary "
    "administration. A fresh activation-only review can reference the certificate."
)

_FAILURES = {
    issuance_native.DNS: issuance_native._FAILURES[issuance_native.DNS],
    issuance_native.AUTHORITY_CAA: issuance_native._FAILURES[issuance_native.AUTHORITY_CAA],
    issuance_native.RATE_LIMITED: issuance_native._FAILURES[issuance_native.RATE_LIMITED],
    issuance_native.ACCOUNT: issuance_native._FAILURES[issuance_native.ACCOUNT],
    issuance_native.ORDER_FAILED: issuance_native._FAILURES[issuance_native.ORDER_FAILED],
}

# Certbot 2.x issues SAN-only certificates, so the subject line exists but may be empty.
_SUBJECT = re.compile(r"^subject=(.*)$", re.MULTILINE)
_DATES = re.compile(r"^(notBefore|notAfter)=(.+)$", re.MULTILINE)
_NAMES = re.compile(r"DNS:([^,\s]+)")
_SERIAL = re.compile(r"^serial=([0-9A-Fa-f]+)$", re.MULTILINE)
_FINGERPRINT = re.compile(r"^sha256 Fingerprint=([0-9A-Fa-f:]+)$", re.MULTILINE | re.IGNORECASE)
_PUBKEY_CERT = re.compile(r"^pubkey_cert=([0-9a-f]{64})$", re.MULTILINE)
_PUBKEY_KEY = re.compile(r"^pubkey_key=([0-9a-f]{64})$", re.MULTILINE)
_CURVE = re.compile(r"^curve=(\S*)$", re.MULTILINE)
_RENEWAL = re.compile(r"^renewal=(yes|no)$", re.MULTILINE)
QUALIFIED_CURVE = "prime256v1"


@dataclass(frozen=True)
class LineageFacts:
    """The public facts of an issued lineage, as one openssl read answered them."""

    # Whether the certificate exists at all; Certbot 2.x SAN-only certificates have an
    # empty subject, so an empty string is not absence.
    present: bool
    subject: str
    not_before: str
    not_after: str
    names: tuple[str, ...]
    fingerprint: str
    serial: str
    curve: str
    key_matches: bool
    renewal: bool


def lineage_facts(stdout: str) -> LineageFacts:
    """Parse the fixed lineage read; a missing subject means no certificate exists."""
    fields = {label: value.strip() for label, value in _DATES.findall(stdout)}
    subject = _SUBJECT.search(stdout)
    names = tuple(match[1] for match in _NAMES.finditer(stdout))
    serial = _SERIAL.search(stdout)
    fingerprint = _FINGERPRINT.search(stdout)
    cert_key = _PUBKEY_CERT.search(stdout)
    private_key = _PUBKEY_KEY.search(stdout)
    curve = _CURVE.search(stdout)
    renewal = _RENEWAL.search(stdout)
    return LineageFacts(
        present=subject is not None,
        subject=subject[1].strip() if subject else "",
        not_before=fields.get("notBefore", ""),
        not_after=fields.get("notAfter", ""),
        names=names,
        fingerprint=fingerprint[1].replace(":", "").lower() if fingerprint else "",
        serial=serial[1].upper() if serial else "",
        curve=curve[1] if curve and curve[1] else "",
        key_matches=bool(cert_key and private_key and cert_key[1] == private_key[1]),
        renewal=renewal is not None and renewal[1] == "yes",
    )


def execution(evidence: UnitEvidence) -> Execution:
    """The payload's own exit codes; every other outcome as bootstrap reads it."""
    exited = evidence.exec_main_code == bootstrap_native.CLD_EXITED
    terminal = evidence.found and evidence.terminal and exited
    if terminal and evidence.exec_main_status in _FAILURES:
        return Execution.FAILED
    return evidence.execution


def failure(run: ApplyRun, execution: Execution, exit_status: int | None) -> str:
    if exit_status in _FAILURES:
        return _FAILURES[exit_status]
    if execution == Execution.DRIFT:
        return DRIFT
    return FAILED


def reviewed_changes(plan: ConfigurationPlan) -> str:
    issuance = plan.issuance
    return (
        f"Order one production certificate for {', '.join(issuance.name_list)} from "
        f"{issuance.authority_name} into Certbot's ordinary lineage "
        f"{issuance_native.lineage_dir(issuance.identifier)}, never referenced by Nginx"
    )


def copy_audit(plan: ConfigurationPlan, run: ApplyRun) -> None:
    issuance = PlanTlsIssuance.objects.get(plan=plan)
    RunTlsIssuance.objects.create(
        run=run,
        identifier=issuance.identifier,
        php_version=issuance.php_version,
        names=issuance.names,
        webroot=issuance.webroot,
        authority=issuance.authority,
        authority_name=issuance.authority_name,
        email=issuance.email,
        cert_name=issuance.cert_name,
        account=issuance.account,
    )


def payload(run: ApplyRun, plan: ConfigurationPlan) -> str:
    try:
        issuance = plan.issuance
        return issuance_native.payload(
            run.unit_name,
            run.boot_id,
            run.admission_deadline_centiseconds,
            identifier=issuance.identifier,
            php_version=issuance.php_version,
            webroot=issuance.webroot,
            names=issuance.name_list,
            email=issuance.email,
            directory=issuance.authority,
            site_digest=_fingerprint(plan, PlanEvidence.Kind.SITE_REVALIDATION),
            renewal_digest=_fingerprint(plan, PlanEvidence.Kind.RENEWAL_REVALIDATION),
            readiness_digest=_fingerprint(plan, PlanEvidence.Kind.READINESS_REVALIDATION),
            lineage_digest=_fingerprint(plan, PlanEvidence.Kind.LINEAGE_REVALIDATION),
        )
    except ObjectDoesNotExist:
        raise OperationRefused(EVIDENCE_FAILURE) from None


def _fingerprint(plan: ConfigurationPlan, kind: str) -> str:
    return plan.evidence.filter(kind=kind).values_list("fingerprint", flat=True).first() or ""


def admit(shell: RemoteShell, run: ApplyRun, *, root: bool) -> None:
    issuance = RunTlsIssuance.objects.filter(run=run).first()
    if issuance is None:
        raise OperationRefused(EVIDENCE_FAILURE)
    if root:
        return
    argv = issuance_native.lineage_argv(issuance.identifier)
    if shell.run(bootstrap_native.authorization(argv)).exit_status != 0:
        raise OperationRefused(VERIFY_PRIVILEGE)


def verify(shell: RemoteShell, run: ApplyRun) -> Verification:
    """docs/tls.md#issuance: fresh reads of the issued lineage's public identity."""
    issuance = RunTlsIssuance.objects.filter(run=run).first()
    if issuance is None:
        return Verification.UNAVAILABLE
    root = bootstrap_native.is_root(shell)
    argv = issuance_native.lineage_argv(issuance.identifier)
    if root is None or (
        not root and shell.run(bootstrap_native.authorization(argv)).exit_status != 0
    ):
        return Verification.UNAVAILABLE
    result = shell.run(bootstrap_native.privileged(argv, root=root))
    if result.exit_status != 0 or result.truncated:
        return Verification.UNAVAILABLE
    facts = lineage_facts(result.stdout)
    problems = []
    if not facts.present:
        problems.append("the issued certificate does not exist under the reviewed lineage.")
    if facts.present and sorted(facts.names) != sorted(issuance.name_list):
        problems.append(f"the issued certificate names {', '.join(facts.names) or 'nothing'}.")
    if not facts.fingerprint or not facts.serial:
        problems.append("the certificate's fingerprint or serial could not be read.")
    if not facts.key_matches:
        problems.append("the certificate's public key does not match the lineage's private key.")
    if facts.curve != QUALIFIED_CURVE:
        problems.append(
            f"the certificate's key is {facts.curve or 'unreadable'}, not the reviewed "
            "ECDSA P-256 policy."
        )
    if not facts.renewal:
        problems.append("Certbot's renewal configuration for the lineage is missing.")
    IssuanceRunResult.objects.update_or_create(
        run=run,
        defaults={
            "subject": facts.subject,
            "not_before": facts.not_before,
            "not_after": facts.not_after,
            "names": "\n".join(facts.names),
            "fingerprint": facts.fingerprint,
            "serial": facts.serial,
            "key_curve": f"ecdsa {facts.curve}" if facts.curve else "",
            "key_matches": facts.key_matches,
            "renewal": facts.renewal,
            "problems": " ".join(problems),
            "verified_at": timezone.now(),
        },
    )
    return Verification.FAILED if problems else Verification.PASSED


def verification_failure(run: ApplyRun) -> str:
    result = IssuanceRunResult.objects.filter(run=run).first()
    problems = " ".join((result.problems if result else "").splitlines())
    return VERIFICATION_FAILED.format(problems=problems or "see the server.")


def audit(run: ApplyRun) -> list[str]:
    issuance = RunTlsIssuance.objects.filter(run=run).first()
    if issuance is None:
        return []
    certificate = IssuanceRunResult.objects.filter(run=run).first()
    dated = (
        f", valid {certificate.not_before} to {certificate.not_after}"
        if certificate and certificate.not_after
        else ""
    )
    return [
        (
            f"Issued a production certificate for {', '.join(issuance.name_list)} from "
            f"{issuance.authority_name}, never referenced by Nginx{dated}"
        )
    ]
