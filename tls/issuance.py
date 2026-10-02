"""A production certificate order: its admission and what the review proposes.

docs/tls.md#issuance. The order repeats the readiness reads fresh, requires the site to be
exactly the convention's and the guarded Certbot of a renewal setup at its qualified
version, records the operator's contact address and explicit acceptance of the authority's
terms, and proposes one order into Certbot's ordinary lineage. An existing lineage for the
same names is a plan without changes that points at a fresh activation review; one for
other names is never adopted, and an existing account with another contact is never
silently reused. A lost response never triggers another order: the run is reconciled like
any other.
"""

import re
import secrets
import shlex
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
from bootstrap.review import EvidenceDraft
from discovery.ssh import RemoteShell
from operations.lifecycle import OperationRefused
from sites import inspection
from sites import native as site_native
from sites.names import IDENTIFIER

from . import issuance_native, readiness, readiness_native, setup_native
from .models import IssuanceRequest

Reason = PlanRefusal.Reason
Kind = PlanEvidence.Kind
Effect = PlanEffect.Kind

SETUP_FIRST = (
    "Certbot is not installed, so there is nothing to order with. Apply the server's "
    "renewal setup plan first; it installs the distribution's Certbot and guards its "
    "scheduled renewal."
)
NOT_QUALIFIED = (
    "Certbot is {found} on the server, but the qualified version is {qualified}. Renewal "
    "setup installs the qualified one; prepare a renewal setup plan again or restore the "
    "qualified version through ordinary administration."
)
TERMS = (
    "The production order requires the operator's explicit acceptance of the authority's "
    "terms, which the request did not carry. Prepare again and tick the acceptance."
)
NO_AUTHORITY = (
    "No production authority is in Barectl's allowlist, so Barectl ordered nothing. Add the "
    "authority's directory to BARECTL_ACME_AUTHORITIES and name it in "
    "BARECTL_ACME_PRODUCTION, then prepare again."
)
UNREADABLE = (
    "Barectl could not read the production lineage or account state, so nothing was ordered. "
    "Inspect /etc/letsencrypt through ordinary administration and prepare again."
)
LINEAGE_UNREADABLE = (
    "A production lineage for {0} exists but its certificate could not be read, so Barectl "
    "cannot prove what it holds and never orders over it. Inspect /etc/letsencrypt/live/{0} "
    "through ordinary administration and prepare again."
)
COLLISION = (
    "A production lineage for {0} already exists with the names {1}, not the site's. Barectl "
    "never adopts or replaces a lineage; remove it through ordinary administration and "
    "prepare again."
)
ACCOUNT_COLLISION = (
    "A production ACME account exists with the contact {0}, not the reviewed address {1}. "
    "Barectl never silently reuses another account or registers over one; inspect "
    "/etc/letsencrypt/accounts through ordinary administration and prepare again."
)

# Certbot 2.x issues SAN-only certificates, so the subject line exists but may be empty.
_SUBJECT = re.compile(r"^subject=(.*)$", re.MULTILINE)
_DATES = re.compile(r"^(notBefore|notAfter)=(.+)$", re.MULTILINE)
_SAN = re.compile(r"DNS:([^,\s]+)")
_CONTACT = re.compile(r'mailto:([^"\\\s]+)')


class IssuanceDraft(readiness.TlsSiteDraft):
    """A production order's review before it is saved."""

    def __init__(
        self,
        identifier: str,
        token: str,
        authority: dict[str, str],
        email: str,
        platform: Platform | None = None,
        release: Release | None = None,
    ) -> None:
        super().__init__(Action.TLS_ISSUANCE, intent(identifier), platform, release)
        self.identifier = identifier
        self.token = token
        self.authority = authority
        self.email = email
        self.account = ""
        # True when a matching production lineage already exists: a plan without changes.
        self.existing = False
        self.lineage: dict[str, str] = {}
        self.state_digest = ""
        self.payload_bytes: int | None = None
        self.inputs: readiness.Inputs | None = None

    @property
    @override
    def revision(self) -> int:
        return readiness.CONVENTION_REVISION


def intent(identifier: str) -> str:
    return (
        f"Order one production certificate for the site {identifier} from the reviewed "
        "authority, into Certbot's ordinary lineage. The site's HTTP serving and Nginx stay "
        "unchanged; serving the certificate is a separate activation review."
    )


def prepare(preparation: PlanPreparation, shell: RemoteShell) -> IssuanceDraft:
    request = IssuanceRequest.objects.filter(preparation=preparation).first()
    if request is None:
        raise OperationRefused(readiness.MISSING_REQUEST)
    if not IDENTIFIER.fullmatch(request.identifier):
        raise OperationRefused(readiness.INVALID_REQUEST)
    if not request.terms_accepted:
        raise OperationRefused(TERMS)
    authority = readiness.production_authority()
    if authority is None:
        raise OperationRefused(NO_AUTHORITY)
    token = secrets.token_hex(16)
    evidence = inspection.inspect(shell, request.identifier, token)
    platform = evidence.platform
    release = releases_of(platform.os) if platform is not None else None
    draft = IssuanceDraft(request.identifier, token, authority, request.email, platform, release)
    if not readiness.challenge_site(draft, evidence, request.identifier, token):
        return draft
    if not _certbot(draft, shell):
        return draft
    inputs = readiness.read_inputs(shell, draft.names, authority["directory"])
    draft.inputs = inputs
    readiness.review(draft, authority=authority, inputs=inputs, site_ipv6=draft.ipv6)
    if not _state(draft, shell, request.identifier):
        return draft
    if draft.existing:
        draft.effects.append(_existing_effect(draft))
        draft.postconditions.append(
            "A production certificate for exactly the reviewed names already exists in "
            "Certbot's ordinary lineage; Nginx and the site's HTTP serving are unchanged."
        )
        return draft
    if not _payload(draft, shell):
        return draft
    draft.effects.append(_order_effect(draft, authority, request.email))
    draft.postconditions.append(
        "A production certificate for exactly the reviewed names exists in Certbot's "
        f"ordinary lineage {issuance_native.lineage_dir(draft.identifier)} with a matching "
        "ECDSA P-256 private key and its renewal configuration, and Nginx and the site's "
        "HTTP serving are unchanged."
    )
    return draft


def _order_effect(
    draft: IssuanceDraft, authority: dict[str, str], email: str
) -> tuple[Effect, str]:
    account = (
        f"reuses the existing account with the contact {email}"
        if draft.account
        else f"registers an account with the contact {email}"
    )
    return (
        Effect.PRODUCTION_ORDER,
        (
            f"Orders one production certificate for {', '.join(draft.names)} from "
            f"{authority['name']} and {account}, through the site's challenge webroot "
            f"{draft.webroot}. Certbot writes its ordinary lineage, account, archive, renewal "
            f"configuration and logs under /etc/letsencrypt; no private key or account "
            "credential is copied into Barectl. Nginx never references the result and the "
            "site's HTTP serving never changes. A lost answer is reconciled from the unit "
            "alone; Barectl never orders twice and never retries automatically."
        ),
    )


def _existing_effect(draft: IssuanceDraft) -> tuple[Effect, str]:
    dates = ""
    if draft.lineage.get("notBefore") and draft.lineage.get("notAfter"):
        dates = f": valid {draft.lineage['notBefore']} to {draft.lineage['notAfter']}"
    return (
        Effect.NO_CHANGES,
        (
            f"A production certificate for exactly these names already exists{dates}. "
            "Barectl never replaces a certificate to work around an authority's limits; "
            "prepare a fresh activation review to serve it, or remove the lineage through "
            "ordinary administration and prepare again for a fresh order."
        ),
    )


def _certbot(draft: IssuanceDraft, shell: RemoteShell) -> bool:
    """The guarded Certbot of a renewal setup, at its qualified version."""
    qualified = draft.release.certbot if draft.release else ""
    version = readiness.certbot_version(shell)
    if version is None:
        draft.refuse(Reason.PREREQUISITE, SETUP_FIRST)
        return False
    if version != qualified:
        draft.refuse(Reason.CUSTOMIZED, NOT_QUALIFIED.format(found=version, qualified=qualified))
        return False
    return True


def _state(draft: IssuanceDraft, shell: RemoteShell, identifier: str) -> bool:
    """The production lineage and account state: propose an order, a no-changes plan or a
    refusal. False when refused."""
    result = shell.run(shlex.join(issuance_native.state_argv(identifier)))
    if result.exit_status != 0 or result.truncated:
        draft.refuse(Reason.INCOMPLETE, UNREADABLE)
        return False
    digest = shell.run(shlex.join(site_native.script(issuance_native.state_digest(identifier))))
    try:
        draft.state_digest = bootstrap_native.parse_digest(digest.stdout)
    except bootstrap_native.Unreadable:
        draft.refuse(Reason.INCOMPLETE, UNREADABLE)
        return False
    draft.fingerprint(
        Kind.LINEAGE_REVALIDATION,
        [result.stdout],
        "The production lineage and account state, read fresh and rechecked before applying.",
    )
    subject = _SUBJECT.search(result.stdout)
    fields = {label: value.strip() for label, value in _DATES.findall(result.stdout)}
    names = tuple(match[1] for match in _SAN.finditer(result.stdout))
    contacts = tuple(dict.fromkeys(_CONTACT.findall(result.stdout)))
    lineage = "lineage=yes" in result.stdout
    if lineage:
        if subject is None:
            draft.refuse(Reason.CUSTOMIZED, LINEAGE_UNREADABLE.format(identifier))
            return False
        if sorted(names) != sorted(draft.names):
            draft.refuse(Reason.COLLISION, COLLISION.format(identifier, ", ".join(names) or "none"))
            return False
        draft.existing = True
        draft.lineage = fields
        draft.account = (
            draft.email if draft.email in contacts else (contacts[0] if contacts else "")
        )
        return True
    if contacts and draft.email not in contacts:
        draft.refuse(Reason.COLLISION, ACCOUNT_COLLISION.format(", ".join(contacts), draft.email))
        return False
    draft.account = draft.email if contacts else ""
    return True


def _payload(draft: IssuanceDraft, shell: RemoteShell) -> bool:
    platform, site_digest = draft.platform, _site_digest(draft)
    renewal_digest = _renewal_digest(shell)
    readiness_digest = _readiness_digest(draft, shell)
    if (
        platform is None
        or platform.uptime_centiseconds is None
        or not site_digest
        or not renewal_digest
        or not readiness_digest
        or not draft.state_digest
    ):
        draft.refuse(
            Reason.INCOMPLETE,
            "Barectl could not compute every evidence digest that applying rechecks.",
        )
        return False
    payload = issuance_native.payload(
        bootstrap_native.new_unit_name(),
        platform.boot_id,
        platform.uptime_centiseconds + ADMISSION_CENTISECONDS,
        identifier=draft.identifier,
        php_version=draft.php_version,
        webroot=draft.webroot,
        names=draft.names,
        email=draft.email,
        directory=draft.authority["directory"],
        site_digest=site_digest,
        renewal_digest=renewal_digest,
        readiness_digest=readiness_digest,
        lineage_digest=draft.state_digest,
    )
    draft.evidence.append(
        EvidenceDraft(
            Kind.RENEWAL_REVALIDATION,
            renewal_digest,
            "The guarded renewal setup's state, read fresh and rechecked before applying.",
        )
    )
    draft.evidence.append(
        EvidenceDraft(
            Kind.READINESS_REVALIDATION,
            readiness_digest,
            "Fresh DNS, addresses, clock and directory reads, rechecked before applying.",
        )
    )
    draft.payload_bytes = len(payload.encode())
    if draft.payload_bytes > bootstrap_native.MAX_PAYLOAD:
        draft.refuse(
            Reason.PAYLOAD_TOO_LARGE,
            f"Applying this order would need {draft.payload_bytes} bytes, more than the "
            f"{bootstrap_native.MAX_PAYLOAD} bytes Barectl submits in one run.",
        )
        return False
    return True


def _site_digest(draft: IssuanceDraft) -> str:
    return next(
        (item.fingerprint for item in draft.evidence if item.kind == Kind.SITE_REVALIDATION),
        "",
    )


def _renewal_digest(shell: RemoteShell) -> str:
    result = shell.run(shlex.join(setup_native.renewal_digest_argv()))
    try:
        return bootstrap_native.parse_digest(result.stdout)
    except bootstrap_native.Unreadable:
        return ""


def _readiness_digest(draft: IssuanceDraft, shell: RemoteShell) -> str:
    command = readiness_native.readiness_digest(draft.names, draft.authority["directory"])
    result = shell.run(shlex.join(site_native.script(command)))
    try:
        return bootstrap_native.parse_digest(result.stdout)
    except bootstrap_native.Unreadable:
        return ""
