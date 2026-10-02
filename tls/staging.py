"""A staging certificate order: its admission and what the review proposes.

docs/tls.md#staging. The order repeats the readiness reads fresh, requires the site to be
exactly the convention's and the guarded Certbot of a renewal setup at its qualified
version, records the operator's contact address and explicit acceptance of the authority's
terms, and proposes a real order against the staging authority into isolated
configuration, work and log directories. An existing staging lineage for the same names is
a plan without changes; one for other names is never adopted. A lost response never
triggers another order: the run is reconciled like any other.
"""

import re
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
    Privilege,
)
from bootstrap.releases import Release
from bootstrap.releases import of as releases_of
from bootstrap.review import check_platform
from discovery.ssh import RemoteShell
from operations.lifecycle import OperationRefused
from sites import admission as site_admission
from sites import inspection
from sites.convention import Stage, recognize_site
from sites.inspection import SiteEvidence
from sites.names import IDENTIFIER

from . import admission as challenge_admission
from . import readiness, readiness_native, staging_native
from .models import StagingRequest

Reason = PlanRefusal.Reason
Kind = PlanEvidence.Kind
Effect = PlanEffect.Kind

CERTBOT_VERSION = re.compile(r"certbot (\d+\.\d+\.\d+)")
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
    "The staging order requires the operator's explicit acceptance of the authority's "
    "terms, which the request did not carry. Prepare again and tick the acceptance."
)
UNKNOWN_AUTHORITY = (
    "The request's certificate authority is not in Barectl's allowlist, so Barectl ordered "
    "nothing from it. Prepare again and choose a listed authority."
)
SITE_FIRST = (
    "The site {0} is not exactly the convention's: its account, directories, pool, Nginx "
    "file, link and socket must all exist and match. Apply its site plan first."
)
VERIFY_PRIVILEGE = (
    "The SSH user is not root, and sudo -n -l does not authorize Barectl's fixed read-only "
    "read of the staged certificate, so Barectl submitted nothing. Barectl never installs a "
    "sudo policy or asks for a password."
)

# Certbot 2.x issues SAN-only certificates, so the subject line exists but may be empty.
_SUBJECT = re.compile(r"^subject=(.*)$", re.MULTILINE)
_DATES = re.compile(r"^(notBefore|notAfter)=(.+)$", re.MULTILINE)
_SAN = re.compile(r"DNS:([^,\s]+)")


class StagingDraft(readiness.TlsSiteDraft):
    """A staging order's review before it is saved."""

    def __init__(
        self,
        identifier: str,
        token: str,
        authority: dict[str, str],
        email: str,
        platform: Platform | None = None,
        release: Release | None = None,
    ) -> None:
        super().__init__(Action.TLS_STAGING, intent(identifier), platform, release)
        self.identifier = identifier
        self.token = token
        self.authority = authority
        self.email = email
        self.payload_bytes: int | None = None
        self.inputs: readiness.Inputs | None = None

    @property
    @override
    def revision(self) -> int:
        return readiness.CONVENTION_REVISION


def intent(identifier: str) -> str:
    return (
        f"Order a staging certificate for the site {identifier} from the reviewed authority, "
        "into isolated staging directories. The site's HTTP serving and its production "
        "certificate state are never touched, and Nginx never references the result."
    )


def prepare(preparation: PlanPreparation, shell: RemoteShell) -> StagingDraft:
    request = StagingRequest.objects.filter(preparation=preparation).first()
    if request is None:
        raise OperationRefused(readiness.MISSING_REQUEST)
    if not IDENTIFIER.fullmatch(request.identifier):
        raise OperationRefused(readiness.INVALID_REQUEST)
    authority = readiness.authority_of(request.authority)
    if authority is None:
        raise OperationRefused(UNKNOWN_AUTHORITY)
    if not request.terms_accepted:
        raise OperationRefused(TERMS)
    token = secrets.token_hex(16)
    evidence = inspection.inspect(shell, request.identifier, token)
    platform = evidence.platform
    release = releases_of(platform.os) if platform is not None else None
    draft = StagingDraft(request.identifier, token, authority, request.email, platform, release)
    if not _site(draft, evidence, request.identifier, token):
        return draft
    if not _certbot(draft, shell):
        return draft
    inputs = readiness.read_inputs(shell, draft.names, authority["directory"])
    draft.inputs = inputs
    readiness.review(draft, authority=authority, inputs=inputs, site_ipv6=draft.ipv6)
    if _lineage_changed(draft, shell, request.identifier) or not _payload(draft):
        return draft
    draft.effects.append(_order_effect(draft, authority, request.email))
    draft.postconditions.append(
        "A staging certificate for exactly the reviewed names exists in the isolated "
        "staging configuration, and the site's Nginx file and HTTP serving are unchanged."
    )
    return draft


def _order_effect(draft: StagingDraft, authority: dict[str, str], email: str) -> tuple[Effect, str]:
    return (
        Effect.STAGING_ORDER,
        (
            f"Orders a staging certificate for {', '.join(draft.names)} from "
            f"{authority['name']} with the contact address {email}, through the site's "
            f"challenge webroot {draft.webroot}. The order writes only Certbot's isolated "
            f"staging state under {staging_native.config_dir(draft.identifier)}, "
            f"{staging_native.work_dir(draft.identifier)} and "
            f"{staging_native.logs_dir(draft.identifier)}: the staged certificate, its "
            "private key and the staging account. Nginx never references them, the site's "
            "HTTP serving never changes, and production Certbot state is never read or "
            "written. A lost answer is reconciled from the unit alone; Barectl never "
            "orders twice."
        ),
    )


def _site(draft: StagingDraft, evidence: SiteEvidence, identifier: str, token: str) -> bool:
    """The site part of the review: a complete convention site whose file serves its
    challenge route, with the site admission's evidence merged in. False when refused."""
    check_platform(draft, evidence.platform)
    for gap in evidence.gaps:
        draft.refuse(Reason.INCOMPLETE, gap)
    paths = evidence.paths
    if evidence.release is None or paths is None:
        return False
    draft.platform, draft.release = evidence.platform, evidence.release
    draft.webroot = paths.webroot
    draft.php_version = evidence.release.php
    if not evidence.read_privilege:
        draft.refuse(Reason.PRIVILEGE, readiness.PRIVILEGE)
        return False
    text = evidence.contents.get(paths.source)
    site = recognize_site(identifier, text) if text is not None else None
    if site is None:
        draft.refuse(Reason.PARTIAL_SITE, readiness.NOT_A_SITE.format(identifier))
        return False
    if site.stage != Stage.CHALLENGE:
        draft.refuse(Reason.PREREQUISITE, readiness.ROUTE_FIRST)
        return False
    draft.names = site.names
    draft.ipv6 = site.ipv6
    checked = site_admission.review(identifier, site.names, token, evidence)
    challenge_admission._copy_refusals(draft, checked)
    challenge_admission._merge_evidence(draft, checked)
    if not checked.eligible:
        return False
    if not checked.no_changes:
        draft.refuse(Reason.PARTIAL_SITE, SITE_FIRST.format(identifier))
    return checked.no_changes


def _certbot(draft: StagingDraft, shell: RemoteShell) -> bool:
    """The guarded Certbot of a renewal setup, at its qualified version."""
    qualified = draft.release.certbot if draft.release else ""
    version = _certbot_version(shell)
    if version is None:
        draft.refuse(Reason.PREREQUISITE, SETUP_FIRST)
        return False
    if version != qualified:
        draft.refuse(Reason.CUSTOMIZED, NOT_QUALIFIED.format(found=version, qualified=qualified))
        return False
    return True


def _certbot_version(shell: RemoteShell) -> str | None:
    result = shell.run(readiness_native.certbot_version_command())
    if result.exit_status != 0:
        return None
    found = CERTBOT_VERSION.search(result.stdout)
    return found[1] if found else None


def _lineage(
    draft: StagingDraft, shell: RemoteShell, identifier: str, *, root: bool
) -> dict[str, str] | None:
    """The staged certificate's state when one exists, read as the verification reads it."""
    argv = staging_native.lineage_argv(identifier)
    if not root and shell.run(bootstrap_native.authorization(argv)).exit_status != 0:
        draft.refuse(Reason.PRIVILEGE, VERIFY_PRIVILEGE)
        return None
    result = shell.run(bootstrap_native.privileged(argv, root=root))
    stdout = result.stdout
    fields = {label: value.strip() for label, value in _DATES.findall(stdout)}
    subject = _SUBJECT.search(stdout)
    if subject is None:
        return None
    fields["subject"] = subject[1].strip()
    names = tuple(match[1] for match in _SAN.finditer(stdout))
    return {
        "subject": fields.get("subject", ""),
        "not_before": fields.get("notBefore", ""),
        "not_after": fields.get("notAfter", ""),
        "names": names,
    }


def _lineage_changed(draft: StagingDraft, shell: RemoteShell, identifier: str) -> bool:
    """The staged certificate's state ends the review: a matching lineage is no changes,
    another lineage is refused, and its absence proposes the order. True when it decided."""
    root = draft.platform.privilege == Privilege.ROOT if draft.platform else False
    lineage = _lineage(draft, shell, identifier, root=root)
    if not draft.eligible or lineage is None:
        return not draft.eligible
    if sorted(lineage["names"]) != sorted(draft.names):
        draft.refuse(
            Reason.COLLISION,
            f"A staging lineage already exists for "
            f"{', '.join(lineage['names'] or ('nothing',))}. "
            "Barectl never adopts a lineage for other names; remove it through ordinary "
            "administration and prepare again.",
        )
        return True
    draft.effects.append(
        (
            Effect.NO_CHANGES,
            (
                "A staging certificate for exactly these names already exists: valid "
                f"{lineage['not_before']} to {lineage['not_after']}. Barectl never replaces "
                "a certificate to work around an authority's limits; remove the staging "
                "lineage through ordinary administration and prepare again for a fresh one."
            ),
        )
    )
    return True


def _payload(draft: StagingDraft) -> bool:
    platform, digest = draft.platform, _site_digest(draft)
    if platform is None or platform.uptime_centiseconds is None or not digest:
        draft.refuse(
            Reason.INCOMPLETE,
            "Barectl could not compute the site evidence digest that applying rechecks.",
        )
        return False
    payload = staging_native.payload(
        bootstrap_native.new_unit_name(),
        platform.boot_id,
        platform.uptime_centiseconds + ADMISSION_CENTISECONDS,
        identifier=draft.identifier,
        php_version=draft.php_version,
        webroot=draft.webroot,
        names=draft.names,
        email=draft.email,
        directory=draft.authority["directory"],
        site_digest=digest,
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


def _site_digest(draft: StagingDraft) -> str:
    return next(
        (item.fingerprint for item in draft.evidence if item.kind == Kind.SITE_REVALIDATION),
        "",
    )
