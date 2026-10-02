"""An HTTPS activation: its admission and what the review proposes.

docs/tls.md#activation. The review reads the issued lineage's public identity, the shared
default TLS rejection server's state and every effective default server on 443, and proposes
the two exact Nginx candidate states: HTTPS with HTTP unchanged, then the reviewed HTTP
redirect with the challenge route preserved. A site already serving the redirect is a plan
without changes; a site already serving HTTPS proposes only the redirect.
"""

import datetime
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
from discovery.ssh import RemoteShell
from operations.lifecycle import OperationRefused
from sites import inspection
from sites import native as site_native
from sites.convention import RecognizedSite, SitePaths, Stage, recognize_site, render_site
from sites.names import IDENTIFIER

from . import activation_native, issuance_apply, issuance_native, readiness
from .models import ActivationRequest

Reason = PlanRefusal.Reason
Kind = PlanEvidence.Kind
Effect = PlanEffect.Kind

NO_LINEAGE = (
    "No production certificate lineage exists for {0}, so there is nothing to serve. Apply "
    "the site's production order plan first."
)
LINEAGE_MISMATCH = (
    "The production lineage for {0} names {1}, not the site's. Barectl never adopts another "
    "lineage; inspect /etc/letsencrypt through ordinary administration and prepare again."
)
LINEAGE_UNREADABLE = (
    "The production lineage for {0} could not be read or does not match the reviewed policy: "
    "{1} Inspect /etc/letsencrypt through ordinary administration and prepare again."
)
COMPETING_DEFAULT = (
    "Another Nginx configuration declares an effective default server on port 443, so the "
    "shared rejection server would not answer unknown names. Remove the competing default "
    "through ordinary administration and prepare again."
)
DEFAULT_CUSTOM = (
    "The shared default TLS rejection server {0} exists with other bytes than the "
    "convention's. Inspect it and remove or restore it through ordinary administration, then "
    "prepare again."
)
INCOMPLETE = (
    "Barectl could not read the default TLS rejection server's state or the effective Nginx "
    "configuration, so nothing was proposed. Prepare again."
)
PRIVILEGE = (
    "The SSH user is not root, and sudo -n -l does not authorize Barectl's fixed read-only "
    "commands that read the issued lineage and the effective Nginx configuration, so nothing "
    "was proposed. Barectl never installs a sudo policy or asks for a password."
)


class ActivationDraft(readiness.TlsSiteDraft):
    """An HTTPS activation's review before it is saved."""

    def __init__(
        self,
        identifier: str,
        token: str,
        platform: Platform | None = None,
        release: Release | None = None,
    ) -> None:
        super().__init__(Action.TLS_ACTIVATION, intent(identifier), platform, release)
        self.identifier = identifier
        self.token = token
        self.paths: SitePaths | None = None
        self.preimage = ""
        self.https_content = ""
        self.redirect_content = ""
        self.default_content = activation_native.DEFAULT_CONTENT
        self.default_exists = False
        self.redirect_only = False
        self.certificate = ""
        self.not_after = ""
        self.lineage_digest = ""
        self.payload_bytes: int | None = None

    @property
    @override
    def revision(self) -> int:
        return readiness.CONVENTION_REVISION


def intent(identifier: str) -> str:
    return (
        f"Activate HTTPS for the site {identifier} from its issued lineage: publish the HTTPS "
        "server block, verify the served certificate, then redirect HTTP to the canonical "
        "name while preserving the HTTP-01 challenge route. No HSTS and no certificate order."
    )


def prepare(preparation: PlanPreparation, shell: RemoteShell) -> ActivationDraft:
    request = ActivationRequest.objects.filter(preparation=preparation).first()
    if request is None:
        raise OperationRefused(readiness.MISSING_REQUEST)
    if not IDENTIFIER.fullmatch(request.identifier):
        raise OperationRefused(readiness.INVALID_REQUEST)
    token = secrets.token_hex(16)
    evidence = inspection.inspect(shell, request.identifier, token)
    platform = evidence.platform
    release = releases_of(platform.os) if platform is not None else None
    draft = ActivationDraft(request.identifier, token, platform, release)
    if not readiness.challenge_site(draft, evidence, request.identifier, token):
        return draft
    paths = evidence.paths
    text = evidence.contents.get(paths.source) if paths is not None else None
    site = recognize_site(request.identifier, text or "")
    if site is None or paths is None:
        return draft
    draft.paths = paths
    draft.preimage = text or ""
    if site.stage == Stage.REDIRECT:
        return _repeated(draft, shell, request.identifier)
    if not _lineage(draft, shell, request.identifier):
        return draft
    if not _default(draft, shell):
        return draft
    if not _candidates(draft, site):
        return draft
    if not _payload(draft):
        return draft
    draft.effects.extend(_effects(draft))
    draft.postconditions.append(
        "Nginx serves the reviewed lineage's certificate for every reviewed name over HTTPS, "
        f"HTTP answers a 301 redirect to https://{draft.names[0]} for everything but the "
        "challenge route, the challenge route still answers, and unknown or mismatched names "
        "are not served a site."
    )
    return draft


def _repeated(draft: ActivationDraft, shell: RemoteShell, identifier: str) -> ActivationDraft:
    """A site already redirecting: prove the lineage again and propose no changes.

    The repeated review still reads the lineage as root, so the plan without changes carries
    the certificate's public identity and validity dates.
    """
    if _lineage(draft, shell, identifier):
        draft.effects.append(_no_changes_effect(draft))
    return draft


def _no_changes_effect(draft: ActivationDraft) -> tuple[Effect, str]:
    return (
        Effect.NO_CHANGES,
        (
            f"No changes. The site {draft.identifier} already serves HTTPS and redirects HTTP "
            "to its canonical name while preserving the challenge route, as the convention "
            "specifies."
        ),
    )


def _effects(draft: ActivationDraft) -> list[tuple[Effect, str]]:
    effects: list[tuple[Effect, str]] = [
        (
            Effect.TLS_DEFAULT_SERVER,
            (
                "Publishes or verifies the shared default TLS rejection server "
                f"{activation_native.DEFAULT_PATH} (root:root 0644), whose IPv4 and IPv6 443 "
                "listeners reject the TLS handshake for unknown names. The distribution's HTTP "
                "default is unchanged."
            ),
        )
    ]
    if draft.redirect_only:
        effects.append(
            (
                Effect.HTTPS_ACTIVATION,
                (
                    f"Keeps the site {draft.identifier} serving HTTPS for "
                    f"{', '.join(draft.names)} from "
                    f"{issuance_native.lineage_dir(draft.identifier)}; the served certificate "
                    "is verified for every name before anything changes."
                ),
            )
        )
    else:
        effects.append(
            (
                Effect.HTTPS_ACTIVATION,
                (
                    f"Replaces the site file {draft.identifier}.conf with the reviewed HTTPS "
                    f"candidate: the challenge route stays on port 80, and an HTTPS server "
                    f"block serves {', '.join(draft.names)} from "
                    f"{issuance_native.lineage_dir(draft.identifier)}. The previous bytes are "
                    "kept as a root-only recovery preimage, nginx -t must accept the candidate "
                    "before any reload, and the served certificate is verified for every name "
                    "afterwards. HTTP is otherwise unchanged and no HSTS is set."
                ),
            )
        )
    effects.append(
        (
            Effect.HTTP_REDIRECT,
            (
                f"Then replaces the site file with the reviewed redirect candidate: the "
                "challenge location is preserved and every other HTTP request answers 301 to "
                f"https://{draft.names[0]}. A refused or failed second candidate leaves the "
                "verified HTTPS state in place; that is partial completion."
            ),
        )
    )
    return effects


def _root_read(draft: ActivationDraft, shell: RemoteShell, argv: list[str]) -> str | None:
    """One fixed read as root or through noninteractive sudo; ``None`` when refused.

    docs/tls.md#activation: the issued lineage and the effective Nginx configuration are
    root-only, so preparation uses the same authorization the verification later needs.
    """
    root = bootstrap_native.is_root(shell)
    if root is None or (
        not root and shell.run(bootstrap_native.authorization(argv)).exit_status != 0
    ):
        draft.refuse(Reason.PRIVILEGE, PRIVILEGE)
        return None
    result = shell.run(bootstrap_native.privileged(argv, root=root))
    if result.exit_status != 0 or result.truncated:
        return None
    return result.stdout


def _lineage(draft: ActivationDraft, shell: RemoteShell, identifier: str) -> bool:
    """The issued lineage's public identity, as the activation rechecks it."""
    output = _root_read(draft, shell, issuance_native.lineage_argv(identifier))
    if output is None:
        if draft.eligible:
            draft.refuse(Reason.PREREQUISITE, NO_LINEAGE.format(identifier))
        return False
    digest = _root_read(
        draft, shell, site_native.script(issuance_native.lineage_digest(identifier))
    )
    if digest is None:
        if draft.eligible:
            draft.refuse(Reason.INCOMPLETE, INCOMPLETE)
        return False
    try:
        draft.lineage_digest = bootstrap_native.parse_digest(digest)
    except bootstrap_native.Unreadable:
        draft.refuse(Reason.INCOMPLETE, INCOMPLETE)
        return False
    facts = issuance_apply.lineage_facts(output)
    draft.certificate = facts.fingerprint
    draft.not_after = facts.not_after
    if not facts.present:
        draft.refuse(Reason.PREREQUISITE, NO_LINEAGE.format(identifier))
        return False
    if sorted(facts.names) != sorted(draft.names):
        draft.refuse(
            Reason.COLLISION, LINEAGE_MISMATCH.format(identifier, ", ".join(facts.names) or "none")
        )
        return False
    problems = _lineage_problems(facts)
    if problems:
        draft.refuse(Reason.CUSTOMIZED, LINEAGE_UNREADABLE.format(identifier, " ".join(problems)))
        return False
    draft.fingerprint(
        Kind.LINEAGE_REVALIDATION,
        [output],
        "The issued lineage's names, key identity, renewal configuration and validity, read "
        "fresh and rechecked before activating.",
    )
    return True


def _lineage_problems(facts: issuance_apply.LineageFacts) -> list[str]:
    problems = []
    if not facts.key_matches:
        problems.append("its private key does not match the certificate.")
    if facts.curve != issuance_apply.QUALIFIED_CURVE:
        problems.append(f"its key is {facts.curve or 'unreadable'}, not ECDSA P-256.")
    if not facts.renewal:
        problems.append("Certbot's renewal configuration is missing.")
    if not facts.fingerprint or not facts.not_after:
        problems.append("its fingerprint or expiry could not be read.")
    elif _expired(facts.not_after):
        problems.append("it has expired.")
    return problems


def _expired(not_after: str) -> bool:
    try:
        expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=datetime.UTC
        )
    except ValueError:
        return True
    return expiry <= datetime.datetime.now(datetime.UTC)


def _default(draft: ActivationDraft, shell: RemoteShell) -> bool:
    """The shared rejection server's state and every effective 443 default server."""
    output = _root_read(draft, shell, activation_native.config_argv())
    if output is None:
        if draft.eligible:
            draft.refuse(Reason.INCOMPLETE, INCOMPLETE)
        return False
    lines = output.splitlines()
    draft.default_exists = any(line.startswith("path ") for line in lines)
    sha = next((line.split()[1] for line in lines if line.startswith("sha ")), "")
    defaults = [line for line in lines if line.startswith("listen")]
    expected = 2 if draft.default_exists else 0
    if len(defaults) > expected:
        draft.refuse(Reason.CONFLICT, COMPETING_DEFAULT)
        return False
    expected_sha = hashlib.sha256(draft.default_content.encode()).hexdigest()
    if draft.default_exists and sha != expected_sha:
        draft.refuse(Reason.CUSTOMIZED, DEFAULT_CUSTOM.format(activation_native.DEFAULT_PATH))
        return False
    return True


def _candidates(draft: ActivationDraft, site: RecognizedSite) -> bool:
    identifier = draft.identifier
    draft.redirect_only = site.stage == Stage.HTTPS
    draft.https_content = (
        draft.preimage
        if draft.redirect_only
        else render_site(identifier, draft.names, ipv6=draft.ipv6, stage=Stage.HTTPS)
    )
    draft.redirect_content = render_site(
        identifier, draft.names, ipv6=draft.ipv6, stage=Stage.REDIRECT
    )
    if not draft.preimage:
        draft.refuse(Reason.INCOMPLETE, "The site file's bytes could not be read.")
        return False
    return True


def _payload(draft: ActivationDraft) -> bool:
    platform, paths = draft.platform, draft.paths
    digest = next(
        (item.fingerprint for item in draft.evidence if item.kind == Kind.SITE_REVALIDATION),
        "",
    )
    if (
        platform is None
        or paths is None
        or platform.uptime_centiseconds is None
        or not digest
        or not draft.lineage_digest
        or not draft.certificate
    ):
        draft.refuse(
            Reason.INCOMPLETE,
            "Barectl could not compute every evidence digest that applying rechecks.",
        )
        return False
    payload = activation_native.activation_payload(
        bootstrap_native.new_unit_name(),
        platform.boot_id,
        platform.uptime_centiseconds + ADMISSION_CENTISECONDS,
        activation_native.ActivationChange(
            paths=paths,
            names=draft.names,
            ipv6=draft.ipv6,
            digest=digest,
            preimage=draft.preimage,
            https_content=draft.https_content,
            redirect_content=draft.redirect_content,
            fingerprint=draft.certificate,
            lineage_digest=draft.lineage_digest,
            default_content=draft.default_content,
            default_exists=draft.default_exists,
        ),
    )
    draft.payload_bytes = len(payload.encode())
    if draft.payload_bytes > bootstrap_native.MAX_PAYLOAD:
        draft.refuse(
            Reason.PAYLOAD_TOO_LARGE,
            f"Applying this activation would need {draft.payload_bytes} bytes, more than the "
            f"{bootstrap_native.MAX_PAYLOAD} bytes Barectl submits in one run.",
        )
        return False
    return True
