"""Change one site's names and HTTPS setting as native Caddy evidence (Phase B #442).

docs/tls.md and docs/sites.md: a site's names and scheme live in its own Caddy file, so a
fresh controller reconstructs them without a Barectl marker. One reviewed change republishes
the recognized serving form, validates the whole Caddy tree, reloads Caddy and proves the
primary name serves while WordPress and Laravel aliases redirect to it.
"""

import base64
import gzip
import hashlib
import importlib.resources
import json
import shlex
from dataclasses import dataclass
from typing import Final

from bootstrap.standing import Standing
from discovery.ssh import RemoteShell
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import InputShape, PreparationInputs, decode_inputs
from operations.models import ChangeReview

from . import observation
from .bodies.common import NativeState
from .change import SiteEvidence, dns_evidence, dns_warnings
from .configuration import SiteSettings, render_caddy, render_laravel_caddy, render_wordpress_caddy

SLUG: Final = "set_site_domains"
LABEL: Final = "Change domains and HTTPS"
FORMS: Final = ("plain", "wordpress", "laravel")

BODY_SOURCE: Final = (
    observation.COMMON_SOURCE
    + "\n"
    + importlib.resources.files("sites.bodies")
    .joinpath("domains.py")
    .read_text()
    .replace("from sites.bodies.common import set_site_domains\n", "")
)
BODY_BYTES: Final = (
    "#!/bin/sh\nexec python3 -c "
    + shlex.quote(
        "import base64,gzip; exec(gzip.decompress(base64.b64decode("
        + repr(base64.b64encode(gzip.compress(BODY_SOURCE.encode(), mtime=0)).decode())
        + ")))"
    )
    + ' "$@"'
).encode()
BODY_SHA256: Final = hashlib.sha256(BODY_BYTES).hexdigest()


def render_form(settings: SiteSettings, form: str) -> str:
    if form == "plain":
        return render_caddy(settings)
    if form == "wordpress":
        return render_wordpress_caddy(settings)
    if form == "laravel":
        return render_laravel_caddy(settings)
    raise ValueError("The site's serving form cannot be republished.")


@dataclass(frozen=True)
class DomainsEvidence:
    standing: Standing | None
    native: NativeState | None
    dns: dict[str, object] | None


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> DomainsEvidence:
    from discovery.observations import collect

    snapshot = collect(shell, sites=False)
    return DomainsEvidence(
        snapshot.standing.standing if snapshot.standing else None,
        observation.read(shell, "observed", "", protections=False),
        dns_evidence(shell, inputs.names) if inputs.https else None,
    )


def review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, DomainsEvidence):
        raise ValueError("A domains change needs native evidence.")
    native = evidence.native
    site = (
        next(
            (row for row in native["sites"] if row["identifier"] == inputs.identifier),
            None,
        )
        if native is not None
        else None
    )
    refusals: list[str] = []
    if evidence.standing != Standing.TARGET_STACK:
        refusals.append("Set up and verify the host foundation before changing a site.")
    if native is None:
        refusals.append("The site's native serving configuration could not be read.")
    elif site is None:
        refusals.append("The site was not observed in the current server configuration.")
    elif site["state"] != "complete":
        refusals.append(site["problem"] or "The site is incomplete or outside supported settings.")
    form = str(site["serving_form"]) if site is not None else ""
    if site is not None and site["state"] == "complete" and form not in FORMS:
        refusals.append("The site's serving form is outside supported settings.")
    current_names = tuple(str(name) for name in site["names"]) if site is not None else ()
    current_https = bool(site["https"]) if site is not None else False
    settings = (
        SiteSettings(
            inputs.identifier,
            inputs.names,
            site["runtime"],
            https=inputs.https,
            readiness=str(site["readiness"]),
        )
        if site is not None and inputs.names
        else None
    )
    reportable = site is not None and site["state"] == "complete" and settings is not None
    unchanged = reportable and current_names == inputs.names and current_https == inputs.https
    caddy = (
        render_form(settings, form) if reportable and settings is not None and form in FORMS else ""
    )
    dns_findings = dns_warnings(SiteEvidence(None, None, None, None, evidence.dns), inputs.names)
    document: dict[str, object] = {
        "version": 1,
        "identifier": inputs.identifier,
        "names": list(inputs.names),
        "https": inputs.https,
        "form": form,
        "previous_names": list(current_names),
        "previous_https": current_https,
        "caddy": caddy,
        "body_sha256": BODY_SHA256,
        "precondition_digest": native["digest"] if native is not None else "",
        "details": [
            {"label": "Site", "value": inputs.identifier},
            {"label": "Previous names", "value": ", ".join(current_names) or "Not observed"},
            {"label": "New names", "value": ", ".join(inputs.names)},
            {
                "label": "HTTPS",
                "value": (
                    "On; Caddy issues and renews the certificate."
                    if inputs.https
                    else "Off; the site answers over HTTP only."
                ),
            },
            {
                "label": "Apply",
                "value": (
                    "Publish this site's Caddy file, validate the whole configuration, "
                    "reload Caddy and check every name."
                ),
            },
            *([{"label": "DNS warning", "value": "\n".join(dns_findings)}] if dns_findings else []),
        ],
    }
    if dns_findings:
        document["acknowledgement"] = " ".join(dns_findings)
    affected = (
        tuple(
            sorted(
                str(row["identifier"])
                for row in native["sites"]
                if str(row["file"]).startswith("/etc/caddy/sites/")
            )
        )
        if native is not None
        else ()
    )
    return ReviewDraft(
        SLUG,
        f"Change {inputs.identifier}'s domains and HTTPS setting.",
        effects=()
        if refusals or unchanged
        else (
            DeclaredEffect(
                Scope.SHARED,
                "Publish this site's names and HTTPS setting and reload Caddy for every site.",
                affected,
            ),
        ),
        sites_read=observation.SITE_IDENTIFIERS_COMMAND if reportable else "",
        current_sites=affected if reportable else None,
        stages=("preflight", "caddy", "verify"),
        refusals=tuple(refusals),
        document=document,
        boot_id=str(native["boot"]) if native is not None else "",
        uptime_centiseconds=int(str(native["uptime"])) if native is not None else None,
    )


def body(document: dict[str, object], context: BodyContext) -> NativeBody:
    inputs = decode_inputs(
        {key: document.get(key) for key in ("version", "identifier", "names", "https")},
        (),
        InputShape.SITE_DOMAINS,
    )
    form = document.get("form")
    previous = document.get("previous_names")
    previous_https = document.get("previous_https")
    digest = document.get("precondition_digest")
    if (
        document.get("body_sha256") != BODY_SHA256
        or not isinstance(form, str)
        or form not in FORMS
        or not isinstance(previous, list)
        or not all(isinstance(name, str) for name in previous)
        or type(previous_https) is not bool
        or not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise ValueError("The domains review is not a valid immutable native selection.")
    settings = SiteSettings(inputs.identifier, inputs.names, "php84", https=inputs.https)
    if document.get("caddy") != render_form(settings, form):
        raise ValueError("The domains review does not match its own names and setting.")
    encoded = base64.b64encode(gzip.compress(json.dumps(document).encode(), mtime=0)).decode()
    return NativeBody(BODY_BYTES, (encoded,))


def verify(shell: RemoteShell, stored: ChangeReview) -> bool | None:
    body(stored.document, BodyContext("", "", 0))
    native = observation.read(shell, "observed", "", protections=False)
    if native is None:
        return None
    site = next(
        (row for row in native["sites"] if row["identifier"] == stored.document["identifier"]),
        None,
    )
    return (
        site is not None
        and site["state"] == "complete"
        and site["serving_form"] == stored.document["form"]
        and list(site["names"]) == stored.document["names"]
        and site["https"] is stored.document["https"]
    )


SET_SITE_DOMAINS: Final = ChangeKind(
    SLUG,
    LABEL,
    inspect,
    review,
    body,
    verify,
    refresh_discovery=True,
    input_shape=InputShape.SITE_DOMAINS,
)
