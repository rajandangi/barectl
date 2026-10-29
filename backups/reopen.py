"""Reopen a site left paused by a full backup that stopped partway (#399, #179 Journey 7).

One reviewed Site change publishes the site's reviewed open Caddy file. Background work
stays stopped: Scheduled tasks and Queue workers ask the operator what should run again
(docs/adr/0036). A Shared effect follows the Caddy reload when other sites exist.
"""

import base64
import gzip
import hashlib
import importlib.resources
import json
from dataclasses import dataclass
from typing import Final

from automation.bodies.source import without_imports
from bootstrap.standing import Standing
from discovery.observations import collect
from discovery.ssh import RemoteShell
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import InputShape, PreparationInputs
from operations.models import ChangeReview
from sites import observation as site_observation
from sites.bodies.common import SITE_GATED
from sites.configuration import (
    SiteSettings,
    render_caddy,
    render_laravel_caddy,
    render_maintenance,
    render_wordpress_caddy,
)

from . import change as backups_change

SLUG: Final = "reopen_site"
LABEL: Final = "Reopen site"
STAGES: Final = ("preflight", "publish", "verify")
ALL_SITES_READ: Final = backups_change.ALL_SITES_READ
CORE_SOURCE: Final = without_imports(
    importlib.resources.files("backups.bodies").joinpath("reopen.py").read_text(),
    ("sites.bodies.common",),
)
BODY_SOURCE: Final = site_observation.COMMON_SOURCE + "\n" + CORE_SOURCE
BODY_BYTES: Final = backups_change._packed(BODY_SOURCE)
BODY_SHA256: Final = hashlib.sha256(BODY_BYTES).hexdigest()


@dataclass(frozen=True)
class ReopenEvidence:
    standing: Standing | None
    site: dict[str, object] | None
    boot_id: str
    uptime_centiseconds: int | None
    current_sites: tuple[str, ...]


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> ReopenEvidence:
    observed = collect(shell, sites=False)
    listing = site_observation.read(shell, "observed", "", protections=False)
    record = None
    current: tuple[str, ...] = ()
    if listing is not None:
        record = next(
            (site for site in listing["sites"] if site["identifier"] == inputs.identifier),
            None,
        )
    found = shell.run(ALL_SITES_READ)
    if found.exit_status == 0 and not found.truncated:
        current = tuple(found.stdout.splitlines())
    return ReopenEvidence(
        observed.standing.standing if observed.standing else None,
        dict(record) if record is not None else None,
        str(listing["boot"]) if listing is not None else "",
        int(str(listing["uptime"])) if listing is not None else None,
        current,
    )


def _site(record: dict[str, object] | None) -> tuple[SiteSettings | None, str]:
    if record is None:
        return None, ""
    application = str(record.get("application", "plain"))
    names = record.get("names")
    if application not in ("plain", "wordpress", "laravel") or not isinstance(names, list):
        return None, application
    if not all(isinstance(name, str) for name in names):
        return None, application
    try:
        settings = SiteSettings(
            str(record["identifier"]),
            tuple(str(name) for name in names),
            str(record.get("runtime", "")),
            https=bool(record.get("https", True)),
            readiness=str(record.get("readiness", "/")),
        )
    except ValueError:
        return None, application
    return settings, application


def _open_file(settings: SiteSettings, application: str) -> str:
    if application == "wordpress":
        return render_wordpress_caddy(settings)
    if application == "laravel":
        return render_laravel_caddy(settings)
    return render_caddy(settings)


def review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, ReopenEvidence):
        raise ValueError("Reopening a site needs native evidence.")
    settings, application = _site(evidence.site)
    refusals: list[str] = []
    if evidence.standing != Standing.TARGET_STACK:
        refusals.append("Set up and verify the host foundation before reopening a site.")
    if settings is None or evidence.site is None:
        refusals.append("The site's configuration could not be read.")
    elif (
        evidence.site.get("state") != "partial"
        or evidence.site.get("problem") != SITE_GATED
        or evidence.site.get("serving_form") != "maintenance"
    ):
        refusals.append("The site is not paused, so there is nothing to reopen.")
    other = tuple(site for site in evidence.current_sites if site != inputs.identifier)
    caddy = _open_file(settings, application) if settings is not None else ""
    gate = render_maintenance(settings) if settings is not None else ""
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": BODY_SHA256,
        "identifier": inputs.identifier,
        "application": application,
        "names": list(settings.names) if settings is not None else [],
        "runtime": settings.runtime if settings is not None else "",
        "https": bool(settings.https) if settings is not None else True,
        "readiness": settings.readiness if settings is not None else "/",
        "caddy": caddy,
        "gate": gate,
        "details": [
            {
                "label": "Visitors",
                "value": "The maintenance page is removed and the site serves its files again.",
            },
            {
                "label": "Background work",
                "value": (
                    "Stays off. Open Scheduled tasks or Queue workers to choose what runs again."
                ),
            },
        ],
        "note": (
            "This only reopens the site. It does not take another copy or start background work."
        ),
    }
    effects: tuple[DeclaredEffect, ...] = ()
    if not refusals:
        effects = (
            DeclaredEffect(
                Scope.SITE,
                f"Remove {inputs.identifier}'s maintenance page and serve its files again.",
                (inputs.identifier,),
            ),
            *(
                (
                    DeclaredEffect(
                        Scope.SHARED,
                        "Reload Caddy for every site; other sites keep serving.",
                        evidence.current_sites,
                    ),
                )
                if other
                else ()
            ),
        )
    return ReviewDraft(
        kind=SLUG,
        intent=f"Reopen site {inputs.identifier}.",
        effects=effects,
        stages=STAGES if effects else (),
        postconditions=(
            "The site serves its reviewed files instead of the maintenance page.",
            "The site's background work is unchanged and asks the operator what to start.",
        )
        if effects
        else (),
        refusals=tuple(refusals),
        boot_id=evidence.boot_id,
        uptime_centiseconds=evidence.uptime_centiseconds,
        sites_read=ALL_SITES_READ if effects else "",
        current_sites=evidence.current_sites if effects else None,
        document=document,
    )


def _document(document: dict[str, object]) -> None:
    if document.get("version") != 1 or document.get("body_sha256") != BODY_SHA256:
        raise ValueError("Unsupported reopen review.")
    identifier = document.get("identifier")
    application = document.get("application")
    names = document.get("names")
    if (
        not isinstance(identifier, str)
        or application not in ("plain", "wordpress", "laravel")
        or not isinstance(names, list)
        or not all(isinstance(name, str) for name in names)
    ):
        raise ValueError("The reopen review is not a supported site.")
    settings = SiteSettings(
        identifier,
        tuple(str(name) for name in names),
        str(document.get("runtime", "")),
        https=document.get("https", True) is not False,
        readiness=str(document.get("readiness", "/")),
    )
    if _open_file(settings, str(application)) != document.get("caddy"):
        raise ValueError("The reopen review changed the site's configuration.")
    if render_maintenance(settings) != document.get("gate"):
        raise ValueError("The reopen review changed the maintenance page.")


def body(document: dict[str, object], context: BodyContext) -> NativeBody:
    _document(document)
    value = {
        key: document[key]
        for key in (
            "identifier",
            "application",
            "names",
            "runtime",
            "https",
            "readiness",
            "caddy",
            "gate",
        )
    }
    encoded = base64.b64encode(gzip.compress(json.dumps(value).encode(), mtime=0)).decode()
    return NativeBody(BODY_BYTES, (encoded,))


def verify(shell: RemoteShell, review: ChangeReview) -> bool | None:
    _document(review.document)
    listing = site_observation.read(shell, "observed", "", protections=False)
    if listing is None:
        return None
    record = next(
        (site for site in listing["sites"] if site["identifier"] == review.document["identifier"]),
        None,
    )
    return bool(record is not None and record.get("state") == "complete")


REOPEN_SITE: Final = ChangeKind(
    slug=SLUG,
    label=LABEL,
    inspect=inspect,
    review=review,
    body=body,
    verify=verify,
    refresh_discovery=True,
    input_shape=InputShape.SITE,
)
