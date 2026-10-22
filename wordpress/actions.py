"""A WordPress site's actions as reviewed changes (Phase B #381, ADR 0017).

Reset administrator password writes a new value over the confidential input channel and
proves WordPress accepts it; Verify core files compares the installed core with the official
checksums. Both run WP-CLI as the site user in the transient unit and report one bounded,
sanitized result line, and neither runs application code during discovery.
"""

import base64
import gzip
import hashlib
import importlib.resources
import json
import re
import shlex
from dataclasses import dataclass
from typing import Final

from bootstrap.standing import Standing
from discovery.ssh import RemoteShell
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import InputShape, PreparationInputs, decode_inputs
from operations.models import ChangeReview
from sites import observation
from sites.bodies.common import NativeState, SiteRecord
from sites.change import membership_command
from sites.configuration import PHP_RUNTIMES

from . import convention

PASSWORD_SLUG: Final = "reset_wordpress_password"  # noqa: S105 - a kind slug
CORE_SLUG: Final = "verify_wordpress_core"
PASSWORD_LABEL: Final = "Reset WordPress administrator password"  # noqa: S105 - a label
CORE_LABEL: Final = "Verify WordPress core files"
SECRET_PATH: Final = re.compile(r"/run/barectl/secrets/[0-9a-f]{32}")
VERSION_NAME: Final = re.compile(r"[0-9A-Za-z.-]{1,40}")
DIGEST: Final = re.compile(r"[0-9a-f]{64}")

BODY_SOURCE: Final = (
    observation.COMMON_SOURCE
    + "\n"
    + importlib.resources.files("wordpress").joinpath("convention.py").read_text()
    + "\n"
    + importlib.resources.files("wordpress.bodies")
    .joinpath("actions.py")
    .read_text()
    .replace(
        "from sites.bodies.common import NativeState, native_state, result, setting, stage\n",
        "",
    )
    .replace("from wordpress.convention import ADMIN_USERNAME, public_root\n", "")
)
BODY_BYTES: Final = (
    (
        "#!/bin/sh\nexec python3 -c "
        + shlex.quote(
            "import base64,gzip; exec(gzip.decompress(base64.b64decode("
            + repr(base64.b64encode(gzip.compress(BODY_SOURCE.encode(), mtime=0)).decode())
            + ")))"
        )
        + ' "$@"\n'
    )
    .encode()
    .rstrip(b"\n")
)
BODY_SHA256: Final = hashlib.sha256(BODY_BYTES).hexdigest()


@dataclass(frozen=True)
class WordPressActionEvidence:
    standing: Standing | None
    native: NativeState | None


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> WordPressActionEvidence:
    from discovery.observations import collect

    # The affected site comes from this preparation's own bounded read; the snapshot's site
    # inventory would read every other site's protections for nothing.
    snapshot = collect(shell, sites=False)
    return WordPressActionEvidence(
        snapshot.standing.standing if snapshot.standing else None,
        observation.read(shell, "observed", "", protections=False),
    )


def _site_of(native: NativeState, identifier: str) -> SiteRecord | None:
    return next((row for row in native["sites"] if row["identifier"] == identifier), None)


def _refusals(
    evidence: WordPressActionEvidence, identifier: str, *, password: bool
) -> tuple[list[str], SiteRecord | None]:
    refusals: list[str] = []
    if evidence.standing != Standing.TARGET_STACK:
        refusals.append("Set up and verify the host foundation before changing a site.")
    native = evidence.native
    if native is None:
        refusals.append("The site's native serving configuration could not be read.")
        return refusals, None
    site = _site_of(native, identifier)
    if site is None:
        refusals.append("The site was not observed in the current server configuration.")
        return refusals, None
    if site["state"] != "complete":
        refusals.append(site["problem"] or "The site is incomplete or outside supported settings.")
    if site["application"] not in ("wordpress", "wordpress_partial"):
        refusals.append(
            "This site is not a WordPress application. These actions need a WordPress site."
        )
    elif site["application_problem"]:
        refusals.append(site["application_problem"])
    if password and not site["names"]:
        refusals.append("The site has no DNS name to sign in to.")
    if site["state"] == "complete" and (
        site["runtime"] not in PHP_RUNTIMES or site["account"] is None
    ):
        refusals.append("The site's PHP runtime or Linux account is not observed.")
    return refusals, site


def _details(
    site: SiteRecord | None, identifier: str, *, password: bool, username: str
) -> list[dict[str, str]]:
    details = [
        {"label": "Site", "value": identifier},
        {
            "label": "WordPress",
            "value": (
                f"WordPress {site['application_version']}" if site is not None else "Not observed"
            ),
        },
        {
            "label": "Runs as",
            "value": (
                f"Linux user s{identifier} with the site's own PHP runtime"
                if site is not None
                else "The site's own Linux user"
            ),
        },
    ]
    if password:
        details += [
            {"label": "Administrator username", "value": username},
            {
                "label": "New password",
                "value": (
                    "Typed on this confirm screen and sent only over the confidential channel. "
                    "It is never stored."
                ),
            },
            {
                "label": "Proof",
                "value": (
                    "WordPress's own sign-in page must accept the new password before the run "
                    "reports success."
                ),
            },
        ]
    else:
        details += [
            {
                "label": "Checksums",
                "value": (
                    "The official checksums for WordPress "
                    + (site["application_version"] if site is not None else convention.CORE_VERSION)
                    + " from WordPress.org, compared by WP-CLI as the site user."
                ),
            },
            {
                "label": "Result",
                "value": (
                    "A match reports success. A mismatch and an unavailable checksum service "
                    "are reported as separate refusals, and nothing on the server changes."
                ),
            },
        ]
    return details


def _draft(
    evidence: WordPressActionEvidence,
    inputs: PreparationInputs,
    *,
    password: bool,
    slug: str,
) -> ReviewDraft:
    identifier = inputs.identifier
    username = inputs.admin_username
    refusals, site = _refusals(evidence, identifier, password=password)
    native = evidence.native
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": BODY_SHA256,
        "identifier": identifier,
        "details": _details(site, identifier, password=password, username=username),
    }
    if site is not None:
        document.update(
            names=list(site["names"]),
            selection=site["runtime"],
            https=bool(site["https"]),
            identity=site["account"][0] if site["account"] is not None else 0,
            core_version=site["application_version"],
            precondition_digest=native["digest"] if native is not None else "",
        )
    if password:
        document.update(
            admin_username=username,
            secret_label="New WordPress administrator password",  # noqa: S106 - a label
            secret_generate=True,
        )
    effects: tuple[DeclaredEffect, ...] = ()
    if not refusals:
        effects = (
            DeclaredEffect(
                Scope.SITE,
                (
                    f"Reset the WordPress administrator password for {identifier}."
                    if password
                    else (
                        f"Compare {identifier}'s WordPress core files with the official "
                        "checksums; nothing on the server changes."
                    )
                ),
                (identifier,),
            ),
        )
    stages = ("preflight", "password", "verify") if password else ("preflight", "checksums")
    postconditions = (
        (
            "WordPress accepts the new administrator password at its own sign-in page.",
            (
                "The new password is not stored in the controller or on the server outside "
                "WordPress's own hash."
            ),
        )
        if password
        else (
            (
                "Every installed WordPress core file matches the official checksums for the "
                "reviewed version."
            ),
            "Nothing on the server changed.",
        )
    )
    return ReviewDraft(
        slug,
        (
            f"Reset the WordPress administrator password for {identifier}."
            if password
            else f"Verify {identifier}'s WordPress core files."
        ),
        effects=effects,
        stages=stages,
        postconditions=postconditions,
        refusals=tuple(dict.fromkeys(refusals)),
        boot_id=str(native["boot"]) if native is not None else "",
        uptime_centiseconds=int(str(native["uptime"])) if native is not None else None,
        sites_read=(membership_command(site["runtime"]) if effects and site is not None else ""),
        current_sites=(identifier,) if effects else None,
        document=document,
    )


def password_review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, WordPressActionEvidence):
        raise ValueError("A WordPress action needs native evidence.")
    return _draft(evidence, inputs, password=True, slug=PASSWORD_SLUG)


def core_review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, WordPressActionEvidence):
        raise ValueError("A WordPress action needs native evidence.")
    return _draft(evidence, inputs, password=False, slug=CORE_SLUG)


def _document(document: dict[str, object], *, password: bool) -> dict[str, object]:
    keys = ("version", "identifier", "admin_username") if password else ("version", "identifier")
    inputs = decode_inputs(
        {key: document.get(key) for key in keys},
        PHP_RUNTIMES,
        InputShape.WORDPRESS_PASSWORD if password else InputShape.WORDPRESS_CORE,
    )
    names = document.get("names")
    selection = document.get("selection")
    identity = document.get("identity")
    core_version = document.get("core_version")
    digest = document.get("precondition_digest")
    if (
        document.get("body_sha256") != BODY_SHA256
        or not isinstance(names, list)
        or not names
        or not all(isinstance(name, str) for name in names)
        or not isinstance(selection, str)
        or selection not in PHP_RUNTIMES
        or type(document.get("https")) is not bool
        or type(identity) is not int
        or not 1000 <= identity < 30000
        or not isinstance(core_version, str)
        or VERSION_NAME.fullmatch(core_version) is None
        or not isinstance(digest, str)
        or DIGEST.fullmatch(digest) is None
    ):
        raise ValueError("The WordPress action review is not a valid immutable native selection.")
    return {
        **document,
        "identifier": inputs.identifier,
        "admin_username": inputs.admin_username,
        "action": "password" if password else "core",
    }


def password_body(document: dict[str, object], context: BodyContext) -> NativeBody:
    if not context.secret_path or SECRET_PATH.fullmatch(context.secret_path) is None:
        raise ValueError("The WordPress review needs a staged confidential value.")
    payload = {**_document(document, password=True), "secret_path": context.secret_path}
    encoded = base64.b64encode(gzip.compress(json.dumps(payload).encode(), mtime=0)).decode()
    return NativeBody(BODY_BYTES.rstrip(b"\n"), (encoded,))


def core_body(document: dict[str, object], context: BodyContext) -> NativeBody:
    payload = _document(document, password=False)
    encoded = base64.b64encode(gzip.compress(json.dumps(payload).encode(), mtime=0)).decode()
    return NativeBody(BODY_BYTES.rstrip(b"\n"), (encoded,))


def verify(shell: RemoteShell, stored: ChangeReview) -> bool | None:
    document = stored.document
    identifier = str(document.get("identifier", ""))
    native = observation.read(shell, "observed", "", protections=False)
    if native is None:
        return None
    site = _site_of(native, identifier)
    return (
        site is not None
        and site["state"] == "complete"
        and site["application"] == "wordpress"
        and site["application_version"] == document.get("core_version")
        and site["names"] == document.get("names")
        and site["runtime"] == document.get("selection")
    )


RESET_PASSWORD: Final = ChangeKind(
    PASSWORD_SLUG,
    PASSWORD_LABEL,
    inspect,
    password_review,
    password_body,
    verify,
    writes_secrets=True,
    input_shape=InputShape.WORDPRESS_PASSWORD,
)

VERIFY_CORE: Final = ChangeKind(
    CORE_SLUG,
    CORE_LABEL,
    inspect,
    core_review,
    core_body,
    verify,
    input_shape=InputShape.WORDPRESS_CORE,
)
