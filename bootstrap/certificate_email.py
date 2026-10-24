"""The optional certificate contact email in Caddy's main configuration (#444).

docs/tls.md#certificate-contact-email. Caddy's global ``email`` option is the one place a
certificate authority may reach the operator, so the setting stays optional and the main
configuration carries no line when it is unset. One reviewed Shared change republishes the
main configuration with only that line changed, validates it with Caddy, reloads Caddy and
verifies the running configuration equals the file. Discovery reads the same rendered file,
so a fresh controller shows the setting without a Barectl marker.
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
from discovery.observations.caddy_email import (
    ABSENT,
    MAX_TEXT,
    OUTSIDE,
    SET,
    UNREADABLE,
    email_lines,
    email_state,
    read_main,
    valid_email,
)
from discovery.ssh import RemoteShell
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import InputShape, PreparationInputs
from operations.models import ChangeReview

SLUG: Final = "set_certificate_email"
LABEL: Final = "Change certificate contact email"
MAIN_PATH: Final = "/etc/caddy/Caddyfile"
STAGES: Final = ("preflight", "caddy", "verify")
# The compressed reviewed document is one native argument; this bound leaves room for the
# engine's admission and the body itself under ADR 0006's payload limit.
MAX_ARGUMENT: Final = 4096

__all__ = [  # noqa: RUF022 - the setting's states and its change seam
    "ABSENT",
    "BODY_BYTES",
    "BODY_SHA256",
    "CertificateEmailEvidence",
    "LABEL",
    "MAIN_PATH",
    "OUTSIDE",
    "SET",
    "SET_CERTIFICATE_EMAIL",
    "SLUG",
    "STAGES",
    "UNREADABLE",
    "body",
    "email_state",
    "encode_document",
    "inspect",
    "read_main",
    "render_main",
    "review",
    "valid_email",
    "verify",
]

SOURCE: Final = importlib.resources.files("bootstrap.bodies").joinpath("certificate_email.py")
BODY_SOURCE: Final = SOURCE.read_text()
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

PRECONDITION_COMMAND: Final = "; ".join(
    [
        "printf 'boot\\t%s\\n' \"$(cat /proc/sys/kernel/random/boot_id)\"",
        "printf 'uptime\\t%s\\n' \"$(cut -d' ' -f1 /proc/uptime | tr -d .)\"",
        (f"printf 'file\\t%s\\n' \"$(stat -c '%u %g %a %h %F' {MAIN_PATH} 2>/dev/null || true)\""),
    ]
)
SITE_IDENTIFIERS_COMMAND: Final = (
    "find /etc/caddy/sites -maxdepth 1 -type f -name '*.caddy' -printf '%f\\n' "
    "| sed 's/\\.caddy$//'"
)
_BOOT = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
_UPTIME = re.compile(r"[0-9]{1,16}")
_FILE = re.compile(r"0 0 644 1 regular file")


def encode_document(document: dict[str, object]) -> str:
    """The one native argument: the reviewed texts compressed and base64 encoded."""
    value = {
        "email": document.get("email"),
        "previous": document.get("previous"),
        "caddy": document.get("caddy"),
    }
    return base64.b64encode(gzip.compress(json.dumps(value).encode(), mtime=0)).decode()


def render_main(previous: str, email: str) -> str:
    """The main configuration with only its global ``email`` line set, replaced or removed.

    Every other line, including options the operator added through ordinary administration,
    stays byte-identical. A file without the supported leading global block is refused.
    """
    if not valid_email(email):
        raise ValueError("The certificate contact email is not one bare address.")
    lines = previous.splitlines(keepends=True)
    found = email_lines(lines)
    if found is None:
        raise ValueError("The main Caddy configuration has no supported global block.")
    start, end, indices = found
    if len(indices) > 1:
        raise ValueError("The main Caddy configuration has more than one email line.")
    newline = "\r\n" if lines[start].endswith("\r\n") else "\n"
    if email:
        if indices:
            index = indices[0]
            indent = lines[index][: len(lines[index]) - len(lines[index].lstrip(" \t"))]
            ending = "\r\n" if lines[index].endswith("\r\n") else newline
            lines[index] = f"{indent}email {email}{ending}"
        else:
            index = start + 1
            for position in range(start + 1, end):
                if re.match(r"[ \t]*admin(?:\s|$)", lines[position]):
                    index = position + 1
                    break
            lines.insert(index, f"\temail {email}{newline}")
    else:
        for index in reversed(indices):
            del lines[index]
    candidate = "".join(lines)
    expected = (SET, email) if email else (ABSENT, "")
    if email_state(candidate) != expected:
        raise ValueError("The rendered main Caddy configuration does not hold the setting.")
    return candidate


@dataclass(frozen=True)
class CertificateEmailEvidence:
    standing: Standing | None
    boot_id: str
    uptime_centiseconds: int | None
    file_metadata: str
    file_state: str
    previous: str
    current: str
    sites: tuple[str, ...] | None


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> CertificateEmailEvidence:
    from discovery.observations import collect

    observed = collect(shell, sites=False)
    values: dict[str, str] = {}
    result = shell.run(PRECONDITION_COMMAND)
    if result.exit_status == 0 and not result.truncated:
        for line in result.stdout.splitlines():
            name, separator, value = line.partition("\t")
            if separator:
                values[name] = value
    text = read_main(shell)
    state, current = email_state(text) if text is not None else (UNREADABLE, "")
    previous = text if text is not None and len(text.encode()) <= MAX_TEXT else ""
    sites_result = shell.run(SITE_IDENTIFIERS_COMMAND)
    sites = (
        tuple(sorted(sites_result.stdout.splitlines()))
        if sites_result.exit_status == 0 and not sites_result.truncated
        else None
    )
    uptime = values.get("uptime", "")
    return CertificateEmailEvidence(
        standing=observed.standing.standing if observed.standing else None,
        boot_id=values.get("boot", ""),
        uptime_centiseconds=int(uptime) if _UPTIME.fullmatch(uptime) else None,
        file_metadata=values.get("file", ""),
        file_state=state,
        previous=previous,
        current=current,
        sites=sites,
    )


def _refusals(evidence: CertificateEmailEvidence) -> list[str]:
    refusals: list[str] = []
    if evidence.standing != Standing.TARGET_STACK:
        refusals.append(
            "Set up and verify the host foundation before changing the certificate contact email."
        )
    if evidence.file_state == UNREADABLE:
        refusals.append("The main Caddy configuration could not be read.")
    elif evidence.file_state == OUTSIDE:
        refusals.append(
            "The main Caddy configuration is outside supported settings for the certificate "
            "contact email. Resolve its global options through ordinary administration."
        )
    if not _FILE.fullmatch(evidence.file_metadata):
        refusals.append(
            "The main Caddy configuration is missing or outside the root-owned 0644 convention."
        )
    if evidence.sites is None:
        refusals.append(
            "The server's site files could not be read, so the reload cannot be bounded."
        )
    if not _BOOT.fullmatch(evidence.boot_id) or evidence.uptime_centiseconds is None:
        refusals.append("The server's clock could not be read.")
    return refusals


def review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:
    if not isinstance(evidence, CertificateEmailEvidence):
        raise ValueError("A certificate contact email change needs native evidence.")
    requested = inputs.certificate_email or ""
    refusals = _refusals(evidence)
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": BODY_SHA256,
        "email": requested,
        "previous": evidence.previous,
        "caddy": "",
        "details": [],
    }
    candidate = ""
    if not refusals:
        try:
            candidate = render_main(evidence.previous, requested)
        except ValueError as error:
            refusals.append(str(error))
    unchanged = not refusals and candidate == evidence.previous
    sites = evidence.sites or ()
    document.update(
        caddy=candidate,
        details=[
            {
                "label": "Certificate contact email",
                "value": requested or "None. The main configuration has no email line.",
            },
            {
                "label": "Previous contact email",
                "value": evidence.current or "Not set",
            },
            {
                "label": "Apply",
                "value": (
                    "Publish /etc/caddy/Caddyfile, validate it with Caddy, reload Caddy and "
                    "verify that its running configuration equals the file."
                ),
            },
            {
                "label": "Sites",
                "value": ", ".join(sites) or "No sites yet; the reload still reaches Caddy.",
            },
            {
                "label": "Main configuration",
                "value": f"{MAIN_PATH} (root:root, 0644):\n{candidate}",
            },
        ],
    )
    if not refusals and len(encode_document(document)) > MAX_ARGUMENT:
        refusals.append(
            "The main Caddy configuration is larger than one reviewed change publishes."
        )
    return ReviewDraft(
        kind=SLUG,
        intent=(
            "Set the certificate contact email."
            if requested
            else "Remove the certificate contact email."
        ),
        effects=()
        if refusals or unchanged
        else (
            DeclaredEffect(
                Scope.SHARED,
                "Republish Caddy's main configuration with the certificate contact email "
                "and reload Caddy for every site.",
                sites,
            ),
        ),
        stages=STAGES,
        postconditions=(
            "The main Caddy configuration holds the reviewed certificate contact email.",
            "Caddy's running configuration equals the file and every site keeps serving.",
        ),
        refusals=tuple(refusals),
        boot_id=evidence.boot_id,
        uptime_centiseconds=evidence.uptime_centiseconds,
        sites_read=SITE_IDENTIFIERS_COMMAND if evidence.sites is not None else "",
        current_sites=evidence.sites,
        document={**document, "note": "The setting is already as reviewed." if unchanged else ""},
    )


def body(document: dict[str, object], context: BodyContext) -> NativeBody:
    email = document.get("email")
    previous = document.get("previous")
    candidate = document.get("caddy")
    if (
        type(document.get("version")) is not int
        or document.get("version") != 1
        or document.get("body_sha256") != BODY_SHA256
        or not isinstance(email, str)
        or not valid_email(email)
        or not isinstance(previous, str)
        or not isinstance(candidate, str)
        or len(previous.encode()) > MAX_TEXT
        or len(candidate.encode()) > MAX_TEXT
        or "\0" in previous
        or "\0" in candidate
        or render_main(previous, email) != candidate
    ):
        raise ValueError("The certificate contact email review is not a valid native selection.")
    encoded = encode_document(document)
    if len(encoded) > MAX_ARGUMENT:
        raise ValueError("The certificate contact email review is larger than one native argument.")
    return NativeBody(BODY_BYTES, (encoded,))


def verify(shell: RemoteShell, stored: ChangeReview) -> bool | None:
    from bootstrap import foundation

    body(stored.document, BodyContext("", "", 0))
    text = read_main(shell)
    values = foundation.read(shell)
    if text is None or values is None:
        return None
    state, current = email_state(text)
    return (
        text == stored.document["caddy"]
        and state == (SET if stored.document["email"] else ABSENT)
        and current == stored.document["email"]
        and values.get("caddy_valid") == "yes"
        and values.get("caddy_file") == "0 0 644"
        and foundation.same_caddy(
            values.get("caddy_json", ""), values.get("caddy_running_json", "")
        )
    )


SET_CERTIFICATE_EMAIL: Final = ChangeKind(
    slug=SLUG,
    label=LABEL,
    inspect=inspect,
    review=review,
    body=body,
    verify=verify,
    refresh_discovery=True,
    input_shape=InputShape.CERTIFICATE_EMAIL,
)
