"""Public certificate facts of activated sites.

docs/v0.3.md#tls-preparation-issuance-and-renewal: ordinary discovery reads the lineage's
public certificate and the certificate served over 127.0.0.1 with the SSH user's
permissions, and never private-key or ACME account bytes.
"""

import re
import shlex
from dataclasses import replace
from typing import NamedTuple

from ..models import ObservationOutcome
from ..snapshot import (
    Observation,
    ObservedCertificate,
    ObservedSite,
    ServedCertificate,
)
from ..ssh import RemoteShell
from .probes import _Failed, _path_missing, _run, _test, _unreadable
from .sites import CERTIFICATE_ROOT

OBSERVED = ObservationOutcome.OBSERVED
ABSENT = ObservationOutcome.ABSENT
INACCESSIBLE = ObservationOutcome.INACCESSIBLE
UNSUPPORTED = ObservationOutcome.UNSUPPORTED

CERTIFICATE = "cert.pem"
RENEWAL_DIR = "/etc/letsencrypt/renewal"
# sha256sum hashes the empty input the pipeline leaves when the TLS probe reads nothing.
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
X509_COMMAND = (
    "openssl x509 -noout -subject -issuer -dates -serial -fingerprint -sha256 "
    "-ext subjectAltName -in {path}"
)
# No ``-quiet``: it implies ``-ign_eof``, so s_client would wait for the server's
# keepalive close instead of finishing; ``timeout`` bounds a stalled handshake.
SERVED_COMMAND = (
    "timeout 5 openssl s_client -connect 127.0.0.1:443 -servername {name} </dev/null "
    "2>/dev/null | openssl x509 -outform DER 2>/dev/null | sha256sum"
)
_ISSUER = re.compile(r"^issuer=(.*)$", re.MULTILINE)
_DATES = re.compile(r"^(notBefore|notAfter)=(.+)$", re.MULTILINE)
_SERIAL = re.compile(r"^serial=([0-9A-Fa-f]+)$", re.MULTILINE)
_FINGERPRINT = re.compile(r"^sha256 Fingerprint=([0-9A-Fa-f:]+)$", re.MULTILINE | re.IGNORECASE)
_NAMES = re.compile(r"DNS:([^,\s]+)")
_SERVED = re.compile(r"\A([0-9a-f]{64})  -\Z")


class CertificateFacts(NamedTuple):
    """The public fields an ``openssl x509`` read reports."""

    issuer: str
    not_before: str
    not_after: str
    serial: str
    fingerprint: str
    names: tuple[str, ...]


def parse_certificate(output: str) -> CertificateFacts | None:
    """Parse one fixed ``openssl x509`` read, or ``None`` when it is unsupported."""
    dates = {label: value.strip() for label, value in _DATES.findall(output)}
    issuer = _ISSUER.search(output)
    serial = _SERIAL.search(output)
    fingerprint = _FINGERPRINT.search(output)
    not_after = dates.get("notAfter")
    if issuer is None or serial is None or fingerprint is None or not not_after:
        return None
    return CertificateFacts(
        issuer[1].strip(),
        dates.get("notBefore", ""),
        not_after,
        serial[1].upper(),
        fingerprint[1].replace(":", "").lower(),
        tuple(dict.fromkeys(_NAMES.findall(output))),
    )


def _read_certificate(shell: RemoteShell, path: str) -> CertificateFacts | _Failed:
    command = X509_COMMAND.format(path=shlex.quote(path))
    output = _run(shell, command)
    if not isinstance(output, _Failed):
        facts = parse_certificate(output)
        if facts is None:
            return _Failed(UNSUPPORTED, f"{path} is not in a supported certificate form.", command)
        return facts
    if output.missing:
        return output
    failure = _unreadable(shell, path)
    if failure.missing:
        return replace(failure, status=ABSENT, warning=f"There is no certificate at {path}.")
    return failure


def _served(shell: RemoteShell, name: str) -> tuple[str, str]:
    """The fingerprint the server serves for ``name``, and the probe's command."""
    command = SERVED_COMMAND.format(name=shlex.quote(name))
    output = _run(shell, command)
    if isinstance(output, _Failed):
        return "", command
    match = _SERVED.fullmatch(output.strip())
    if match is None or match[1] == EMPTY_SHA256:
        return "", command
    return match[1], command


def _renewal(shell: RemoteShell, path: str) -> tuple[str, str, _Failed | None]:
    """The renewal configuration's existence, and why it could not be read."""
    command = f"test -e {shlex.quote(path)}"
    if _test(shell, "-e", path):
        return "present", command, None
    if _path_missing(shell, path):
        return "absent", command, None
    failure = _Failed(
        INACCESSIBLE,
        f"The SSH user cannot read {path}. Barectl does not use sudo.",
        command,
    )
    return "inaccessible", command, failure


def _site_certificate(shell: RemoteShell, site: ObservedSite) -> ObservedCertificate | None:
    if not site.stage.activated:
        return None
    path = f"{CERTIFICATE_ROOT}/{site.identifier}/{CERTIFICATE}"
    certificate_command = X509_COMMAND.format(path=shlex.quote(path))
    facts = _read_certificate(shell, path)
    served: list[ServedCertificate] = []
    served_commands: list[str] = []
    for name in site.server_names:
        fingerprint, command = _served(shell, name)
        served.append(ServedCertificate(name, fingerprint))
        served_commands.append(command)
    renewal, renewal_command, renewal_failure = _renewal(
        shell, f"{RENEWAL_DIR}/{site.identifier}.conf"
    )
    source = (certificate_command, *served_commands, renewal_command)
    warnings: list[str] = []
    if isinstance(facts, _Failed):
        return ObservedCertificate(
            outcome=facts.status,
            conforms=False,
            served=tuple(served),
            renewal=renewal,
            source=source,
            warning=_joined([facts.warning, renewal_failure.warning if renewal_failure else ""]),
        )
    if renewal_failure is not None:
        warnings.append(renewal_failure.warning)
    mismatched = [
        item.name
        for item in served
        if item.fingerprint and facts.fingerprint and item.fingerprint != facts.fingerprint
    ]
    if mismatched:
        names = ", ".join(mismatched)
        warnings.append(f"The certificate served for {names} is not the one on disk.")
    conforms = frozenset(facts.names) == frozenset(site.server_names) and renewal == "present"
    return ObservedCertificate(
        outcome=OBSERVED,
        conforms=conforms,
        issuer=facts.issuer,
        not_before=facts.not_before,
        not_after=facts.not_after,
        serial=facts.serial,
        fingerprint=facts.fingerprint,
        names=facts.names,
        served=tuple(served),
        renewal=renewal,
        source=source,
        warning=_joined(warnings),
    )


def _joined(warnings: list[str]) -> str:
    return " ".join(dict.fromkeys(warning for warning in warnings if warning))


def collect_certificates(
    shell: RemoteShell, sites: Observation[tuple[ObservedSite, ...]]
) -> Observation[tuple[ObservedSite, ...]]:
    """The sites, each activated one with its certificate's public facts."""
    if not sites.value:
        return sites
    return replace(
        sites,
        value=tuple(
            replace(site, certificate=_site_certificate(shell, site)) for site in sites.value
        ),
    )
