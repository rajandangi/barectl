"""TLS readiness: the fresh external evidence every certificate order stands on.

docs/tls.md#readiness. For a complete convention site whose file serves its HTTP-01
challenge route, preparation resolves each of the site's names from the server's own
resolver, reads the server's addresses and clock, and reaches the authority's directory
over each family the names publish. A proxy or content delivery network in front of the
site, a published AAAA record without a working IPv6 path, a CAA record that does not name
the authority, an unsynchronized clock or an unreachable directory refuses readiness. The
reads are the same for the standalone readiness review and for a staging order's
preparation; nothing here writes anything.
"""

import json
import re
import secrets
from dataclasses import dataclass, field
from typing import override
from urllib.parse import urlsplit

from django.conf import settings

from bootstrap.evidence import Platform
from bootstrap.models import (
    Action,
    PlanEffect,
    PlanEvidence,
    PlanPreparation,
    PlanRefusal,
)
from bootstrap.releases import Release
from bootstrap.releases import of as releases_of
from bootstrap.review import Draft, EvidenceDraft, check_platform
from discovery.ssh import RemoteShell
from operations.lifecycle import OperationRefused
from sites import admission as site_admission
from sites import inspection
from sites.convention import (
    CONVENTION_REVISION as CONVENTION_REVISION,
)
from sites.convention import (
    RecognizedSite,
    recognize_site,
)
from sites.inspection import SiteEvidence
from sites.names import IDENTIFIER

from . import admission as challenge_admission
from . import readiness_native
from .models import TlsRequest

CERTBOT_VERSION = re.compile(r"certbot (\d+\.\d+\.\d+)")

Reason = PlanRefusal.Reason
Kind = PlanEvidence.Kind
Effect = PlanEffect.Kind

PRIVILEGE = (
    "The SSH user is not root, and sudo -n -l does not authorize Barectl's fixed read-only "
    "site reads without a password, so the site's own evidence stays inaccessible. The "
    "permission to prepare TLS plans is the explicit authority for that read. Barectl never "
    "installs a sudo policy or asks for a password."
)
NOT_A_SITE = (
    "The site's Nginx file is not a site file of the convention, so there is no site {0} to "
    "review. Create the site first."
)
SITE_FIRST = (
    "The site {0} is not exactly the convention's: its account, directories, pool, Nginx "
    "file, link and socket must all exist and match. Apply its site plan first."
)
ROUTE_FIRST = (
    "The site's file does not serve its HTTP-01 challenge route yet, so an order could not "
    "be validated over it. Apply the site's challenge route plan first."
)
INVALID_REQUEST = (
    "The stored TLS request is not a valid site identifier, so Barectl read nothing from the "
    "server. Prepare a new plan."
)
MISSING_REQUEST = (
    "The TLS request of this preparation is not recorded, so Barectl read nothing from the server."
)


def authorities() -> tuple[dict[str, str], ...]:
    """docs/tls.md#readiness: the allowlisted authorities, as the settings name them."""
    entries: tuple[dict[str, str], ...] = settings.ACME_AUTHORITIES
    return entries


def authority_of(directory: str) -> dict[str, str] | None:
    return next((entry for entry in authorities() if entry["directory"] == directory), None)


def default_authority() -> dict[str, str]:
    return authorities()[0]


def production_authority() -> dict[str, str] | None:
    """The allowlisted authority a production order uses (docs/tls.md#issuance)."""
    return authority_of(settings.ACME_PRODUCTION_DIRECTORY)


@dataclass
class NameRecords:
    """What the server's resolver answered for one name, and what it refused."""

    name: str
    a: tuple[str, ...] = ()
    aaaa: tuple[str, ...] = ()
    cname: str = ""
    caa: tuple[str, ...] = ()
    # Why no answer came, as the operator can act on it; empty when the name resolved.
    problem: str = ""


@dataclass
class Inputs:
    """Everything the external reads answered, shared by readiness and staging."""

    names: tuple[NameRecords, ...] = field(default_factory=tuple)
    # The server's own global addresses, split by family.
    ipv4: tuple[str, ...] = ()
    ipv6: tuple[str, ...] = ()
    ntp_synchronized: bool = False
    # Per family, why the directory did not answer; empty when it did. The IPv6 entry is
    # present only when the names publish AAAA records.
    unreachable: dict[str, str] = field(default_factory=dict)

    @property
    def published_ipv6(self) -> bool:
        return any(record.aaaa for record in self.names)


class TlsSiteDraft(Draft):
    """What both TLS reviews' drafts carry about the site, beyond ``Draft``."""

    names: tuple[str, ...] = ()
    ipv6: bool = False
    webroot: str = ""
    php_version: str = ""


class ReadinessDraft(TlsSiteDraft):
    """A readiness review before it is saved."""

    def __init__(
        self,
        identifier: str,
        token: str,
        authority: dict[str, str],
        platform: Platform | None = None,
        release: Release | None = None,
    ) -> None:
        super().__init__(Action.TLS_READINESS, intent(identifier), platform, release)
        self.identifier = identifier
        self.token = token
        self.authority = authority
        self.names: tuple[str, ...] = ()
        self.ipv6 = False
        self.webroot = ""
        self.php_version = ""
        self.inputs: Inputs | None = None

    @property
    @override
    def revision(self) -> int:
        return CONVENTION_REVISION


def intent(identifier: str) -> str:
    return (
        f"Review the external TLS prerequisites of the site {identifier}: fresh DNS, the "
        "server's addresses, its clock and the authority's reachability. Nothing changes."
    )


_A = re.compile(r"(\S+) IN A (\S+)")
_AAAA = re.compile(r"(\S+) IN AAAA (\S+)")
_CNAME = re.compile(r"(\S+) IN CNAME (\S+)")
_CAA = re.compile(r"(\S+) IN CAA ([0-9]+ )?(?:(\w+) )?\"?([^\"]*)\"?")


def _dns_problem(stdout: str) -> str:
    if "not found" in stdout:
        return "the name does not exist in DNS"
    if "does not have any RR" in stdout:
        # The name exists but holds none of this type; the other records still count.
        return ""
    if "SERVFAIL" in stdout:
        return "the resolver reported a server failure"
    return "the resolver did not answer"


def _names(shell: RemoteShell, names: tuple[str, ...]) -> tuple[NameRecords, ...]:
    read: list[NameRecords] = []
    for name in names:
        kinds = {}
        problems = []
        for kind in ("A", "AAAA", "CNAME", "CAA"):
            result = shell.run(readiness_native.dns_command(name, kind))
            kinds[kind] = result.stdout
            if result.exit_status != 0:
                problems.append(_dns_problem(result.stdout))
        a, cname_target = _dns_records(kinds["A"], "A")
        aaaa, _ = _dns_records(kinds["AAAA"], "AAAA")
        _, hop = _dns_records(kinds["CNAME"], "CNAME")
        caa, _ = _dns_records(kinds["CAA"], "CAA")
        cname = cname_target or hop
        problem = next((text for text in problems if text), "")
        if not problem and not a and not aaaa:
            problem = "the name holds neither an A nor an AAAA record" + (
                f"; it is a CNAME to {cname}, which does not resolve" if cname else ""
            )
        read.append(NameRecords(name=name, a=a, aaaa=aaaa, cname=cname, caa=caa, problem=problem))
    return tuple(read)


def _dns_records(stdout: str, kind: str) -> tuple[tuple[str, ...], str]:
    """The records of one kind from one answer, and the CNAME target when it holds one.

    Answers come padded with a `-- link: <interface>` suffix, which is not an answer.
    """
    records: list[str] = []
    target = ""
    for line in stdout.splitlines():
        if line.startswith("rc="):
            continue
        text = " ".join(line.partition("-- link:")[0].split())
        pattern = {"A": _A, "AAAA": _AAAA, "CNAME": _CNAME, "CAA": _CAA}[kind]
        match = pattern.fullmatch(text)
        if match is None:
            continue
        if kind == "CNAME":
            target = match[2].rstrip(".")
        else:
            values = _caa_values(match) if kind == "CAA" else match[2]
            if isinstance(values, str):
                records.append(values)
            else:
                records.extend(values)
    return tuple(records), target


def _caa_values(match: re.Match[str]) -> list[str]:
    """The CAA values an answer holds: only the values, never the flags or tags, and only
    the non-empty ones (docs/tls.md#readiness)."""
    value = match[4]
    return [part for part in value.split(";") if part] if value else []


def _own_addresses(shell: RemoteShell) -> tuple[tuple[str, ...], tuple[str, ...]]:
    result = shell.run(readiness_native.addresses_command())
    parsed = json.loads(result.stdout or "[]")
    ipv4: list[str] = []
    ipv6: list[str] = []
    for interface in parsed:
        for address in interface.get("addr_info", []):
            if address.get("scope") == "global":
                (ipv6 if address.get("family") == "inet6" else ipv4).append(address["local"])
    return tuple(sorted(ipv4)), tuple(sorted(ipv6))


def _clock(shell: RemoteShell) -> bool:
    result = shell.run(readiness_native.clock_command())
    return result.exit_status == 0 and result.stdout.strip() == "yes"


def _directory(shell: RemoteShell, directory: str, family: str) -> str:
    result = shell.run(readiness_native.directory_command(directory, family))
    return "" if "newNonce" in result.stdout else "the directory did not answer an ACME document"


def read_inputs(shell: RemoteShell, names: tuple[str, ...], directory: str) -> Inputs:
    """Run every external read once: DNS per name, the server's addresses and clock, and
    the directory over IPv4 always and over IPv6 when the names publish AAAA records."""
    url = urlsplit(directory)
    if url.scheme != "https" or not url.hostname:
        raise ValueError("Not an https directory URL.")
    ipv4, ipv6 = _own_addresses(shell)
    inputs = Inputs(
        names=_names(shell, names), ipv4=ipv4, ipv6=ipv6, ntp_synchronized=_clock(shell)
    )
    inputs.unreachable["-4"] = _directory(shell, directory, "-4")
    if inputs.published_ipv6:
        inputs.unreachable["-6"] = _directory(shell, directory, "-6")
    return inputs


def review(
    draft: Draft,
    *,
    authority: dict[str, str],
    inputs: Inputs,
    site_ipv6: bool = True,
) -> None:
    """Judge the inputs: refuse what an order could not stand on, else record each read as
    the plan's evidence. Shared by the readiness review and a staging order's preparation.
    ``site_ipv6`` is whether the site file publishes IPv6 listeners."""
    directory = authority["directory"]
    if inputs.published_ipv6 and not site_ipv6:
        draft.refuse(
            Reason.DESTINATION,
            "The names publish AAAA records, but the site file publishes no IPv6 listener, "
            "so nothing here would answer over IPv6. Give the site an IPv6 listener first.",
        )
    for record in inputs.names:
        _destination(draft, record, inputs)
    if len({frozenset(set(record.a) | set(record.aaaa)) for record in inputs.names}) > 1:
        draft.refuse(
            Reason.DESTINATION,
            "The names do not all resolve to the same addresses, so several servers would "
            "answer the order. Barectl never orders for multiple-server routing; point every "
            "name at this server through ordinary administration.",
        )
    for family, problem in sorted(inputs.unreachable.items()):
        if problem:
            draft.refuse(
                Reason.INCOMPLETE,
                f"The server cannot reach {directory} over "
                f"{'IPv4' if family == '-4' else 'IPv6'}: {problem}.",
            )
    if not inputs.ntp_synchronized:
        draft.refuse(
            Reason.INCOMPLETE,
            "The server's clock is not NTP synchronized. A certificate order validates "
            "against the authority's clock; synchronize time through ordinary "
            "administration, then prepare again.",
        )
    _caa(draft, inputs, authority)
    if draft.eligible:
        draft.evidence.append(
            EvidenceDraft(
                Kind.EXTERNAL_READS,
                _fingerprint(inputs, directory),
                _summary(inputs, directory),
            )
        )
        draft.effects.append(
            (
                Effect.EXTERNAL_READS,
                (
                    f"Resolved {', '.join(record.name for record in inputs.names)} from the "
                    "server's own resolver and read the server's addresses, its clock and the "
                    "directory's reachability. Nothing changes."
                ),
            )
        )


def _destination(draft: Draft, record: NameRecords, inputs: Inputs) -> None:
    """One name's destination must be this server's own addresses, over the right family."""
    if record.problem:
        draft.refuse(Reason.INCOMPLETE, f"{record.name} does not resolve: {record.problem}.")
        return
    destinations = sorted(set(record.a) | set(record.aaaa))
    foreign = sorted(set(destinations) - set(inputs.ipv4) - set(inputs.ipv6))
    if foreign:
        draft.refuse(
            Reason.DESTINATION,
            f"{record.name} resolves to {', '.join(destinations)}, which are not this "
            "server's own addresses. A proxy or content delivery network serves the name, "
            "so an order would prove their path, not this server's. Barectl does not "
            "manage DNS; repoint the name at this server through ordinary administration.",
        )
        return
    if inputs.published_ipv6 and not inputs.ipv6:
        draft.refuse(
            Reason.DESTINATION,
            "The names publish AAAA records, but the server has no global IPv6 address. "
            "An AAAA record must work over IPv6; IPv4 cannot stand in for it.",
        )


def _caa(draft: Draft, inputs: Inputs, authority: dict[str, str]) -> None:
    for record in inputs.names:
        if record.problem or not record.caa:
            continue
        if authority["caa"] not in record.caa:
            draft.refuse(
                Reason.AUTHORITY,
                f"{record.name} carries CAA records naming {', '.join(record.caa)}, which do "
                f"not include {authority['caa']}, the authority {authority['name']} records "
                "its orders under. The authority would refuse the order; change the CAA "
                "records or choose an authority the records name.",
            )


def _fingerprint(inputs: Inputs, directory: str) -> str:
    """The ordered read, as text: one line per name, then the server's own state."""
    lines = [f"directory {directory}"]
    lines.extend(
        f"{record.name} A {','.join(record.a)}; AAAA {','.join(record.aaaa)}; "
        f"CNAME {record.cname}; CAA {'|'.join(record.caa)}; {record.problem}"
        for record in inputs.names
    )
    lines.append(f"ipv4 {','.join(inputs.ipv4)}")
    lines.append(f"ipv6 {','.join(inputs.ipv6)}")
    lines.append(f"ntp {inputs.ntp_synchronized}")
    lines.extend(
        f"unreachable {family} {problem}" for family, problem in inputs.unreachable.items()
    )
    return json.dumps(lines, sort_keys=True)


def _summary(inputs: Inputs, directory: str) -> str:
    families = "IPv4 and IPv6" if inputs.published_ipv6 else "IPv4"
    return (
        f"{', '.join(record.name for record in inputs.names)} resolved from the server's own "
        f"resolver to this server's addresses; the directory answered over {families}; the "
        "clock is NTP synchronized. Read nothing but these answers."
    )


def inspect_site(shell: RemoteShell, identifier: str, token: str) -> SiteEvidence:
    """The site evidence both reviews read, as the site inspection reads it."""
    return inspection.inspect(shell, identifier, token)


def checked_site(
    draft: TlsSiteDraft, evidence: SiteEvidence, identifier: str
) -> tuple[RecognizedSite | None, str, str]:
    """The recognized convention site both reviews stand on, with the platform's and the
    site's own refusals already recorded. Returns the site, its webroot and the release's
    PHP version, or empty strings when the draft is refused."""
    check_platform(draft, evidence.platform)
    for gap in evidence.gaps:
        draft.refuse(Reason.INCOMPLETE, gap)
    if evidence.release is None or evidence.paths is None:
        return None, "", ""
    if not evidence.read_privilege:
        draft.refuse(Reason.PRIVILEGE, PRIVILEGE)
        return None, "", ""
    text = evidence.contents.get(evidence.paths.source)
    site = recognize_site(identifier, text) if text is not None else None
    if site is None:
        draft.refuse(Reason.PARTIAL_SITE, NOT_A_SITE.format(identifier))
        return None, "", ""
    if not site.stage.routes_challenges:
        draft.refuse(Reason.PREREQUISITE, ROUTE_FIRST)
        return None, "", ""
    draft.names = site.names
    draft.ipv6 = site.ipv6
    webroot, php = evidence.paths.webroot, evidence.release.php
    draft.webroot = webroot
    draft.php_version = php
    return site, webroot, php


def certbot_version(shell: RemoteShell) -> str | None:
    """The server's Certbot version, or ``None`` when it cannot be read."""
    result = shell.run(readiness_native.certbot_version_command())
    if result.exit_status != 0:
        return None
    found = CERTBOT_VERSION.search(result.stdout)
    return found[1] if found else None


def challenge_site(
    draft: TlsSiteDraft, evidence: SiteEvidence, identifier: str, token: str
) -> bool:
    """The site part of an order's review: a complete convention site whose file serves its
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
        draft.refuse(Reason.PRIVILEGE, PRIVILEGE)
        return False
    text = evidence.contents.get(paths.source)
    site = recognize_site(identifier, text) if text is not None else None
    if site is None:
        draft.refuse(Reason.PARTIAL_SITE, NOT_A_SITE.format(identifier))
        return False
    if not site.stage.routes_challenges:
        draft.refuse(Reason.PREREQUISITE, ROUTE_FIRST)
        return False
    draft.names = site.names
    draft.ipv6 = site.ipv6
    checked = site_admission.review(
        identifier, site.names, token, evidence, certificates_expected=True
    )
    challenge_admission._copy_refusals(draft, checked)
    challenge_admission._merge_evidence(draft, checked)
    if not checked.eligible:
        return False
    if not checked.no_changes:
        draft.refuse(Reason.PARTIAL_SITE, SITE_FIRST.format(identifier))
    return checked.no_changes


def prepare(preparation: PlanPreparation, shell: RemoteShell) -> ReadinessDraft:
    """The readiness review of one site, through requests and the worker."""
    request = TlsRequest.objects.filter(preparation=preparation).first()
    if request is None:
        raise OperationRefused(MISSING_REQUEST)
    if not IDENTIFIER.fullmatch(request.identifier):
        raise OperationRefused(INVALID_REQUEST)
    authority = default_authority()
    token = secrets.token_hex(16)
    evidence = inspect_site(shell, request.identifier, token)
    platform = evidence.platform
    release = releases_of(platform.os) if platform is not None else None
    draft = ReadinessDraft(request.identifier, token, authority, platform, release)
    site, _webroot, _php = checked_site(draft, evidence, request.identifier)
    if site is None or not draft.eligible:
        return draft
    inputs = read_inputs(shell, site.names, authority["directory"])
    draft.inputs = inputs
    review(draft, authority=authority, inputs=inputs, site_ipv6=draft.ipv6)
    return draft
