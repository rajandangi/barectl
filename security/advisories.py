import json
import operator
import re
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from http.client import HTTPException, HTTPResponse, HTTPSConnection
from types import MappingProxyType
from typing import TYPE_CHECKING, Literal, NamedTuple, TypedDict

from backups.convention import RESTIC_ENTRY
from bootstrap.standing import Standing
from runtimes.catalog import Architecture, Build, Kind, architecture_of, load
from runtimes.extensions import CLIENT
from runtimes.extensions import build as extension_build
from runtimes.presentation import runtime_label
from runtimes.updates import installed_builds

if TYPE_CHECKING:
    from discovery.snapshot import CollectedSnapshot


class Source(NamedTuple):
    name: str
    repo: str


PHP = Source("PHP", "php/php-src")
NODE = Source("Node.js", "")
TOOLS = MappingProxyType(
    {
        "composer": Source("Composer", "composer/composer"),
        "caddy": Source("Caddy", "caddyserver/caddy"),
        "fcgi": Source("FastCGI client", "FastCGI-Archives/fcgi2"),
        "haproxy": Source("HAProxy", "haproxy/haproxy"),
        RESTIC_ENTRY: Source("restic", "restic/restic"),
        "wp-cli": Source("WP-CLI", "wp-cli/wp-cli"),
    }
)
MAX_RESPONSE = 2 * 1024 * 1024
MAX_FINDINGS = 20
TIMEOUT = 4
MAX_WORKERS = 4
VERSION = re.compile(r"v?([0-9]{1,6})\.([0-9]{1,6})\.([0-9]{1,6})")
RELEASE = re.compile(r"v?[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}-[0-9A-Za-z.-]+")
COMPARISON = re.compile(r"(<=|>=|<|>|=)?\s*(v?[0-9]{1,6}\.[0-9]{1,6}(?:\.[0-9]{1,6})?)")
GHSA = re.compile(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}")
CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,12}")
COMPARE = MappingProxyType(
    {
        "<": operator.lt,
        "<=": operator.le,
        ">": operator.gt,
        ">=": operator.ge,
        "=": operator.eq,
        None: operator.eq,
    }
)

type CatalogComparison = Literal["reaches_fix", "older_offer", "no_offer", "unknown"]


class Finding(TypedDict):
    name: str
    version: str
    advisory: str
    url: str
    fixed: str
    catalog_version: str
    catalog_comparison: CatalogComparison


class AdvisoryReport(TypedDict):
    findings: list[Finding]
    notes: list[str]
    checked: list[str]


class Match(NamedTuple):
    label: str
    url: str
    fixed: str


type Version = tuple[int, int, int]


@dataclass(frozen=True)
class Feed:
    records: tuple[object, ...] | None
    note: str = ""


def check(collected: CollectedSnapshot) -> AdvisoryReport:
    architecture = architecture_of(collected.architecture.value or "")
    if architecture is None:
        return {
            "findings": [],
            "notes": ["Could not identify the server architecture."],
            "checked": [],
        }

    profiles = _observed_paths(collected, architecture)
    installed = installed_builds(architecture, profiles)
    offered = {build.entry: build for build in load().offered(architecture)}
    notes = _coverage_notes(collected, profiles, installed)
    groups = _source_groups(installed, notes)
    checked: list[str] = []
    findings: list[Finding] = []
    omitted = 0
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        responses = pool.map(_source, groups)
        for (source, builds), feed in zip(groups.items(), responses, strict=True):
            if feed.note:
                notes.append(f"{source.name}: {feed.note}")
            if feed.records is None:
                continue
            checked.append(source.name)
            unsupported = False
            for build, version in builds:
                matches, skipped = _matches(feed.records, source, version)
                unsupported |= skipped
                for match in matches:
                    if len(findings) < MAX_FINDINGS:
                        findings.append(_finding(build, source, match, offered.get(build.entry)))
                    else:
                        omitted += 1
            if unsupported:
                notes.append(f"{source.name}: some upstream records were unsupported.")
    if omitted:
        notes.append(f"The display limit was reached. Omitted matches: {omitted}.")
    return {"findings": findings, "notes": notes, "checked": checked}


def _observed_paths(collected: CollectedSnapshot, architecture: Architecture) -> dict[str, str]:
    profiles = {
        entry: path
        for entry, path in (collected.standing.profiles if collected.standing else ())
        if path
    }
    profiles.update({row.entry: row.path for row in collected.runtimes if row.path})
    restic = next((row.profile for row in collected.backups.value if row.profile), "")
    if restic:
        profiles[RESTIC_ENTRY] = restic
    for runtime in sorted(
        {site.php_version for site in collected.sites.value if site.client == CLIENT}
    ):
        if extension := extension_build(architecture, runtime):
            profiles.setdefault(extension.entry, extension.path)
    return profiles


def _coverage_notes(
    collected: CollectedSnapshot, profiles: Mapping[str, str], installed: Mapping[str, Build]
) -> list[str]:
    notes = [
        f"Could not match the installed {entry} profile to a catalog build."
        for entry in sorted(profiles.keys() - installed.keys())
    ]
    if not installed:
        notes.append("No installed catalog builds could be identified.")
    if collected.standing is not None and collected.standing.standing == Standing.TARGET_STACK:
        if "fcgi" not in profiles:
            notes.append("Discovery did not establish the installed FastCGI client build.")
        if RESTIC_ENTRY not in profiles and not collected.backups.value:
            notes.append("Discovery did not establish the installed restic build.")
        if collected.runtime_warning:
            notes.append("Discovery could not read the installed runtime profiles.")
    return notes


def _source_for(build: Build) -> Source | None:
    if build.kind == Kind.PHP:
        return PHP
    if build.kind == Kind.NODE:
        return NODE
    if build.kind == Kind.TOOL:
        return TOOLS.get(build.entry)
    return None


def _source_groups(
    installed: Mapping[str, Build], notes: list[str]
) -> dict[Source, list[tuple[Build, Version]]]:
    groups: dict[Source, list[tuple[Build, Version]]] = {}
    for build in sorted(installed.values(), key=lambda build: build.entry):
        source = _source_for(build)
        version = _version(build.version)
        if source is None:
            notes.append(
                f"{build.entry} {build.version} has no upstream advisory source in this check."
            )
        elif version is None:
            notes.append(
                f"{_build_name(build, source)} {build.version} uses an unsupported version format."
            )
        else:
            groups.setdefault(source, []).append((build, version))
    return groups


def _version(value: object) -> Version | None:
    match = VERSION.fullmatch(value) if isinstance(value, str) else None
    return (int(match[1]), int(match[2]), int(match[3])) if match else None


def _source(source: Source) -> Feed:
    host = "api.github.com" if source.repo else "nodejs.org"
    path = (
        f"/repos/{source.repo}/security-advisories?per_page=100&state=published&sort=published"
        if source.repo
        else "/dist/index.json"
    )
    connection = HTTPSConnection(host, timeout=TIMEOUT)
    try:
        return _read_feed(connection, path, github=bool(source.repo))
    except OSError, HTTPException:
        return Feed(None, "could not read the upstream source.")
    finally:
        connection.close()


def _read_feed(connection: HTTPSConnection, path: str, *, github: bool) -> Feed:
    connection.request("GET", path, headers={"User-Agent": "Barectl", "Accept": "application/json"})
    response = connection.getresponse()
    if _rate_limited(response):
        upstream = "GitHub" if github else "Node.js"
        return Feed(None, f"{upstream} rate-limited the advisory request.")
    if response.status != 200:
        return Feed(None, f"the upstream source was unavailable (HTTP {response.status}).")
    body = response.read(MAX_RESPONSE + 1)
    if len(body) > MAX_RESPONSE:
        return Feed(None, "the upstream response exceeded the size limit.")
    try:
        data: object = json.loads(body)
    except ValueError, RecursionError:
        return Feed(None, "the upstream response was malformed.")
    if not isinstance(data, list):
        return Feed(None, "the upstream response was malformed.")
    next_page = 'rel="next"' in (response.getheader("Link") or "")
    note = "additional upstream advisory pages were skipped." if next_page else ""
    return Feed(tuple(data), note)


def _rate_limited(response: HTTPResponse) -> bool:
    return response.status == 429 or (
        response.status == 403
        and (
            response.getheader("X-RateLimit-Remaining") == "0"
            or response.getheader("Retry-After") is not None
        )
    )


def _matches(
    records: tuple[object, ...], source: Source, installed: Version
) -> tuple[list[Match], bool]:
    if source == NODE:
        return _node(records, installed)
    findings: dict[Match, None] = {}
    skipped = False
    for row in records:
        matches, incomplete = _github(row, source, installed)
        skipped |= incomplete
        findings.update(dict.fromkeys(matches))
    return list(findings), skipped


def _node(records: tuple[object, ...], installed: Version) -> tuple[list[Match], bool]:
    releases: list[Version] = []
    incomplete = False
    for row in records:
        if not isinstance(row, dict) or not isinstance(row.get("security"), bool):
            incomplete = True
            continue
        tag = row.get("version")
        if isinstance(tag, str) and RELEASE.fullmatch(tag):
            continue
        version = _version(tag)
        if version is None:
            incomplete = True
        elif row["security"] and version[0] == installed[0] and version > installed:
            releases.append(version)
    if not releases:
        return [], incomplete
    fixed = ".".join(map(str, max(releases)))
    return [
        Match(
            "Newer Node.js security release", f"https://nodejs.org/en/blog/release/v{fixed}", fixed
        )
    ], incomplete


def _github(row: object, source: Source, installed: Version) -> tuple[list[Match], bool]:
    if not isinstance(row, dict):
        return [], True
    if row.get("withdrawn_at") or row.get("state") in ("draft", "closed", "withdrawn"):
        return [], False
    ghsa, entries = row.get("ghsa_id"), row.get("vulnerabilities")
    if (
        row.get("state") != "published"
        or not isinstance(ghsa, str)
        or not GHSA.fullmatch(ghsa)
        or not isinstance(entries, list)
        or not entries
    ):
        return [], True
    cve = row.get("cve_id")
    label = cve if isinstance(cve, str) and CVE.fullmatch(cve) else ghsa
    url = f"https://github.com/{source.repo}/security/advisories/{ghsa}"
    matches: list[Match] = []
    skipped = False
    for entry in entries:
        if not isinstance(entry, dict):
            skipped = True
            continue
        applicable, fixed = _affected(entry, source, installed)
        if applicable is None:
            skipped = True
        elif applicable:
            matches.append(Match(label, url, fixed))
    return matches, skipped


def _affected(
    entry: Mapping[str, object],
    source: Source,
    installed: Version,
) -> tuple[bool | None, str]:
    patched = entry.get("patched_versions")
    fix = _version(patched)
    if source == PHP and fix is not None and fix[:2] != installed[:2]:
        return False, ""
    constraints = entry.get("vulnerable_version_range")
    if not isinstance(constraints, str):
        return None, ""
    clauses: list[tuple[str | None, Version]] = []
    for part in constraints.split(","):
        match = COMPARISON.fullmatch(part.strip())
        if match is None:
            return None, ""
        operand = match[2]
        version = _version(operand if operand.count(".") == 2 else operand + ".0")
        if version is None:
            return None, ""
        clauses.append((match[1], version))
    if not all(COMPARE[comparison](installed, version) for comparison, version in clauses):
        return False, ""
    return True, ".".join(map(str, fix)) if fix else ""


def _build_name(build: Build, source: Source) -> str:
    return runtime_label(build.entry) if build.kind in (Kind.PHP, Kind.NODE) else source.name


def _catalog_comparison(fixed: str, offered: Build | None) -> CatalogComparison:
    if offered is None:
        return "no_offer"
    fix = _version(fixed)
    catalog = _version(offered.version)
    if fix is None or catalog is None:
        return "unknown"
    return "reaches_fix" if catalog >= fix else "older_offer"


def _finding(build: Build, source: Source, match: Match, offered: Build | None) -> Finding:
    return {
        "name": _build_name(build, source),
        "version": build.version,
        "advisory": match.label,
        "url": match.url,
        "fixed": match.fixed,
        "catalog_version": offered.version if offered else "",
        "catalog_comparison": _catalog_comparison(match.fixed, offered),
    }
