import json
import operator
import re
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPException, HTTPSConnection
from typing import TYPE_CHECKING, NamedTuple, TypedDict

from runtimes.catalog import Build, architecture_of, load
from runtimes.presentation import runtime_label
from runtimes.updates import installed_builds

if TYPE_CHECKING:
    from discovery.snapshot import CollectedSnapshot

SOURCES = (
    ("php", "php/php-src", "PHP"),
    ("composer", "composer/composer", "Composer"),
    ("nodejs_", "", "Node.js"),
    ("caddy", "caddyserver/caddy", "Caddy"),
    ("fcgi", "FastCGI-Archives/fcgi2", "FastCGI client"),
    ("haproxy", "haproxy/haproxy", "HAProxy"),
    ("restic", "restic/restic", "restic"),
    ("wp-cli", "wp-cli/wp-cli", "WP-CLI"),
)
MAX_RESPONSE = 2 * 1024 * 1024
MAX_FINDINGS = 20
VERSION = re.compile(r"v?(\d{1,6})\.(\d{1,6})\.(\d{1,6})")
COMPARISON = re.compile(r"(<=|>=|<|>|=)?\s*(v?\d{1,6}\.\d{1,6}\.\d{1,6})")
GHSA = re.compile(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}")
CVE = re.compile(r"CVE-\d{4}-\d{4,}")
COMPARE = {
    "<": operator.lt,
    "<=": operator.le,
    ">": operator.gt,
    ">=": operator.ge,
    "=": operator.eq,
    None: operator.eq,
}


class Finding(TypedDict):
    name: str
    version: str
    advisory: str
    url: str
    fixed: str
    catalog_version: str
    catalog_has_fix: bool


class AdvisoryReport(TypedDict):
    findings: list[Finding]
    notes: list[str]
    checked: list[str]


class Match(NamedTuple):
    label: str
    url: str
    fixed: str


type Version = tuple[int, int, int]


def check(collected: CollectedSnapshot) -> AdvisoryReport:
    architecture = architecture_of(collected.architecture.value or "")
    if architecture is None:
        return {
            "findings": [],
            "notes": ["Could not identify the server architecture."],
            "checked": [],
        }
    profiles = dict(collected.standing.profiles) if collected.standing is not None else {}
    profiles.update({row.entry: row.path for row in collected.runtimes if row.path})
    installed = installed_builds(architecture, profiles)
    offered = {build.entry: build for build in load().offered(architecture)}
    sources = [
        (prefix, repo, name)
        for prefix, repo, name in SOURCES
        if any(entry.startswith(prefix) for entry in installed)
    ]
    notes: list[str] = []
    checked: list[str] = []
    findings: list[Finding] = []
    if not sources:
        notes.append("No installed catalog builds could be identified.")
    if profiles.keys() - installed.keys():
        notes.append("Some installed profiles could not be matched to this Barectl release.")
    with ThreadPoolExecutor(max_workers=4) as pool:
        responses = pool.map(_source, (repo for _, repo, _ in sources))
        for (prefix, repo, name), (records, paginated) in zip(sources, responses, strict=True):
            if records is None:
                notes.append(f"{name}: could not read the upstream source.")
                continue
            checked.append(name)
            incomplete = paginated
            for build in installed.values():
                if build.entry.startswith(prefix):
                    matches, skipped = _matches(records, repo, build)
                    incomplete |= skipped
                    findings.extend(
                        _finding(build, name, match, offered.get(build.entry)) for match in matches
                    )
            if incomplete:
                notes.append(f"{name}: the source contained entries this check could not cover.")
    if len(findings) > MAX_FINDINGS:
        notes.append("The display limit was reached. Some matches were omitted.")
    return {"findings": findings[:MAX_FINDINGS], "notes": notes, "checked": checked}


def _version(value: object) -> Version | None:
    match = VERSION.fullmatch(value) if isinstance(value, str) else None
    return (int(match[1]), int(match[2]), int(match[3])) if match else None


def _source(repo: str) -> tuple[list[object] | None, bool]:
    host = "api.github.com" if repo else "nodejs.org"
    path = (
        f"/repos/{repo}/security-advisories?per_page=100&state=published&sort=published"
        if repo
        else "/dist/index.json"
    )
    connection = HTTPSConnection(host, timeout=4)
    try:
        connection.request(
            "GET", path, headers={"User-Agent": "Barectl", "Accept": "application/json"}
        )
        response = connection.getresponse()
        if response.status != 200:
            return None, False
        body = response.read(MAX_RESPONSE + 1)
        if len(body) > MAX_RESPONSE:
            return None, False
        data: object = json.loads(body)
        if not isinstance(data, list):
            return None, False
        return list(data), 'rel="next"' in response.getheader("Link", "")
    except OSError, HTTPException, ValueError:
        return None, False
    finally:
        connection.close()


def _matches(records: list[object], repo: str, build: Build) -> tuple[list[Match], bool]:
    installed = _version(build.version)
    if installed is None:
        return [], True
    if not repo:
        return _node(records, installed)
    findings: list[Match] = []
    skipped = False
    for row in records:
        matches, incomplete = _github(row, repo, installed)
        skipped |= incomplete
        findings.extend(matches)
    return list(dict.fromkeys(findings)), skipped


def _node(records: list[object], installed: Version) -> tuple[list[Match], bool]:
    releases: list[Version] = []
    incomplete = False
    for row in records:
        if not isinstance(row, dict) or not isinstance(row.get("security"), bool):
            incomplete = True
        elif row.get("security") is True:
            version = _version(row.get("version"))
            if version is None:
                incomplete = True
            elif version[0] == installed[0] and version > installed:
                releases.append(version)
    if not releases:
        return [], incomplete
    fixed = ".".join(map(str, max(releases)))
    return [
        Match(
            "Newer Node.js security release", f"https://nodejs.org/en/blog/release/v{fixed}", fixed
        )
    ], incomplete


def _github(row: object, repo: str, installed: Version) -> tuple[list[Match], bool]:
    if not isinstance(row, dict):
        return [], True
    if row.get("withdrawn_at"):
        return [], False
    ghsa, entries = row.get("ghsa_id"), row.get("vulnerabilities")
    if not isinstance(ghsa, str) or not GHSA.fullmatch(ghsa) or not isinstance(entries, list):
        return [], True
    cve = row.get("cve_id")
    label = cve if isinstance(cve, str) and CVE.fullmatch(cve) else ghsa
    url = f"https://github.com/{repo}/security/advisories/{ghsa}"
    matches: list[Match] = []
    skipped = False
    for entry in entries:
        if not isinstance(entry, dict):
            skipped = True
            continue
        applicable, fixed = _affected(entry, repo, installed)
        if applicable is None:
            skipped = True
        elif applicable:
            matches.append(Match(label, url, fixed))
    return matches, skipped


def _affected(
    entry: Mapping[str, object],
    repo: str,
    installed: Version,
) -> tuple[bool | None, str]:
    patched = entry.get("patched_versions")
    fix = _version(patched)
    if repo == "php/php-src" and fix is not None and fix[:2] != installed[:2]:
        return False, ""
    constraints = entry.get("vulnerable_version_range")
    if not isinstance(constraints, str):
        return None, ""
    clauses: list[tuple[str | None, Version]] = []
    for part in constraints.split(","):
        match = COMPARISON.fullmatch(part.strip())
        if match is None:
            return None, ""
        version = _version(match[2])
        if version is None:
            return None, ""
        clauses.append((match[1], version))
    if not all(COMPARE[comparison](installed, version) for comparison, version in clauses):
        return False, ""
    return True, ".".join(map(str, fix)) if fix else ""


def _finding(build: Build, name: str, match: Match, offered: Build | None) -> Finding:
    fixed = _version(match.fixed)
    catalog = _version(offered.version) if offered else None
    return {
        "name": runtime_label(build.entry) if name in {"PHP", "Node.js"} else name,
        "version": build.version,
        "advisory": match.label,
        "url": match.url,
        "fixed": match.fixed,
        "catalog_version": offered.version if offered else "",
        "catalog_has_fix": fixed is not None and catalog is not None and catalog >= fixed,
    }
