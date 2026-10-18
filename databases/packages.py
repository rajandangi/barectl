"""docs/adr/0007-admit-exact-package-transactions-with-an-inline-apt-guard.md

The exact APT transaction of Phase B's database engines, in the reduced form the phase
specification keeps: the review simulates one fresh installation with APT's own resolver
and names every package and version, the native body installs exactly those under the
inline ``DPkg::Pre-Install-Pkgs`` guard, and the guard refuses unless APT's resolved
actions are exactly the reviewed ones. Nothing here imports Django: the module is standard
library only, so the controller and the asserted native body share one source of truth.

This holds no models and needs no migration. The old per-feature plan tables were deleted at
the Phase A exit; the change engine of ADR 0035 stores the review whole.
"""

import re
import shlex
from dataclasses import dataclass
from typing import Final, NamedTuple

# https://manpages.ubuntu.com/manpages/resolute/man1/dpkg-query.1.html
_PACKAGE = re.compile(r"[a-z0-9][a-z0-9+.-]{0,99}")
_VERSION = re.compile(r"[A-Za-z0-9.+~:-]{1,100}")
_ARCHITECTURE = re.compile(r"[a-z0-9-]{1,20}")
# The guard refuses any action it does not recognize, so a package source is admitted only
# from APT's own archive cache under a fixed path.
ARCHIVES: Final = "/var/cache/apt/archives/"
DPKG_STATUS: Final = "/var/lib/dpkg/status"
STATUS_VARIABLE: Final = "BARECTL_DPKG_STATUS"
GUARD_NAME: Final = "barectl_package_guard"
GUARD_ADMITTED: Final = "barectl-guard: admitted"
GUARD_REFUSED: Final = "barectl-guard: refused"

# docs/adr/0007-admit-exact-package-transactions-with-an-inline-apt-guard.md#installation
INSTALL_OPTIONS: Final = (
    "-q",
    "-y",
    "--no-remove",
    "-o",
    "APT::Install-Recommends=0",
    "-o",
    "APT::Install-Suggests=0",
    "-o",
    "APT::Get::Fix-Missing=0",
    "-o",
    "DPkg::Lock::Timeout=0",
)


@dataclass(frozen=True)
class PackageAction:
    """One dpkg action a reviewed transaction approves: unpacking a new package's version
    or configuring it. The guard compares APT's resolved actions to these lines exactly."""

    unpack: bool
    package: str
    version: str
    architecture: str

    def normalized(self) -> str:
        package = _check(_PACKAGE, self.package, "package name")
        version = _check(_VERSION, self.version, "version")
        architecture = _check(_ARCHITECTURE, self.architecture, "architecture")
        if not self.unpack:
            return f"C {package} {version} {architecture}"
        archive = f"{package}_{version.replace(':', '%3a')}_{architecture}.deb"
        return f"U {package} {version} {architecture} {archive}"


class Transition(NamedTuple):
    """One action line of ``apt-get -s install``."""

    # "Inst", "Conf", "Remv" or "Purg".
    action: str
    package: str
    # The version installed before, for upgrades, downgrades, reinstalls and removals.
    previous: str
    # The version installed or configured; empty for removals.
    version: str
    architecture: str
    origins: tuple[str, ...]


class Simulation(NamedTuple):
    transitions: tuple[Transition, ...]
    # Why APT's answer cannot be used, such as an error it reported; empty when usable.
    problems: tuple[str, ...]


_INST = re.compile(
    rf"(Inst|Conf) ({_PACKAGE.pattern})(?::{_ARCHITECTURE.pattern})? (?:\[({_VERSION.pattern})\] )?"
    rf"\(({_VERSION.pattern}) ([^\[\]()]{{0,500}}) \[({_ARCHITECTURE.pattern})\]\)"
    rf"(?: \[[^\]]{{0,500}}\])?"
)
_REMOVE = re.compile(
    rf"(Remv|Purg) ({_PACKAGE.pattern})(?::{_ARCHITECTURE.pattern})? "
    rf"\[({_VERSION.pattern})\](?: \[[^\]]{{0,500}}\])?"
)
_SUMMARY = re.compile(
    r"(\d+) upgraded, (\d+) newly installed, (?:(\d+) downgraded, )?(?:(\d+) reinstalled, )?"
    r"(\d+) to remove and (\d+) not upgraded\."
)


def simulate_command(roots: tuple[str, ...]) -> str:
    """The read that resolves ``roots`` against the server's own package indexes."""
    for root in roots:
        _check(_PACKAGE, root, "package name")
    options = " ".join(shlex.quote(option) for option in INSTALL_OPTIONS)
    requested = " ".join(shlex.quote(root) for root in roots)
    return f"DEBIAN_FRONTEND=noninteractive apt-get {options} --simulate install {requested}"


def parse_simulation(text: str) -> Simulation:
    """Read ``apt-get -s install``: every action line strictly, checked against its summary."""
    transitions: list[Transition] = []
    problems: list[str] = []
    summaries: list[re.Match[str]] = []
    for line in text.splitlines():
        if line.startswith(("Inst ", "Conf ", "Remv ", "Purg ")):
            transitions.append(_action(line))
        elif line.startswith(("E: ", "Err")):
            problems.append("APT reported an error while simulating the installation.")
        elif "cannot be authenticated" in line or line.startswith("W: "):
            problems.append("APT reported a warning, such as unauthenticated packages.")
        elif summary := _SUMMARY.fullmatch(line):
            summaries.append(summary)
    if len(transitions) > 400:
        raise ValueError("APT's simulation proposes more changes than Barectl reviews.")
    problems.extend(_summary_problems(transitions, summaries))
    return Simulation(tuple(transitions), tuple(dict.fromkeys(problems)))


def _action(line: str) -> Transition:
    if line.startswith(("Remv ", "Purg ")):
        match = _REMOVE.fullmatch(line)
        if match is None:
            raise ValueError("APT's simulation reported a removal in an unknown form.")
        return Transition(match[1], match[2], match[3], "", "", ())
    match = _INST.fullmatch(line)
    if match is None:
        raise ValueError("APT's simulation reported a package action in an unknown form.")
    origins = tuple(origin.strip() for origin in match[5].split(",") if origin.strip())
    return Transition(match[1], match[2], match[3] or "", match[4], match[6], origins)


def _summary_problems(transitions: list[Transition], summaries: list[re.Match[str]]) -> list[str]:
    if not transitions:
        return []
    if len(summaries) != 1:
        return ["APT's simulation did not report one summary of its changes."]
    counts = [int(value or 0) for value in summaries[0].groups()]
    upgraded, installed, downgraded, reinstalled, removed = counts[:5]
    unpacks = [t for t in transitions if t.action == "Inst"]
    new = sum(1 for t in unpacks if not t.previous)
    changed = sum(1 for t in unpacks if t.previous)
    removals = sum(1 for t in transitions if t.action in {"Remv", "Purg"})
    if (new, changed, removals) != (installed, upgraded + downgraded + reinstalled, removed):
        return ["APT's simulated actions do not match its own summary."]
    return []


def actions_of(transitions: tuple[Transition, ...], architecture: str) -> tuple[PackageAction, ...]:
    """The approved actions of a fresh installation, or a ``ValueError`` when it is not one.

    A removal, an upgrade, a downgrade, a reinstall or a foreign architecture refuses: this
    reduced transaction only installs missing packages, and Barectl never changes an
    installed package's version (docs/adr/0024-admit-exact-reviewed-upgrade-transactions.md).
    """
    actions: list[PackageAction] = []
    for transition in transitions:
        if transition.action in {"Remv", "Purg"}:
            raise ValueError(f"Installing would remove {transition.package} {transition.previous}.")
        if transition.action == "Inst" and transition.previous:
            raise ValueError(
                f"Installing would change {transition.package} from {transition.previous} "
                f"to {transition.version}."
            )
        if not transition.origins:
            raise ValueError(f"APT did not name the source of {transition.package}.")
        if transition.architecture not in {architecture, "all"}:
            raise ValueError(f"{transition.package} would be installed for another architecture.")
        actions.append(
            PackageAction(
                transition.action == "Inst",
                transition.package,
                transition.version,
                transition.architecture,
            )
        )
    return tuple(actions)


def guard(actions: tuple[PackageAction, ...]) -> str:
    """docs/adr/0007-admit-exact-package-transactions-with-an-inline-apt-guard.md#the-guard"""
    approved = sorted(action.normalized() for action in actions)
    if not approved or len(set(approved)) != len(approved):
        raise ValueError("Not a valid package transaction.")
    expected = " ".join(f"'{line}'" for line in approved)
    refuse = "barectl_refuse"
    body = [
        "set -f",
        f'{refuse}() {{ echo "{GUARD_REFUSED} $1"; exit 1; }}',
        f'[ "${{DPKG_FRONTEND_LOCKED:-}}" = true ] || {refuse} frontend-lock',
        f'[ "${{APT_HOOK_INFO_FD:-}}" = 0 ] || {refuse} descriptor',
        (
            f'[ "$(sha256sum {DPKG_STATUS} | cut -d\' \' -f1)" = "${{{STATUS_VARIABLE}:-}}" ] '
            f"|| {refuse} dpkg-status"
        ),
        f"IFS= read -r l || {refuse} truncated",
        f'[ "$l" = "VERSION 3" ] || {refuse} version',
        f'while :; do IFS= read -r l || {refuse} truncated; [ -n "$l" ] || break; done',
        "a=",
        (
            "while IFS= read -r l; do IFS=' '; set -- $l; IFS=; "
            f"[ $# -eq 9 ] || {refuse} form; "
            f'[ "$l" = "$1 $2 $3 $4 $5 $6 $7 $8 $9" ] || {refuse} form; '
            f"case \"$2 $3 $4 $5\" in '- - none <'|'- - no <') ;; *) {refuse} transition;; esac; "
            f'case "$8" in none|no|same|foreign|allowed) ;; *) {refuse} form;; esac; '
            'case "$9" in '
            "'**CONFIGURE**') a=\"$a|C $1 $6 $7\";; "
            f'{ARCHIVES}*.deb) a="$a|U $1 $6 $7 ${{9#{ARCHIVES}}}";; '
            f"*) {refuse} action;; esac; done"
        ),
        f'[ -z "$l" ] || {refuse} truncated',
        (
            "[ \"$(printf '%s\\n' \"${a#|}\" | tr '|' '\\n' | LC_ALL=C sort)\" = "
            f"\"$(printf '%s\\n' {expected})\" ] || {refuse} transaction"
        ),
        f'echo "{GUARD_ADMITTED}"',
    ]
    return f"{GUARD_NAME}() {{ {'; '.join(body)}; }}; {GUARD_NAME}"


def _check(pattern: re.Pattern[str], value: str, what: str) -> str:
    if not pattern.fullmatch(value):
        raise ValueError(f"Not a valid {what}.")
    return value


def check_package(value: str) -> str:
    return _check(_PACKAGE, value, "package name")


def valid_digest(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-f]{64}", value))
