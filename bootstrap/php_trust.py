"""Native signing, expiry and effective PHP-source admission (ADR 0016)."""

import hashlib
import re
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime

from discovery.ssh import RemoteShell

from . import inspection, native, php_source, php_supply, review
from .evidence import (
    AptEvidence,
    PackageState,
    PhpSourceEvidence,
    parse_offers,
    parse_package_states,
)
from .models import Action, PlanRefusal, Privilege
from .releases import Release
from .review import Draft


def release_file(release: Release) -> str:
    return f"/var/lib/apt/lists/packages.sury.org_php_dists_{release.codename}_InRelease"


def index_authentication(
    release: Release, *, path: str | None = None, key: str = php_supply.KEY_FILE
) -> str:
    return _index_authentication(path or release_file(release), key=key)


def _index_authentication(path: str, *, key: str = php_supply.KEY_FILE) -> str:
    return (
        'printf "CLOCK|%s\\n" "$(date -u +%s)"; '
        f"{{ {_verified_content(path, key=key)} "
        "|| printf 'UNVERIFIED\\n'; } | "
        "grep -E '^(UNVERIFIED|\\[GNUPG:\\]|"
        "(Origin|Suite|Codename|Date|Valid-Until|Architectures|Components):)'"
    )


def _verified_content(path: str, *, key: str = php_supply.KEY_FILE) -> str:
    return f"gpgv --status-fd 1 --output - --keyring {key} {path}"


def policies() -> str:
    return "LC_ALL=C apt-cache policy " + " ".join(php_supply.allowed_packages())


UNAUTHENTICATED = (
    "The PHP index lacks a current approved-primary-key signature or its own "
    "release and architecture."
)


def signature_refusal(text: str, release: Release, architecture: str) -> str | None:
    lines = text.splitlines()
    now = next((line.removeprefix("CLOCK|") for line in lines if line.startswith("CLOCK|")), "")
    signed = [line.split() for line in lines if line.startswith("[GNUPG:] VALIDSIG ")]
    if not now.isdecimal() or len(signed) != 1 or "UNVERIFIED" in lines:
        return UNAUTHENTICATED
    if signed[0][-1] != php_supply.PRIMARY_FINGERPRINT:
        return UNAUTHENTICATED
    if any(
        re.search(r"\[GNUPG:\] (EXPKEYSIG|REVKEYSIG|BADSIG|ERRSIG|EXPSIG|KEYEXPIRED) ", line)
        for line in lines
    ):
        return UNAUTHENTICATED
    entries = [
        line.split(": ", 1)
        for line in lines
        if not line.startswith(("CLOCK|", "[GNUPG:]")) and ": " in line
    ]
    fields = dict(entries)
    if len(fields) != len(entries):
        return UNAUTHENTICATED
    if any(
        fields.get(name) != value
        for name, value in (
            ("Origin", "deb.sury.org"),
            ("Suite", release.codename),
            ("Codename", release.codename),
            ("Components", "main"),
        )
    ):
        return UNAUTHENTICATED
    if architecture not in fields.get("Architectures", "").split():
        return UNAUTHENTICATED
    try:
        published = parsedate_to_datetime(fields["Date"])
        current = datetime.fromtimestamp(int(now), UTC)
        expires = (
            parsedate_to_datetime(fields["Valid-Until"])
            if "Valid-Until" in fields
            else published + timedelta(days=7)
        )
    except KeyError, ValueError, OverflowError:
        return UNAUTHENTICATED
    if published.tzinfo is None or expires.tzinfo is None or current < published:
        return UNAUTHENTICATED
    limit = min(expires, published + timedelta(days=7))
    if current >= limit:
        return (
            f"The approved PHP source's signed metadata was published "
            f"{published.astimezone(UTC):%Y-%m-%d %H:%M} UTC and stopped being current "
            f"{limit.astimezone(UTC):%Y-%m-%d %H:%M} UTC. Prepare a metadata refresh. If the "
            "refresh reports its Release file as expired, the publisher has not published "
            "newer metadata yet: wait until it does, refresh again, then prepare a new plan."
        )
    return None


def _priorities(text: str, release: Release) -> bool:
    version_priority = ""
    seen: set[str] = set()
    package = ""
    for line in text.splitlines():
        stripped = line.strip()
        if not line.startswith(" ") and stripped.endswith(":"):
            package = stripped[:-1]
        elif re.fullmatch(r"(?:\*\*\* )?[A-Za-z0-9.+~:-]+ -?[0-9]+", stripped):
            version_priority = stripped.split()[-1]
        elif php_supply.SOURCE_URL.rstrip("/") in stripped:
            if version_priority != "700" or not re.fullmatch(
                rf"-1 https://packages\.sury\.org/php {release.codename}/main "
                r"(amd64|arm64|all) Packages",
                stripped,
            ):
                return False
            seen.add(package)
    return "php-common" in seen


def collect(
    shell: RemoteShell, release: Release, architecture: str, privilege: str, *, indexes: bool = True
) -> PhpSourceEvidence:
    draft = Draft(Action.PHP_SOURCE, "Inspect the approved native PHP supply.", None, release)
    state = php_source._read(shell, php_source.STATE, privilege)
    if state is None:
        return PhpSourceEvidence(False, ("The dedicated PHP source setup could not be read.",))
    missing = php_source._resources(draft, state, release, architecture)
    if missing:
        draft.refuse(
            PlanRefusal.Reason.PREREQUISITE, "The dedicated PHP source setup is incomplete."
        )
    if not draft.eligible:
        return PhpSourceEvidence(False, tuple(text for _, text in draft.refusals))
    keys = php_source._read(shell, php_source.KEY_STATE, privilege)
    environment = php_source._read(shell, php_source.ENVIRONMENT, privilege)
    signatures = (
        php_source._read(shell, index_authentication(release), privilege) if indexes else ""
    )
    policy = shell.run(policies()) if indexes else None
    if (
        keys is None
        or environment is None
        or signatures is None
        or (policy is not None and (policy.exit_status or policy.truncated))
    ):
        return PhpSourceEvidence(
            False, ("PHP-source authentication or effective selection could not be read.",)
        )
    php_source._trust(draft, keys)
    if environment.strip():
        draft.refuse(
            PlanRefusal.Reason.PACKAGE_SOURCE,
            "Other PHP sources or preference policies interfere with the selected supply.",
        )
    if indexes and (refusal := signature_refusal(signatures, release, architecture)):
        draft.refuse(PlanRefusal.Reason.PACKAGE_SOURCE, refusal)
    if policy is not None and not _priorities(policy.stdout, release):
        draft.refuse(
            PlanRefusal.Reason.PACKAGE_SOURCE,
            "Effective priorities must be 700 for exact PHP names and -1 for other "
            "source packages.",
        )
    normalized = (
        state
        + keys.partition("\n")[2]
        + (policy.stdout if policy is not None else "")
        + signatures.partition("\n")[2]
    )
    return PhpSourceEvidence(
        draft.eligible,
        tuple(text for _, text in draft.refusals),
        hashlib.sha256(normalized.encode()).hexdigest(),
    )


def observed_supply(shell: RemoteShell, release: Release, architecture: str) -> str | None:
    root = shell.run(native.USER_ID)
    if root.exit_status or root.truncated:
        return None
    privilege = Privilege.ROOT if root.stdout.strip() == "0" else Privilege.SUDO
    state = php_source._read(shell, php_source.STATE, privilege)
    if state is None:
        return None
    supply = (
        "ubuntu"
        if all(path + "|absent" in state.splitlines() for path in php_source.FILES)
        else "sury"
    )
    if supply == "sury" and not collect(shell, release, architecture, privilege).admitted:
        return None
    reader = inspection.Reader(shell)
    apt = inspection._apt(reader)
    states = reader.parse(
        reader.read(php_source.PHP_STATES, "the installed PHP supply", ok=(0, 1)),
        parse_package_states,
    )
    if apt is None or states is None or apt.changed_while_read:
        return None
    installed = tuple(state for state in states if not state.absent)
    if not installed or not _supply_states(installed, release, architecture, supply):
        return None
    draft = Draft(Action.PHP, "Inspect the installed PHP supply.", None, release)
    draft.php_source_admitted = supply == "sury"
    review._check_apt(draft, release, apt, package_plan=True)
    return (
        supply
        if draft.eligible and _supply_offers(reader, apt, installed, release, architecture, supply)
        else None
    )


def _supply_states(
    states: tuple[PackageState, ...], release: Release, architecture: str, supply: str
) -> bool:
    return all(
        state.installed
        and state.architecture in {architecture, "all"}
        and (
            state.name in php_supply.allowed_packages()
            if supply == "sury"
            else state.name.startswith(f"php{release.php}-") or state.name == "php-common"
        )
        for state in states
    )


def _supply_offers(
    reader: inspection.Reader,
    apt: AptEvidence,
    states: tuple[PackageState, ...],
    release: Release,
    architecture: str,
    supply: str,
) -> bool:
    offered = reader.parse(
        reader.read(inspection.offers(state.name for state in states), "the PHP supply's offers"),
        parse_offers,
    )
    if offered is None:
        return False
    targets = {(t.site, t.release, t.component, t.architecture): t for t in apt.targets}
    exact: set[tuple[str, str]] = set()
    for offer in offered:
        target = targets.get((offer.site, offer.release, offer.component, offer.architecture))
        if target is None or not target.trusted or target.architecture not in {architecture, "all"}:
            return False
        owned = (
            release.owns(target)
            if supply == "ubuntu"
            else (
                target.site == php_supply.SOURCE_URL.rstrip("/")
                and target.origin == "deb.sury.org"
                and target.suite == target.codename == target.release == release.codename
                and target.component == "main"
            )
        )
        if owned:
            exact.add((offer.package, offer.version))
        elif (
            supply == "ubuntu"
            or not release.owns(target)
            or any(s.name == offer.package and s.version == offer.version for s in states)
        ):
            return False
    return all((state.name, state.version) in exact for state in states)


def revalidation(release: Release, *, indexes: bool = True) -> str:
    if not indexes:
        return (
            f"{{ {php_source.STATE}; {{ {php_source.KEY_STATE}; }} | sed '/^CLOCK|/d'; "
            "} 2>/dev/null | sha256sum"
        )
    return "{ " + _index_revalidation(release_file(release)) + "; } 2>/dev/null | sha256sum"


def _index_revalidation(path: str) -> str:
    age = (
        "n=$(date -u +%s); "
        'd=$(printf "%s\\n" "$a" | grep "^Date: " | cut -d" " -f2-); '
        'p=$(date -u -d "$d" +%s) || echo expired; '
        '[ "$n" -ge "$p" ] && [ "$n" -lt "$((p + 604800))" ] || echo expired; '
        'd=$(printf "%s\\n" "$a" | grep "^Valid-Until: " | cut -d" " -f2-); '
        'if [ -n "$d" ]; then p=$(date -u -d "$d" +%s) || echo expired; '
        '[ "$n" -lt "$p" ] || echo expired; fi'
    )
    return (
        f"{php_source.STATE}; {{ {php_source.KEY_STATE}; }} | sed '/^CLOCK|/d'; "
        f"{policies()}; a=$({_index_authentication(path)}); "
        'printf "%s\\n" "$a" | sed "/^CLOCK|/d"; '
        f"{age}"
    )


def conditional_revalidation() -> str:
    """Native site fence: Ubuntu needs no GnuPG, configured source needs complete live trust."""
    temporal = (
        "n=$(date -u +%s); for f in Date Valid-Until; do "
        'd=$(printf "%s\\n" "$o" | sed -n "s/^$f: //p"); '
        '[ -n "$d" ] || continue; t=$(date -u -d "$d" +%s) || echo expired; '
        'if [ "$f" = Date ]; then [ "$n" -ge "$t" ] || echo expired; '
        't=$((t+604800)); fi; [ "$n" -lt "$t" ] || echo expired; done'
    )
    verify = _verified_content('"$i"', key='"$k"')
    return (
        f"{{ LC_ALL=C apt-config dump; {inspection.APT_FILES} | sort; "
        "sha256sum /etc/os-release /var/lib/apt/lists/*_InRelease; "
        "stat -c '%n %F %u %g %a %h' /etc/apt /etc/apt/* /etc/apt/*/sury-php*; "
        "a=/etc/apt; k=$a/keyrings/sury-php.gpg; s=$a/sources.list.d/sury-php.sources; "
        "p=$a/preferences.d/sury-php; for x in $k $s $p; do "
        '[ -e "$x" ] || [ -L "$x" ] || continue; '
        "v=$(sed -n 's/^VERSION_ID=//p' /etc/os-release | tr -d '\"'); "
        'case "$v" in 24.04)c=noble;;26.04)c=resolute;;*) echo unsupported;break;;esac; '
        "i=/var/lib/apt/lists/packages.sury.org_php_dists_${c}_InRelease; "
        f"o=$({verify}) || echo invalid; "
        'printf "%s\\n" "$o" | sha256sum; ' + temporal + "; break; done; } 2>/dev/null | sha256sum"
    )
