"""Reviewed native source publication; docs/adr/0016-limit-third-party-php-supply.md."""

import hashlib
import re
import shlex
from dataclasses import dataclass

from discovery.ssh import RemoteShell
from operations.lifecycle import OperationRefused

from . import inspection, native, php_supply, releases
from .models import (
    Action,
    ApplyRun,
    ConfigurationPlan,
    PlanEffect,
    PlanEvidence,
    PlanRefusal,
    Privilege,
    Verification,
)
from .review import Draft, EvidenceDraft, check_platform

INTENT = "Set up the approved unified PHP source without refreshing metadata or installing PHP."
DIRECTORIES = (
    "/etc",
    "/etc/apt",
    "/etc/apt/keyrings",
    "/etc/apt/sources.list.d",
    "/etc/apt/preferences.d",
)
FILES = (php_supply.KEY_FILE, php_supply.PREFERENCE_FILE, php_supply.SOURCE_FILE)
PHP_STATES = inspection.release_states("php*")
TOOLS = (
    "test -x /usr/lib/apt/apt-helper && test -x /usr/bin/gpg && "
    "test -r /etc/ssl/certs/ca-certificates.crt && test -s /etc/ssl/certs/ca-certificates.crt && "
    "[ \"$(dpkg-query -W -f='${Status}' ca-certificates 2>/dev/null)\" = 'install ok installed' ]"
)

# Exact supported layout; arbitrary preference policies need a separate admission review.
ENVIRONMENT = (
    "for p in /etc/apt/preferences /etc/apt/preferences.d/*; do "
    '[ -e "$p" ] || continue; '
    f'[ "$p" = {php_supply.PREFERENCE_FILE} ] && continue; '
    'h=$(sha256sum -- "$p" | cut -d" " -f1); '
    'case "$p:$h" in '
    "/etc/apt/preferences.d/ubuntu-pro-esm-apps:"
    "9bd3a762177751e58cefe1f96e6fde8b7342e1fa75e642074a674f3ad2c4677b|"
    "/etc/apt/preferences.d/ubuntu-pro-esm-infra:"
    "29da6877bf63ff235fa7e42efd8d24c665e19daea69898bb854bb05062bc93c9) continue;; esac; "
    "grep -qE '^[[:space:]]*[^#[:space:]]' \"$p\" && printf '%s\\n' \"$p\"; done; "
    "find /etc/apt/sources.list.d -maxdepth 1 -type f "
    f"! -path {php_supply.SOURCE_FILE} "
    "-exec grep -lEi 'packages[.]sury[.]org|ondrej/php' {} +; "
    "if [ -f /etc/apt/sources.list ]; then "
    "grep -lEi 'packages[.]sury[.]org|ondrej/php' /etc/apt/sources.list; fi; "
    "apt-config shell target APT::Default-Release"
)

KEY_STATE = (
    'printf "CLOCK|%s\\n" "$(date -u +%s)"; '
    f"for k in {php_supply.KEY_FILE} /etc/apt/trusted.gpg /etc/apt/trusted.gpg.d/*.gpg "
    "/etc/apt/trusted.gpg.d/*.asc; do "
    '[ -e "$k" ] || continue; printf "KEY|%s\\n" "$k"; '
    "/usr/bin/gpg --batch --no-options --homedir /etc/apt --no-keyring "
    '--trust-model always --no-auto-check-trustdb --with-colons --show-keys "$k" '
    "|| exit 1; done"
)


def resource_state() -> str:
    paths = shlex.join((*DIRECTORIES, *FILES))
    return (
        f"for p in {paths}; do "
        'if [ -e "$p" ] || [ -L "$p" ]; then '
        "stat -c '%n|%F|%u|%g|%a|%h' -- \"$p\" || exit 1; "
        '[ ! -L "$p" ] || exit 1; '
        'if [ -f "$p" ]; then sha256sum -- "$p" || exit 1; fi; '
        "else printf '%s|absent\\n' \"$p\"; fi; done"
    )


STATE = resource_state()
REVALIDATION = (
    f"{{ {STATE}; {PHP_STATES} 2>/dev/null; {ENVIRONMENT}; "
    f"{{ {KEY_STATE}; }} | sed '/^CLOCK|/d'; }} | sha256sum"
)


@dataclass
class SourceDraft(Draft):
    missing: tuple[str, ...] = ()


def _read(shell: RemoteShell, command: str, privilege: str) -> str | None:
    argv = ["/usr/bin/sh", "-c", command]
    if privilege == Privilege.ROOT:
        result = shell.run(command)
    else:
        allowed = shell.run(shlex.join(["sudo", "-n", "-l", *argv]))
        if allowed.exit_status or allowed.truncated:
            return None
        result = shell.run(native.privileged(argv, root=False))
    return None if result.exit_status or result.truncated else result.stdout


def _hash(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()


def expected(release: releases.Release, architecture: str) -> dict[str, str]:
    return {
        php_supply.KEY_FILE: php_supply.KEY_SHA256,
        php_supply.PREFERENCE_FILE: _hash(php_supply.preference_content(release)),
        php_supply.SOURCE_FILE: _hash(php_supply.source_content(release, architecture)),
    }


def _resources(draft: Draft, state: str, release: releases.Release, architecture: str) -> list[str]:
    lines = state.splitlines()
    wanted = expected(release, architecture)
    missing: list[str] = []
    for directory in DIRECTORIES:
        rows = [line for line in lines if line.startswith(directory + "|")]
        if rows == [directory + "|absent"] and directory in {
            "/etc/apt/keyrings",
            "/etc/apt/preferences.d",
        }:
            continue
        if len(rows) != 1 or not re.fullmatch(
            re.escape(directory) + r"\|directory\|0\|0\|7[05][05]\|[0-9]+", rows[0]
        ):
            draft.refuse(
                PlanRefusal.Reason.CUSTOMIZED,
                f"{directory} must be root-owned without group or other write permission.",
            )
    for path, digest in wanted.items():
        if path + "|absent" in lines:
            missing.append(path)
            continue
        normal = f"{path}|regular file|0|0|644|1" in lines
        if not normal or f"{digest}  {path}" not in lines:
            draft.refuse(
                PlanRefusal.Reason.NOT_FOLLOWING,
                f"{path} differs from the approved PHP-source convention; "
                "it will not be overwritten.",
            )
    return missing


def _primary(draft: Draft, current: str, fingerprint: str) -> None:
    if current == php_supply.KEY_FILE and fingerprint != php_supply.PRIMARY_FINGERPRINT:
        draft.refuse(
            PlanRefusal.Reason.PACKAGE_SOURCE,
            "The dedicated keyring contains another primary signing key.",
        )
    if current != php_supply.KEY_FILE and fingerprint == php_supply.PRIMARY_FINGERPRINT:
        draft.refuse(
            PlanRefusal.Reason.PACKAGE_SOURCE,
            f"{current} contains the PHP publisher in global APT trust.",
        )


def _trust(draft: Draft, evidence: str | None) -> None:
    if evidence is None:
        draft.refuse(
            PlanRefusal.Reason.INCOMPLETE,
            "Dedicated and global signing keys could not be inspected.",
        )
        return
    current = ""
    primary = False
    now = 0
    for line in evidence.splitlines():
        if line.startswith("CLOCK|"):
            value = line.removeprefix("CLOCK|")
            if not value.isdecimal():
                draft.refuse(PlanRefusal.Reason.INCOMPLETE, "The server clock was not reported.")
                return
            now = int(value)
        elif line.startswith("KEY|"):
            current = line.removeprefix("KEY|")
        elif line.startswith("pub:"):
            fields = line.split(":")
            primary = True
            if current == php_supply.KEY_FILE and (
                len(fields) < 7
                or fields[1] in {"r", "e", "i"}
                or (fields[6] and (not fields[6].isdecimal() or int(fields[6]) <= now))
            ):
                draft.refuse(
                    PlanRefusal.Reason.PACKAGE_SOURCE,
                    "The dedicated PHP signing key is invalid, expired or revoked.",
                )
        elif line.startswith("fpr:") and primary:
            fingerprint = line.split(":")[9]
            primary = False
            _primary(draft, current, fingerprint)
    if not now:
        draft.refuse(PlanRefusal.Reason.INCOMPLETE, "The server clock was not reported.")


def inspect(shell: RemoteShell) -> SourceDraft:
    reader = inspection.Reader(shell)
    platform = inspection.read_platform(reader)
    release = releases.of(platform.os) if platform else None
    draft = SourceDraft(Action.PHP_SOURCE, INTENT, platform, release)
    check_platform(draft, platform)
    for gap in reader.gaps:
        draft.refuse(PlanRefusal.Reason.INCOMPLETE, gap)
    if (
        platform is None
        or release is None
        or platform.privilege == Privilege.UNAVAILABLE
        or platform.architecture not in releases.ARCHITECTURES
    ):
        return draft
    before = _read(shell, REVALIDATION, platform.privilege)
    state = _read(shell, STATE, platform.privilege)
    packages = shell.run(PHP_STATES)
    apt = _read(shell, native.APT_DIGEST, platform.privilege)
    tools = _read(shell, TOOLS, platform.privilege)
    environment = _read(shell, ENVIRONMENT, platform.privilege)
    _trust(draft, _read(shell, KEY_STATE, platform.privilege))
    if environment is None:
        draft.refuse(
            PlanRefusal.Reason.INCOMPLETE,
            "The competing source and preference configuration could not be read.",
        )
    elif environment.strip():
        draft.refuse(
            PlanRefusal.Reason.APT_CONFIGURATION,
            "Competing PHP sources, preference files or APT target-release settings need "
            "ordinary administration before source setup: " + environment.strip()[:300],
        )
    if (
        before is None
        or state is None
        or apt is None
        or packages.truncated
        or packages.exit_status not in {0, 1}
    ):
        draft.refuse(
            PlanRefusal.Reason.INCOMPLETE,
            "The source resources or current PHP package evidence could not be read.",
        )
        return draft
    if tools is None:
        draft.refuse(
            PlanRefusal.Reason.PREREQUISITE,
            "Native apt-helper, gpg and the installed distribution ca-certificates trust "
            "bundle are required. Install missing distribution prerequisites through "
            "ordinary administration first.",
        )
    installed = [
        line.split("\t")[0] for line in packages.stdout.splitlines() if not line.endswith("\tun ")
    ]
    if installed:
        draft.refuse(
            PlanRefusal.Reason.INSTALLED_PACKAGE_CHANGE,
            "Existing PHP package state requires a separately reviewed supplier migration: "
            + ", ".join(installed[:5])
            + ".",
        )
    missing = _resources(draft, state, release, platform.architecture)
    if _read(shell, REVALIDATION, platform.privilege) != before:
        draft.refuse(
            PlanRefusal.Reason.INCOMPLETE, "Source resources or PHP state changed during review."
        )
    draft.missing = tuple(missing)
    draft.evidence.extend(
        (
            EvidenceDraft(
                PlanEvidence.Kind.APT_REVALIDATION,
                apt.split()[0],
                "APT configuration, sources, keys and preferences are rechecked "
                "under the native lock.",
            ),
            EvidenceDraft(
                PlanEvidence.Kind.PACKAGE_REVALIDATION,
                before.split()[0],
                "Native source resources and current PHP state are rechecked "
                "under the native lock.",
            ),
        )
    )
    draft.effects.append(
        (
            PlanEffect.Kind.THIRD_PARTY_SOURCES,
            (
                f"Trust {php_supply.SOURCE_URL}, suite {release.codename}, main, "
                f"architecture {platform.architecture}; primary signing fingerprint "
                f"{php_supply.PRIMARY_FINGERPRINT}. Publisher package code can run as root."
            ),
        )
    )
    draft.effects.extend(
        (PlanEffect.Kind.SITE_FILES, f"Create only missing native resource {path}.")
        for path in missing
    )
    draft.effects.append(
        (
            PlanEffect.Kind.INVALIDATES_PLANS,
            (
                "Prepare an explicit metadata refresh after setup. Source setup does not refresh "
                "indexes or install any package."
            ),
        )
    )
    if not missing:
        draft.effects.append(
            (
                PlanEffect.Kind.NO_CHANGES,
                "The native key, source and preferences already match the approved convention.",
            )
        )
    draft.postconditions.extend(
        (
            "Every dedicated source resource matches its reviewed bytes and root ownership.",
            "The package database is unchanged.",
        )
    )
    return draft


def payload(run: ApplyRun, plan: ConfigurationPlan) -> str:
    release = releases.RELEASES.get(run.release)
    if release is None:
        raise OperationRefused("The reviewed PHP source release is unavailable.")
    apt = (
        plan.evidence.filter(kind=PlanEvidence.Kind.APT_REVALIDATION)
        .values_list("fingerprint", flat=True)
        .first()
    )
    state = (
        plan.evidence.filter(kind=PlanEvidence.Kind.PACKAGE_REVALIDATION)
        .values_list("fingerprint", flat=True)
        .first()
    )
    if (
        not apt
        or not state
        or not re.fullmatch(r"[0-9a-f]{64}", apt)
        or not re.fullmatch(r"[0-9a-f]{64}", state)
    ):
        raise OperationRefused("The reviewed PHP source evidence is unavailable.")
    wanted = expected(release, plan.architecture)
    steps = [
        *native.admission(run.unit_name, run.boot_id, run.admission_deadline_centiseconds),
        f'[ "$({native.APT_DIGEST} | cut -d" " -f1)" = {apt} ] || exit 15',
        f'[ "$({REVALIDATION} | cut -d" " -f1)" = {state} ] || exit 15',
        "umask 022",
        "mkdir -p -m 0755 /etc/apt/keyrings /etc/apt/preferences.d || exit 20",
        "t=$(mktemp -d /etc/apt/keyrings/.php-source.XXXXXXXX) || exit 20",
        "trap 'rm -rf -- \"$t\"' EXIT",
        "trap 'exit 20' HUP INT TERM",
        (
            "/usr/lib/apt/apt-helper -o APT::Sandbox::User=root download-file "
            f'{php_supply.SOURCE_URL}apt.gpg "$t/key" SHA256:{php_supply.KEY_SHA256} '
            "|| exit 20"
        ),
        (
            'g=$(/usr/bin/gpg --batch --no-options --homedir "$t" --with-colons '
            '--show-keys "$t/key") || exit 20'
        ),
        "n=$(printf '%s\\n' \"$g\" | grep -c '^pub:')",
        '[ "$n" = 1 ] || exit 20',
        "f=$(printf '%s\\n' \"$g\" | awk -F: '$1==\"fpr\" {print $10;exit}')",
        f'[ "$f" = {php_supply.PRIMARY_FINGERPRINT} ] || exit 20',
        (
            'printf \'%s\\n\' "$g" | awk -F: \'$1=="pub" && ($2=="r" || $2=="e" || '
            '($7!="" && $7+0<=systime())) {exit 1}\' || exit 20'
        ),
    ]
    contents = {
        php_supply.PREFERENCE_FILE: php_supply.preference_content(release),
        php_supply.SOURCE_FILE: php_supply.source_content(release, plan.architecture),
    }
    for path, digest in wanted.items():
        stage = '"$t/key"' if path == php_supply.KEY_FILE else '"$t/' + path.rsplit("/", 1)[1] + '"'
        if path in contents:
            steps.append(f"printf '%s' {shlex.quote(contents[path])} > {stage} || exit 20")
        steps.extend(
            (
                f"chmod 0644 {stage} || exit 20",
                f"if [ ! -e {path} ] && [ ! -L {path} ]; then ln -- {stage} {path} || exit 20; fi",
                f"[ \"$(sha256sum {path} | cut -d' ' -f1)\" = {digest} ] || exit 24",
            )
        )
    steps.append("exit 0")
    return "; ".join(steps)


def verify(shell: RemoteShell, run: ApplyRun) -> Verification:
    release = releases.RELEASES.get(run.release)
    architecture = shell.run(inspection.ARCHITECTURE)
    before = ApplyRun.objects.values_list("dpkg_status_before", flat=True).get(pk=run.pk)
    after = shell.run(native.DPKG_STATUS_DIGEST)
    if (
        release is None
        or architecture.exit_status
        or architecture.truncated
        or after.exit_status
        or after.truncated
    ):
        return Verification.UNAVAILABLE
    wanted = expected(release, architecture.stdout.strip())
    privilege = (
        Privilege.ROOT if shell.run(inspection.USER_ID).stdout.strip() == "0" else Privilege.SUDO
    )
    state = _read(shell, STATE, privilege)
    if state is None:
        return Verification.UNAVAILABLE
    lines = state.splitlines()
    correct = all(
        f"{path}|regular file|0|0|644|1" in lines and f"{digest}  {path}" in lines
        for path, digest in wanted.items()
    )
    return (
        Verification.PASSED
        if correct and before == after.stdout.split()[0]
        else Verification.FAILED
    )
