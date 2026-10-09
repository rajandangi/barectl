"""The WordPress PHP runtime plan's review (docs/wordpress.md#php-runtime).

A runtime plan is a bootstrap package profile for the selected site's PHP branch. Bootstrap
reviews and applies the exact Ubuntu package transaction, and the databases app's driver
mechanics supply the site's native PHP selection, the pools the reload restarts and the
site-digest precondition; this module adds the WordPress baseline's capabilities and the
temporary pool probe that proves the selected CLI and the site's own pool agree.
"""

import dataclasses
import hashlib
import re
import secrets
from dataclasses import dataclass, field
from typing import Final

from bootstrap import native as bootstrap_native
from bootstrap import profiles
from bootstrap.models import (
    ADMISSION_CENTISECONDS,
    Action,
    PackageTransition,
    PlanEffect,
    PlanEvidence,
    PlanRefusal,
)
from databases import drivers
from discovery.ssh import RemoteShell
from sites import native as site_native
from sites.convention import SitePaths
from sites.names import IDENTIFIER

from . import qualification, runtime_native
from .models import RuntimeCapability

Effect = PlanEffect.Kind
Reason = PlanRefusal.Reason
TOKEN: Final = re.compile(r"[0-9a-f]{32}")


@dataclass(frozen=True)
class Capability:
    """A PHP capability the WordPress baseline requires, by the name ``extension_loaded``
    reports, and the package suffix that enables it; empty for the build's own."""

    name: str
    label: str
    package: str


# docs/wordpress-native-design.md#compatibility-and-supply: the capabilities checked in the
# selected CLI and in the site's own pool.
CAPABILITIES: Final = (
    Capability("mysqli", "MySQL database access (mysqli)", "mysql"),
    Capability("json", "JSON", ""),
    Capability("hash", "Hash", ""),
    Capability("fileinfo", "File information (fileinfo)", ""),
    Capability("exif", "Image metadata (exif)", ""),
    Capability("mbstring", "Multibyte strings (mbstring)", "mbstring"),
    Capability("curl", "HTTP requests (cURL)", "curl"),
    Capability("dom", "DOM", "xml"),
    Capability("xml", "XML", "xml"),
    Capability("zip", "ZIP archives", "zip"),
    Capability("gd", "Image processing (GD)", "gd"),
    Capability("intl", "Internationalization (intl)", "intl"),
)


def probe_path(identifier: str, token: str) -> str:
    """The temporary probe, in the root-owned site directory, never the document root."""
    if not TOKEN.fullmatch(token) or not IDENTIFIER.fullmatch(identifier):
        raise ValueError("Not a probe token or site identifier.")
    return f"/var/www/{identifier}/wpprobe-{token}.php"


def render_probe(token: str) -> str:
    """What the site's pool and the selected CLI each print: their identity and, for each
    capability, whether it is loaded."""
    if not TOKEN.fullmatch(token):
        raise ValueError("Not a probe token.")
    names = ",".join(f"'{item.name}'" for item in CAPABILITIES)
    return (
        "<?php\n"
        f"$t='{token}';$o=[];\n"
        f"foreach([{names}] as $m)$o[]=extension_loaded($m)?1:0;\n"
        'echo "barectl-wordpress $t ",posix_geteuid()," ",implode(" ",$o),"\\n";\n'
    )


def expected_probe(token: str, uid: int) -> str:
    """The line both report when every capability is loaded for the site's own user."""
    ones = " ".join("1" for _ in CAPABILITIES)
    return f"barectl-wordpress {token} {uid} {ones}"


def digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


@dataclass(frozen=True)
class CapabilityDraft:
    name: str
    label: str
    package: str
    cli: bool
    fpm: bool
    state: RuntimeCapability.State


@dataclass
class RuntimeDraft(drivers.DriverDraft):
    identifier: str = ""
    token: str = ""
    capabilities: list[CapabilityDraft] = field(default_factory=list)


def prepare(shell: RemoteShell, identifier: str) -> RuntimeDraft:
    """Review the baseline for the selected site's PHP branch without changing anything."""
    reviewed = drivers.prepare(shell, Action.PHP_WORDPRESS, identifier=identifier)
    draft = RuntimeDraft(
        **{item.name: getattr(reviewed, item.name) for item in dataclasses.fields(reviewed)},
        identifier=identifier,
        token=secrets.token_hex(16),
    )
    if draft.php_supply != "ubuntu":
        draft.refuse(
            Reason.UNSUPPORTED_VERSION,
            f"Site {identifier} selects PHP {draft.php_version} from the approved unified PHP "
            "source. The WordPress baseline is reviewed only for Ubuntu's own packages; a "
            "supplier-specific extension profile needs its own reviewed admission and "
            "qualification, so Barectl installs nothing from that source for WordPress.",
        )
    elif (
        draft.release is not None
        and draft.platform is not None
        and not qualification.qualified(
            draft.release.version, draft.platform.architecture, draft.php_version, "ubuntu"
        )
    ):
        draft.refuse(
            Reason.UNSUPPORTED_VERSION,
            qualification.reason(
                draft.release.version, draft.platform.architecture, draft.php_version, "ubuntu"
            ),
        )
    _observe(draft)
    if draft.eligible and draft.transitions and _too_large(draft):
        return draft
    if draft.eligible and draft.transitions:
        _effects(draft)
    return draft


def payload_size(draft: RuntimeDraft) -> int | None:
    """The bytes the run's payload would need, built exactly as applying builds it; ``None``
    when the draft lacks the evidence to build it."""
    platform, release = draft.platform, draft.release
    if platform is None or platform.uptime_centiseconds is None or release is None:
        return None
    digests = {item.kind: item.fingerprint for item in draft.evidence}
    unit = bootstrap_native.new_unit_name()
    deadline = platform.uptime_centiseconds + ADMISSION_CENTISECONDS
    profile = profiles.profile(
        release, Action.PHP_WORDPRESS, version=draft.php_version, supply=draft.php_supply
    )
    paths = SitePaths(draft.identifier, draft.php_version, revision=draft.site_revision)
    try:
        steps = runtime_native.probe_steps(
            unit,
            paths=paths,
            token=draft.token,
            uid=draft.site_uid,
            content=render_probe(draft.token),
        )
        payload = bootstrap_native.package_change(
            unit,
            platform.boot_id,
            deadline,
            apt=digests.get(PlanEvidence.Kind.APT_REVALIDATION, "0" * 64),
            packages=digests.get(PlanEvidence.Kind.PACKAGE_REVALIDATION, "0" * 64),
            scope=profile.revalidation,
            roots=[(root.name, root.version) for root in draft.roots if not root.installed],
            actions=[
                bootstrap_native.PackageAction(
                    item.step == PackageTransition.Step.INSTALL,
                    item.package,
                    item.version,
                    item.architecture,
                )
                for item in draft.transitions
            ],
            services=profile.units,
            enable=False,
            start=False,
            check=profile.check,
            reload=profile.reload,
            sockets=(
                *((profile.socket,) if profile.socket else ()),
                *(pool.socket for pool in draft.pools if not pool.default),
            ),
            preconditions=(
                (
                    site_native.site_digest(paths),
                    digests.get(PlanEvidence.Kind.SITE_REVALIDATION, "0" * 64),
                ),
            ),
            after=steps,
        )
    except ValueError:
        return None
    return len(payload.encode())


def _too_large(draft: RuntimeDraft) -> bool:
    """Refuse a review whose payload cannot be submitted in one run, rather than split it."""
    size = payload_size(draft)
    if size is None:
        draft.refuse(Reason.INCOMPLETE, "Barectl could not build the reviewed payload.")
        return True
    if size <= bootstrap_native.MAX_PAYLOAD:
        return False
    draft.refuse(
        Reason.PAYLOAD_TOO_LARGE,
        f"Applying this plan would need {size} bytes, more than the "
        f"{bootstrap_native.MAX_PAYLOAD} bytes Barectl submits in one run: the missing "
        "dependencies are too many to review as one transaction. Install some baseline "
        "packages through ordinary administration, then prepare again.",
    )
    return True


def _observe(draft: RuntimeDraft) -> None:
    """Each capability as the CLI and PHP-FPM list it, and which package enables it."""
    if draft.fpm_modules is None or draft.cli_modules is None or draft.release is None:
        return
    installed = {root.name for root in draft.roots if root.installed}
    prefix = f"php{draft.php_version}-"
    for item in CAPABILITIES:
        package = f"{prefix}{item.package}" if item.package else ""
        cli = item.name in draft.cli_modules
        fpm = item.name in draft.fpm_modules
        if package and package not in installed:
            state = RuntimeCapability.State.PLANNED
        elif cli and fpm:
            state = RuntimeCapability.State.ENABLED
        else:
            state = RuntimeCapability.State.UNAVAILABLE
        draft.capabilities.append(CapabilityDraft(item.name, item.label, package, cli, fpm, state))


def _effects(draft: RuntimeDraft) -> None:
    unit = f"php{draft.php_version}-fpm.service"
    path = probe_path(draft.identifier, draft.token)
    missing = ", ".join(root.name for root in draft.roots if not root.installed)
    draft.effects.append(
        (
            Effect.WORDPRESS_RUNTIME,
            (
                f"Installs {missing} for the PHP {draft.php_version} branch that site "
                f"{draft.identifier} selects, so the CLI and every pool of the branch can load "
                "them. Packages already installed are not touched. No other PHP branch and no "
                "other package is changed, and the reload restarts only "
                f"{unit}. After the reload, as root, Barectl briefly publishes the probe {path} "
                f"(root:s{draft.identifier} 0640, outside the document root, never served by "
                f"Nginx), asks site {draft.identifier}'s own pool through its FastCGI socket and "
                f"the selected CLI /usr/bin/php{draft.php_version}, run as the site user, which "
                "capabilities they load, requires both to report every baseline capability, "
                "and removes the probe. This plan installs no WP-CLI, WordPress, database or "
                "certificate."
            ),
        )
    )
    draft.postconditions.append(
        f"The selected CLI and site {draft.identifier}'s own pool both report every "
        "baseline capability."
    )
