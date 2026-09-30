"""Certbot renewal setup's fixed reads, payload and verification read (docs/tls.md).

The renewal state is one fixed root script. Its output is parsed for admission and
verification; its SHA-256, without the parts that change as Certbot runs, is the renewal
digest a plan records and its payload recomputes under the mutation lock.
"""

import re
import shlex
from typing import Final

from bootstrap import native as bootstrap_native
from sites import native as site_native

from . import renewal

_ENV = "export LC_ALL=C PATH=/usr/sbin:/usr/bin"
_DIGEST = re.compile(r"[0-9a-f]{64}")
AUTOMATION: Final = r"certbot|letsencrypt|acme\.sh|lego|dehydrated|getssl|uacme"
PATHS: Final = (
    "/usr",
    "/usr/local",
    "/usr/local/sbin",
    renewal.DEPLOY_HOOK,
    renewal.WRAPPER,
    "/etc/systemd/system",
    renewal.DROP_IN_DIRECTORY,
    renewal.DROP_IN,
    "/etc/letsencrypt",
    "/root/.config/letsencrypt",
    "/var/lib/letsencrypt",
    "/var/log/letsencrypt",
    "/etc/cron.d/certbot",
)
_CRON = (
    "/etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* "
    "/etc/cron.monthly/* /var/spool/cron/crontabs/*"
)


def _state_lines(*, digest: bool) -> list[str]:
    """Each fact on its own line, prefixed by its kind; for the digest, only stable ones."""
    quoted = " ".join(shlex.quote(path) for path in PATHS)
    systemd = "/etc/systemd/system /run/systemd/system"
    lines = [
        _ENV,
        (
            f'for p in {quoted}; do if [ -e "$p" ] || [ -L "$p" ]; then '
            'stat -c \'path %F|%U|%G|%a|%h|%n\' -- "$p"; else echo "absent $p"; fi; done'
        ),
        (
            f"find {systemd} -maxdepth 2 -name 'certbot*' -printf 'unit %y %p %l\\n' "
            "2>/dev/null | sort"
        ),
        (
            "for f in "
            f"{renewal.DEPLOY_HOOK} {renewal.WRAPPER} {renewal.DROP_IN} "
            "/etc/letsencrypt/cli.ini /etc/cron.d/certbot; do "
            '[ -f "$f" ] && echo "sha $(sha256sum <"$f" | cut -d" " -f1) $f" '
            '&& echo "md5 $(md5sum <"$f" | cut -d" " -f1) $f"; done'
        ),
        (
            "find /etc/letsencrypt -mindepth 1 -printf 'letsencrypt %y %m %U %G %p\\n' "
            "2>/dev/null | sort"
        ),
        (
            "find /var/lib/letsencrypt -mindepth 1 -maxdepth 1 -printf 'lib %y %m %U %G %p\\n' "
            "2>/dev/null | sort"
        ),
        (f"grep -lE '{AUTOMATION}' {_CRON} 2>/dev/null | sort | sed 's/^/cron /'"),
        (
            "systemctl list-unit-files --no-legend --plain --type=service,timer 2>/dev/null "
            f"| awk '{{print $1}}' | grep -E '{AUTOMATION}|acme' | sort | sed 's/^/unitfile /'"
        ),
        (
            "command -v snap >/dev/null && snap list 2>/dev/null | awk 'NR > 1 {print $1}' "
            f"| grep -E '{AUTOMATION}' | sed 's/^/snap /'"
        ),
        (
            "dpkg-query -W -f='${Conffiles}\\n' certbot 2>/dev/null "
            "| awk 'NF >= 2 {print \"conffile\", $2, $1}'"
        ),
        (
            "for u in certbot.service certbot.timer; do systemctl show -p LoadState "
            '-p UnitFileState -p FragmentPath -p DropInPaths "$u" | sed "s/^/show $u /"; done'
        ),
        "true",
    ]
    if digest:
        return lines
    return [
        *lines[:-1],
        (
            "for u in certbot.service certbot.timer; do systemctl show -p ActiveState "
            "-p ExecStart -p SuccessExitStatus -p TimeoutStartUSec -p TimeoutStopUSec "
            "-p KillMode -p RandomizedDelayUSec -p Result -p ExecMainStatus "
            "-p ExecMainExitTimestamp -p LastTriggerUSec -p NextElapseUSecRealtime "
            '"$u" | sed "s/^/show $u /"; done'
        ),
        (
            f"for s in {renewal.WRAPPER} {renewal.DEPLOY_HOOK}; do "
            '[ -f "$s" ] && sh -n "$s" && echo "syntax ok $s"; done'
        ),
        "certbot --version 2>/dev/null | sed 's/^/version /'",
        "true",
    ]


def renewal_digest() -> str:
    """docs/tls.md#certbot-renewal-setup: what the payload rechecks, as root."""
    return "{ " + "; ".join(_state_lines(digest=True)) + "; } 2>/dev/null | sha256sum"


def renewal_state() -> list[str]:
    """Every fact admission and verification read, as root."""
    return site_native.script("; ".join(_state_lines(digest=False)))


def renewal_digest_argv() -> list[str]:
    return site_native.script(renewal_digest())


class Exit:
    """docs/tls.md#recovering-a-partial-setup: the setup payload's own boundaries."""

    DRIFT = bootstrap_native.Exit.DRIFT
    RENEWAL_ACTIVE = bootstrap_native.Exit.RENEWAL_ACTIVE
    INHIBITION = 27
    FILES = 28
    OVERRIDE = 29
    TIMER = 30


def _publish(file: renewal.RenewalFile) -> str:
    lines = " ".join(shlex.quote(line) for line in file.content.removesuffix("\n").split("\n"))
    arguments = " ".join(
        shlex.quote(value) for value in (file.directory, file.name, "root:root", file.mode)
    )
    return (
        f"if [ ! -e {file.path} ] && [ ! -L {file.path} ]; then "
        f"printf '%s\\n' {lines} | w {arguments} {file.sha256} || exit {Exit.FILES}; fi"
    )


def _override_check() -> str:
    """The service systemd loads is the packaged one with exactly the reviewed drop-in."""
    show = "systemctl show -p {0} --value certbot.service"
    expected = {
        "LoadState": "loaded",
        "FragmentPath": "/usr/lib/systemd/system/certbot.service",
        "DropInPaths": renewal.DROP_IN,
        "SuccessExitStatus": f"{renewal.Outcome.LOCK_HELD} {renewal.Outcome.APPLY_ACTIVE}",
        "TimeoutStartUSec": "30min",
        "TimeoutStopUSec": "1min",
        "KillMode": "control-group",
    }
    checks = [
        f'[ "$({show.format(key)})" = {shlex.quote(value)} ]' for key, value in expected.items()
    ]
    argv = f"argv[]=/usr/bin/sh {renewal.WRAPPER} ;"
    checks.append(
        f'[ "$({show.format("ExecStart")} | grep -c .)" = 1 ] && '
        f"{show.format('ExecStart')} | grep -qF {shlex.quote(argv)}"
    )
    checks += [f"sh -n {renewal.WRAPPER}", f"sh -n {renewal.DEPLOY_HOOK}"]
    return " && ".join(checks)


def setup_steps(
    unit: str,
    boot_id: str,
    deadline: int,
    *,
    apt: str,
    packages: str,
    scope: str,
    digest: str,
    roots: list[tuple[str, str]],
    actions: list[bootstrap_native.PackageAction],
    check: bootstrap_native.Check,
) -> list[site_native.Step]:
    """docs/tls.md#applying-renewal-setup: each named fragment of the payload, in order."""
    for value in (apt, packages, digest):
        if not _DIGEST.fullmatch(value):
            raise ValueError("Not a valid digest.")
    suffix = unit.removeprefix(bootstrap_native.UNIT_PREFIX).removesuffix(".service")
    units = "certbot.timer certbot.service"
    unmask = f"u(){{ systemctl unmask --runtime {units} >/dev/null 2>&1; }}"
    revalidation = bootstrap_native.package_revalidation(apt, packages, scope)
    steps = [
        site_native.Step(
            "admission", "; ".join(bootstrap_native.admission(unit, boot_id, deadline))
        ),
        site_native.Step(
            "helpers",
            "; ".join(
                (
                    "export PATH=/usr/sbin:/usr/bin; umask 022; set -C",
                    site_native.ANCESTORS,
                    site_native.writer(suffix),
                    unmask,
                )
            ),
        ),
        site_native.Step(
            "revalidation",
            "; ".join(
                (
                    *revalidation,
                    f'[ "$({renewal_digest()} | cut -d" " -f1)" = {digest} ] || exit {Exit.DRIFT}',
                    f"a /usr/local/sbin /etc/systemd/system || exit {Exit.DRIFT}",
                )
            ),
        ),
        site_native.Step(
            "inhibition",
            "; ".join(
                (
                    (
                        f"systemctl mask --runtime {units} >/dev/null 2>&1 "
                        f"|| {{ u; exit {Exit.INHIBITION}; }}"
                    ),
                    # A renewal the timer started before the mask must have ended.
                    *(
                        step.replace(
                            f"exit {Exit.RENEWAL_ACTIVE}", f"{{ u; exit {Exit.RENEWAL_ACTIVE}; }}"
                        )
                        for step in bootstrap_native.renewal_check()
                    ),
                )
            ),
        ),
    ]
    if actions:
        steps.append(
            site_native.Step(
                "installation",
                "; ".join(bootstrap_native.install_steps(roots, actions, refuse="u; ")),
            )
        )
    steps += [
        site_native.Step(
            "files",
            "; ".join(
                (
                    (
                        f"[ -d {renewal.DROP_IN_DIRECTORY} ] || "
                        f"mkdir -m 0755 -- {renewal.DROP_IN_DIRECTORY} || exit {Exit.FILES}"
                    ),
                    *(_publish(file) for file in renewal.files()),
                )
            ),
        ),
        site_native.Step(
            "override",
            "; ".join(
                (
                    f"systemctl daemon-reload || exit {Exit.OVERRIDE}",
                    (
                        "systemctl unmask --runtime certbot.service >/dev/null 2>&1 "
                        f"|| exit {Exit.OVERRIDE}"
                    ),
                    f"{_override_check()} || exit {Exit.OVERRIDE}",
                )
            ),
        ),
        site_native.Step(
            "timer",
            (
                "systemctl unmask --runtime certbot.timer >/dev/null 2>&1 && "
                f"systemctl enable --now certbot.timer || exit {Exit.TIMER}"
            ),
        ),
        site_native.Step(
            "check",
            f"{check.step()}; echo 'barectl-tls: renewal setup verified'; exit 0",
        ),
    ]
    return steps


def setup_payload(unit: str, boot_id: str, deadline: int, **reviewed: object) -> str:
    steps = setup_steps(unit, boot_id, deadline, **reviewed)  # type: ignore[arg-type]
    return "; ".join(step.text for step in steps)
