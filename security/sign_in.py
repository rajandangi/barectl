"""Reviewed key-only SSH sign-in through the shared access-change window (#308)."""

import hashlib
import importlib.resources
import re
from dataclasses import dataclass
from typing import Final

from bootstrap.standing import Standing
from databases.packages import valid_digest
from discovery.root_read import run_root
from discovery.ssh import RemoteShell
from operations import revert
from operations.consent import DeclaredEffect, Scope
from operations.engine import BodyContext, ChangeKind, NativeBody, ReviewDraft
from operations.inputs import PreparationInputs
from operations.models import ChangeReview

from . import observation

SLUG: Final = "require_key_sign_in"
LABEL: Final = "Require key sign-in"
PATH: Final = "/etc/ssh/sshd_config.d/00-barectl-sign-in.conf"
SITES_READ: Final = (
    "find /etc/caddy/sites -maxdepth 1 -type f -name '*.caddy' -printf '%f\\n' "
    "| sed 's/\\.caddy$//' | LC_ALL=C sort"
)
STAGES: Final = ("preflight", "preimage", "apply", "verify")
PRESTATE_COMMAND: Final = (
    "{ sha256sum /etc/ssh/sshd_config 2>/dev/null || true; "
    "find /etc/ssh/sshd_config.d -maxdepth 1 \\( -type f -o -type l \\) -name '*.conf' -print0 "
    "| sort -z | xargs -0 -r sha256sum; "
    "getent passwd; sshd -T; } | sha256sum | cut -d' ' -f1"
)
_RELOAD: Final = (
    "sshd -t || exit 1; "
    'if [ "$(systemctl is-active ssh.service 2>/dev/null || true)" = active ]; then '
    "systemctl reload ssh.service || exit 1; fi"
)
BODY_BYTES: Final = (
    importlib.resources.files("security.bodies")
    .joinpath("sign_in.sh")
    .read_text()
    .replace("# SIGN_IN_PRESTATE", f"sign_in_prestate() {{ {PRESTATE_COMMAND}; }}")
    .replace("# SIGN_IN_SAVE", revert.save_steps((PATH,), _RELOAD, capture_ufw=False))
    .replace("# SIGN_IN_ARM", revert.arm_step())
    .rstrip("\n")
    .encode()
)
BODY_SHA256: Final = hashlib.sha256(BODY_BYTES).hexdigest()
_VERIFY_UNIT: Final = "barectl-apply-" + "0" * 32 + ".service"
_ACCOUNT = re.compile(r"[a-z_][a-z0-9_-]*[$]?")
_ADDRESS = re.compile(r"[0-9a-fA-F:.]+")


@dataclass(frozen=True)
class SignInEvidence:
    ssh: observation.SshState | None
    standing: str
    boot_id: str
    uptime_centiseconds: int | None
    precondition_digest: str
    user: str
    privileged: bool
    client_address: str
    local_address: str
    local_port: str
    sites: tuple[str, ...]
    ssh_warning: str = ""


def inspect(shell: RemoteShell, inputs: PreparationInputs) -> SignInEvidence:
    from discovery.observations import collect

    collected = collect(shell)
    security = collected.security.value if collected.security.observed else None
    check = security.ssh if security is not None else None
    state = check.value if check is not None and check.observed and not check.warning else None
    prestate = run_root(shell, PRESTATE_COMMAND)
    boot = shell.run("cat /proc/sys/kernel/random/boot_id")
    uptime = shell.run("cut -d' ' -f1 /proc/uptime | tr -d .")
    user = shell.run("id -un")
    privileged = run_root(shell, "id -u")
    session = shell.run("printenv SSH_CONNECTION")
    fields = session.stdout.split() if session.exit_status == 0 and not session.truncated else []
    sites = (
        tuple(sorted({site.identifier for site in collected.sites.value}))
        if collected.sites.observed and collected.sites.value is not None
        else ()
    )
    return SignInEvidence(
        state,
        collected.standing.standing.value if collected.standing else "",
        boot.stdout.strip() if boot.exit_status == 0 and not boot.truncated else "",
        int(uptime.stdout.strip())
        if uptime.exit_status == 0 and not uptime.truncated and uptime.stdout.strip().isdigit()
        else None,
        prestate.stdout.strip() if prestate.exit_status == 0 and not prestate.truncated else "",
        user.stdout.strip() if user.exit_status == 0 and not user.truncated else "",
        privileged.exit_status == 0
        and not privileged.truncated
        and privileged.stdout.strip() == "0",
        fields[0] if len(fields) == 4 else "",
        fields[2] if len(fields) == 4 else "",
        fields[3] if len(fields) == 4 else "",
        sites,
        check.warning if check is not None else "",
    )


def _context_valid(evidence: SignInEvidence) -> bool:
    return (
        bool(_ADDRESS.fullmatch(evidence.client_address))
        and bool(_ADDRESS.fullmatch(evidence.local_address))
        and evidence.local_port.isdigit()
        and 0 < int(evidence.local_port) < 65536
    )


def _policy_holds(state: observation.SshState, root_policy: str) -> bool:
    return (
        state.password_authentication == "no"  # noqa: S105 - OpenSSH setting
        and state.keyboard_interactive == "no"
        and state.permit_root_login == root_policy
        and state.contexts_checked
        and state.accounts_readable
        and not state.match_overrides
    )


def review(evidence: object, inputs: PreparationInputs) -> ReviewDraft:  # noqa: C901
    if not isinstance(evidence, SignInEvidence):
        raise ValueError("An SSH sign-in change needs native evidence.")
    refusals: list[str] = []
    if evidence.standing != Standing.TARGET_STACK.value:
        refusals.append("Set up and verify this server before changing sign-in.")
    if evidence.ssh is None:
        refusals.append(
            evidence.ssh_warning
            or "Barectl could not read the effective SSH settings and login accounts."
        )
    elif not evidence.ssh.contexts_checked or not evidence.ssh.accounts_readable:
        refusals.append("Barectl could not check sign-in for every login account.")
    if not evidence.privileged or not evidence.user:
        refusals.append("Barectl needs root or authorized passwordless sudo for this change.")
    if not valid_digest(evidence.precondition_digest) or not evidence.boot_id:
        refusals.append("Barectl could not read the current SSH configuration.")
    if not _context_valid(evidence):
        refusals.append("Barectl could not check this connection's SSH address and port.")
    root_policy = "no" if evidence.user != "root" and evidence.privileged else "prohibit-password"
    state = evidence.ssh
    no_changes = state is not None and _policy_holds(state, root_policy)
    effects = (
        (DeclaredEffect(Scope.SERVER, "Require keys to sign in to this server.", evidence.sites),)
        if not refusals and not no_changes
        else ()
    )
    details = [
        {"label": "What happens", "value": "Passwords can no longer sign in to SSH."},
        {"label": "Root sign-in", "value": "Disabled." if root_policy == "no" else "Key only."},
        {
            "label": f"{revert.WINDOW_MINUTES}-minute window",
            "value": (
                "Barectl opens a new key connection to confirm access. If it cannot, "
                "the server puts the previous sign-in settings back."
            ),
        },
        {
            "label": "If your connection drops",
            "value": "The server restores the previous settings on its own.",
        },
        {
            "label": "If the server restarts",
            "value": "A restart inside the window keeps the new sign-in settings.",
        },
        {"label": "Affected sites", "value": ", ".join(evidence.sites) or "None."},
        {
            "label": "OpenSSH protection",
            "value": (
                "OpenSSH's default slows repeated failed attempts. Barectl leaves it on."
                if state is not None
                and state.per_source_penalties
                and state.per_source_penalties != "no"
                else (
                    "OpenSSH's default slows repeated failed attempts. This server reports "
                    "it off; Barectl leaves it unchanged."
                    if state is not None and state.per_source_penalties == "no"
                    else "Barectl could not read OpenSSH's repeated-attempt protection."
                )
            ),
        },
    ]
    if state is not None and state.accounts_without_keys:
        details.append(
            {
                "label": "Accounts without readable keys",
                "value": ", ".join(state.accounts_without_keys)
                + ". They will lose password sign-in.",
            }
        )
    if state is not None and state.match_overrides:
        details.append(
            {
                "label": "Sign-in exceptions found",
                "value": ", ".join(state.match_overrides)
                + ". Barectl will refuse if the reviewed policy still does not hold.",
            }
        )
    document: dict[str, object] = {
        "version": 1,
        "body_sha256": BODY_SHA256,
        "precondition_digest": evidence.precondition_digest,
        "root_policy": root_policy,
        "client_address": evidence.client_address,
        "local_address": evidence.local_address,
        "local_port": evidence.local_port,
        "accounts": list(state.login_accounts) if state is not None else [],
        "details": details,
    }
    if no_changes:
        document["note"] = "Only key sign-in is already required."
    return ReviewDraft(
        SLUG,
        "Require key sign-in for SSH.",
        effects=effects,
        stages=STAGES,
        postconditions=(
            (
                "Passwords and keyboard-interactive sign-in are disabled for every "
                "checked login account."
            ),
            "Root sign-in follows the reviewed policy.",
            "Barectl confirms a new key connection before keeping the change.",
        ),
        refusals=tuple(refusals),
        sites_read=SITES_READ,
        current_sites=evidence.sites,
        boot_id=evidence.boot_id,
        uptime_centiseconds=evidence.uptime_centiseconds,
        document=document,
    )


def body(document: dict[str, object], context: BodyContext) -> NativeBody:
    digest = document.get("precondition_digest")
    root_policy = document.get("root_policy")
    client = document.get("client_address")
    local = document.get("local_address")
    port = document.get("local_port")
    accounts = document.get("accounts")
    if (
        document.get("version") != 1
        or document.get("body_sha256") != BODY_SHA256
        or not isinstance(digest, str)
        or not valid_digest(digest)
        or root_policy not in {"no", "prohibit-password"}
        or not isinstance(client, str)
        or not isinstance(local, str)
        or not isinstance(port, str)
        or not isinstance(accounts, list)
        or not all(isinstance(name, str) and _ACCOUNT.fullmatch(name) for name in accounts)
        or len(accounts) > 500
        or not _ADDRESS.fullmatch(client)
        or not _ADDRESS.fullmatch(local)
        or not port.isdigit()
        or not 0 < int(port) < 65536
    ):
        raise ValueError("The SSH sign-in review is not a valid immutable selection.")
    window = revert.names(context.unit)
    return NativeBody(
        BODY_BYTES,
        (digest, root_policy, client, local, port, ",".join(accounts), window.identifier),
    )


def verify(shell: RemoteShell, stored: ChangeReview) -> bool | None:
    document = stored.document
    body(document, BodyContext(_VERIFY_UNIT, "", 0))
    observed = observation.collect(shell)
    if not observed.observed or observed.value is None:
        return None
    check = observed.value.ssh
    if not check.observed or check.value is None or check.warning:
        return None
    return _policy_holds(check.value, str(document["root_policy"]))


REQUIRE_KEY_SIGN_IN: Final = ChangeKind(
    SLUG,
    LABEL,
    inspect,
    review,
    body,
    verify,
    refresh_discovery=True,
    input_choices=("on",),
    access_changing=True,
)
