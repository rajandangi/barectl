"""Encrypted browser first access.

docs/adr/0026-encrypt-wordpress-first-access-for-the-requesting-browser.md
"""

import base64
import binascii
import hashlib
import json
import shlex
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.contrib.auth.models import User
from django.db import transaction
from django.utils import timezone

from bootstrap import native as bootstrap_native
from bootstrap.models import Action, ApplyRun, Execution, Verification
from discovery.ssh import RemoteShell
from operations.models import RemoteOperation

from . import execution
from .first_access_models import FirstAccessDelivery

MARKER = "barectl-wordpress-first-access"
MAX_KEY = 1024
PERMISSIONS = ("servers.view_server", "wordpress.view_wordpressplan", "wordpress.install_wordpress")


def validate_key(encoded: str) -> bytes:
    if not encoded or len(encoded) > MAX_KEY:
        raise ValueError("The browser public key is missing or too large.")
    try:
        raw = base64.b64decode(encoded, validate=True)
        public = serialization.load_der_public_key(raw)
    except ValueError, binascii.Error:
        raise ValueError("The browser public key is not canonical RSA SPKI.") from None
    if not isinstance(public, rsa.RSAPublicKey):
        raise ValueError("The browser public key must use RSA.")
    if public.key_size != 4096 or public.public_numbers().e != 65537:
        raise ValueError("The browser public key must use RSA 4096 with exponent 65537.")
    canonical = public.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if canonical != raw or base64.b64encode(raw).decode("ascii") != encoded:
        raise ValueError("The browser public key is not canonical RSA SPKI.")
    return raw


def key_digest(encoded: str) -> str:
    return hashlib.sha256(validate_key(encoded)).hexdigest()


def install_script(encoded: str) -> str:
    validate_key(encoded)
    return "; ".join(
        (
            "umask 077",
            'k=$(/usr/bin/mktemp "$TMPDIR/wp-access-XXXXXX") || exit 1',
            'o=""',
            'trap \'rm -f -- "$k" "$o"\' EXIT',
            'o=$(/usr/bin/mktemp "$TMPDIR/wp-cipher-XXXXXX") || exit 1',
            f'printf %s {shlex.quote(encoded)} | /usr/bin/openssl base64 -d -A >"$k" || exit 1',
            '/usr/bin/openssl pkey -pubin -inform DER -in "$k" -noout >/dev/null 2>&1 || exit 1',
            "p=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 32)",
            '[ "${#p}" -eq 32 ] || exit 1',
            'printf "%s\\n" "$p" | "$@" >/dev/null 2>&1',
            'r=$?; if [ "$r" -ne 0 ]; then unset p; exit "$r"; fi',
            (
                'printf %s "$p" | /usr/bin/openssl pkeyutl -encrypt -pubin '
                '-keyform DER -inkey "$k" -out "$o" -pkeyopt rsa_padding_mode:oaep '
                "-pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 2>/dev/null"
            ),
            'r=$?; unset p; [ "$r" -eq 0 ] || exit 1',
            '[ "$(stat -c %s -- "$o")" -eq 512 ] || exit 1',
            'c=$(/usr/bin/openssl base64 -A -in "$o") || exit 1',
            '[ "${#c}" -eq 684 ] || exit 1',
            'printf %s "$c"; unset c',
        )
    )


def parse_ciphertext(value: str) -> str:
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError, binascii.Error:
        raise ValueError("The encrypted first-access record is invalid.") from None
    if (
        len(value) != 684
        or len(decoded) != 512
        or base64.b64encode(decoded).decode("ascii") != value
    ):
        raise ValueError("The encrypted first-access record is invalid.")
    return value


def _journal_ciphertext(text: str, run: ApplyRun, digest: str, invocation: str) -> str:
    lines = text.splitlines()
    if len(lines) < 2 or lines[:2] != ["residue absent", "journal ok"]:
        raise ValueError("The encrypted first-access journal is unavailable.")
    found = []
    for line in lines[2:]:
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if not isinstance(entry, dict):
            continue
        if (
            entry.get("_SYSTEMD_UNIT"),
            entry.get("_SYSTEMD_INVOCATION_ID"),
            entry.get("_TRANSPORT"),
            entry.get("_UID"),
        ) != (run.unit_name, invocation, "stdout", "0"):
            continue
        message = entry.get("MESSAGE")
        if isinstance(message, str) and message.startswith(f"{MARKER} "):
            parts = message.split(" ")
            if len(parts) != 3 or parts[1] != digest:
                raise ValueError("The encrypted first-access journal does not match its review.")
            found.append(parse_ciphertext(parts[2]))
    if len(found) != 1:
        raise ValueError("The encrypted first-access journal is absent or ambiguous.")
    return found[0]


def capture(
    shell: RemoteShell, run: ApplyRun, identifier: str, encoded: str, expires_at: datetime
) -> None:
    if FirstAccessDelivery.objects.filter(run=run, retrieved_at__isnull=False).exists():
        return
    invocation = (
        ApplyRun.objects.filter(pk=run.pk).values_list("invocation_id", flat=True).first() or ""
    )
    digest = key_digest(encoded)
    cipher = ""
    root = bootstrap_native.is_root(shell)
    if root is not None and execution.INVOCATION.fullmatch(invocation):
        argv = execution.retrieval_argv(run.unit_name, identifier)
        if root or shell.run(bootstrap_native.authorization(argv)).exit_status == 0:
            answer = shell.run(execution.retrieval_command(argv, invocation, root=root))
            if not answer.exit_status and not answer.truncated:
                with suppress(ValueError):
                    cipher = _journal_ciphertext(answer.stdout, run, digest, invocation)
    with transaction.atomic():
        delivery, _ = FirstAccessDelivery.objects.select_for_update().get_or_create(
            run=run,
            defaults={
                "requested_by_id": run.requested_by_id,
                "key_sha256": digest,
                "expires_at": expires_at,
                "unavailable": True,
            },
        )
        if delivery.retrieved_at is None:
            delivery.ciphertext = cipher
            delivery.unavailable = not cipher
            delivery.retrieved_at = timezone.now()
            delivery.save(update_fields=["ciphertext", "unavailable", "retrieved_at"])


def _authorized(user: User, action: str) -> bool:
    permission = {
        Action.WORDPRESS_INSTALL: "wordpress.install_wordpress",
        "wordpress_access": "wordpress.manage_wordpress_credentials",
    }.get(action)
    current = User.objects.filter(pk=user.pk, is_active=True).first()
    return (
        current is not None
        and permission is not None
        and current.has_perms((*PERMISSIONS[:2], permission))
    )


def _verified(run: ApplyRun) -> bool:
    return (
        run.status == RemoteOperation.Status.SUCCEEDED
        and run.execution == Execution.SUCCEEDED
        and run.verification == Verification.PASSED
    )


@dataclass(frozen=True)
class DeliveryView:
    run_id: int
    key_sha256: str
    expires_at: datetime
    state: str


def read_delivery(user: User, run_id: int) -> DeliveryView | None:
    delivery = (
        FirstAccessDelivery.objects.select_related("run")
        .filter(run_id=run_id, requested_by=user)
        .first()
    )
    if delivery is None or not _authorized(user, delivery.run.action):
        return None
    state = "available"
    if delivery.consumed_at is not None:
        state = "consumed"
    elif delivery.expires_at <= timezone.now():
        state = "expired"
    elif delivery.run.status in RemoteOperation.ACTIVE:
        state = "pending"
    elif delivery.unavailable or not delivery.ciphertext or not _verified(delivery.run):
        state = "unavailable"
    else:
        try:
            parse_ciphertext(delivery.ciphertext)
        except ValueError:
            state = "unavailable"
    return DeliveryView(run_id, delivery.key_sha256, delivery.expires_at, state)


def reveal(user: User, run_id: int) -> dict[str, str] | None:
    with transaction.atomic():
        delivery = (
            FirstAccessDelivery.objects.select_for_update()
            .select_related("run")
            .filter(
                run_id=run_id,
                requested_by=user,
                consumed_at=None,
                unavailable=False,
                expires_at__gt=timezone.now(),
            )
            .first()
        )
        if delivery is None or not delivery.ciphertext:
            return None
        run = delivery.run
        if not _verified(run) or not _authorized(user, run.action):
            return None
        try:
            parse_ciphertext(delivery.ciphertext)
        except ValueError:
            return None
        result = {"ciphertext": delivery.ciphertext, "key_sha256": delivery.key_sha256}
        delivery.consumed_at = timezone.now()
        delivery.ciphertext = ""
        claimed = FirstAccessDelivery.objects.filter(
            run_id=run_id,
            consumed_at=None,
            expires_at__gt=delivery.consumed_at,
        ).update(consumed_at=delivery.consumed_at, ciphertext="")
        return result if claimed == 1 else None
