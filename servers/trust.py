"""Fingerprint confirmation for saved connections (docs/adr/0034)."""

import base64
import binascii
import fcntl
import os
import tempfile
from pathlib import Path

from django.conf import settings
from django.contrib.auth.models import User
from django.db import transaction
from paramiko import PKey, SSHException

from discovery.models import DiscoveryAttempt
from discovery.services import DiscoveryBusy, queue_discovery
from discovery.ssh import read_trust, trusted_host
from operations import lifecycle
from servers.connections import agent_target
from servers.models import ConnectionDefinition, Server


class ConfirmationRefused(Exception):
    """A safe reason the captured key cannot be recorded."""


def pending_challenge(server: Server) -> DiscoveryAttempt | None:
    latest = DiscoveryAttempt.objects.filter(server=server).select_related("connection").first()
    if (
        latest is None
        or latest.status != DiscoveryAttempt.Status.FAILED
        or not latest.challenge_key_blob
        or latest.connection is None
        or latest.connection.mode == "alias"
        or latest.connection.revision != server.connection_revision
    ):
        return None
    return latest


def confirm_host(
    server: Server, *, attempt_id: int, revision: int, fingerprint: str, user: User
) -> None:
    if not user.is_active or not user.has_perms(
        ("servers.view_server", "servers.change_server", "discovery.add_discoveryattempt")
    ):
        raise ConfirmationRefused("Permission to confirm this server is unavailable.")
    with transaction.atomic():
        if not Server.objects.filter(pk=server.pk, connection_revision=revision).update(
            connection_revision=revision
        ):
            raise ConfirmationRefused("The saved connection changed; request a new check.")
        if lifecycle.active_operation(server) is not None:
            raise ConfirmationRefused("Wait for the active operation to finish.")
        definition, key = _validated_challenge(server, attempt_id, revision, fingerprint)
        _record_key(server, definition, key)
        try:
            queue_discovery(
                server,
                user=user,
                authority="servers.change_server",
                expected_host_key=f"{key.get_name()} {key.get_base64()}",
            )
        except DiscoveryBusy:
            raise ConfirmationRefused("Wait for the active operation to finish.") from None


def _validated_challenge(
    server: Server, attempt_id: int, revision: int, fingerprint: str
) -> tuple[ConnectionDefinition, PKey]:
    challenge = pending_challenge(server)
    if challenge is None or challenge.pk != attempt_id or challenge.connection is None:
        raise ConfirmationRefused("This host key challenge is no longer current.")
    definition = challenge.connection
    if (
        challenge.challenge_address != definition.address
        or challenge.challenge_port != definition.port
        or revision != definition.revision
    ):
        raise ConfirmationRefused("The host key challenge does not match this connection.")
    try:
        key = PKey.from_type_string(
            challenge.challenge_key_type,
            base64.b64decode(challenge.challenge_key_blob, validate=True),
        )
    except SSHException, ValueError, binascii.Error:
        raise ConfirmationRefused(
            "The captured host key is invalid; request a new check."
        ) from None
    if fingerprint != key.fingerprint or fingerprint != challenge.challenge_fingerprint:
        raise ConfirmationRefused("The fingerprint does not exactly match the presented host key.")
    return definition, key


def _record_key(server: Server, definition: ConnectionDefinition, key: PKey) -> None:
    target = agent_target(
        server.ssh_alias, definition.address, definition.username, definition.port
    )
    path = Path(settings.SSH_KNOWN_HOSTS_PATH).expanduser()
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with path.with_name(path.name + ".lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            trusted, revoked = read_trust(target.known_hosts_files)
            if key.asbytes() in revoked:
                raise ConfirmationRefused("This host key is revoked; confirmation is refused.")
            known = trusted_host(target, trusted)
            if known is not None:
                if known.get(key.get_name()) != key:
                    raise ConfirmationRefused(
                        "The trusted host key changed; confirmation is refused."
                    )
            else:
                _append_key(path, definition.address, definition.port, key)
    except OSError, UnicodeError:
        raise ConfirmationRefused("The controller trust file could not be updated.") from None


def _append_key(path: Path, address: str, port: int, key: PKey) -> None:
    if path.is_symlink():
        raise ConfirmationRefused("The controller trust file must be a regular owned file.")
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    name = address if port == 22 else f"[{address}]:{port}"
    line = f"{name} {key.get_name()} {key.get_base64()}\n"
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, delete=False
        ) as output:
            temporary = output.name
            output.write(text + ("\n" if text and not text.endswith("\n") else "") + line)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            os.unlink(temporary)
