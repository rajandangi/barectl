"""docs/saved-server-connections.md"""

import getpass
import hashlib
import ipaddress
import json
import re
from pathlib import Path
from typing import TYPE_CHECKING

from django.conf import settings
from django.core.exceptions import ValidationError

from .ssh_config import ConnectionTarget

if TYPE_CHECKING:
    from operations.models import RemoteOperation


def normalize_address(value: str) -> str:
    if not value.isascii() or len(value) > 253 or "%" in value:
        raise ValidationError("Enter an ASCII host name, IPv4 or IPv6 address without a port.")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        labels = value.removesuffix(".").split(".")
        if not all(
            re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in labels
        ):
            raise ValidationError(
                "Enter a host name or IP address, without a URL, user or port."
            ) from None
        if all(label.isdecimal() for label in labels):
            raise ValidationError("Enter a valid IPv4 address.") from None
        return value.lower().removesuffix(".")


def validate_address(value: str) -> None:
    normalize_address(value)


def validate_username(value: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9_.][A-Za-z0-9_.-]{0,63}", value):
        raise ValidationError("Enter up to 64 safe SSH user characters, without a leading hyphen.")


def agent_target(alias: str, address: str, username: str, port: int) -> ConnectionTarget:
    validate_username(username)
    if not 1 <= port <= 65535:
        raise ValidationError("Enter a port from 1 to 65535.")
    return ConnectionTarget(
        alias=alias,
        hostname=normalize_address(address),
        user=username,
        port=port,
        identity_files=(),
        known_hosts_files=(Path(settings.SSH_KNOWN_HOSTS_PATH).expanduser(),),
        agent_only=True,
    )


def connection_label(operation: RemoteOperation) -> str:
    definition = operation.connection
    return (
        definition.address
        if definition is not None and definition.mode != "alias"
        else operation.ssh_alias
    )


def saved_alias(address: str, username: str, port: int) -> str:
    endpoint = f"{address}:{port}:{username}"
    return "saved-" + hashlib.sha256(endpoint.encode()).hexdigest()


def alias_digest(target: ConnectionTarget) -> str:
    document = {
        "address": target.hostname,
        "username": target.user or getpass.getuser(),
        "port": target.port,
        "identities": [str(path) for path in target.identity_files],
        "trust": [str(path) for path in target.known_hosts_files],
    }
    return hashlib.sha256(json.dumps(document, sort_keys=True).encode()).hexdigest()
