"""The confidential input channel (docs/adr/0032-keep-secrets-in-private-native-files.md).

A value typed in the dashboard is sealed before it is stored, opened only by the worker
that owns SSH, and scrubbed from anything the engine records. The sealing key is generated
by the worker when it starts and lives in the controller account's private key file, so no
plaintext secret is ever stored, and a worker restart replaces the key so an earlier value
can no longer be read.
"""

import base64
import binascii
import os
import secrets
from collections.abc import Iterable
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.conf import settings

KEY_BYTES = 32
NONCE_BYTES = 12
# A WordPress administrator password or an environment value, not a file.
MAX_SECRET_BYTES = 4096
# What a scrubbed value becomes in stored output and audit.
REDACTED = "<secret>"


# The worker's in-memory copy of the sealing key; ``None`` before it is read or generated.
class _Key:
    value: bytes | None = None


_KEY = _Key()


def _path() -> Path:
    return Path(settings.CONFIDENTIAL_KEY_PATH)


def rotate() -> None:
    """Replace the sealing key. Called when a worker process starts, and by tests.

    Values sealed with the previous key can no longer be opened, so a worker restart makes
    every stored secret unreadable and the run that carries it fails as expired.
    """
    _KEY.value = secrets.token_bytes(KEY_BYTES)
    _write(_KEY.value)


def reset() -> None:
    """Forget the in-memory key without replacing the file; tests use it to reload."""
    _KEY.value = None


def seal(secret: bytes) -> str:
    """Seal ``secret`` for one run, so no plaintext is stored at rest.

    The request handler reads the worker's current key from the file each time, so a worker
    restart is picked up without restarting the web process.
    """
    if not 0 < len(secret) <= MAX_SECRET_BYTES or b"\0" in secret:
        raise ValueError("Not a confidential value.")
    nonce = secrets.token_bytes(NONCE_BYTES)
    sealed = AESGCM(_file_key()).encrypt(nonce, secret, None)
    return base64.urlsafe_b64encode(nonce + sealed).decode("ascii")


def unseal(value: str) -> bytes | None:
    """Open a sealed value, or ``None`` when the key changed or the value is malformed."""
    try:
        raw = base64.urlsafe_b64decode(value.encode("ascii"))
        if len(raw) <= NONCE_BYTES:
            return None
        return AESGCM(_key()).decrypt(raw[:NONCE_BYTES], raw[NONCE_BYTES:], None)
    except InvalidTag, binascii.Error, UnicodeEncodeError, ValueError:
        return None


def scrub(text: str, secrets: Iterable[str]) -> str:
    """Replace every known submitted value in ``text`` before it is stored."""
    for secret in secrets:
        if secret:
            text = text.replace(secret, REDACTED)
    return text


def _key() -> bytes:
    """The worker's in-memory key, read or minted once when this process is not a worker."""
    if _KEY.value is None:
        _KEY.value = _file_key()
    return _KEY.value


def _file_key() -> bytes:
    path = _path()
    if path.is_file():
        stored = _read(path)
        if len(stored) != KEY_BYTES:
            raise ValueError("The confidential key file is not a valid key.")
        return stored
    key = secrets.token_bytes(KEY_BYTES)
    _write(key)
    return key


def _read(path: Path) -> bytes:
    return path.read_bytes()


def _write(key: bytes) -> None:
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(descriptor, key)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    os.chmod(path, 0o600)
