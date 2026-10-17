"""docs/saved-server-connections.md#approved-key-files"""

import os
import stat
from dataclasses import dataclass
from io import StringIO
from pathlib import Path

from django.conf import settings
from paramiko import ECDSAKey, Ed25519Key, PasswordRequiredException, PKey, RSAKey, SSHException


class CredentialUnavailable(Exception):
    """A sanitized credential failure."""


@dataclass(frozen=True)
class ApprovedKey:
    reference: str
    public_key: str = ""
    file_identity: str = ""
    problem: str = ""


def load_key(reference: str) -> tuple[PKey, ApprovedKey]:
    catalogue: object = settings.SSH_APPROVED_KEYS
    if not isinstance(catalogue, dict) or reference not in catalogue:
        raise CredentialUnavailable(
            "The SSH credential is unavailable. Choose an approved key again."
        )
    path_value: object = catalogue[reference]
    if not isinstance(path_value, str):
        raise CredentialUnavailable(
            "The SSH credential is unavailable. Contact the controller administrator."
        )
    try:
        path = Path(path_value).expanduser()
        with path.open(encoding="utf-8") as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode) or not before.st_mode & 0o444:
                raise OSError
            text = source.read(65537)
            after = os.fstat(source.fileno())
        current = path.stat()
        identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        if len(text) > 65536 or any(
            identity
            != (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
            for value in (after, current)
        ):
            raise OSError
        key: PKey | None = None
        for key_class in (Ed25519Key, ECDSAKey, RSAKey):
            try:
                key = key_class.from_private_key(StringIO(text))
                break
            except PasswordRequiredException:
                raise CredentialUnavailable(
                    "This key is passphrase-protected. Load it into the controller SSH agent "
                    "and choose agent mode."
                ) from None
            except SSHException, ValueError:
                continue
        if key is None:
            raise OSError
    except OSError, UnicodeError, ValueError:
        raise CredentialUnavailable(
            "The SSH credential is unavailable. Contact the controller administrator."
        ) from None
    return key, ApprovedKey(
        reference, f"{key.get_name()} {key.get_base64()}", ":".join(map(str, identity))
    )


def approved_keys() -> tuple[ApprovedKey, ...]:
    catalogue: object = settings.SSH_APPROVED_KEYS
    if not isinstance(catalogue, dict):
        return ()
    result: list[ApprovedKey] = []
    for reference in catalogue:
        if (
            not isinstance(reference, str)
            or not reference.isascii()
            or not reference.replace("-", "").replace("_", "").isalnum()
            or len(reference) > 64
        ):
            continue
        try:
            _, entry = load_key(reference)
        except CredentialUnavailable as problem:
            entry = ApprovedKey(reference, problem=str(problem))
        result.append(entry)
    return tuple(result)
