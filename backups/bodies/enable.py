"""Enable backups on one site: realise restic, create its repository and add its keys.

The operator's recovery passphrase arrives only through the confidential input channel as
the staged file named by ``secret_path``; it is passed to restic as a password *file*
(docs/adr/0032-keep-secrets-in-private-native-files.md). The repository is initialised with
the passphrase so plain restic opens it, then a random server key is added for the units.
"""

import base64
import gzip
import json
import os
import pathlib
import pwd
import secrets
import subprocess
import sys
from typing import TYPE_CHECKING, NoReturn

PROFILE_ROOT = "/nix/var/nix/profiles/barectl"
RESTIC_PROFILE = PROFILE_ROOT + "/restic"
RESTIC_BIN = RESTIC_PROFILE + "/bin/restic"
REPOSITORY_ROOT = "/var/lib/barectl-backups"
KEY_ROOT = "/etc/barectl/backups"
INTEGRITY_ROOT = KEY_ROOT + "/integrity"
CACHE_DIR = "/var/cache/barectl/restic"
NIX_BIN = "/nix/var/nix/profiles/default/bin"
REFUSED = 1
PARTIAL = 2

if TYPE_CHECKING:

    def check_mode(payload: str, location: str) -> None: ...


def emit(text: str) -> None:
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


def stage(name: str) -> None:
    emit("barectl-stage " + name)


def site_directory(identifier: str) -> str:
    return f"{REPOSITORY_ROOT}/{identifier}"


def server_key(identifier: str) -> str:
    return f"{KEY_ROOT}/{identifier}.key"


def result(value: dict[str, object]) -> None:
    emit("barectl-result " + json.dumps(value, separators=(",", ":")))


def refused(reason: str) -> NoReturn:
    result({"class": "refused", "reason": reason})
    raise SystemExit(REFUSED)


def failed(reason: str = "") -> NoReturn:
    result({"class": "failed", "reason": reason} if reason else {"class": "failed"})
    raise SystemExit(REFUSED)


def partial(reason: str) -> NoReturn:
    result({"class": "partial", "reason": reason})
    raise SystemExit(PARTIAL)


def safe(path: str, *, mode: int, kind: int = 0o100000) -> bool:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    return (
        info.st_uid == 0
        and info.st_gid == 0
        and (info.st_mode & 0o170000) == kind
        and (info.st_mode & 0o777) == mode
        and info.st_nlink == 1
    )


def safe_config(path: str) -> bool:
    """restic's local backend writes its config read-only (0400) on some versions."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    return (
        info.st_uid == 0
        and info.st_gid == 0
        and (info.st_mode & 0o170000) == 0o100000
        and (info.st_mode & 0o777) in (0o400, 0o600)
        and info.st_nlink == 1
    )


def controlled(path: str) -> bool:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    return (
        info.st_uid == 0
        and info.st_gid == 0
        and (info.st_mode & 0o170000) == 0o040000
        and (info.st_mode & 0o022) == 0
    )


def run(argv: list[str], *, password: str, repository: str) -> int:
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/root",
        "LANG": "C",
        "RESTIC_REPOSITORY": repository,
        "RESTIC_PASSWORD_FILE": password,
        "RESTIC_CACHE_DIR": CACHE_DIR,
    }
    process = subprocess.run(  # noqa: S603 - fixed native argv and validated paths
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=environment,
        timeout=180,
        check=False,
    )
    return process.returncode


def realise(path: str) -> None:
    output = subprocess.run(  # noqa: S603 - fixed native argv and a validated store path
        [
            f"{NIX_BIN}/nix-store",
            "--realise",
            path,
            "--option",
            "max-jobs",
            "0",
            "--option",
            "fallback",
            "false",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=180,
        check=False,
    )
    if output.returncode:
        refused("runtime_cache")


def install_profile(path: str) -> None:
    os.makedirs(PROFILE_ROOT, mode=0o755, exist_ok=True)
    if not controlled(PROFILE_ROOT):
        refused("evidence")
    output = subprocess.run(  # noqa: S603 - fixed native argv and a validated store path
        [f"{NIX_BIN}/nix-env", "--profile", RESTIC_PROFILE, "--set", path],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=180,
        check=False,
    )
    if output.returncode or os.path.realpath(RESTIC_PROFILE) != path:
        refused("runtime_config")


def make_directory(path: str) -> None:
    if not os.path.exists(path):
        os.makedirs(path, mode=0o700)
    if not controlled(path) or (os.stat(path).st_mode & 0o777) != 0o700:
        refused("evidence")


def write_key(path: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(descriptor, secrets.token_hex(32).encode())
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if not safe(path, mode=0o600):
        raise ValueError("The server key was not written safely.")


def install_check(value: object, identifier: str) -> None:  # noqa: C901 - one reviewed install
    """Publish the weekly integrity units reviewed with Enable backups (#405)."""
    if value is None:
        return
    if not isinstance(value, dict) or set(value) != {"version", "payload", "units"}:
        partial("backup_check")
    if value.get("version") != 1:
        partial("backup_check")
    payload_value = value.get("payload")
    units = value.get("units")
    if (
        not isinstance(payload_value, dict)
        or not isinstance(units, dict)
        or payload_value.get("identifier") != identifier
        or set(payload_value) != {"version", "identifier", "repository", "server_key", "filename"}
    ):
        partial("backup_check")
    try:
        script = pathlib.Path(sys.argv[1]).read_bytes()
    except OSError:
        partial("backup_check")
    os.makedirs(INTEGRITY_ROOT, mode=0o700, exist_ok=True)
    if not controlled(INTEGRITY_ROOT) or (os.stat(INTEGRITY_ROOT).st_mode & 0o777) != 0o700:
        partial("backup_check")
    write_private(f"{INTEGRITY_ROOT}/{identifier}.sh", script, mode=0o700)
    write_private(
        f"{INTEGRITY_ROOT}/{identifier}.json",
        json.dumps(payload_value, sort_keys=True, separators=(",", ":")).encode(),
        mode=0o600,
    )
    for key, text in units.items():
        if not isinstance(key, str) or not isinstance(text, str):
            partial("backup_check")
        path = check_unit_path(identifier, key)
        if path is None:
            partial("backup_check")
        if os.path.lexists(path) and (os.path.islink(path) or not safe(path, mode=0o644)):
            partial("backup_check")
        existing = pathlib.Path(path).read_text(encoding="utf-8") if os.path.exists(path) else None
        if existing is not None and existing != text:
            partial("backup_check")
        if existing is None:
            write_private(path, text.encode(), mode=0o644)
    if subprocess.run(
        ["/usr/bin/systemctl", "daemon-reload"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=False,
    ).returncode:
        partial("backup_check")
    for role in ("check", "checkoffsite"):
        if subprocess.run(  # noqa: S603 - fixed native argv
            ["/usr/bin/systemctl", "enable", "--now", f"barectl-site-{identifier}-{role}.timer"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
        ).returncode:
            partial("backup_check")


def check_unit_path(identifier: str, key: str) -> str | None:
    if key == "slice":
        return f"/etc/systemd/system/barectl-site-{identifier}-backup.slice"
    role, _, kind = key.partition(".")
    if role not in ("check", "checkoffsite") or kind not in ("service", "timer"):
        return None
    return f"/etc/systemd/system/barectl-site-{identifier}-{role}.{kind}"


def write_private(path: str, data: bytes, *, mode: int) -> None:
    temporary = path + ".tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.write(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    if not safe(path, mode=mode):
        raise ValueError("The integrity file was not written safely.")


def main() -> None:  # noqa: C901 - one linear native sequence
    if len(sys.argv) == 5 and sys.argv[2] == "check":
        check_mode(sys.argv[3], sys.argv[4])
        return
    raw = base64.b64decode(sys.argv[2])
    document = json.loads(gzip.decompress(raw))
    identifier = str(document.get("identifier", ""))
    restic_path = str(document.get("restic_path", ""))
    staged = str(document.get("secret_path", ""))
    if (
        not identifier
        or not restic_path.startswith("/nix/store/")
        or not staged.startswith("/run/barectl/secrets/")
        or not os.path.isfile(staged)
        or not safe(staged, mode=0o600)
        or os.path.getsize(staged) < 12
    ):
        refused("backup_password")
    stage("preflight")
    try:
        account = pwd.getpwnam("s" + identifier)
    except KeyError:
        refused("backup_site")
    if account.pw_uid < 1000 or account.pw_uid >= 30000:
        refused("backup_site")
    current = os.path.realpath(RESTIC_PROFILE) if os.path.lexists(RESTIC_PROFILE) else ""
    if current and current != str(document.get("profile_path", "")):
        refused("evidence")
    if not current:
        stage("restic")
        realise(restic_path)
        install_profile(restic_path)
    elif current != restic_path:
        refused("evidence")
    if not os.access(RESTIC_BIN, os.X_OK):
        refused("runtime_config")

    repository = str(document.get("repository", ""))
    key = str(document.get("server_key", ""))
    directory = site_directory(identifier)
    if (
        repository != f"{directory}/onsite"
        or key != server_key(identifier)
        or not repository.startswith(REPOSITORY_ROOT + "/")
        or not key.startswith(KEY_ROOT + "/")
    ):
        failed()
    stage("repository")
    for parent in (REPOSITORY_ROOT, KEY_ROOT, CACHE_DIR):
        os.makedirs(parent, mode=0o700, exist_ok=True)
        if not controlled(parent) or (os.stat(parent).st_mode & 0o777) != 0o700:
            refused("evidence")
    make_directory(directory)
    make_directory(repository)
    config = os.path.join(repository, "config")
    initialised = os.path.isfile(config)
    if initialised and not safe_config(config):
        refused("backup_repository")
    key_exists = os.path.isfile(key)
    if key_exists and not safe(key, mode=0o600):
        refused("evidence")
    created_key = False
    stage("keys")
    try:
        if not key_exists:
            try:
                write_key(key)
            except OSError, ValueError:
                refused("backup_key")
            created_key = True
        if not initialised:
            if run([RESTIC_BIN, "init"], password=staged, repository=repository):
                raise _Repository()
            initialised = True
        if not safe_config(config):
            raise _Repository()
        # The passphrase key exists once the repository opens with the passphrase alone.
        if run([RESTIC_BIN, "snapshots", "--json"], password=staged, repository=repository):
            raise _Password()
        if os.path.realpath(RESTIC_PROFILE) != restic_path:
            raise _Evidence()
        if run(
            [RESTIC_BIN, "key", "add", "--new-password-file", key],
            password=staged,
            repository=repository,
        ):
            raise _Key()
        if run([RESTIC_BIN, "snapshots", "--json"], password=key, repository=repository):
            raise _Key()
    except _Repository:
        if created_key:
            pathlib.Path(key).unlink(missing_ok=True)
        refused("backup_repository")
    except _Password:
        if created_key:
            pathlib.Path(key).unlink(missing_ok=True)
        refused("backup_password")
    except _Key:
        pathlib.Path(key).unlink(missing_ok=True)
        if initialised and not safe(os.path.join(repository, "config"), mode=0o600):
            refused("backup_repository")
        if str(document.get("repository_existed", "")) == "yes":
            refused("backup_key")
        partial("backup_key")
    except _Evidence:
        if created_key:
            pathlib.Path(key).unlink(missing_ok=True)
        refused("evidence")
    try:
        install_check(document.get("check"), identifier)
    except OSError, ValueError:
        partial("backup_check")
    stage("verify")
    result({"class": "succeeded"})


class _Repository(Exception):
    pass


class _Password(Exception):
    pass


class _Key(Exception):
    pass


class _Evidence(Exception):
    pass
