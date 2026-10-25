"""The native body that creates one WordPress site (Phase B #380).

Executed as root by the change engine's staged payload under the mutation lock. It builds
the site's layout, publishes the maintenance gate, creates the site's MariaDB binding,
downloads and verifies the pinned core archive, installs it as the site user, writes the
private configuration with server-generated salts, runs ``wp core install`` with the
operator's password on standard input, opens the site and verifies it.

This module is also a complete Python module for the fast layer: it imports the site and
WordPress convention helpers it uses. When a body is assembled, those imports are stripped
and the helpers are inlined from ``sites.observation``'s ``COMMON_SOURCE`` and
``wordpress.convention``.
"""

import base64
import gzip
import hashlib
import json
import os
import pathlib
import pwd
import re
import shutil
import stat
import subprocess
import sys
import time
from types import SimpleNamespace

from sites.bodies.common import (
    configure_pool,
    create_account,
    create_layout,
    current_bytes,
    identity_name_exists,
    maintenance_file,
    pool_file,
    publish_caddy,
    result,
    runtime_admission,
    setting,
    stage,
    validate_candidate,
    validate_pool_candidate,
    wordpress_caddy_file,
)
from sites.bodies.logrotate import logrotate_install, logrotate_present
from wordpress.convention import (
    CORE_ARCHIVE_SHA256,
    CORE_ARCHIVE_SIZE,
    CORE_ARCHIVE_URL,
    CORE_MARKERS,
    CORE_VERSION,
    loader_problem,
    new_salts,
    private_configuration_path,
    private_configuration_problem,
    public_root,
    render_loader,
    render_private_configuration,
    version_of,
)

# The ``databases.bodies.site`` source, injected at assembly time.
DATABASE_BODY = ""

ARCHIVE_NAME = "wordpress-" + CORE_VERSION + ".zip"
WP_CLI = "bin/wp"
EXTRACT_SCRIPT = (
    "import os,stat,sys,zipfile\n"
    "archive,dest=sys.argv[1],sys.argv[2]\n"
    "total=0\n"
    "with zipfile.ZipFile(archive) as value:\n"
    "    entries=value.infolist()\n"
    "    if len(entries)>20000: sys.exit(3)\n"
    "    for entry in entries:\n"
    "        name=entry.filename\n"
    "        parts=name.rstrip('/').split('/')\n"
    "        if not name.startswith('wordpress/') or any(p in ('','.','..') for p in parts):\n"
    "            sys.exit(4)\n"
    "        mode=entry.external_attr >> 16\n"
    "        if stat.S_ISLNK(mode) or mode & 0o7000: sys.exit(5)\n"
    "        if entry.is_dir(): continue\n"
    "        if entry.file_size>67108864: sys.exit(6)\n"
    "        total+=entry.file_size\n"
    "        if total>536870912: sys.exit(7)\n"
    "    value.extractall(dest)\n"
)


def user_run(
    settings: SimpleNamespace,
    argv: list[str],
    *,
    input_data: bytes | None = None,
    cwd: str | pathlib.Path | None = None,
    timeout: int = 1800,
    check: bool = False,
) -> subprocess.CompletedProcess[bytes]:
    environment = {
        "HOME": str(settings.directory),
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }
    completed = subprocess.run(  # noqa: S603 - fixed argv as the site's own user
        ["/usr/sbin/runuser", "-u", str(settings.account), "--", *argv],
        cwd=cwd,
        env=environment,
        input=input_data,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if check and completed.returncode:
        raise ValueError("A site-identity command failed.")
    return completed


def _file(path: pathlib.Path) -> str | None:
    try:
        descriptor = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 65536:
            return None
        data = os.read(descriptor, 65537)
    except OSError:
        return None
    finally:
        os.close(descriptor)
    return data.decode("utf-8", "replace") if len(data) <= 65536 else None


def _exists(path: pathlib.Path) -> bool:
    try:
        path.lstat()
    except OSError:
        return False
    return True


def _remove_tree(path: pathlib.Path) -> None:
    if not _exists(path):
        return
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        path.unlink()
        return
    shutil.rmtree(path)


def _core_present(identifier: str) -> bool:
    base = pathlib.Path(public_root(identifier))
    return all(_exists(base / marker) for marker in CORE_MARKERS) and bool(
        version_of(_file(base / "wp-includes" / "version.php") or "")
    )


def _download(settings: SimpleNamespace, destination: pathlib.Path) -> None:
    if destination.exists() or destination.is_symlink():
        destination.unlink()
    completed = user_run(
        settings,
        [
            "/usr/bin/curl",
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--output",
            str(destination),
            CORE_ARCHIVE_URL,
        ],
        timeout=900,
    )
    if completed.returncode:
        destination.unlink(missing_ok=True)
        raise ValueError("The pinned WordPress archive could not be downloaded.")
    info = destination.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size != CORE_ARCHIVE_SIZE:
        destination.unlink(missing_ok=True)
        raise ValueError("The downloaded WordPress archive is not the pinned size.")
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    if digest != CORE_ARCHIVE_SHA256:
        destination.unlink(missing_ok=True)
        raise ValueError("The downloaded WordPress archive is not the pinned checksum.")


def _extract(settings: SimpleNamespace, archive: pathlib.Path, stage_dir: pathlib.Path) -> None:
    _remove_tree(stage_dir)
    stage_dir.mkdir(mode=0o700)
    os.chown(stage_dir, *site_ids(settings))
    os.chmod(stage_dir, 0o700)
    completed = user_run(
        settings,
        ["/usr/bin/python3", "-c", EXTRACT_SCRIPT, str(archive), str(stage_dir)],
        timeout=600,
    )
    if completed.returncode:
        raise ValueError("The pinned WordPress archive could not be extracted.")


def site_ids(settings: SimpleNamespace) -> tuple[int, int]:
    account = pwd.getpwnam(str(settings.account))
    return int(account.pw_uid), int(account.pw_gid)


def _public_directory(path: pathlib.Path, uid: int, caddy_gid: int) -> None:
    if path.exists() and path.is_symlink():
        path.unlink()
    if not path.exists():
        path.mkdir(mode=0o750)
    os.chown(path, uid, caddy_gid)
    os.chmod(path, 0o2750)  # noqa: S103 - the root Caddy serves from


def _public_file(
    path: pathlib.Path, target: pathlib.Path, uid: int, gid: int, caddy_gid: int
) -> None:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("The WordPress archive contains a special file.")
    destination = target / path.name
    if destination.exists() and destination.is_symlink():
        destination.unlink()
    temporary = target / (".barectl-" + path.name)
    if temporary.exists() or temporary.is_symlink():
        temporary.unlink()
    shutil.copyfile(path, temporary)
    os.chown(temporary, uid, caddy_gid)
    os.chmod(temporary, 0o640)
    os.replace(temporary, destination)


def _sync_public(settings: SimpleNamespace, source: pathlib.Path) -> None:
    uid, gid = site_ids(settings)
    caddy = pwd.getpwnam("caddy")
    public = pathlib.Path(public_root(str(settings.identifier)))
    if not source.is_dir():
        raise ValueError("The WordPress archive has no supported root.")
    for root, directories, files in os.walk(source, followlinks=False):
        here = pathlib.Path(root)
        relative = here.relative_to(source)
        target = public if relative == pathlib.Path(".") else public / relative
        _public_directory(target, uid, caddy.pw_gid)
        for name in directories:
            path = here / name
            if path.is_symlink():
                raise ValueError("The WordPress archive contains a link.")
            _public_directory(target / name, uid, caddy.pw_gid)
        for name in files:
            _public_file(here / name, target, uid, gid, caddy.pw_gid)
    _public_directory(public, uid, caddy.pw_gid)


def _write_private(
    path: pathlib.Path, contents: str, uid: int, gid: int, mode: int = 0o600
) -> None:
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, "w") as output:
        output.write(contents)
        output.flush()
        os.fsync(output.fileno())
        os.fchown(output.fileno(), uid, gid)
        os.fchmod(output.fileno(), mode)


def _configuration(settings: SimpleNamespace, identifier: str, uid: int, gid: int) -> None:
    public = pathlib.Path(public_root(identifier)) / "wp-config.php"
    private = pathlib.Path(private_configuration_path(identifier))
    existing_public = _file(public)
    if existing_public is not None and loader_problem(existing_public, identifier):
        raise ValueError("The public WordPress loader is outside the supported layout.")
    if existing_public is None:
        _write_private(public, render_loader(identifier), uid, gid)
    if private.exists() or private.is_symlink():
        info = private.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError("The private WordPress configuration is not private.")
        text = _file(private)
        if text is None or private_configuration_problem(text, identifier):
            raise ValueError(
                "The private WordPress configuration is outside the supported grammar."
            )
        return
    salts = new_salts()
    _write_private(private, render_private_configuration(identifier, salts), uid, gid)


def _installed(settings: SimpleNamespace) -> bool:
    completed = user_run(
        settings,
        [str(settings.directory) + "/" + WP_CLI, "core", "is-installed"],
        cwd=public_root(str(settings.identifier)),
        timeout=120,
    )
    return completed.returncode == 0


def _tables(settings: SimpleNamespace) -> list[str]:
    completed = user_run(
        settings,
        [
            "/usr/bin/mariadb",
            "--no-defaults",
            "--protocol=socket",
            "--socket=/run/mysqld/mysqld.sock",
            f"s{settings.identifier}",
            "-N",
            "-B",
            "-e",
            "SHOW TABLES LIKE 'wp\\_%'",
        ],
        timeout=60,
    )
    return completed.stdout.decode("utf-8", "replace").split() if completed.returncode == 0 else []


def _install(settings: SimpleNamespace, document: dict[str, object], password: bytes) -> None:
    if _installed(settings):
        return
    if _tables(settings):
        raise ValueError("The site's WordPress tables already exist without a complete install.")
    command = [
        str(settings.directory) + "/" + WP_CLI,
        "core",
        "install",
        f"--url={'https' if settings.https else 'http'}://{settings.names[0]}",
        f"--title={document['title']}",
        f"--admin_user={document['admin_username']}",
        f"--admin_email={document['admin_email']}",
        "--skip-email",
        "--prompt=admin_password",
    ]
    completed = user_run(
        settings,
        command,
        input_data=password + b"\n",
        cwd=public_root(str(settings.identifier)),
        timeout=600,
    )
    if completed.returncode:
        raise ValueError("WordPress could not complete its installation.")


def _permalinks(settings: SimpleNamespace) -> None:
    for arguments in (
        ["rewrite", "structure", "/%postname%/", "--hard"],
        ["rewrite", "flush", "--hard"],
    ):
        completed = user_run(
            settings,
            [str(settings.directory) + "/" + WP_CLI, *arguments],
            cwd=public_root(str(settings.identifier)),
            timeout=120,
        )
        if completed.returncode:
            raise ValueError("WordPress could not store its pretty permalinks.")


def _http_status(settings: SimpleNamespace, path: str, *, secure: bool) -> tuple[int, str]:
    host = str(settings.names[0])
    argv = [
        "/usr/bin/curl",
        "--silent",
        "--show-error",
        "--insecure",
        "--location",
        "--max-time",
        "15",
    ]
    if secure:
        argv += ["--resolve", f"{host}:443:127.0.0.1", f"https://{host}{path}"]
    else:
        argv += ["--header", f"Host: {host}", f"http://127.0.0.1{path}"]
    argv += ["--output", "/dev/null", "--write-out", "%{http_code} %{redirect_url}"]
    completed = subprocess.run(  # noqa: S603 - fixed probe
        argv, capture_output=True, timeout=30, check=False
    )
    text = completed.stdout.decode("ascii", "replace").strip()
    code, _, redirect = text.partition(" ")
    problem = redirect or completed.stderr.decode("utf-8", "replace")
    return (int(code) if code.isdigit() else 0), problem


def _verify_site(settings: SimpleNamespace) -> None:
    deadline = time.monotonic() + 45
    while True:
        try:
            for path in ("/", "/wp-login.php", "/wp-json/"):
                code, problem = _http_status(settings, path, secure=bool(settings.https))
                if code != 200:
                    raise ValueError(f"The site answered {code} at {path}: {problem}")
            for path in ("/wp-config.php", "/.env", "/wp-content/uploads/barectl.php"):
                code, _problem = _http_status(settings, path, secure=bool(settings.https))
                if code != 404:
                    raise ValueError(f"The site did not deny {path}.")
            return
        except (ValueError, OSError, subprocess.TimeoutExpired) as error:
            if not settings.https or time.monotonic() >= deadline:
                sys.stderr.write("barectl-problem " + str(error)[-900:] + "\n")
                sys.stderr.flush()
                raise
            time.sleep(0.5)


def database_state(document: dict[str, object]) -> tuple[str, str]:
    """Run #379's site-database body in an isolated namespace."""
    namespace: dict[str, object] = {"__name__": "databases.bodies.site"}
    exec(compile(DATABASE_BODY, "databases/bodies/site.py", "exec"), namespace)  # noqa: S102
    publish_probe = namespace["publish_probe"]
    probe = namespace["probe"]
    apply_statements = namespace["apply_statements"]
    prove = namespace["prove"]
    remove_probe = namespace["remove_probe"]
    if not publish_probe(document):  # type: ignore[operator]
        return ("refused", "site_database")
    if probe(document, "pre") != document["expected_pre"]:  # type: ignore[operator]
        return ("refused", "site_database_driver")
    reason = apply_statements(document)  # type: ignore[operator]
    if reason:
        return ("partial", str(reason))
    reason = prove(document)  # type: ignore[operator]
    if reason:
        return ("partial", str(reason))
    if not remove_probe(document):  # type: ignore[operator]
        return ("partial", "site_database_probe")
    return ("", "")


def _preflight(document: dict[str, object], settings: SimpleNamespace) -> str:
    if document.get("existing"):
        account = pwd.getpwnam(str(settings.account))
        if int(account.pw_uid) != int(str(document["identity"])):
            return "evidence"
        path = pathlib.Path(f"/etc/caddy/sites/{settings.identifier}.caddy")
        if not _exists(path):
            return "evidence"
        text = current_bytes(path)
        if text != wordpress_caddy_file(settings) and text != maintenance_file(settings):
            return "evidence"
        return ""
    identity = document.get("identity")
    if type(identity) is not int:
        return "evidence"
    stage("preflight-runtime")
    try:
        before = runtime_admission(document, settings)
    except ValueError, OSError, subprocess.TimeoutExpired:
        return "evidence"
    stage("preflight-state")
    if (
        before["digest"] != document["precondition_digest"]
        or before["disk_digest"] != document["disk_digest"]
        or before["next_id"] != document["identity"]
        or before["next_proxy_id"] != document["proxy_identity"]
        or settings.identifier in before["current_sites"]
        or pathlib.Path(settings.directory).exists()
        or identity_name_exists(settings.identifier)
    ):
        return "evidence"
    stage("preflight-candidate")
    try:
        validate_candidate(settings.identifier, wordpress_caddy_file(settings))
        validate_pool_candidate(settings, identity, pool_file(settings))
    except ValueError, OSError, subprocess.TimeoutExpired:
        return "evidence"
    return ""


def _install_files(settings: SimpleNamespace, document: dict[str, object], password: bytes) -> None:
    identifier = str(settings.identifier)
    uid, gid = site_ids(settings)
    if not _core_present(identifier):
        stage("download")
        archive = pathlib.Path(settings.directory) / "private" / ARCHIVE_NAME
        _download(settings, archive)
        stage("extract")
        staging = pathlib.Path(settings.directory) / "private" / "wp-stage"
        _extract(settings, archive, staging)
        _sync_public(settings, staging / "wordpress")
        _remove_tree(staging)
        archive.unlink(missing_ok=True)
    stage("configure")
    _configuration(settings, identifier, uid, gid)
    stage("install")
    _install(settings, document, password)
    _permalinks(settings)


def _open_site(settings: SimpleNamespace) -> bool:
    stage("publish")
    if not publish_caddy(
        settings.identifier, wordpress_caddy_file(settings), maintenance_file(settings)
    ):
        return False
    stage("verify")
    try:
        _verify_site(settings)
    except ValueError, OSError, subprocess.TimeoutExpired:
        publish_caddy(
            settings.identifier, maintenance_file(settings), wordpress_caddy_file(settings)
        )
        raise
    return True


def create_wordpress(document: dict[str, object]) -> None:  # noqa: C901 - the reviewed stages
    names = document.get("names")
    if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
        result("refused", "evidence")
        return
    https = document.get("https", True) is not False
    settings = setting(str(document["identifier"]), names, str(document["selection"]), https=https)
    stage("preflight")
    refusal = _preflight(document, settings)
    if refusal:
        result("refused", refusal)
        return
    secret_path = str(document.get("secret_path", ""))
    if re.fullmatch(r"/run/barectl/secrets/[0-9a-f]{32}", secret_path) is None:
        result("refused", "evidence")
        return
    changed = bool(document.get("existing"))
    deployment_lock: int | None = None
    try:
        password = pathlib.Path(secret_path).read_bytes()
        pathlib.Path(secret_path).unlink()
        if not 0 < len(password) <= 4096 or b"\0" in password:
            result("refused", "wordpress_secret")
            return
        if not document.get("existing"):
            stage("site")
            identity = document.get("identity")
            if type(identity) is not int:
                raise ValueError("Invalid reviewed identity.")
            changed = True
            account = create_account(settings, identity)
            deployment_lock = create_layout(settings)
            logrotate_install(settings.identifier, logrotate_present(settings.identifier))
            stage("pool")
            configure_pool(settings, account, int(str(document["proxy_identity"])))
        stage("gate")
        path = pathlib.Path(f"/etc/caddy/sites/{settings.identifier}.caddy")
        preimage = current_bytes(path) if _exists(path) else None
        if preimage != maintenance_file(settings) and not publish_caddy(
            settings.identifier, maintenance_file(settings), preimage
        ):
            result("partial" if changed else "refused", "wordpress_gate")
            return
        stage("database")
        outcome, reason = database_state(document)
        if outcome:
            result(outcome, reason)
            return
        _install_files(settings, document, password)
        if not _open_site(settings):
            result("partial", "wordpress_publish")
            return
        result("succeeded")
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        sys.stderr.write("barectl-problem " + str(error)[-900:] + "\n")
        sys.stderr.flush()
        result("partial" if changed else "refused", "wordpress_create" if changed else "evidence")
    finally:
        pathlib.Path(secret_path).unlink(missing_ok=True)
        if deployment_lock is not None:
            os.close(deployment_lock)


if __name__ == "__main__":
    create_wordpress(json.loads(gzip.decompress(base64.b64decode(sys.argv[1]))))
