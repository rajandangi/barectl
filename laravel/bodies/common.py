"""Laravel release primitives shared by the Deploy and Roll back native bodies.

This module is also a complete Python module for the fast layer: it imports the site
convention helpers it uses. When a body is assembled, those imports are stripped and the
helpers are inlined from ``sites.observation``'s ``COMMON_SOURCE`` (the same pattern
``sites.bodies.common`` uses).
"""

import json
import os
import pathlib
import pwd
import re
import stat
import subprocess
import sys
from collections.abc import Callable
from types import SimpleNamespace
from typing import Final

from sites.bodies.common import (
    canonical,
    current_bytes,
    open_site_lock,
    reload_caddy,
    replace_caddy,
    result,
    safe,
    same_site_lock,
    setting,
    site_account,
    stage,
)

RELEASE_NAME: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
COMMIT_NAME: Final = re.compile(r"[0-9a-f]{7,40}")
IDENTIFIER: Final = re.compile(r"[a-z][a-z0-9]{2,23}")
RETAINED_RELEASES: Final = 5
MAX_RELEASES: Final = 64
MIGRATION_FILE: Final = re.compile(r"^([0-9]{4}_[0-9]{2}_[0-9]{2}_[0-9]{6}_[a-z0-9_]+)\.php$")
_CREDENTIAL: Final = re.compile(r"(?i)^https?://[^/@]*@")
_PATH = tuple[pathlib.Path, pathlib.Path, pathlib.Path, pathlib.Path]


def laravel_paths(identifier: str) -> _PATH:
    directory = pathlib.Path("/var/www") / identifier
    return (directory, directory / "releases", directory / "current", directory / "private")


def version_of(name: str) -> str:
    head = name.split("-", 1)[0]
    return head if COMMIT_NAME.fullmatch(head) else ""


def release_names(identifier: str) -> list[str]:
    _, releases, _, _ = laravel_paths(identifier)
    if not safe(str(releases), directory=True):
        return []
    try:
        entries = sorted(
            entry.name
            for entry in releases.iterdir()
            if entry.is_dir()
            and not entry.is_symlink()
            and RELEASE_NAME.fullmatch(entry.name)
            and entry.name != "initial"
        )
    except OSError:
        return []
    return entries[:MAX_RELEASES]


def current_name(identifier: str) -> str | None:
    _, _, current, _ = laravel_paths(identifier)
    try:
        if current.lstat().st_uid != 0 or not current.is_symlink():
            return None
        target = os.readlink(current)
    except OSError:
        return None
    if not target.startswith("releases/"):
        return None
    name = target[len("releases/") :]
    return name if RELEASE_NAME.fullmatch(name) else None


def site_owner(identifier: str) -> tuple[int, int] | None:
    """The site account's uid and gid, or ``None`` when the account is absent."""
    account = site_account(identifier)
    if account is None:
        return None
    return (int(str(account[0])), int(str(account[1])))


def _owned(path: pathlib.Path, uid: int, *, directory: bool) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    if info.st_uid not in (0, uid) or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
        return False
    if directory:
        return stat.S_ISDIR(info.st_mode)
    return stat.S_ISREG(info.st_mode) and info.st_nlink == 1


def owned_ok(path: pathlib.Path, uid: int, site: pathlib.Path, *, directory: bool = False) -> bool:
    """Whether a path inside the site directory is writable only by the site user and root.

    A release is owned by the site user and shared Laravel state lives in the site's
    private area, so the root-only ``safe`` guard does not apply to them. The site
    directory and every directory between it and the path must still be real directories
    that only root or the site user can write, which keeps the site boundary in force.
    """
    if not _owned(site, uid, directory=True):
        return False
    if path == site:
        return True
    if not _owned(path, uid, directory=directory):
        return False
    for ancestor in path.parents:
        if ancestor == site:
            return True
        if not _owned(ancestor, uid, directory=True):
            return False
    return False


def _site_ok(path: pathlib.Path, identifier: str, *, directory: bool = False) -> bool:
    owner = site_owner(identifier)
    return owner is not None and owned_ok(
        path, owner[0], laravel_paths(identifier)[0], directory=directory
    )


def release_state(identifier: str, name: str) -> str:
    release = laravel_paths(identifier)[1] / name
    if not _site_ok(release, identifier, directory=True):
        return "unsupported"
    return "complete" if _site_ok(release / "artisan", identifier) else "partial"


def git_locator(identifier: str, name: str) -> tuple[str, str]:
    """The repository URL and branch read from a release's Git metadata, sanitized.

    This reads native files only, never running Git. A URL carrying a credential is
    refused (an empty locator) rather than recorded.
    """
    release = laravel_paths(identifier)[1] / name
    repository = ""
    in_origin = False
    config = release / ".git" / "config"
    text = config.read_text() if _site_ok(config, identifier) else ""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[remote "):
            in_origin = "origin" in stripped
            continue
        if stripped.startswith("[") and in_origin:
            in_origin = False
        if in_origin and stripped.startswith("url = "):
            repository = stripped[len("url = ") :]
    if _CREDENTIAL.match(repository):
        repository = ""
    head = release / ".git" / "HEAD"
    value = head.read_text().strip() if _site_ok(head, identifier) else ""
    branch = value[len("ref: refs/heads/") :] if value.startswith("ref: refs/heads/") else ""
    return repository, branch


def shared_state(identifier: str) -> dict[str, bool]:
    private = laravel_paths(identifier)[3]
    return {
        "environment": _site_ok(private / "laravel.env", identifier),
        "storage": _site_ok(private / "storage", identifier, directory=True),
        "cache": _site_ok(private / "cache", identifier, directory=True),
    }


def php_requirement(identifier: str, name: str) -> str:
    """The PHP version a release's ``composer.json`` requires, read natively.

    This reads one file and never runs Composer or PHP. ``require.php`` is preferred;
    ``config.platform.php`` is the pin Composer itself would resolve against.
    """
    manifest = laravel_paths(identifier)[1] / name / "composer.json"
    if not _site_ok(manifest, identifier):
        return ""
    try:
        text = manifest.read_text(encoding="utf-8", errors="replace")
    except OSError, ValueError:
        return ""
    if len(text) > 1024 * 1024:
        return ""
    try:
        data = json.loads(text)
    except ValueError:
        return ""
    if not isinstance(data, dict):
        return ""
    require = data.get("require")
    requirement = require.get("php") if isinstance(require, dict) else None
    if not isinstance(requirement, str):
        config = data.get("config")
        platform = config.get("platform") if isinstance(config, dict) else None
        requirement = platform.get("php") if isinstance(platform, dict) else None
    return requirement.strip()[:100] if isinstance(requirement, str) else ""


def release_record(identifier: str, name: str) -> dict[str, object]:
    release = laravel_paths(identifier)[1] / name
    try:
        created = int(release.stat().st_mtime)
    except OSError:
        created = 0
    repository, branch = git_locator(identifier, name)
    return {
        "name": name,
        "commit": version_of(name),
        "created": created,
        "state": release_state(identifier, name),
        "repository": repository,
        "branch": branch,
    }


def site_record(identifier: str) -> dict[str, object]:
    names = release_names(identifier)
    current = current_name(identifier)
    releases = [release_record(identifier, name) for name in names]
    application, repository, branch = "plain", "", ""
    for record in releases:
        if record["name"] == current and record["state"] == "complete":
            application = "laravel"
            repository = str(record["repository"])
            branch = str(record["branch"])
    if current is not None and current not in names:
        current = None
    return {
        "identifier": identifier,
        "application": application,
        "current": current or "",
        "repository": repository,
        "branch": branch,
        "php_requirement": php_requirement(identifier, current) if current else "",
        "releases": releases,
        "shared": shared_state(identifier),
        "problem": "",
    }


def _is_site(entry: pathlib.Path) -> bool:
    return bool(
        entry.is_dir()
        and not entry.is_symlink()
        and IDENTIFIER.fullmatch(entry.name)
        and site_account(entry.name) is not None
        and (entry / "releases").is_dir()
    )


def _entries(base: pathlib.Path) -> list[pathlib.Path]:
    if not safe(str(base), directory=True):
        return []
    try:
        return sorted(base.iterdir())
    except OSError:
        return []


def inventory() -> dict[str, object]:
    base = pathlib.Path("/var/www")
    sites = [site_record(entry.name) for entry in _entries(base) if _is_site(entry)]
    return {"version": 1, "sites": sites[:64]}


def gate_file(settings: SimpleNamespace, template: str) -> str:
    addresses = ", ".join("http://" + str(name) for name in settings.names)
    return template.format(settings=settings, addresses=addresses)


def request_readiness(
    settings: SimpleNamespace, *, socket_path: str = "", https: bool = True
) -> int:
    """Send ``GET /up`` to the site's own address and return its HTTP status, or 0.

    Through the private HAProxy socket while a maintenance gate keeps visitors out, or
    through Caddy over the primary name. The body is never read.
    """
    import http.client
    import socket

    host = str(settings.names[0])
    headers = {
        "Host": host,
        "X-Forwarded-Proto": "https",
        "X-Forwarded-Host": host,
    }
    connection: http.client.HTTPConnection
    try:
        if socket_path:
            unix = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            unix.settimeout(5)
            unix.connect(socket_path)
            connection = http.client.HTTPConnection(host)
            connection.sock = unix
        elif https:
            connection = http.client.HTTPSConnection(host, timeout=5)
        else:
            connection = http.client.HTTPConnection(host, 80, timeout=5)
        connection.request("GET", "/up", headers=headers)
        status = connection.getresponse().status
        connection.close()
        return int(status)
    except OSError, ValueError, http.client.HTTPException:
        return 0


def prune(identifier: str, reviewed: list[str]) -> None:
    """Remove exactly the releases a review named, never ``current`` and never shared state."""
    releases = laravel_paths(identifier)[1]
    keep = set(reviewed)
    current = current_name(identifier)
    if current is not None:
        keep.add(current)
    owner = site_owner(identifier)
    for name in release_names(identifier):
        if name in keep:
            continue
        path = releases / name
        if owner is None or not owned_ok(path, owner[0], releases.parent, directory=True):
            continue
        subprocess.run(  # noqa: S603 - fixed argv in the site's own release layout
            ["/usr/bin/rm", "-rf", "--", str(path)], check=True, timeout=60
        )


def laravel_read() -> None:
    sys.stdout.write(canonical(inventory()) + "\n")
    sys.stdout.flush()


def _strings(value: object) -> list[str]:
    return [str(item) for item in value] if isinstance(value, list) else []


def _user(
    settings: SimpleNamespace,
    argv: list[str],
    *,
    cwd: str | pathlib.Path | None = None,
    check: bool = True,
) -> str:
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
        check=False,
        capture_output=True,
        text=True,
        timeout=1800,
    )
    if check and completed.returncode:
        raise ValueError("A site-identity command failed.")
    return completed.stdout


def _source_ok(locator: str) -> bool:
    if not locator or len(locator) > 512 or any(character.isspace() for character in locator):
        return False
    if locator.startswith("-") or "\x00" in locator:
        return False
    if locator.startswith("https://"):
        return "@" not in locator[len("https://") :].split("/", 1)[0]
    return bool(re.fullmatch(r"[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:[A-Za-z0-9._/-]+", locator))


def release_path(settings: SimpleNamespace, name: str) -> pathlib.Path:
    return laravel_paths(settings.identifier)[1] / name


def disk_ok(settings: SimpleNamespace, required: int) -> bool:
    statistics = os.statvfs(settings.directory)
    return statistics.f_bavail * statistics.f_frsize >= required


def fetch(settings: SimpleNamespace, repository: str, commit: str, release: pathlib.Path) -> None:
    if release.exists() or release.is_symlink():
        raise ValueError("The reviewed release already exists.")
    owner = site_owner(str(settings.identifier))
    if owner is None:
        raise ValueError("The site's account is missing.")
    # ``releases/`` is root-controlled, so the site user cannot create its own release
    # entry: root publishes the empty directory, hands it to the site user and the build
    # runs in place in it.
    release.mkdir(mode=0o755)
    os.chown(release, owner[0], owner[1])
    # The site-owned release directory Caddy traverses to reach current/public; mkdir's
    # mode is masked by the umask, and a strict umask would leave Caddy unable to serve.
    os.chmod(release, 0o755)  # noqa: S103 - site-owned release directory Caddy traverses
    _user(settings, ["/usr/bin/git", "init", "--quiet", str(release)])
    _user(settings, ["/usr/bin/git", "remote", "add", "origin", repository], cwd=release)
    _user(settings, ["/usr/bin/git", "fetch", "--depth", "1", "origin", commit], cwd=release)
    _user(settings, ["/usr/bin/git", "checkout", "--quiet", "--detach", "FETCH_HEAD"], cwd=release)
    if not (release / ".git").is_dir() or not (release / "composer.json").is_file():
        raise ValueError("The fetched release has no supported Laravel layout.")


def build(settings: SimpleNamespace, release: pathlib.Path) -> None:
    composer = str(settings.directory) + "/bin/composer"
    _user(
        settings,
        [
            composer,
            "install",
            "--no-dev",
            "--no-interaction",
            "--prefer-dist",
            "--optimize-autoloader",
            "--no-plugins",
            "--no-scripts",
        ],
        cwd=release,
    )
    _user(settings, [composer, "check-platform-reqs", "--no-dev"], cwd=release)


def link_shared(settings: SimpleNamespace, release: pathlib.Path) -> None:
    private = laravel_paths(settings.identifier)[3]
    for target, source in (
        ("laravel.env", ".env"),
        ("storage", "storage"),
        ("cache", "bootstrap/cache"),
    ):
        destination = release / source
        if destination.exists() or destination.is_symlink():
            if not destination.is_symlink() or os.readlink(destination) != str(private / target):
                raise ValueError("A release shared-state link is outside the convention.")
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.symlink_to(private / target)


def discover(settings: SimpleNamespace, release: pathlib.Path) -> None:
    php = str(settings.directory) + "/bin/php"
    _user(settings, [php, str(release / "artisan"), "package:discover", "--ansi"], cwd=release)
    _user(settings, [php, str(release / "artisan"), "optimize", "--ansi"], cwd=release)


def caddy_ids() -> tuple[int, int]:
    """The Caddy account's uid and gid, resolved on the target."""
    account = pwd.getpwnam("caddy")
    return account.pw_uid, account.pw_gid


def classify(settings: SimpleNamespace, release: pathlib.Path) -> None:
    """Close a release to every account but the site user and Caddy's public root.

    Caddy reads only ``public``, where static files stay group-readable and PHP source
    stays the site user's; everywhere else a release keeps directory traversal and nothing
    more (Phase B). Symlinks are never followed, so the shared ``.env``, ``storage`` and
    ``bootstrap/cache`` links into the site's private area are left untouched.
    """
    owner = site_owner(str(settings.identifier))
    if owner is None:
        raise ValueError("The site's account is missing.")
    _, caddy_gid = caddy_ids()
    public = release / "public"
    for root, directories, files in os.walk(release, followlinks=False):
        here = pathlib.Path(root)
        public_below = here == public or public in here.parents
        for name in directories:
            path = here / name
            if path.is_symlink():
                continue
            if path == public or public_below:
                os.chown(path, owner[0], caddy_gid)
                os.chmod(path, 0o2750)  # noqa: S103 - the root Caddy serves from
            else:
                os.chown(path, owner[0], owner[1])
                os.chmod(path, 0o711)  # noqa: S103 - traversal only
        for name in files:
            path = here / name
            if path.is_symlink():
                continue
            if public_below and path.suffix != ".php":
                os.chown(path, owner[0], caddy_gid)
                os.chmod(path, 0o640)
            else:
                os.chown(path, owner[0], owner[1])
                os.chmod(path, 0o600)
    os.chown(release, owner[0], owner[1])
    os.chmod(release, 0o711)  # noqa: S103 - the site user's release, traversal only


def _database_argv(identifier: str) -> list[str] | None:
    database = "s" + identifier
    if pathlib.Path("/usr/bin/mariadb").exists():
        return ["/usr/bin/mariadb", database, "--batch", "--skip-column-names", "-e"]
    if pathlib.Path("/usr/bin/psql").exists():
        return ["/usr/bin/psql", "-X", "-t", "-A", "-d", database, "-c"]
    return None


def pending_migrations(settings: SimpleNamespace, release: pathlib.Path) -> list[str] | None:
    directory = release / "database" / "migrations"
    if not directory.is_dir():
        return []
    files: list[str] = []
    for path in sorted(directory.iterdir()):
        match = MIGRATION_FILE.match(path.name)
        if path.is_file() and match:
            files.append(match.group(1))
    if not files:
        return []
    argv = _database_argv(str(settings.identifier))
    if argv is None:
        return None
    records = _user(settings, [*argv, "SELECT migration FROM migrations"], check=False)
    recorded = set(records.split())
    return [name for name in files if name not in recorded]


def record_migrations(
    settings: SimpleNamespace, release: pathlib.Path, expected: list[str]
) -> bool:
    argv = _database_argv(str(settings.identifier))
    if argv is None:
        return False
    records = set(_user(settings, [*argv, "SELECT migration FROM migrations"], check=False).split())
    return all(name in records for name in expected)


def migrate(settings: SimpleNamespace, release: pathlib.Path) -> None:
    php = str(settings.directory) + "/bin/php"
    _user(settings, [php, str(release / "artisan"), "migrate", "--force", "--ansi"], cwd=release)


def switch_current(settings: SimpleNamespace, name: str) -> None:
    current = laravel_paths(settings.identifier)[2]
    temporary = current.parent / (".current-" + name)
    if temporary.exists() or temporary.is_symlink():
        temporary.unlink()
    temporary.symlink_to("releases/" + name)
    os.replace(temporary, current)


def _publish_gate(settings: SimpleNamespace, template: str) -> str | None:
    path = pathlib.Path("/etc/caddy/sites") / (str(settings.identifier) + ".caddy")
    preimage = current_bytes(path)
    replace_caddy(path, gate_file(settings, template), preimage)
    reload_caddy()
    return preimage


def _restore_gate(settings: SimpleNamespace, preimage: str | None) -> None:
    path = pathlib.Path("/etc/caddy/sites") / (str(settings.identifier) + ".caddy")
    candidate = current_bytes(path)
    if candidate is None:
        raise ValueError("The maintenance page vanished before restoration.")
    replace_caddy(path, preimage if preimage is not None else candidate, candidate)
    reload_caddy()


def _attempt(
    action: Callable[[], None], reason: str, outcome: str = "partial"
) -> tuple[str, str] | None:
    try:
        action()
    except OSError, ValueError, subprocess.TimeoutExpired:
        return (outcome, reason)
    return None


def _preflight(
    settings: SimpleNamespace,
    identifier: str,
    document: dict[str, object],
    descriptor: int,
) -> str:
    if not same_site_lock(descriptor, identifier):
        return "evidence"
    if release_names(identifier) != _strings(document["releases"]):
        return "evidence"
    if (current_name(identifier) or "") != str(document["current"]):
        return "evidence"
    if not _source_ok(str(document["repository"])):
        return "laravel_source"
    if not disk_ok(settings, int(str(document["disk_required"]))):
        return "laravel_disk"
    if not all(shared_state(identifier).values()):
        return "laravel_shared"
    return ""


def _publish(settings: SimpleNamespace, document: dict[str, object]) -> None:
    _publish_gate(settings, str(document["gate"]))


def report_pending(pending: list[str]) -> None:
    """Write the pending migrations a Deploy did not run into the run's journal."""
    for name in pending:
        sys.stdout.write("barectl-pending " + name + "\n")
    sys.stdout.flush()


def _migrations(
    settings: SimpleNamespace, release: pathlib.Path, document: dict[str, object]
) -> tuple[str, str] | None:
    """The migration step inside the maintenance window.

    Pending migrations are run once and verified when the site's Deploy switch leaves
    them enabled; otherwise they are reported into the run's journal and not run.
    """
    pending = pending_migrations(settings, release)
    if pending is None:
        return ("partial", "laravel_migrations")
    if not pending:
        return None
    if not bool(document.get("migrations", True)):
        report_pending(pending)
        return None
    stage("migrations")
    problem = _attempt(lambda: migrate(settings, release), "laravel_migrations")
    if problem:
        return problem
    if not record_migrations(settings, release, pending):
        return ("partial", "laravel_migrations")
    return None


def _activate(
    settings: SimpleNamespace,
    identifier: str,
    document: dict[str, object],
    name: str,
    gate: bool,
    preimage: str | None,
) -> tuple[str, str]:
    stage("switch")
    problem = _attempt(lambda: switch_current(settings, name), "laravel_readiness")
    if problem:
        return problem
    stage("readiness")
    if gate:
        if request_readiness(settings, socket_path=str(settings.proxy_socket)) != 200:
            return ("partial", "laravel_readiness")
        problem = _attempt(lambda: _restore_gate(settings, preimage), "laravel_gate")
        if problem:
            return problem
        gate = False
    if request_readiness(settings) != 200:
        if not gate:
            _attempt(lambda: _publish(settings, document), "laravel_gate")
        return ("partial", "laravel_readiness")
    stage("prune")
    problem = _attempt(lambda: prune(identifier, _strings(document["prune"])), "laravel_release")
    if problem:
        return problem
    return ("succeeded", "")


def _deploy_release(
    document: dict[str, object],
    settings: SimpleNamespace,
    identifier: str,
    descriptor: int,
) -> tuple[str, str]:
    commit, token = str(document["commit"]), str(document["token"])
    repository = str(document["repository"])
    release = release_path(settings, f"{commit}-{token}")
    problem = _preflight(settings, identifier, document, descriptor)
    if problem:
        return ("refused", problem)
    stages = (
        (lambda: fetch(settings, repository, commit, release), "fetch", "laravel_fetch", "refused"),
        (lambda: build(settings, release), "build", "laravel_composer", "partial"),
        (lambda: link_shared(settings, release), "shared", "laravel_shared", "partial"),
        (lambda: discover(settings, release), "discover", "laravel_composer", "partial"),
        (lambda: classify(settings, release), "classify", "laravel_release", "partial"),
    )
    for action, label, reason, outcome in stages:
        stage(label)
        failure = _attempt(action, reason, outcome)
        if failure:
            return failure
    # Until a native scenario proves code pickup, every deploy that switches code runs
    # inside the maintenance window (Phase B #259), so the gate goes up before the
    # migration step whether or not migrations run.
    stage("gate")
    try:
        preimage = _publish_gate(settings, str(document["gate"]))
    except OSError, ValueError:
        return ("refused", "laravel_gate")
    migration = _migrations(settings, release, document)
    if migration:
        return migration
    return _activate(settings, identifier, document, f"{commit}-{token}", True, preimage)


def deploy(document: dict[str, object]) -> None:
    identifier = str(document["identifier"])
    settings = setting(identifier, _strings(document["names"]), str(document["runtime"]))
    try:
        descriptor = open_site_lock(identifier)
    except BlockingIOError:
        result("lock_busy")
        return
    except OSError, ValueError:
        result("refused", "unsafe_lock")
        return
    try:
        outcome, reason = _deploy_release(document, settings, identifier, descriptor)
    finally:
        os.close(descriptor)
    result(outcome, reason)


def _rollback_preflight(
    settings: SimpleNamespace, identifier: str, document: dict[str, object], descriptor: int
) -> str:
    if not same_site_lock(descriptor, identifier):
        return "evidence"
    if release_names(identifier) != _strings(document["releases"]):
        return "evidence"
    if (current_name(identifier) or "") != str(document["current"]):
        return "evidence"
    target = str(document["release"])
    if target not in release_names(identifier) or release_state(identifier, target) != "complete":
        return "release_absent"
    return ""


def _rollback_release(
    document: dict[str, object],
    settings: SimpleNamespace,
    identifier: str,
    descriptor: int,
) -> tuple[str, str]:
    problem = _rollback_preflight(settings, identifier, document, descriptor)
    if problem:
        return ("refused", problem)
    stage("gate")
    try:
        preimage = _publish_gate(settings, str(document["gate"]))
    except OSError, ValueError:
        return ("refused", "laravel_gate")
    return _activate(settings, identifier, document, str(document["release"]), True, preimage)


def roll_back(document: dict[str, object]) -> None:
    identifier = str(document["identifier"])
    settings = setting(identifier, _strings(document["names"]), str(document["runtime"]))
    try:
        descriptor = open_site_lock(identifier)
    except BlockingIOError:
        result("lock_busy")
        return
    except OSError, ValueError:
        result("refused", "unsafe_lock")
        return
    try:
        outcome, reason = _rollback_release(document, settings, identifier, descriptor)
    finally:
        os.close(descriptor)
    result(outcome, reason)
