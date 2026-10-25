"""The native body that turns one WordPress site's object cache on or off (Phase C #392).

Executed as root by the change engine's staged payload under the mutation lock. Turning on
creates the site's own instance from the packaged template, writes the three reserved
WordPress constants and installs the pinned Redis Object Cache plugin from the mirror.
Turning off disconnects WordPress first — the plugin drop-in and the constants — and only
then stops and removes the instance. The body proves the final state either way.

This module is also a complete Python module for the fast layer: it imports the helpers it
uses. When a body is assembled, those imports are stripped and the helpers are inlined
from ``sites.observation``'s ``COMMON_SOURCE``, ``cache.convention`` and
``wordpress.convention``.
"""

import base64
import contextlib
import gzip
import hashlib
import json
import os
import pathlib
import pwd
import re
import stat
import subprocess
import sys
import time
from collections.abc import Mapping
from typing import cast

from automation.bodies.units import fence, restore
from automation.bodies.worker_env import restart_workers
from cache.convention import (
    MAXMEMORY_MIB,
    config_shape,
    instance_paths,
    render_config,
    render_drop_in,
)
from cache.laravel import laravel_managed, laravel_values, laravel_wiring
from laravel.bodies.common import (
    _private_file_ok,
    apply_environment,
    environment_entries_from_text,
    environment_path,
    read_environment,
)
from sites.bodies.common import (
    native_state,
    open_site_lock,
    result,
    stage,
)
from wordpress.convention import (
    cache_wiring,
    private_configuration_path,
    private_configuration_problem,
    set_cache_constants,
    write_as_site,
)

IDENTIFIER = re.compile(r"[a-z][a-z0-9]{2,23}")
DIGEST = re.compile(r"[0-9a-f]{64}")
VALKEY_CLI = "/usr/bin/valkey-cli"
WP_CLI = "bin/wp"
PLUGIN_PATH = "wp-content/plugins/redis-cache/redis-cache.php"
DROP_IN_PATH = "wp-content/object-cache.php"
LARAVEL_CONFIG = "current/bootstrap/cache/config.php"


def _read(path: pathlib.Path, limit: int = 65536) -> str | None:
    try:
        info = path.lstat()
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_size > limit:
        return None
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _site_file(path: pathlib.Path, account: str) -> bool:
    try:
        info = path.lstat()
        owner = pwd.getpwnam(account)
    except OSError, KeyError:
        return False
    return (
        stat.S_ISREG(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and info.st_uid == owner.pw_uid
        and info.st_mode & 0o077 == 0
    )


def _same_ids(account: str) -> tuple[int, int]:
    found = pwd.getpwnam(account)
    return int(found.pw_uid), int(found.pw_gid)


def _write(path: pathlib.Path, text: str, uid: int, gid: int, mode: int) -> None:
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    temporary = path.with_name("." + path.name + ".barectl-tmp")
    descriptor = os.open(
        str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(text)
            output.flush()
            os.fsync(output.fileno())
            os.fchown(output.fileno(), uid, gid)
            os.fchmod(output.fileno(), mode)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    parent = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def _tree(path: pathlib.Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        path.unlink()
        return
    import shutil

    shutil.rmtree(path)


def _run(argv: list[str], timeout: int = 120) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(  # noqa: S603 - fixed reviewed argv
        argv, capture_output=True, timeout=timeout, check=False
    )


def _site(
    settings: dict[str, object],
    argv: list[str],
    timeout: int = 900,
    cwd: str = "",
) -> subprocess.CompletedProcess[bytes]:
    environment = {
        "HOME": f"/var/www/{settings['identifier']}",
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
    }
    return subprocess.run(  # noqa: S603 - fixed argv as the site's own user
        ["/usr/sbin/runuser", "-u", str(settings["account"]), "--", *argv],
        cwd=cwd or f"/var/www/{settings['identifier']}/current/public",
        env=environment,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def _wp(
    settings: dict[str, object], argv: list[str], timeout: int = 900
) -> subprocess.CompletedProcess[bytes]:
    return _site(settings, [f"/var/www/{settings['identifier']}/{WP_CLI}", *argv], timeout=timeout)


def _valkey(settings: dict[str, object], *argv: str) -> subprocess.CompletedProcess[bytes]:
    socket = instance_paths(str(settings["identifier"])).socket
    return _site(
        settings,
        [VALKEY_CLI, "-s", socket, *argv],
        timeout=30,
    )


def _unit(unit: str) -> dict[str, str]:
    completed = _run(
        [
            "/usr/bin/systemctl",
            "show",
            "--no-pager",
            "--property=LoadState",
            "--property=ActiveState",
            "--property=SubState",
            "--property=UnitFileState",
            "--property=User",
            "--property=Group",
            unit,
        ],
        timeout=30,
    )
    if completed.returncode:
        return {}
    values: dict[str, str] = {}
    for line in completed.stdout.decode("utf-8", "replace").splitlines():
        key, separator, value = line.partition("=")
        if separator and key not in values:
            values[key] = value
    return values


def _plugin_version(path: pathlib.Path) -> str:
    text = _read(path)
    if text is None:
        return ""
    for line in text.splitlines()[:40]:
        if line.startswith(" * Version: "):
            return line.removeprefix(" * Version: ").strip()[:40]
    return ""


def _mapping(value: object) -> dict[str, object]:
    return cast("dict[str, object]", value) if isinstance(value, dict) else {}


def _instance_row(identifier: str) -> dict[str, object]:
    paths = instance_paths(identifier)
    config = _read(pathlib.Path(paths.config))
    shape = config_shape(identifier, config) if config is not None else None
    drop_in = _read(pathlib.Path(paths.drop_in))
    try:
        info = pathlib.Path(paths.socket).lstat()
        socket = {
            "present": stat.S_ISSOCK(info.st_mode),
            "uid": info.st_uid,
            "mode": stat.S_IMODE(info.st_mode),
        }
    except OSError:
        socket = {"present": False, "uid": -1, "mode": -1}
    return {
        "config_present": config is not None,
        "config": config or "",
        "memory_mib": shape.memory_mib if shape is not None else None,
        "problem": shape.problem if shape is not None else "",
        "drop_in": drop_in or "",
        "drop_in_supported": drop_in == render_drop_in(identifier),
        "unit": _unit(paths.unit),
        "socket": socket,
        "data": pathlib.Path(paths.data_directory).is_dir(),
    }


def _settings(document: dict[str, object]) -> dict[str, object] | None:
    identifier = str(document.get("identifier", ""))
    if IDENTIFIER.fullmatch(identifier) is None:
        return None
    account = "s" + identifier
    try:
        _same_ids(account)
    except KeyError:
        return None
    return {"identifier": identifier, "account": account}


def _laravel_settings(
    settings: dict[str, object], site: Mapping[str, object]
) -> dict[str, object] | None:
    runtime = site.get("runtime")
    if runtime not in ("php84", "php85"):
        return None
    return {**settings, "runtime": runtime}


def _laravel_environment(identifier: str) -> str | None:
    path = environment_path(identifier)
    if not _private_file_ok(path, identifier):
        return None
    text = read_environment(identifier)
    return text or None


def _environment_entries(text: str) -> dict[str, str]:
    entries: dict[str, str] = {}
    for key, value in environment_entries_from_text(text):
        entries.setdefault(key, value)
    return entries


def _write_environment(identifier: str, text: str) -> None:
    write_as_site("s" + identifier, str(environment_path(identifier)), text)


def _laravel_config(settings: dict[str, object]) -> bool:
    """Rebuild Laravel's cached configuration only when one is in use."""
    identifier = str(settings["identifier"])
    current = f"/var/www/{identifier}/current"
    if not pathlib.Path(f"/var/www/{identifier}/{LARAVEL_CONFIG}").exists():
        return True
    if not pathlib.Path(f"{current}/artisan").is_file():
        return True
    runtime = settings.get("runtime")
    if runtime not in ("php84", "php85"):
        return False
    php = f"/nix/var/nix/profiles/barectl/{runtime}/bin/php"
    try:
        completed = _site(settings, [php, "artisan", "config:cache"], timeout=600, cwd=current)
    except OSError, subprocess.TimeoutExpired:
        return False
    return completed.returncode == 0


def _laravel_changes(
    identifier: str, text: str, document: dict[str, object]
) -> list[dict[str, object]]:
    entries = _environment_entries(text)
    managed = laravel_managed(identifier, entries)
    changes: list[dict[str, object]] = []
    if document.get("enabled") is True:
        for key, value in laravel_values(identifier).items():
            changes.append({"key": key, "action": "set", "value": value})
        return changes
    if document.get("restore_store") is True:
        if document.get("previous_store_present") is True:
            changes.append(
                {
                    "key": "CACHE_STORE",
                    "action": "set",
                    "value": str(document.get("previous_store", "")),
                }
            )
        else:
            changes.append({"key": "CACHE_STORE", "action": "remove"})
    changes.extend(
        {"key": key, "action": "remove"} for key in ("REDIS_HOST", "REDIS_PORT") if key in managed
    )
    return changes


def _private_configuration(identifier: str) -> str | None:
    path = pathlib.Path(private_configuration_path(identifier))
    if not _site_file(path, "s" + identifier):
        return None
    text = _read(path)
    if text is None or private_configuration_problem(text, identifier):
        return None
    return text


def _write_configuration(identifier: str, text: str) -> None:
    write_as_site("s" + identifier, private_configuration_path(identifier), text)


def _start_instance(settings: dict[str, object], memory: int) -> str:
    identifier = str(settings["identifier"])
    paths = instance_paths(identifier)
    uid, gid = _same_ids(str(settings["account"]))
    try:
        config_root = pathlib.Path("/etc/valkey")
        config_root.mkdir(mode=0o755, parents=True, exist_ok=True)
        # The package keeps its directory 2770 valkey:valkey; a site must be able to
        # traverse to its own root-owned 0640 file without joining that group.
        os.chown(config_root, 0, 0)
        os.chmod(config_root, 0o755)  # noqa: S103 - the package directory must be traversable
        data_root = pathlib.Path("/var/lib/valkey")
        data_root.mkdir(mode=0o755, parents=True, exist_ok=True)
        os.chown(data_root, 0, 0)
        os.chmod(data_root, 0o755)  # noqa: S103 - the parent must be traversable
        _write(pathlib.Path(paths.config), render_config(identifier, memory), 0, gid, 0o640)
        _write(pathlib.Path(paths.drop_in), render_drop_in(identifier), 0, 0, 0o644)
        data = pathlib.Path(paths.data_directory)
        if not data.is_dir():
            data.mkdir(mode=0o700)
        os.chown(data, uid, gid)
        os.chmod(data, 0o700)
    except OSError:
        return "object_cache_instance"
    # No daemon-reload and no ``enable``: both reload systemd, which clears every running
    # unit's execution metadata (#428) and would make other sites unverifiable. Starting a
    # new instance reads its drop-in; the boot symlink is what ``enable`` would create.
    wants = pathlib.Path("/etc/systemd/system/multi-user.target.wants")
    try:
        wants.mkdir(mode=0o755, parents=True, exist_ok=True)
        link = wants / paths.unit
        link.unlink(missing_ok=True)
        link.symlink_to("/usr/lib/systemd/system/valkey-server@.service")
    except OSError:
        return "object_cache_instance"
    if _run(["/usr/bin/systemctl", "start", paths.unit], timeout=120).returncode:
        return "object_cache_instance"
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        state = _unit(paths.unit)
        try:
            info = pathlib.Path(paths.socket).lstat()
            present = stat.S_ISSOCK(info.st_mode)
        except OSError:
            present = False
        if state.get("ActiveState") == "active" and present:
            return ""
        time.sleep(0.2)
    return "object_cache_instance"


def _remove_instance(identifier: str) -> None:
    paths = instance_paths(identifier)
    _run(["/usr/bin/systemctl", "stop", paths.unit], timeout=120)
    link = pathlib.Path("/etc/systemd/system/multi-user.target.wants") / paths.unit
    with contextlib.suppress(OSError):
        link.unlink(missing_ok=True)
    _run(["/usr/bin/systemctl", "reset-failed", paths.unit], timeout=60)
    # A stopped, disabled instance with no files is gone; the next start reads the
    # convention's drop-in again, so no daemon-reload is needed here either.
    for path in (
        paths.config,
        paths.data_directory,
        paths.run_directory,
        paths.drop_in_directory,
    ):
        _tree(pathlib.Path(path))


def _download_plugin(settings: dict[str, object], document: dict[str, object]) -> str:
    identifier = str(settings["identifier"])
    archive = pathlib.Path(
        f"/var/www/{identifier}/private/redis-cache-{document['plugin_version']}.zip"
    )
    archive.unlink(missing_ok=True)
    completed = _site(
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
            str(archive),
            str(document["plugin_url"]),
        ],
    )
    if completed.returncode:
        archive.unlink(missing_ok=True)
        return "object_cache_plugin"
    try:
        info = archive.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_size != document["plugin_size"]
            or hashlib.sha256(archive.read_bytes()).hexdigest() != document["plugin_sha256"]
        ):
            archive.unlink(missing_ok=True)
            return "object_cache_plugin"
    except OSError:
        archive.unlink(missing_ok=True)
        return "object_cache_plugin"
    return ""


def _install_plugin(settings: dict[str, object], document: dict[str, object]) -> str:
    identifier = str(settings["identifier"])
    public = pathlib.Path(f"/var/www/{identifier}/current/public")
    plugin = public / PLUGIN_PATH
    reason = ""
    if _plugin_version(plugin) != document["plugin_version"]:
        reason = _download_plugin(settings, document)
        if reason:
            return reason
        archive = pathlib.Path(
            f"/var/www/{identifier}/private/redis-cache-{document['plugin_version']}.zip"
        )
        completed = _wp(settings, ["plugin", "install", str(archive), "--force", "--activate"])
        archive.unlink(missing_ok=True)
        if completed.returncode:
            sys.stderr.write(completed.stdout.decode("utf-8", "replace")[-900:] + "\n")
            return "object_cache_plugin"
    if _plugin_version(plugin) != document["plugin_version"]:
        return "object_cache_plugin"
    if (
        _wp(settings, ["plugin", "is-active", "redis-cache"], timeout=120).returncode
        and _wp(settings, ["plugin", "activate", "redis-cache"], timeout=300).returncode
    ):
        return "object_cache_plugin"
    return ""


def _status(settings: dict[str, object]) -> str:
    completed = _wp(settings, ["redis", "status"], timeout=300)
    return completed.stdout.decode("utf-8", "replace")


def _connected(settings: dict[str, object], version: str) -> bool:
    text = _status(settings)
    required = ("Status: Connected", "Client: PhpRedis", "Drop-in: Valid")
    return all(line in text for line in required) and f"Plugin Version: {version}" in text


def _fenced_units(document: dict[str, object], identifier: str) -> bool:
    """Whether the reviewed fence plan stops this site's own services.

    A fenced cache change stops the site's workers before it edits the environment, so a
    restart here would start a masked unit and fail; ``restore`` starts exactly the reviewed
    work again, on the new environment, after the change verifies.
    """
    plan = document.get("automation_fence")
    if not isinstance(plan, dict):
        return False
    for entry in plan.get("sites", []):
        if isinstance(entry, dict) and entry.get("identifier") == identifier:
            services = entry.get("services")
            return isinstance(services, list) and bool(services)
    return False


def _restart_site_workers(document: dict[str, object], identifier: str) -> bool:
    if _fenced_units(document, identifier):
        return True
    restarted, succeeded = restart_workers(identifier)
    if restarted:
        stage("workers")
    return succeeded


def _apply_laravel(  # noqa: C901 - one reviewed sequence
    document: dict[str, object],
    settings: dict[str, object],
    identifier: str,
) -> tuple[str, str]:
    """Turn a Laravel site's cache on or off, returning ``(outcome, reason)``."""
    enabled = document.get("enabled") is True
    memory = int(str(document.get("maxmemory_mib")))
    text = _laravel_environment(identifier)
    if text is None or hashlib.sha256(text.encode("utf-8")).hexdigest() != document.get(
        "environment_digest"
    ):
        return "refused", "evidence"
    before_wiring = laravel_wiring(identifier, _environment_entries(text))
    if not fence(document, identifier):
        return "refused", "automation_fence"
    changed = False
    if enabled:
        stage("instance")
        reason = _start_instance(settings, memory)
        if reason:
            return ("partial" if changed else "refused"), reason
        changed = True
        if _valkey(settings, "PING").stdout.strip() != b"PONG":
            return "partial", "object_cache_instance"
        if document.get("write_environment") is True:
            stage("environment")
            changes = _laravel_changes(identifier, text, document)
            staged = apply_environment(text, changes)
            if staged != text:
                try:
                    _write_environment(identifier, staged)
                except OSError, ValueError, subprocess.TimeoutExpired:
                    return "partial", "laravel_environment"
                text = staged
                changed = True
            if laravel_wiring(identifier, _environment_entries(text)) != "complete":
                return "partial", "object_cache_wiring"
            if not _laravel_config(settings):
                return "partial", "laravel_config"
            if not _restart_site_workers(document, identifier):
                return "partial", "laravel_worker"
        stage("verify")
        after = _instance_row(identifier)
        unit = _mapping(after["unit"])
        socket = _mapping(after["socket"])
        if (
            after["memory_mib"] != memory
            or after["config"] != render_config(identifier, memory)
            or not after["drop_in_supported"]
            or unit.get("ActiveState") != "active"
            or socket.get("present") is not True
            or socket.get("mode") != 0o600
            or laravel_wiring(
                identifier, _environment_entries(_laravel_environment(identifier) or "")
            )
            != "complete"
        ):
            return "partial", "object_cache_verify"
        if not restore(document, identifier):
            return "partial", "automation_restore"
        return "succeeded", ""
    stage("disconnect")
    if document.get("write_environment") is True:
        changes = _laravel_changes(identifier, text, document)
        staged = apply_environment(text, changes)
        if staged != text:
            try:
                _write_environment(identifier, staged)
            except OSError, ValueError, subprocess.TimeoutExpired:
                return "partial", "laravel_environment"
            text = staged
            changed = True
        if not _laravel_config(settings):
            return "partial", "laravel_config"
        if not _restart_site_workers(document, identifier):
            return "partial", "laravel_worker"
    stage("stop")
    _remove_instance(identifier)
    stage("verify")
    after = _instance_row(identifier)
    unit = _mapping(after["unit"])
    socket = _mapping(after["socket"])
    remaining = laravel_managed(
        identifier,
        _environment_entries(_laravel_environment(identifier) or ""),
    )
    if (
        after["config_present"]
        or after["drop_in"]
        or after["data"]
        or socket.get("present") is True
        or unit.get("ActiveState") == "active"
        or remaining
        or (before_wiring == "complete" and document.get("restore_store") is not True)
    ):
        return "partial", "object_cache_verify"
    if not restore(document, identifier):
        return "partial", "automation_restore"
    return "succeeded", ""


def apply(document: dict[str, object]) -> None:  # noqa: C901 - one reviewed sequence
    settings = _settings(document)
    if settings is None:
        result("refused", "evidence")
        return
    identifier = str(settings["identifier"])
    application = str(document.get("application", ""))
    enabled = document.get("enabled") is True
    memory = document.get("maxmemory_mib")
    if enabled and memory not in MAXMEMORY_MIB:
        result("refused", "evidence")
        return
    try:
        descriptor = open_site_lock(identifier)
    except BlockingIOError:
        result("lock_busy")
        return
    except OSError, ValueError:
        result("refused", "unsafe_lock")
        return
    changed = False
    try:
        stage("preflight")
        before = native_state("observed", "", protections=False)
        if before["digest"] != document.get("precondition_digest"):
            result("refused", "evidence")
            return
        site = next((row for row in before["sites"] if row["identifier"] == identifier), None)
        if site is None or application not in ("wordpress", "laravel"):
            result("refused", "evidence")
            return
        if application == "wordpress" and site["application"] != "wordpress":
            result("refused", "evidence")
            return
        if enabled and (site["state"] != "complete" or site.get("client") != "phpredis"):
            result("refused", "evidence")
            return
        if application == "laravel":
            if not pathlib.Path(f"/var/www/{identifier}/current/artisan").is_file():
                result("refused", "evidence")
                return
            laravel_settings = _laravel_settings(settings, site)
            if laravel_settings is None:
                result("refused", "evidence")
                return
            outcome, reason = _apply_laravel(document, laravel_settings, identifier)
            result(outcome, reason)
            return
        text = _private_configuration(identifier)
        if text is None or hashlib.sha256(text.encode("utf-8")).hexdigest() != document.get(
            "configuration_digest"
        ):
            result("refused", "evidence")
            return
        if not fence(document, identifier):
            result("refused", "automation_fence")
            return
        if enabled:
            stage("instance")
            reason = _start_instance(settings, int(str(memory)))
            if reason:
                result("partial" if changed else "refused", reason)
                return
            changed = True
            if _valkey(settings, "PING").stdout.strip() != b"PONG":
                result("partial", "object_cache_instance")
                return
            staged = set_cache_constants(text, identifier, enabled=True)
            if staged != text:
                try:
                    _write_configuration(identifier, staged)
                except OSError, ValueError, subprocess.TimeoutExpired:
                    result("partial", "object_cache_wiring")
                    return
                text = staged
            if cache_wiring(text, identifier) != "complete":
                result("partial", "object_cache_wiring")
                return
            stage("plugin")
            reason = _install_plugin(settings, document)
            if reason:
                result("partial", reason)
                return
            if _wp(settings, ["redis", "enable"], timeout=300).returncode:
                result("partial", "object_cache_plugin")
                return
            stage("verify")
            if not _connected(settings, str(document["plugin_version"])):
                result("partial", "object_cache_verify")
                return
            after = _instance_row(identifier)
            unit = _mapping(after["unit"])
            socket = _mapping(after["socket"])
            if (
                after["memory_mib"] != memory
                or after["config"] != render_config(identifier, int(str(memory)))
                or not after["drop_in_supported"]
                or unit.get("ActiveState") != "active"
                or socket.get("present") is not True
                or socket.get("mode") != 0o600
            ):
                result("partial", "object_cache_verify")
                return
        else:
            stage("disconnect")
            drop_in = pathlib.Path(f"/var/www/{identifier}/current/public/{DROP_IN_PATH}")
            if drop_in.exists() or drop_in.is_symlink():
                _wp(settings, ["redis", "disable"], timeout=120)
                if drop_in.exists() or drop_in.is_symlink():
                    try:
                        drop_in.unlink()
                    except OSError:
                        result("partial", "object_cache_wiring")
                        return
                changed = True
            _wp(settings, ["plugin", "deactivate", "redis-cache"], timeout=120)
            cleared = set_cache_constants(text, identifier, enabled=False)
            if cleared != text:
                try:
                    _write_configuration(identifier, cleared)
                except OSError, ValueError, subprocess.TimeoutExpired:
                    result("partial", "object_cache_wiring")
                    return
                text = cleared
                changed = True
            stage("stop")
            _remove_instance(identifier)
        stage("verify")
        after = _instance_row(identifier)
        wiring = cache_wiring(_private_configuration(identifier) or "", identifier)
        unit = _mapping(after["unit"])
        socket = _mapping(after["socket"])
        if enabled:
            if (
                after["config"] != render_config(identifier, int(str(memory)))
                or unit.get("ActiveState") != "active"
                or socket.get("present") is not True
                or wiring != "complete"
            ):
                result("partial", "object_cache_verify")
                return
        else:
            drop_in = pathlib.Path(f"/var/www/{identifier}/current/public/{DROP_IN_PATH}")
            if (
                after["config_present"]
                or after["drop_in"]
                or after["data"]
                or socket.get("present") is True
                or unit.get("ActiveState") == "active"
                or wiring
                or drop_in.exists()
                or drop_in.is_symlink()
            ):
                result("partial", "object_cache_verify")
                return
        if not restore(document, identifier):
            result("partial", "automation_restore")
            return
        result("succeeded")
    except (OSError, KeyError, ValueError, subprocess.TimeoutExpired) as error:
        sys.stderr.write("barectl-problem " + str(error)[-900:] + "\n")
        sys.stderr.flush()
        result("partial" if changed else "refused", "object_cache")
    finally:
        os.close(descriptor)


if __name__ == "__main__":
    apply(json.loads(gzip.decompress(base64.b64decode(sys.argv[1]))))
