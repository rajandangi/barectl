"""Read backups from native evidence without running restic or touching a repository.

The controller validates this bounded answer strictly. It reports the restic profile, each
site's root-only repository and server key, whether the site database exists, and the newest
safe result line in the journal; it never reads key contents or snapshot data.
"""

import json
import os
import pathlib
import pwd
import stat
import subprocess
import sys

REPOSITORY_ROOT = "/var/lib/barectl-backups"
KEY_ROOT = "/etc/barectl/backups"
OFFSITE_ROOT = KEY_ROOT + "/offsite"
OFFSITE_CONFIG = OFFSITE_ROOT + "/config"
OFFSITE_CAPTURE = OFFSITE_ROOT + "/capture.env"
OFFSITE_PRUNE = OFFSITE_ROOT + "/prune.env"
OFFSITE_HEALTH = "_health"
PROFILE_ROOT = "/nix/var/nix/profiles/barectl"
RESTIC_PROFILE = PROFILE_ROOT + "/restic"
MAX_SITES = 64
MAX_TEXT = 500
PROVIDERS = ("s3", "r2")
# The controller prepends databases/binding.py to this body; its names are our globals.
binding = sys.modules[__name__]


def metadata(path: str) -> dict[str, object] | None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError:
        return {"unreadable": True}
    return {
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": stat.S_IMODE(info.st_mode),
        "type": stat.S_IFMT(info.st_mode),
        "links": info.st_nlink,
    }


def controlled(path: str) -> bool:
    value = metadata(path)
    return bool(
        value
        and value.get("uid") == 0
        and value.get("gid") == 0
        and value.get("type") == stat.S_IFDIR
        and isinstance(value.get("mode"), int)
        and int(str(value["mode"])) & 0o022 == 0
    )


def site_account(identifier: str) -> bool:
    try:
        user = pwd.getpwnam("s" + identifier)
    except KeyError:
        return False
    return 1000 <= user.pw_uid < 30000


def database_present(engine: str, identifier: str) -> tuple[bool, str]:
    if engine not in ("mariadb", "postgresql"):
        return False, "This server has no database engine."
    name = "s" + identifier
    try:
        status, output = bounded(["/bin/sh", "-c", binding.read_command(engine, name)])
    except OSError, ValueError:
        return False, "The site's database could not be read."
    if status:
        return False, "The site's database could not be read."
    try:
        facts = binding.parse_facts(engine, output.decode("utf-8", "replace"))
        locale = (
            binding.read_locale(output.decode("utf-8", "replace"))
            if engine == binding.POSTGRESQL
            else ""
        )
        found = binding.recognize(engine, identifier, facts, locale=locale)
    except ValueError:
        return False, "The site's database could not be read."
    return (
        found.state == "satisfied" and "database" in found.completed,
        "",
    )


def bounded(argv: list[str], *, limit: int = 32768) -> tuple[int, bytes]:
    process = subprocess.Popen(  # noqa: S603 - fixed native argv
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        output, _ = process.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        return 124, b""
    if len(output) > limit:
        return 125, b""
    return process.returncode, output


def journal() -> tuple[dict[str, dict[str, object]], dict[str, dict[str, object]]]:  # noqa: C901 - one journal read
    status, output = bounded(
        [
            "/usr/bin/journalctl",
            "--no-pager",
            "--reverse",
            "-o",
            "cat",
            "-n",
            "500",
            "--grep",
            "^barectl-result ",
        ],
        limit=512 * 1024,
    )
    if status:
        return {}, {}
    newest: dict[str, dict[str, object]] = {}
    copies: dict[str, dict[str, object]] = {}
    for line in output.decode("utf-8", "replace").splitlines():
        if not line.startswith("barectl-result "):
            continue
        try:
            value = json.loads(line[len("barectl-result ") :])
        except ValueError:
            continue
        if not isinstance(value, dict) or value.get("kind") not in ("backup", "copy", "restore"):
            continue
        identifier = value.get("site")
        if not isinstance(identifier, str) or not identifier:
            continue
        if value.get("kind") == "copy":
            if identifier in copies:
                continue
            copy: dict[str, object] = {}
            for key in ("class", "reason", "at", "point"):
                item = value.get(key)
                copy[key] = item if isinstance(item, str) and len(item) <= MAX_TEXT else ""
            if copy["class"] in ("succeeded", "partial", "failed", "refused", "lock_busy"):
                copies[identifier] = copy
            continue
        if identifier in newest:
            continue
        row: dict[str, object] = {}
        for key in ("class", "reason", "scope", "origin", "at", "point", "offsite"):
            item = value.get(key)
            row[key] = item if isinstance(item, str) and len(item) <= MAX_TEXT else ""
        for key in ("snapshots", "bytes"):
            item = value.get(key)
            row[key] = item if type(item) is int and item >= 0 else 0
        if row["class"] not in ("succeeded", "partial", "failed", "refused", "lock_busy"):
            continue
        if row["offsite"] not in ("", "copied", "failed"):
            row["offsite"] = ""
        newest[identifier] = row
    return newest, copies


def config_values(text: str) -> dict[str, object] | None:
    """The non-secret offsite setting, or ``None`` when it is outside the template."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        name, separator, value = line.partition("=")
        if (
            not separator
            or name in values
            or name not in ("provider", "bucket", "region", "endpoint", "prefix", "prune")
        ):
            return None
        values[name] = value
    if set(values) != {"provider", "bucket", "region", "endpoint", "prefix", "prune"}:
        return None
    provider = values.get("provider", "")
    endpoint = values.get("endpoint", "")
    if (
        provider not in PROVIDERS
        or not values.get("bucket")
        or len(values["bucket"]) > 63
        or not values.get("region")
        or len(values["region"]) > 32
        or not endpoint.startswith("https://")
        or len(endpoint) > 200
        or not values.get("prefix")
        or len(values["prefix"]) > 200
        or ".." in values["prefix"].split("/")
        or values.get("prune") not in ("yes", "no")
    ):
        return None
    return {
        "provider": provider,
        "bucket": values["bucket"],
        "region": values["region"],
        "endpoint": endpoint,
        "prefix": values["prefix"],
        "prune": values["prune"] == "yes",
        "problem": "",
    }


def offsite() -> dict[str, object] | None:
    if not os.path.lexists(OFFSITE_ROOT):
        return None
    if not controlled(OFFSITE_ROOT):
        return {
            "provider": "",
            "bucket": "",
            "region": "",
            "endpoint": "",
            "prefix": "",
            "prune": False,
            "problem": "The offsite storage setting is outside supported settings.",
        }
    config = metadata(OFFSITE_CONFIG)
    if config is None:
        return None
    safe = bool(
        config.get("uid") == 0
        and config.get("gid") == 0
        and config.get("type") == stat.S_IFREG
        and config.get("mode") == 0o600
        and config.get("links") == 1
    )
    if not safe:
        return {
            "provider": "",
            "bucket": "",
            "region": "",
            "endpoint": "",
            "prefix": "",
            "prune": False,
            "problem": "The offsite storage setting is outside supported settings.",
        }
    try:
        text = pathlib.Path(OFFSITE_CONFIG).read_text(encoding="utf-8")
    except OSError:
        text = ""
    value = config_values(text)
    if value is None:
        return {
            "provider": "",
            "bucket": "",
            "region": "",
            "endpoint": "",
            "prefix": "",
            "prune": metadata(OFFSITE_PRUNE) is not None,
            "problem": "The offsite storage setting is outside supported settings.",
        }
    value["prune"] = metadata(OFFSITE_PRUNE) is not None
    for path in (OFFSITE_CAPTURE, OFFSITE_PRUNE):
        found = metadata(path)
        if found is not None and not (
            found.get("uid") == 0
            and found.get("gid") == 0
            and found.get("type") == stat.S_IFREG
            and found.get("mode") == 0o600
            and found.get("links") == 1
        ):
            value["problem"] = "The offsite storage keys are outside supported settings."
    if metadata(OFFSITE_CAPTURE) is None:
        value["problem"] = "The offsite storage keys are missing."
    return value


def main() -> None:
    payload = json.loads(sys.argv[1])
    engine = str(payload.get("engine", ""))
    sites = payload.get("sites")
    known = payload.get("known")
    if (
        not isinstance(sites, list)
        or len(sites) > MAX_SITES
        or not all(isinstance(item, str) for item in sites)
        or not isinstance(known, list)
        or not all(isinstance(item, str) and item.startswith("/nix/store/") for item in known)
    ):
        raise SystemExit(1)
    profile = os.path.realpath(RESTIC_PROFILE) if os.path.lexists(RESTIC_PROFILE) else ""
    root_safe = (not os.path.lexists(REPOSITORY_ROOT) or controlled(REPOSITORY_ROOT)) and (
        not os.path.lexists(KEY_ROOT) or controlled(KEY_ROOT)
    )
    latest, copies = journal()
    storage = offsite()
    rows = []
    for identifier in sites:
        problems = []
        if not root_safe:
            problems.append("The backup directory is outside supported settings.")
        if profile and profile not in known:
            problems.append("The backup tool is outside supported settings.")
        directory = f"{REPOSITORY_ROOT}/{identifier}"
        repository = directory + "/onsite"
        key = f"{KEY_ROOT}/{identifier}.key"
        if os.path.lexists(directory) and not controlled(directory):
            problems.append("The site's backup directory is outside supported settings.")
        config = metadata(repository + "/config")
        repository_present = bool(
            config
            and config.get("uid") == 0
            and config.get("gid") == 0
            and config.get("type") == stat.S_IFREG
            and config.get("mode") in (0o400, 0o600)
            and config.get("links") == 1
        )
        if config is not None and not repository_present:
            problems.append("The site's backup repository is outside supported settings.")
        key_value = metadata(key)
        key_present = bool(
            key_value
            and key_value.get("uid") == 0
            and key_value.get("gid") == 0
            and key_value.get("type") == stat.S_IFREG
            and key_value.get("mode") == 0o600
            and key_value.get("links") == 1
        )
        if key_value is not None and not key_present:
            problems.append("The site's backup key is outside supported settings.")
        if repository_present != key_present or (
            (repository_present or key_present) and not profile
        ):
            problems.append("The site's backup setup is incomplete.")
        found, database_problem = (
            database_present(engine, identifier)
            if site_account(identifier)
            else (False, "The site's Linux account could not be read.")
        )
        rows.append(
            {
                "identifier": identifier,
                "profile": profile,
                "repository": repository_present,
                "key": key_present,
                "problems": problems[:8],
                "database": found,
                "database_problem": database_problem[:MAX_TEXT],
                "last": latest.get(identifier),
                "copy": copies.get(identifier),
            }
        )
    sys.stdout.write(
        json.dumps({"version": 1, "sites": rows, "offsite": storage}, separators=(",", ":"))
    )


if __name__ == "__main__":
    main()
