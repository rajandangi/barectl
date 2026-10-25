"""The native body that removes one site and every resource of its convention.

docs/sites.md, the phase specification's removal bullet and ADR 0035. Executed as root by
the change engine's staged payload under the mutation lock. It rechecks the reviewed
inventory, gates the site, removes its Caddy file and reloads only after the remaining
tree validates, stops and disables its services, removes its FPM and HAProxy
configuration, drops its database and principal, removes its stored certificates, its
directory and its accounts, and proves that nothing of it remains while the other sites
keep their Caddy configuration.

This module is also a complete Python module for the fast layer: it imports the site
helpers it uses. When a body is assembled, those imports are stripped and the helpers are
inlined from ``sites.observation``'s ``COMMON_SOURCE``.
"""

import base64
import grp
import gzip
import hashlib
import json
import os
import pathlib
import pwd
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from typing import TYPE_CHECKING

from sites.bodies.admission import haproxy_state
from sites.bodies.common import (
    adapt,
    caddy_binary,
    caddy_data_directory,
    candidate_tree,
    canonical,
    certificate_names,
    copied_directory,
    current_bytes,
    extract,
    maintenance_file,
    publish_caddy,
    reload_caddy,
    replace_caddy,
    result,
    run,
    running,
    setting,
    stage,
    walk_routes,
)

if TYPE_CHECKING:
    # Assembled into this body by automation/bodies/source.py (Phase C #395).
    from automation.bodies.units import daemon_reload, fence, forget, reviewed_units

# The ``databases.binding`` source, injected at assembly time.
BINDING_SOURCE = ""

IDENTIFIER = re.compile(r"[a-z][a-z0-9]{2,23}")
RUNTIMES = ("php84", "php85")
CERTIFICATE_SUFFIXES = (".crt", ".key", ".json")
MARIADB = "mariadb"
POSTGRESQL = "postgresql"


def site_paths(identifier: str) -> list[str]:
    """Every reviewed site artifact; the last four belong to its own object cache (#392)."""
    return [
        f"/etc/caddy/sites/{identifier}.caddy",
        f"/etc/haproxy/sites/{identifier}.cfg",
        f"/var/lib/haproxy/sites/{identifier}.state",
        f"/run/haproxy/{identifier}",
        f"/etc/php-fpm/sites/{identifier}",
        f"/var/lib/php-fpm/sites/{identifier}",
        f"/run/php-fpm/sites/{identifier}",
        f"/var/www/{identifier}",
        f"/etc/valkey/{identifier}.conf",
        f"/var/lib/valkey/{identifier}",
        f"/run/valkey/{identifier}",
        f"/etc/systemd/system/valkey-server@{identifier}.service.d",
    ]


def service_units(identifier: str) -> list[str]:
    return [
        f"haproxy-site@{identifier}.service",
        *(f"php-fpm-site-{entry}@{identifier}.service" for entry in RUNTIMES),
        f"valkey-server@{identifier}.service",
    ]


def exists(path: str) -> bool:
    try:
        os.lstat(path)
    except OSError:
        return False
    return True


def account(name: str) -> list[object] | None:
    try:
        found = pwd.getpwnam(name)
    except KeyError:
        return None
    return [
        found.pw_uid,
        found.pw_gid,
        found.pw_dir,
        found.pw_shell,
        sorted(os.getgrouplist(found.pw_name, found.pw_gid)),
    ]


def group(name: str) -> list[object] | None:
    try:
        found = grp.getgrnam(name)
    except KeyError:
        return None
    return [found.gr_gid, sorted(found.gr_mem)]


def service(unit: str) -> list[str]:
    try:
        text = run(
            [
                "/usr/bin/systemctl",
                "show",
                "--value",
                "-p",
                "LoadState",
                "-p",
                "ActiveState",
                "-p",
                "SubState",
                unit,
            ]
        )
    except ValueError, OSError, subprocess.TimeoutExpired:
        return ["not-found", "inactive", "dead"]
    lines = text.splitlines()
    return lines if len(lines) == 3 else ["not-found", "inactive", "dead"]


def file_names(identifier: str, path: pathlib.Path) -> tuple[list[str], bool, str]:
    """The names the file serves, its HTTPS setting and the runtime it selects."""
    try:
        value = adapt(path.read_text())
    except ValueError, OSError, subprocess.TimeoutExpired:
        return [], True, ""
    try:
        settings = extract(identifier, value)
    except ValueError:
        hosts: list[list[str]] = []
        walk_routes(value, hosts, set(), set())
        names = sorted({name for group_ in hosts for name in group_})
        return names, True, ""
    runtime = ""
    try:
        runtime = str(haproxy_state(settings)["selection"])
    except ValueError, KeyError, OSError, subprocess.TimeoutExpired:
        runtime = ""
    return list(settings.names), bool(settings.https), runtime if runtime in RUNTIMES else ""


def certificates(names: list[str]) -> list[str]:  # noqa: C901 - Caddy storage
    """Caddy's stored certificate directories for exactly these names, in order."""
    if not names:
        return []
    base = pathlib.Path(caddy_data_directory()) / "certificates"
    if base.is_symlink() or not base.is_dir():
        return []
    found: list[str] = []
    for issuer in sorted(base.iterdir(), key=lambda path: path.name):
        if issuer.is_symlink() or not issuer.is_dir():
            continue
        for candidate in sorted(issuer.iterdir(), key=lambda path: path.name):
            if candidate.is_symlink() or not candidate.is_dir():
                continue
            covered = candidate.name in names
            if not covered:
                for entry in sorted(candidate.glob("*.crt")):
                    if set(certificate_names(str(entry))).intersection(names):
                        covered = True
                        break
            if covered:
                found.append(str(candidate))
    return found


def inventory(identifier: str) -> dict[str, object]:
    """The site artifacts a review names and the body rechecks under the mutation lock."""
    if IDENTIFIER.fullmatch(identifier) is None:
        raise ValueError("Not a site identifier.")
    paths = {path: exists(path) for path in site_paths(identifier)}
    site_file = f"/etc/caddy/sites/{identifier}.caddy"
    names: list[str] = []
    https = True
    runtime = ""
    problem = ""
    if paths[site_file]:
        names, https, runtime = file_names(identifier, pathlib.Path(site_file))
        if not names:
            problem = "The site's Caddy file does not name a readable host."
    other = sorted(
        path.stem
        for path in pathlib.Path("/etc/caddy/sites").glob("*.caddy")
        if path.stem != identifier
    )
    try:
        caddy_matches = adapt() == running()
    except ValueError, OSError, subprocess.TimeoutExpired:
        caddy_matches = False
    value: dict[str, object] = {
        "version": 1,
        "identifier": identifier,
        "boot": pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "uptime": int(float(pathlib.Path("/proc/uptime").read_text().split()[0]) * 100),
        "paths": paths,
        "names": names,
        "https": https,
        "runtime": runtime,
        "problem": problem,
        "site_file_digest": (
            hashlib.sha256(pathlib.Path(site_file).read_bytes()).hexdigest()
            if paths[site_file]
            else ""
        ),
        "account": account("s" + identifier),
        "proxy_account": account("p" + identifier),
        "account_group": group("s" + identifier),
        "proxy_group": group("p" + identifier),
        "certificates": certificates(names),
        "services": {unit: service(unit) for unit in service_units(identifier)},
        "other_sites": other,
        "caddy_matches": caddy_matches,
        "caddy_data_directory": caddy_data_directory(),
    }
    # The clock advances and services may restart between preparation and apply; the
    # digest binds the artifacts, not the uptime or a service's transient state.
    stable = {key: item for key, item in value.items() if key not in ("uptime", "services")}
    value["digest"] = hashlib.sha256(canonical(stable).encode()).hexdigest()
    return value


def remove_automation(document: dict[str, object], identifier: str) -> None:
    """Remove the reviewed automation unit files and clear their runtime masks.

    The fence already masked and stopped them; removal never starts them again
    (docs/automation.md#fencing).
    """
    names = reviewed_units(document, identifier)
    for name in names:
        remove_path(f"/etc/systemd/system/{name}")
    daemon_reload()
    forget(document, identifier)
    for name in names:
        if exists(f"/etc/systemd/system/{name}"):
            raise ValueError("An automation unit file is still present.")


def remove_path(path: str) -> None:
    """Remove one site artifact without following a link or crossing its boundary."""
    target = pathlib.Path(path)
    try:
        metadata = target.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(metadata.st_mode):
        raise ValueError("A site artifact is a symbolic link.")
    if stat.S_ISDIR(metadata.st_mode):
        shutil.rmtree(target)
    elif stat.S_ISREG(metadata.st_mode) or stat.S_ISFIFO(metadata.st_mode):
        target.unlink()
    else:
        raise ValueError("A site artifact has an unsupported type.")


def validate_removal(identifier: str) -> None:
    """Validate the Caddy tree the server keeps once this site's file is gone."""
    with tempfile.TemporaryDirectory(prefix="site-candidate-", dir="/run") as directory:
        root = pathlib.Path(directory)
        os.chown(root, 0, grp.getgrnam("caddy").gr_gid)
        root.chmod(0o750)
        candidate_tree(root, identifier, "")
        (root / "sites" / (identifier + ".caddy")).unlink()
        scratch = root / "var"
        scratch.mkdir(mode=0o755)
        copied_directory(scratch, "www", 0, 0, 0o755)
        copied_directory(scratch, "lib", 0, 0, 0o755)
        caddy_account = pwd.getpwnam("caddy")
        copied_directory(scratch, "lib/caddy", caddy_account.pw_uid, caddy_account.pw_gid, 0o700)
        for path in (root / "sites").iterdir():
            settings = extract(path.stem, adapt(path.read_text()))
            copied_directory(scratch, "www/" + settings.identifier, 0, 0, 0o755)
            copied_directory(
                scratch,
                "www/" + settings.identifier + "/logs",
                caddy_account.pw_uid,
                caddy_account.pw_gid,
                0o750,
            )
            original = pathlib.Path(settings.directory) / "logs/access.json"
            if original.exists() or original.is_symlink():
                metadata = original.lstat()
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise ValueError("Validation refuses an unsafe access-log entry.")
                copied = scratch / "www" / settings.identifier / "logs/access.json"
                copied.touch()
                os.chown(copied, metadata.st_uid, metadata.st_gid)
                copied.chmod(stat.S_IMODE(metadata.st_mode))
        run(
            [
                "/usr/bin/unshare",
                "--mount",
                "--propagation",
                "private",
                "/bin/sh",
                "-c",
                (
                    '/usr/bin/mount --bind "$1" /var && exec /usr/sbin/runuser '
                    '-u caddy -- "$3" validate '
                    '--config "$2" --adapter caddyfile'
                ),
                "validator",
                str(scratch),
                str(root / "Caddyfile"),
                caddy_binary(),
            ]
        )


def gate(document: dict[str, object]) -> bool:
    """Publish the maintenance gate so visitors see 503 while teardown runs."""
    identifier = str(document["identifier"])
    runtime = str(document.get("runtime", ""))
    names = document.get("names")
    if (
        runtime not in RUNTIMES
        or not isinstance(names, list)
        or not names
        or not all(isinstance(name, str) for name in names)
    ):
        return False
    live = pathlib.Path(f"/etc/caddy/sites/{identifier}.caddy")
    preimage = current_bytes(live)
    if preimage is None:
        return False
    settings = setting(identifier, list(names), runtime, https=bool(document.get("https", True)))
    candidate = maintenance_file(settings)
    if preimage == candidate:
        return False
    if not publish_caddy(identifier, candidate, preimage):
        raise ValueError("Caddy kept its previous configuration.")
    return True


def remove_caddy(identifier: str) -> bool:
    live = pathlib.Path(f"/etc/caddy/sites/{identifier}.caddy")
    preimage = current_bytes(live)
    if preimage is None:
        return False
    old = running()
    if adapt() != old:
        raise ValueError("Caddy's disk and running configurations differ.")
    validate_removal(identifier)
    live.unlink()
    try:
        reload_caddy()
        if running() != adapt():
            raise ValueError("Caddy's loaded configuration differs from disk.")
        return True
    except ValueError, OSError, subprocess.TimeoutExpired:
        replace_caddy(live, preimage, None)
        reload_caddy()
        if adapt() != old or running() != old:
            raise ValueError("Caddy's previous configuration could not be proven.") from None
        raise ValueError("The remaining Caddy tree could not be loaded.") from None


def stop_services(identifier: str) -> None:
    for unit in service_units(identifier):
        for action in ("stop", "disable", "reset-failed"):
            subprocess.run(  # noqa: S603 - fixed reviewed unit name
                ["/usr/bin/systemctl", action, unit],
                capture_output=True,
                timeout=120,
                check=False,
            )
    for unit in service_units(identifier):
        state = service(unit)
        if state and state[1] not in ("inactive", "failed", ""):
            raise ValueError("A site service is still active.")


def binding_namespace() -> dict[str, object]:
    namespace: dict[str, object] = {"__name__": "databases.binding"}
    exec(compile(BINDING_SOURCE, "databases/binding.py", "exec"), namespace)  # noqa: S102
    return namespace


def database_text(document: dict[str, object]) -> str | None:
    engine = str(document.get("engine", ""))
    read_command = document.get("read_command")
    if engine not in (MARIADB, POSTGRESQL) or not isinstance(read_command, str):
        return None
    try:
        completed = subprocess.run(  # noqa: S603 - the reviewed fixed read
            ["/bin/sh", "-c", read_command],
            capture_output=True,
            timeout=20,
            check=False,
        )
    except OSError, subprocess.TimeoutExpired:
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.decode("utf-8", "replace")


def database_facts(document: dict[str, object]) -> dict[str, str] | None:
    text = database_text(document)
    if text is None:
        return None
    engine = str(document.get("engine", ""))
    parse = binding_namespace()["parse_facts"]
    if not callable(parse):
        return None
    try:
        return parse(engine, text)  # type: ignore[no-any-return]
    except ValueError:
        return None


def admin_argv(engine: str, database: str, statement: str) -> list[str]:
    if engine == MARIADB:
        return [
            "/usr/bin/mariadb",
            "--no-defaults",
            "--protocol=socket",
            "--socket=/run/mysqld/mysqld.sock",
            "--user=root",
            "-e",
            statement,
        ]
    psql = ["/usr/bin/psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", database, "-c", statement]
    if database == "postgres":
        return ["/usr/bin/su", "-", "postgres", "-c", shlex.join(psql)]
    return ["/usr/sbin/runuser", "-u", database, "--", *psql]


def database_absent(document: dict[str, object]) -> bool | None:
    facts = database_facts(document)
    if facts is None:
        return None
    return facts.get("database") == "0" and facts.get("principal") == "0"


def drop_database(document: dict[str, object]) -> str:  # noqa: C901 - reviewed statements
    database = document.get("database")
    if not isinstance(database, dict):
        return "site_remove_database"
    if not database.get("exists"):
        absent = database_absent(database)
        if absent is None:
            return "" if not database.get("engine") else "site_remove_database"
        return "" if absent else "site_remove_database"
    engine = str(database.get("engine", ""))
    if engine not in (MARIADB, POSTGRESQL):
        return "site_remove_database"
    if database_absent(database) is not False:
        # Absent already is fine; an unreadable catalog is not.
        if database_absent(database) is None:
            return "site_remove_database"
        return ""
    statements = database.get("statements")
    if not isinstance(statements, list) or not statements:
        return "site_remove_database"
    for entry in statements:
        if (
            not isinstance(entry, list)
            or len(entry) != 3
            or not all(isinstance(value, str) for value in entry)
        ):
            return "site_remove_database"
        completed = subprocess.run(  # noqa: S603 - fixed reviewed statement
            admin_argv(engine, entry[1], entry[2]),
            capture_output=True,
            timeout=120,
            check=False,
        )
        if completed.returncode != 0:
            return "site_remove_database"
    if not database_absent(database):
        return "site_remove_database"
    return ""


def remove_certificates(document: dict[str, object]) -> str:
    values = document.get("certificates")
    if not isinstance(values, list):
        return "site_remove_certificate"
    for value in values:
        if not isinstance(value, str):
            return "site_remove_certificate"
        target = pathlib.Path(value)
        if target.is_symlink() or not target.is_dir():
            return "site_remove_certificate"
        for entry in sorted(target.iterdir(), key=lambda path: path.name):
            if entry.is_symlink() or not entry.is_file():
                return "site_remove_certificate"
            if entry.suffix not in CERTIFICATE_SUFFIXES:
                return "site_remove_certificate"
            entry.unlink()
        target.rmdir()
    return ""


def wait_for_account(name: str, seconds: float = 5.0) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if (
            subprocess.run(  # noqa: S603 - fixed account name
                ["/usr/bin/pgrep", "-u", name], capture_output=True, check=False
            ).returncode
            != 0
        ):
            return
        time.sleep(0.1)


def remove_accounts(document: dict[str, object]) -> str:
    identifier = str(document["identifier"])
    for name in ("s" + identifier, "p" + identifier):
        facts = account(name)
        if facts is None:
            continue
        reviewed = document.get("account" if name.startswith("s") else "proxy_account")
        if reviewed is not None and reviewed != facts:
            return "site_remove_accounts"
        wait_for_account(name)
        completed = subprocess.run(  # noqa: S603 - fixed account name
            ["/usr/sbin/userdel", name], capture_output=True, timeout=60, check=False
        )
        if completed.returncode != 0:
            return "site_remove_accounts"
        subprocess.run(  # noqa: S603 - fixed group name
            ["/usr/sbin/groupdel", name], capture_output=True, timeout=60, check=False
        )
    for name in ("s" + identifier, "p" + identifier):
        if group(name) is not None:
            subprocess.run(  # noqa: S603 - fixed group name
                ["/usr/sbin/groupdel", name], capture_output=True, timeout=60, check=False
            )
    return ""


def verify(document: dict[str, object]) -> str:
    identifier = str(document["identifier"])
    current = inventory(identifier)
    paths = current.get("paths")
    if isinstance(paths, dict) and any(paths.values()):
        return "site_remove_verify"
    if current.get("account") is not None or current.get("proxy_account") is not None:
        return "site_remove_verify"
    if current.get("account_group") is not None or current.get("proxy_group") is not None:
        return "site_remove_verify"
    if current.get("certificates"):
        return "site_remove_verify"
    if not current.get("caddy_matches"):
        return "site_remove_verify"
    expected = document.get("other_sites")
    if isinstance(expected, list) and list(expected) != current.get("other_sites"):
        return "site_remove_verify"
    database = document.get("database")
    if (
        isinstance(database, dict)
        and database.get("engine")
        and database_absent(database) is not True
    ):
        return "site_remove_database"
    return ""


def remove(document: dict[str, object]) -> int:  # noqa: C901 - one reviewed sequence
    identifier = document.get("identifier")
    if not isinstance(identifier, str) or IDENTIFIER.fullmatch(identifier) is None:
        result("refused", "site_remove")
        return 1
    stage("preflight")
    try:
        current = inventory(identifier)
    except ValueError, OSError, KeyError, subprocess.TimeoutExpired:
        result("refused", "site_remove_evidence")
        return 1
    if current["digest"] != document.get("site_digest"):
        result("refused", "precondition")
        return 1
    if document.get("site_file_digest") != current["site_file_digest"]:
        result("refused", "precondition")
        return 1
    database = document.get("database")
    if isinstance(database, dict) and database.get("engine"):
        text = database_text(database)
        if text is None or hashlib.sha256(text.encode()).hexdigest() != database.get(
            "catalog_digest"
        ):
            result("refused", "precondition")
            return 1
    changed = False
    try:
        if not fence(document, identifier):
            result("refused", "automation_fence")
            return 1
        if not current["caddy_matches"]:
            # A previous attempt may have left Caddy serving its old in-memory
            # configuration after the file changed. Make disk and memory agree before
            # the remaining reviewed removals run.
            reload_caddy()
            changed = True
            current = inventory(identifier)
            if not current["caddy_matches"]:
                result("refused", "site_remove_caddy")
                return 1
        stage("gate")
        changed = gate(document) or changed
        stage("caddy")
        changed = remove_caddy(identifier) or changed
        stage("services")
        stop_services(identifier)
        changed = True
        stage("configuration")
        remove_automation(document, identifier)
        # The Caddy file is gone already and the site directory is removed after the
        # database; every other reviewed path is removed by name, never by position.
        keep = {f"/etc/caddy/sites/{identifier}.caddy", f"/var/www/{identifier}"}
        for path in site_paths(identifier):
            if path not in keep:
                remove_path(path)
        stage("database")
        reason = drop_database(document)
        if reason:
            result("partial", reason)
            return 2
        stage("certificate")
        reason = remove_certificates(document)
        if reason:
            result("partial", reason)
            return 2
        stage("files")
        remove_path(f"/var/www/{identifier}")
        stage("accounts")
        reason = remove_accounts(document)
        if reason:
            result("partial", reason)
            return 2
        stage("verify")
        reason = verify(document)
        if reason:
            result("partial", reason)
            return 2
        result("succeeded")
        return 0
    except ValueError, OSError, KeyError, subprocess.TimeoutExpired:
        result("partial" if changed else "refused", "site_remove")
        return 2 if changed else 1


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv if argv is None else argv
    if len(arguments) != 2:
        return 3
    document = json.loads(gzip.decompress(base64.b64decode(arguments[1])))
    return remove(document)
