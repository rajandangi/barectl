import base64
import hashlib
import json
import os
import pathlib
import pwd
import shlex
import stat
import sys
import time
from collections.abc import Sequence
from contextlib import suppress

from runtimes.bounded import bounded

selection, fcgi_path, expected_probe, expected_unit = sys.argv[1:]
root = pathlib.Path("/nix/var/nix/profiles/barectl")
entries = ("php84", "php85", "nodejs_22", "nodejs_24")
EXPECTED_FILES: dict[str, dict[str, str]] = {}
KNOWN_FCGI: dict[str, tuple[str, ...]] = {}
fcgi_profile = root / "fcgi"
if fcgi_profile.exists() or fcgi_profile.is_symlink():
    observed_fcgi = os.path.realpath(fcgi_profile)
    fcgi_path = observed_fcgi if observed_fcgi in KNOWN_FCGI.get(os.uname().machine, ()) else ""


def run(arguments: list[str]) -> str | None:
    try:
        status, output = bounded(shlex.join(arguments) + " 2>/dev/null", limit=32768)
        if status:
            return None
        return output.decode("utf-8")
    except OSError, ValueError:
        return None


def file(path: str | pathlib.Path) -> dict[str, object] | None:
    try:
        p = pathlib.Path(path)
        meta = p.lstat()
        value: dict[str, object] = {
            "uid": meta.st_uid,
            "gid": meta.st_gid,
            "mode": stat.S_IMODE(meta.st_mode),
            "type": stat.S_IFMT(meta.st_mode),
            "ctime": meta.st_ctime_ns,
            "mtime": meta.st_mtime_ns,
        }
        if stat.S_ISLNK(meta.st_mode):
            value["link"] = os.readlink(p)
        elif stat.S_ISREG(meta.st_mode):
            if meta.st_size > 65536:
                return {"unreadable": True}
            value["bytes"] = base64.b64encode(p.read_bytes()).decode()
        after = p.lstat()
        if (after.st_ino, after.st_ctime_ns, after.st_mtime_ns) != (
            meta.st_ino,
            meta.st_ctime_ns,
            meta.st_mtime_ns,
        ):
            return {"unreadable": True}
        return value
    except FileNotFoundError:
        return None
    except OSError:
        return {"unreadable": True}


def identity() -> list[object] | None:
    try:
        user = pwd.getpwnam("php-probe")
        return [
            user.pw_uid,
            user.pw_gid,
            user.pw_dir,
            user.pw_shell,
            sorted(os.getgrouplist("php-probe", user.pw_gid)),
        ]
    except KeyError:
        return None


def paths(entry: str) -> list[str]:
    if entry.startswith("nodejs_"):
        return [
            f"/nix/var/nix/profiles/barectl/{entry}",
            "/etc/nix/nix.conf",
            "/nix/var/nix/profiles/default",
        ]
    values = [
        f"/nix/var/nix/profiles/barectl/{entry}",
        "/nix/var/nix/profiles/barectl/fcgi",
        "/etc/systemd/system/php-fpm@.service",
        "/etc/php-fpm",
        "/etc/php-fpm/diagnostics",
        "/etc/php-fpm/diagnostics/probe.php",
    ]
    if entry.startswith("php"):
        values += [
            f"/etc/php-fpm/{entry}",
            f"/etc/php-fpm/{entry}/php.ini",
            f"/etc/php-fpm/{entry}/php-fpm.conf",
            f"/etc/php-fpm/{entry}/pools",
            f"/etc/php-fpm/{entry}/pools/diagnostic.conf",
        ]
        with suppress(FileNotFoundError):
            values += sorted(str(p) for p in pathlib.Path(f"/etc/php-fpm/{entry}/pools").iterdir())[
                :64
            ]
    return sorted(set(values))


def digest(entry: str) -> str:
    values: dict[str, object] = {path: file(path) for path in paths(entry)}
    if entry.startswith("php"):
        values["identity"] = identity()
        directory = pathlib.Path("/etc/php-fpm/diagnostics")
        values["diagnostic_entries"] = (
            {str(path): file(path) for path in sorted(directory.iterdir())[:8]}
            if directory.is_dir()
            else None
        )
    values["profile_target"] = os.path.realpath(root / entry)
    return hashlib.sha256(
        json.dumps(values, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def controlled_root_directory(path: str) -> bool:
    metadata = file(path)
    return bool(
        metadata
        and metadata.get("uid") == 0
        and metadata.get("type") == stat.S_IFDIR
        and isinstance(metadata.get("mode"), int)
        and int(str(metadata["mode"])) & 0o022 == 0
    )


def shared_diagnostic_safe(user: list[object] | None) -> bool:
    directory = file("/etc/php-fpm/diagnostics")
    probe = file("/etc/php-fpm/diagnostics/probe.php")
    if user is None:
        return directory is None and probe is None
    return all(
        metadata is None or (metadata.get("gid") == user[1] and metadata.get("mode") == mode)
        for metadata, mode in ((directory, 0o750), (probe, 0o640))
    )


def admissible(entry: str) -> bool:
    if entry.startswith("nodejs_"):
        return all(
            controlled_root_directory(path)
            for path in ("/nix", "/nix/var", "/nix/var/nix", "/nix/var/nix/profiles", str(root))
        )
    directory = pathlib.Path("/etc/php-fpm/diagnostics")
    if directory.is_dir() and any(path.name != "probe.php" for path in directory.iterdir()):
        return False
    profile = file(root / entry)
    target = file(f"/etc/php-fpm/{entry}")
    if profile is None and entry.startswith("php") and target is not None:
        return False
    for path in (
        "/nix",
        "/nix/var",
        "/nix/var/nix",
        "/nix/var/nix/profiles",
        str(root),
        "/etc",
        "/etc/php-fpm",
        "/etc/php-fpm/diagnostics",
        "/etc/systemd",
        "/etc/systemd/system",
    ):
        metadata = file(path)
        if metadata is not None and (
            metadata.get("uid") != 0
            or metadata.get("type") != stat.S_IFDIR
            or not isinstance(metadata.get("mode"), int)
            or int(str(metadata["mode"])) & 0o022
        ):
            return False
    for path, expected in (
        ("/etc/systemd/system/php-fpm@.service", expected_unit),
        ("/etc/php-fpm/diagnostics/probe.php", expected_probe),
    ):
        metadata = file(path)
        if metadata is not None and (
            metadata.get("uid") != 0
            or metadata.get("type") != stat.S_IFREG
            or metadata.get("bytes") != expected
            or not isinstance(metadata.get("mode"), int)
            or int(str(metadata["mode"])) & 0o022
        ):
            return False
    user = identity()
    if user is not None and (
        user[0] == 0 or user[2:4] != ["/nonexistent", "/usr/sbin/nologin"] or user[4] != [user[1]]
    ):
        return False
    if not shared_diagnostic_safe(user):
        return False
    tool = file(root / "fcgi")
    return tool is None or os.path.realpath(root / "fcgi") == fcgi_path


def matches_file(path: str, content: str) -> bool:
    metadata = file(path)
    return bool(
        metadata
        and metadata.get("uid") == 0
        and metadata.get("gid") == 0
        and metadata.get("type") == stat.S_IFREG
        and metadata.get("mode") in (0o600, 0o644)
        and metadata.get("bytes") == content
    )


def diagnostic_pools_only(entry: str) -> bool:
    return sorted(
        path.name for path in pathlib.Path(f"/etc/php-fpm/{entry}/pools").glob("*.conf")
    ) == ["diagnostic.conf"]


def diagnostic_safe(entry: str) -> bool:
    expected = EXPECTED_FILES.get(entry)
    user = identity()
    directory_path = pathlib.Path("/etc/php-fpm/diagnostics")
    if directory_path.is_dir() and any(
        path.name != "probe.php" for path in directory_path.iterdir()
    ):
        return False
    if expected is None or user is None or not isinstance(user[0], int) or user[0] <= 0:
        return False
    if user[2:4] != ["/nonexistent", "/usr/sbin/nologin"] or user[4] != [user[1]]:
        return False
    directory = file("/etc/php-fpm/diagnostics")
    probe = file("/etc/php-fpm/diagnostics/probe.php")
    if (
        directory is None
        or directory.get("mode") != 0o750
        or directory.get("gid") != user[1]
        or probe is None
        or probe.get("mode") != 0o640
        or probe.get("gid") != user[1]
    ):
        return False
    if not matches_file(f"/etc/php-fpm/{entry}/php-fpm.conf", expected["master"]):
        return False
    if not matches_file(f"/etc/php-fpm/{entry}/pools/diagnostic.conf", expected["pool"]):
        return False
    if not diagnostic_pools_only(entry):
        return False
    metadata = file(f"/etc/php-fpm/{entry}/php.ini")
    if metadata is None or metadata.get("uid") != 0 or metadata.get("type") != stat.S_IFREG:
        return False
    encoded = metadata.get("bytes")
    if not isinstance(encoded, str):
        return False
    values = dict(
        line.split("=", 1)
        for line in base64.b64decode(encoded).decode().splitlines()
        if "=" in line
    )
    allowed = {
        "opcache.enable",
        "opcache.validate_permission",
        "opcache.validate_root",
        "expose_php",
    }
    return (
        set(values) == allowed | {"opcache.restrict_api", "opcache.file_cache", "opcache.preload"}
        and all(values[key] in ("0", "1") for key in allowed)
        and values["opcache.restrict_api"] == "/etc/php-fpm/diagnostics/"
        and values["opcache.file_cache"] == values["opcache.preload"] == ""
    )


def bus_properties(
    entry: str, interface: str, properties: tuple[tuple[str, str], ...]
) -> dict[str, object] | None:
    result = run(
        [
            "busctl",
            "--json=short",
            "get-property",
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1/unit/php_2dfpm_40" + entry + "_2eservice",
            "org.freedesktop.systemd1." + interface,
            *(name for name, _ in properties),
        ]
    )
    if result is None:
        return None
    try:
        lines = result.splitlines()
        if len(lines) != len(properties):
            return None
        values: dict[str, object] = {}
        for line, (name, expected_type) in zip(lines, properties, strict=True):
            value: object = json.loads(line)
            if not isinstance(value, dict) or set(value) != {"type", "data"}:
                return None
            if value["type"] != expected_type:
                return None
            values[name] = value["data"]
        return values
    except ValueError:
        return None


def execution_context(entry: str) -> dict[str, object] | None:
    values = bus_properties(
        entry,
        "Service",
        (
            ("ExecMainStartTimestamp", "t"),
            ("ExecMainStartTimestampMonotonic", "t"),
            ("ExecStart", "a(sasbttttuii)"),
            ("ExecReload", "a(sasbttttuii)"),
            ("Environment", "as"),
            ("EnvironmentFiles", "a(sb)"),
            ("PassEnvironment", "as"),
            ("UnsetEnvironment", "as"),
        ),
    )
    unit = bus_properties(entry, "Unit", (("DropInPaths", "as"),))
    if values is None or unit is None:
        return None
    return {**values, **unit}


def supported_execution(entry: str, pid: str, context: dict[str, object]) -> bool:
    commands = context["ExecStart"]
    executable = str(root / entry / "bin/php-fpm")
    argv = [
        executable,
        "-y",
        f"/etc/php-fpm/{entry}/php-fpm.conf",
        "-c",
        f"/etc/php-fpm/{entry}/php.ini",
    ]
    if not isinstance(commands, list) or len(commands) != 1 or not isinstance(commands[0], list):
        return False
    command = commands[0]
    if len(command) != 10 or command[:2] != [executable, argv] or command[2] is not False:
        return False
    if any(type(value) is not int for value in command[3:]):
        return False
    return (
        command[3:5]
        == [context["ExecMainStartTimestamp"], context["ExecMainStartTimestampMonotonic"]]
        and command[3] > 0
        and command[4] > 0
        and command[5:7] == [0, 0]
        and command[7] == int(pid)
        and command[8:] == [0, 0]
        and all(
            context[name] == []
            for name in (
                "Environment",
                "EnvironmentFiles",
                "PassEnvironment",
                "UnsetEnvironment",
                "DropInPaths",
            )
        )
    )


def load_boundary(
    context: dict[str, object], offset: int
) -> tuple[int, int, list[object], bool] | None:
    start, monotonic, reload = (
        context["ExecMainStartTimestamp"],
        context["ExecMainStartTimestampMonotonic"],
        context["ExecReload"],
    )
    if type(start) is not int or type(monotonic) is not int or start <= 0 or monotonic <= 0:
        return None
    if not isinstance(reload, list) or len(reload) != 1 or not isinstance(reload[0], list):
        return None
    command = reload[0]
    if len(command) != 10 or command[:2] != ["/bin/kill", ["/bin/kill", "-USR2", "$MAINPID"]]:
        return None
    if command[2] is not False or any(type(value) is not int for value in command[3:]):
        return None
    reloaded = command[3] > start
    if reloaded:
        if command[4] <= monotonic or command[5] < command[3] or command[6] < command[4]:
            return None
        if command[7] <= 0 or command[8:] != [1, 0]:
            return None
        start, monotonic = command[3], command[4]
    if abs(start - monotonic - offset) > 1000000:
        return None
    return start, monotonic, command, reloaded


def journal_event_clocks(
    event: dict[str, object], pid: str, invocation: str, executable: str, boot: str, offset: int
) -> tuple[int, int] | None:
    if any(
        event.get(key) != value
        for key, value in {
            "_PID": pid,
            "_UID": "0",
            "_EXE": executable,
            "_BOOT_ID": boot,
            "_SYSTEMD_INVOCATION_ID": invocation,
            "_TRANSPORT": "syslog",
        }.items()
    ):
        return None
    real, mono = event.get("__REALTIME_TIMESTAMP"), event.get("__MONOTONIC_TIMESTAMP")
    if not isinstance(real, str) or not real.isdecimal():
        return None
    if not isinstance(mono, str) or not mono.isdecimal():
        return None
    if abs(int(real) - int(mono) - offset) > 1000000:
        return None
    return int(real), int(mono)


def complete_load(messages: list[object], pid: str, reloaded: bool) -> bool:
    expected = ["[NOTICE] fpm is running, pid " + pid, "[NOTICE] ready to handle connections"]
    if reloaded:
        if len(messages) != 4 or messages[0] != "[NOTICE] Reloading in progress ...":
            return False
        if not isinstance(messages[1], str) or not messages[1].startswith(
            "[NOTICE] reloading: execvp("
        ):
            return False
        messages = messages[2:]
    return messages == expected


def master_load_events(
    pid: str,
    invocation: str,
    executable: str,
    start: int,
    monotonic: int,
    reloaded: bool,
    offset: int,
) -> list[dict[str, object]] | None:
    text = run(
        [
            "journalctl",
            "--no-pager",
            "-b",
            "-o",
            "json",
            "-n",
            "33",
            "--since=@" + str(start // 1000000),
            "_SYSTEMD_INVOCATION_ID=" + invocation,
            "_PID=" + pid,
            (
                "--grep=fpm is running|ready to handle connections|"
                "Reloading in progress|reloading: execvp"
            ),
            (
                "--output-fields=MESSAGE,_TRANSPORT,_EXE,_PID,_UID,_BOOT_ID,"
                "_SYSTEMD_INVOCATION_ID,__REALTIME_TIMESTAMP,__MONOTONIC_TIMESTAMP"
            ),
        ]
    )
    if text is None:
        return None
    try:
        events: list[dict[str, object]] = []
        lines = text.splitlines()
        if len(lines) >= 33:
            return None
        boot = pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-", "")
        for line in lines:
            event: object = json.loads(line)
            if not isinstance(event, dict):
                return None
            clocks = journal_event_clocks(event, pid, invocation, executable, boot, offset)
            if clocks is None:
                return None
            real, mono = clocks
            if mono < monotonic:
                continue
            if real < start:
                return None
            events.append(event)
        events.sort(key=lambda event: int(str(event["__MONOTONIC_TIMESTAMP"])))
        if not complete_load([event.get("MESSAGE") for event in events], pid, reloaded):
            return None
    except OSError, ValueError, KeyError:
        return None
    return events


def load_evidence(entry: str, report: str, executable: str) -> dict[str, object] | None:
    properties = dict(line.split("=", 1) for line in report.splitlines() if "=" in line)
    pid, invocation = properties.get("MainPID", ""), properties.get("InvocationID", "")
    if not pid.isdecimal() or int(pid) <= 0 or len(invocation) != 32:
        return None
    context = execution_context(entry)
    if context is None or not supported_execution(entry, pid, context):
        return None
    offset = time.time_ns() // 1000 - time.monotonic_ns() // 1000
    boundary = load_boundary(context, offset)
    if boundary is None:
        return None
    start, monotonic, command, reloaded = boundary
    events = master_load_events(pid, invocation, executable, start, monotonic, reloaded, offset)
    if events is None:
        return None
    guarded = [
        str(root / entry),
        "/etc/systemd/system/php-fpm@.service",
        "/etc/php-fpm/diagnostics/probe.php",
        f"/etc/php-fpm/{entry}",
        f"/etc/php-fpm/{entry}/php.ini",
        f"/etc/php-fpm/{entry}/php-fpm.conf",
        f"/etc/php-fpm/{entry}/pools",
        f"/etc/php-fpm/{entry}/pools/diagnostic.conf",
    ]
    guarded += [
        str(path)
        for path in pathlib.Path(f"/etc/php-fpm/{entry}/pools").glob("*.conf")
        if path.name != "diagnostic.conf"
    ]
    metadata = {path: file(path) for path in guarded}
    for value in metadata.values():
        if value is None or any(
            type(value.get(key)) is not int or int(str(value[key])) >= start * 1000
            for key in ("ctime", "mtime")
        ):
            return None
    return {
        "start": start,
        "monotonic": monotonic,
        "reload": command,
        "execution": context,
        "files": metadata,
        "events": events,
        "pid": pid,
        "invocation": invocation,
    }


rows = []
names: Sequence[str] = (
    sorted(set(entries) | {p.name for p in root.iterdir() if "-link" not in p.name})
    if root.is_dir()
    else entries
)
if selection.startswith("nodejs_"):
    names = (selection,)
if len(names) > 64:
    raise ValueError("too many profiles")
for entry in names:
    if entry in ("caddy", "composer", "wp-cli", "restic", "fcgi", "haproxy"):
        continue
    p = root / entry
    if not p.is_symlink() and not p.exists():
        continue
    path = os.path.realpath(p)
    generation = os.readlink(p) if p.is_symlink() else ""
    row: dict[str, object] = {"entry": entry, "path": path, "generation": generation, "files": {}}
    if entry in ("php84", "php85"):
        row["files"] = {path: file(path) for path in paths(entry)}
        row["identity"] = identity()
        report = run(
            [
                "systemctl",
                "show",
                f"php-fpm@{entry}.service",
                "-p",
                "LoadState",
                "-p",
                "ActiveState",
                "-p",
                "SubState",
                "-p",
                "InvocationID",
                "-p",
                "MainPID",
                "-p",
                "ExecStart",
                "-p",
                "Environment",
            ]
        )
        row["unit"] = report or ""
        main = next(
            (
                line.partition("=")[2]
                for line in (report or "").splitlines()
                if line.startswith("MainPID=")
            ),
            "0",
        )
        if not main.isdecimal():
            main = "0"
        executable = pathlib.Path(f"/proc/{main}/exe")
        row["master_pid"] = int(main)
        row["master_executable"] = os.path.realpath(executable)
        row["expected_executable"] = os.path.realpath(pathlib.Path(path) / "bin/.php-fpm-wrapped")
        row["socket_owned"] = False

        socket = pathlib.Path(f"/run/php-fpm/{entry}/diagnostic.sock")
        row["socket"] = file(socket)
        ancestors = [file(p) for p in ("/etc", "/etc/php-fpm", "/etc/php-fpm/diagnostics")]
        probe = file("/etc/php-fpm/diagnostics/probe.php")

        def controlled_directory(metadata: dict[str, object] | None) -> bool:
            return bool(
                metadata
                and metadata.get("uid") == 0
                and metadata.get("type") == stat.S_IFDIR
                and isinstance(metadata.get("mode"), int)
                and int(str(metadata["mode"])) & 0o022 == 0
            )

        safe = all(controlled_directory(v) for v in ancestors)
        safe = safe and bool(
            probe
            and probe.get("uid") == 0
            and probe.get("type") == stat.S_IFREG
            and isinstance(probe.get("mode"), int)
            and int(str(probe["mode"])) & 0o022 == 0
            and probe.get("bytes") == expected_probe
        )
        sock = file(socket)
        safe = safe and bool(
            sock
            and sock.get("type") == stat.S_IFSOCK
            and sock.get("uid") == 0
            and sock.get("gid") == 0
            and sock.get("mode") == 0o600
        )
        safe = safe and os.path.realpath(root / "fcgi") == fcgi_path
        safe = safe and diagnostic_safe(entry)
        loaded = (
            load_evidence(entry, report or "", str(row["expected_executable"])) if safe else None
        )
        safe = safe and loaded is not None
        row["load_safe"] = safe
        response = None
        if safe:
            response = run(
                [
                    "timeout",
                    "6",
                    "env",
                    "-i",
                    "SCRIPT_FILENAME=/etc/php-fpm/diagnostics/probe.php",
                    "SCRIPT_NAME=/probe.php",
                    "REQUEST_METHOD=GET",
                    "QUERY_STRING=",
                    fcgi_path + "/bin/cgi-fcgi",
                    "-bind",
                    "-connect",
                    str(socket),
                ]
            )
        after = run(
            ["systemctl", "show", f"php-fpm@{entry}.service", "-p", "InvocationID", "-p", "MainPID"]
        )
        before_identity = {
            line
            for line in (report or "").splitlines()
            if line.startswith(("InvocationID=", "MainPID="))
        }
        row["same_invocation"] = after is not None and set(after.splitlines()) == before_identity
        if (
            loaded is not None
            and load_evidence(entry, report or "", str(row["expected_executable"])) != loaded
        ):
            response = None
            row["load_safe"] = False
        row["response"] = response or ""
        try:
            body = (response or "").replace("\r\n", "\n").partition("\n\n")[2]
            data: object = json.loads(body)
            row["socket_owned"] = (
                isinstance(data, dict)
                and type(data.get("parent")) is int
                and data["parent"] == int(main)
                and int(main) > 0
            )
        except ValueError:
            pass
    rows.append(row)
sys.stdout.write(
    json.dumps(
        {
            "version": 1,
            "architecture": os.uname().machine,
            "boot": pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "uptime": int(float(pathlib.Path("/proc/uptime").read_text().split()[0]) * 100),
            "digest": digest(selection),
            "admissible": admissible(selection),
            "runtimes": rows,
        },
        separators=(",", ":"),
    )
)
