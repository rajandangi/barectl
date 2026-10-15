import base64
import grp
import json
import os
import pathlib
import pwd
import re
import shlex
import stat
import subprocess
import time

from runtimes.live import live_values, master_identity, protected


def sfp_status_idle(response: str, identifier: str, pids: list[int]) -> bool:
    header, separator, body = response.replace("\r\n", "\n").partition("\n\n")
    if (
        not separator
        or len(response) > 32768
        or any(
            line.lower().startswith("status:") and line != "Status: 200 OK"
            for line in header.splitlines()
        )
    ):
        return False
    try:
        value: object = json.loads(body)
    except ValueError:
        return False
    if not isinstance(value, dict):
        return False
    processes = value.get("processes")
    if not isinstance(processes, list) or len(processes) != len(pids) or not pids:
        return False
    observed: list[int] = []
    for process in processes:
        if not isinstance(process, dict) or process.get("state") != "Idle":
            return False
        pid = process.get("pid")
        if type(pid) is not int or pid <= 0:
            return False
        observed.append(pid)
    return (
        value.get("pool") == identifier
        and value.get("process manager") == "static"
        and type(value.get("total processes")) is int
        and value.get("total processes") == len(pids)
        and type(value.get("idle processes")) is int
        and value.get("idle processes") == len(pids)
        and type(value.get("active processes")) is int
        and value.get("active processes") == 0
        and len(set(observed)) == len(observed)
        and sorted(observed) == sorted(pids)
    )


def sfp_bus(
    unit: str, interface: str, properties: tuple[tuple[str, str], ...]
) -> dict[str, object] | None:
    escaped = "".join(
        character if character.isascii() and character.isalnum() else f"_{ord(character):02x}"
        for character in unit
    )
    response = sfp_run(
        [
            "busctl",
            "--json=short",
            "get-property",
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1/unit/" + escaped,
            "org.freedesktop.systemd1." + interface,
            *(name for name, _ in properties),
        ]
    )
    if response is None:
        return None
    try:
        lines = response.splitlines()
        if len(lines) != len(properties):
            return None
        values: dict[str, object] = {}
        for line, (name, signature) in zip(lines, properties, strict=True):
            data: object = json.loads(line)
            if (
                not isinstance(data, dict)
                or set(data) != {"type", "data"}
                or data["type"] != signature
            ):
                return None
            values[name] = data["data"]
        return values
    except ValueError:
        return None


def sfp_context(unit: str) -> dict[str, object] | None:
    service = sfp_bus(
        unit,
        "Service",
        (
            ("MainPID", "u"),
            ("ControlGroup", "s"),
            ("Type", "s"),
            ("ExecMainStartTimestamp", "t"),
            ("ExecMainStartTimestampMonotonic", "t"),
            ("ExecStart", "a(sasbttttuii)"),
            ("ExecStartPost", "a(sasbttttuii)"),
            ("ExecReload", "a(sasbttttuii)"),
            ("Environment", "as"),
            ("EnvironmentFiles", "a(sb)"),
            ("PassEnvironment", "as"),
            ("UnsetEnvironment", "as"),
            ("KillSignal", "i"),
            ("TimeoutStopUSec", "t"),
            ("SendSIGKILL", "b"),
        ),
    )
    unit_values = sfp_bus(
        unit,
        "Unit",
        (
            ("InvocationID", "ay"),
            ("ActiveState", "s"),
            ("SubState", "s"),
            ("LoadState", "s"),
            ("FragmentPath", "s"),
            ("DropInPaths", "as"),
        ),
    )
    if service is None or unit_values is None:
        return None
    return {**service, **unit_values}


def sfp_execution(identifier: str, entry: str, context: dict[str, object]) -> bool:
    base = f"/etc/php-fpm/sites/{identifier}/{entry}"
    executable = f"/nix/var/nix/profiles/barectl/{entry}/bin/php-fpm"
    commands = context.get("ExecStart")
    if not isinstance(commands, list) or len(commands) != 1 or not isinstance(commands[0], list):
        return False
    command = commands[0]
    if len(command) != 10 or command[:3] != [
        executable,
        [executable, "-F", "-y", base + "/php-fpm.conf", "-c", base + "/php.ini"],
        False,
    ]:
        return False
    if any(type(item) is not int for item in command[3:]):
        return False
    post = context.get("ExecStartPost")
    if not isinstance(post, list) or len(post) != 1 or not isinstance(post[0], list):
        return False
    chmod = post[0]
    if len(chmod) != 10 or chmod[:3] != [
        "/usr/bin/chmod",
        ["/usr/bin/chmod", "0600", f"/run/php-fpm/sites/{identifier}/{entry}/status/listen.sock"],
        False,
    ]:
        return False
    if any(type(item) is not int for item in chmod[3:]):
        return False
    start, mono = (
        context.get("ExecMainStartTimestamp"),
        context.get("ExecMainStartTimestampMonotonic"),
    )
    return (
        type(start) is int
        and type(mono) is int
        and start > 0
        and mono > 0
        and command[3:5] == [start, mono]
        and command[5:7] == [0, 0]
        and command[7] == context.get("MainPID")
        and command[8:] == [0, 0]
        and chmod[3] >= start
        and chmod[4] >= mono
        and chmod[5] >= chmod[3]
        and chmod[6] >= chmod[4]
        and chmod[7] > 0
        and chmod[8:] == [1, 0]
        and context.get("Type") == "notify"
        and context.get("KillSignal") == 3
        and context.get("TimeoutStopUSec") == 18446744073709551615
        and context.get("SendSIGKILL") is False
        and context.get("LoadState") == "loaded"
        and context.get("ActiveState") == "active"
        and context.get("SubState") == "running"
        and context.get("FragmentPath") == f"/etc/systemd/system/php-fpm-site-{entry}@.service"
        and all(
            context.get(key) == []
            for key in (
                "ExecReload",
                "Environment",
                "EnvironmentFiles",
                "PassEnvironment",
                "UnsetEnvironment",
                "DropInPaths",
            )
        )
    )


def sfp_process(pid: int, executable: str, cgroup: str) -> dict[str, object] | None:
    try:
        directory = pathlib.Path(f"/proc/{pid}")
        before = (directory / "stat").read_text()
        fields = before.rsplit(")", 1)[1].split()
        if len(fields) < 20 or fields[0] == "Z":
            return None
        status = dict(
            line.split(":", 1)
            for line in (directory / "status").read_text().splitlines()
            if ":" in line
        )
        if os.path.realpath(directory / "exe") != executable:
            return None
        if (directory / "cgroup").read_text().strip() != "0::" + cgroup:
            return None
        value: dict[str, object] = {
            "pid": pid,
            "parent": int(fields[1]),
            "start": int(fields[19]),
            "uid": [int(item) for item in status["Uid"].split()],
            "gid": [int(item) for item in status["Gid"].split()],
            "groups": [int(item) for item in status["Groups"].split()],
            "title": (directory / "cmdline").read_bytes().rstrip(b"\0").decode(),
        }
        if (directory / "stat").read_text().rsplit(")", 1)[1].split()[19] != fields[19]:
            return None
        return value
    except OSError, ValueError, KeyError, IndexError:
        return None


def sfp_classify(
    identifier: str, pid: int, processes: list[dict[str, object] | None]
) -> dict[str, object] | None:
    if sum(process is not None and process.get("pid") == pid for process in processes) != 1:
        return None
    app: list[int] = []
    counts = {"status": 0, "diagnostic": 0}
    for process in processes:
        if process is None:
            return None
        child = process["pid"]
        if child == pid:
            if process["uid"] != [0] * 4 or process["gid"] != [0] * 4:
                return None
            continue
        role = sfp_child_role(identifier, pid, process)
        if role is None:
            return None
        if role == "app" and type(child) is int:
            app.append(child)
        elif role in counts:
            counts[role] += 1
    if len(app) != 2 or counts["status"] > 2 or counts["diagnostic"] > 1:
        return None
    return {"processes": processes, "app_pids": app}


def sfp_child_role(identifier: str, pid: int, process: dict[str, object]) -> str | None:
    title = process["title"]
    titles = {
        "php-fpm: pool " + identifier: ("app", "s" + identifier),
        "php-fpm: pool " + identifier + "_status": ("status", "s" + identifier),
        "php-fpm: pool diagnostic": ("diagnostic", "php-probe"),
    }
    if not isinstance(title, str) or title not in titles or process["parent"] != pid:
        return None
    role, name = titles[title]
    user = pwd.getpwnam(name)
    return (
        role
        if process["uid"] == [user.pw_uid] * 4
        and process["gid"] == [user.pw_gid] * 4
        and process.get("groups") == [user.pw_gid]
        else None
    )


def sfp_inventory(
    identifier: str, pid: int, executable: str, cgroup: str
) -> dict[str, object] | None:
    if not cgroup.startswith("/system.slice/") or ".." in cgroup or "\n" in cgroup:
        return None
    try:
        group = pathlib.Path("/sys/fs/cgroup" + cgroup)
        if any(path.is_dir() for path in group.iterdir()):
            return None
        pids = sorted(int(value) for value in (group / "cgroup.procs").read_text().split())
        if not 3 <= len(pids) <= 8 or pid not in pids or len(set(pids)) != len(pids):
            return None
        classified = sfp_classify(
            identifier, pid, [sfp_process(child, executable, cgroup) for child in pids]
        )
        if classified is None:
            return None
        if sorted(int(value) for value in (group / "cgroup.procs").read_text().split()) != pids:
            return None
        return classified
    except OSError, ValueError, KeyError:
        return None


def sfp_run(arguments: list[str]) -> str | None:
    try:
        result = subprocess.run(  # noqa: S603 - fixed native commands and validated catalog paths
            [
                "/usr/bin/timeout",
                "--kill-after=1",
                "8",
                "/bin/bash",
                "-o",
                "pipefail",
                "-c",
                shlex.join(arguments) + " 2>/dev/null | /usr/bin/head -c 32769",
            ],
            capture_output=True,
            timeout=10,
            check=False,
        )
        if len(result.stdout) > 32768 or result.returncode:
            return None
        return result.stdout.decode("utf-8")
    except OSError, ValueError, subprocess.TimeoutExpired:
        return None


def sfp_file(path: str | pathlib.Path) -> dict[str, object] | None:
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
            "device": meta.st_dev,
            "inode": meta.st_ino,
            "links": meta.st_nlink,
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


def sfp_identity() -> list[object] | None:
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


def sfp_journal_event_clocks(
    event: dict[str, object], pid: str, invocation: str, executable: str, boot: str, offset: int
) -> tuple[int, int] | None:
    if any(
        (
            event.get(key) != value
            for key, value in {
                "_PID": pid,
                "_UID": "0",
                "_EXE": executable,
                "_BOOT_ID": boot,
                "_SYSTEMD_INVOCATION_ID": invocation,
                "_TRANSPORT": "syslog",
            }.items()
        )
    ):
        return None
    real, mono = (event.get("__REALTIME_TIMESTAMP"), event.get("__MONOTONIC_TIMESTAMP"))
    if not isinstance(real, str) or not real.isdecimal():
        return None
    if not isinstance(mono, str) or not mono.isdecimal():
        return None
    if abs(int(real) - int(mono) - offset) > 1000000:
        return None
    return (int(real), int(mono))


def sfp_complete_load(messages: list[object], pid: str, reloaded: bool) -> bool:
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


def sfp_master_load_events(
    pid: str,
    invocation: str,
    executable: str,
    start: int,
    monotonic: int,
    reloaded: bool,
    offset: int,
) -> list[dict[str, object]] | None:
    text = sfp_run(
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
            "--output-fields=MESSAGE,_TRANSPORT,_EXE,_PID,_UID,_BOOT_ID,_SYSTEMD_INVOCATION_ID,__REALTIME_TIMESTAMP,__MONOTONIC_TIMESTAMP",
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
            clocks = sfp_journal_event_clocks(event, pid, invocation, executable, boot, offset)
            if clocks is None:
                return None
            real, mono = clocks
            if mono < monotonic:
                continue
            if real < start:
                return None
            events.append(event)
        events.sort(key=lambda event: int(str(event["__MONOTONIC_TIMESTAMP"])))
        if not sfp_complete_load([event.get("MESSAGE") for event in events], pid, reloaded):
            return None
    except OSError, ValueError, KeyError:
        return None
    return events


def sfp_config_metadata(
    path: str, meta: dict[str, object] | None, expected: dict[str, str], probe_gid: int
) -> bool:
    if (
        meta is None
        or meta.get("uid") != 0
        or any(type(meta.get(key)) is not int for key in ("ctime", "mtime"))
    ):
        return False
    if path in expected:
        probe = path == "/etc/php-fpm/diagnostics/probe.php"
        return (
            meta.get("type") == stat.S_IFREG
            and meta.get("links") == 1
            and meta.get("gid") == (probe_gid if probe else 0)
            and meta.get("mode") in ((0o640,) if probe else (0o600, 0o644))
            and meta.get("bytes") == base64.b64encode(expected[path].encode()).decode()
        )
    if path.startswith("/nix/var/nix/profiles/barectl/php"):
        return meta.get("type") == stat.S_IFLNK
    return (
        meta.get("type") == stat.S_IFDIR
        and type(meta.get("mode")) is int
        and int(str(meta["mode"])) & 0o022 == 0
    )


def sfp_diagnostic_convention(base: str, identifier: str, user: pwd.struct_passwd) -> bool:
    return (
        user.pw_uid > 0
        and user.pw_dir == "/nonexistent"
        and user.pw_shell == "/usr/sbin/nologin"
        and os.getgrouplist(user.pw_name, user.pw_gid) == [user.pw_gid]
        and {p.name for p in pathlib.Path(base + "/pools").iterdir()}
        == {identifier + ".conf", "diagnostic.conf"}
        and {p.name for p in pathlib.Path("/etc/php-fpm/diagnostics").iterdir()} == {"probe.php"}
    )


def sfp_files(
    identifier: str, entry: str, expected: dict[str, str], start: int
) -> dict[str, object] | None:
    base = f"/etc/php-fpm/sites/{identifier}/{entry}"
    required = {
        base + "/php.ini",
        base + "/php-fpm.conf",
        base + "/pools/" + identifier + ".conf",
        base + "/pools/diagnostic.conf",
        "/etc/php-fpm/diagnostics/probe.php",
        f"/etc/systemd/system/php-fpm-site-{entry}@.service",
    }
    if set(expected) != required:
        return None
    try:
        user = pwd.getpwnam("php-probe")
        if not sfp_diagnostic_convention(base, identifier, user):
            return None
        paths = set(required)
        paths.add(f"/nix/var/nix/profiles/barectl/{entry}")
        for path in set(paths):
            paths.update(str(parent) for parent in pathlib.Path(path).parents if str(parent) != "/")
        values: dict[str, object] = {}
        for path in sorted(paths):
            meta = sfp_file(path)
            if not sfp_config_metadata(path, meta, expected, user.pw_gid):
                return None
            if meta is None:
                return None
            loaded_path = path in required or path in (
                base,
                base + "/pools",
                f"/nix/var/nix/profiles/barectl/{entry}",
            )
            if loaded_path and any(
                int(str(meta[key])) >= start * 1000 for key in ("ctime", "mtime")
            ):
                return None
            values[path] = meta
        diagnostic_directory = values.get("/etc/php-fpm/diagnostics")
        if (
            not isinstance(diagnostic_directory, dict)
            or diagnostic_directory.get("gid") != user.pw_gid
            or diagnostic_directory.get("mode") != 0o750
        ):
            return None
        return values
    except OSError, ValueError, KeyError:
        return None


def sfp_socket_metadata(path: str, meta: dict[str, object] | None, proxy_gid: int) -> bool:
    if meta is None or meta.get("type") != stat.S_IFSOCK or meta.get("uid") != 0:
        return False
    if path.endswith("/app.sock"):
        return meta.get("gid") == proxy_gid and meta.get("mode") == 0o660
    expected_gid = proxy_gid if path.endswith("/status/listen.sock") else 0
    return meta.get("gid") == expected_gid and meta.get("mode") == 0o600


def sfp_descriptors(pid: int) -> set[str]:
    descriptors: set[str] = set()
    for descriptor in pathlib.Path(f"/proc/{pid}/fd").iterdir():
        try:
            descriptors.add(os.readlink(descriptor))
        except FileNotFoundError:
            continue
    return descriptors


def sfp_sockets(identifier: str, entry: str, pid: int) -> dict[str, object] | None:
    base = f"/run/php-fpm/sites/{identifier}/{entry}"
    try:
        proxy = grp.getgrnam("p" + identifier)
        records: dict[str, object] = {}
        for path in (
            "/run",
            "/run/php-fpm",
            "/run/php-fpm/sites",
            f"/run/php-fpm/sites/{identifier}",
            base,
            base + "/status",
            base + "/diagnostic",
        ):
            meta = sfp_file(path)
            if (
                meta is None
                or meta.get("type") != stat.S_IFDIR
                or meta.get("uid") != 0
                or type(meta.get("mode")) is not int
                or int(str(meta["mode"])) & 0o022
            ):
                return None
            if path in (base + "/status", base + "/diagnostic") and meta.get("mode") != 0o700:
                return None
            records[path] = meta
        paths = (base + "/app.sock", base + "/status/listen.sock", base + "/diagnostic/listen.sock")
        unix = pathlib.Path("/proc/net/unix").read_text().splitlines()[1:]
        inodes: set[str] = set()
        for path in paths:
            meta = sfp_file(path)
            if not sfp_socket_metadata(path, meta, proxy.gr_gid):
                return None
            matches = [
                line.split()
                for line in unix
                if len(line.split()) == 8
                and line.split()[7] == path
                and line.split()[3:6] == ["00010000", "0001", "01"]
            ]
            if len(matches) != 1 or matches[0][3:6] != ["00010000", "0001", "01"]:
                return None
            inodes.add(matches[0][6])
            records[path] = meta
        descriptors = sfp_descriptors(pid)
        if not all(f"socket:[{inode}]" in descriptors for inode in inodes):
            return None
        return records
    except OSError, ValueError, KeyError:
        return None


def sfp_fcgi(path: str, socket: str, *, status: bool = False) -> str | None:
    return sfp_run(
        [
            "timeout",
            "6",
            "env",
            "-i",
            "SCRIPT_FILENAME=" + ("/status" if status else "/etc/php-fpm/diagnostics/probe.php"),
            "SCRIPT_NAME=" + ("/status" if status else "/probe.php"),
            "REQUEST_METHOD=GET",
            "QUERY_STRING=" + ("json&full" if status else ""),
            "REQUEST_URI=" + ("/status?json&full" if status else "/probe.php"),
            path + "/bin/cgi-fcgi",
            "-bind",
            "-connect",
            socket,
        ]
    )


def sfp_selected_build(
    identifier: str, entry: str, known_php: tuple[str, ...], fcgi_path: str
) -> tuple[str, str] | None:
    if re.fullmatch(r"[a-z][a-z0-9]{2,23}", identifier) is None or entry not in ("php84", "php85"):
        return None
    profile = f"/nix/var/nix/profiles/barectl/{entry}"
    path = os.path.realpath(profile)
    version = re.fullmatch(r"/nix/store/[a-z0-9]{32}-php-with-extensions-(8\.[45]\.[0-9]+)", path)
    if (
        path not in known_php
        or version is None
        or not version[1].startswith("8." + entry[-1] + ".")
    ):
        return None
    if (
        not fcgi_path.startswith("/nix/store/")
        or os.path.realpath("/nix/var/nix/profiles/barectl/fcgi") != fcgi_path
    ):
        return None
    executable = os.path.realpath(path + "/bin/.php-fpm-wrapped")
    if not executable.startswith("/nix/store/") or not executable.endswith("/bin/php-fpm"):
        return None
    return version[1], executable


def sfp_invocation(value: object) -> str | None:
    if (
        not isinstance(value, list)
        or len(value) != 16
        or any(type(byte) is not int or not 0 <= byte <= 255 for byte in value)
    ):
        return None
    return bytes(value).hex()


def site_fpm_evidence(
    identifier: str,
    entry: str,
    expected: dict[str, str],
    known_php: tuple[str, ...],
    fcgi_path: str,
) -> dict[str, object] | None:
    selected = sfp_selected_build(identifier, entry, known_php, fcgi_path)
    if selected is None:
        return None
    version, executable = selected
    unit = f"php-fpm-site-{entry}@{identifier}.service"
    context = sfp_context(unit)
    if context is None or not sfp_execution(identifier, entry, context):
        return None
    pid = context.get("MainPID")
    invocation = sfp_invocation(context.get("InvocationID"))
    cgroup = context.get("ControlGroup")
    if type(pid) is not int or pid <= 0 or not isinstance(cgroup, str) or invocation is None:
        return None
    start, mono = (
        context.get("ExecMainStartTimestamp"),
        context.get("ExecMainStartTimestampMonotonic"),
    )
    if type(start) is not int or type(mono) is not int:
        return None
    offset = time.time_ns() // 1000 - time.monotonic_ns() // 1000
    if abs(start - mono - offset) > 1000000:
        return None
    files = sfp_files(identifier, entry, expected, start)
    events = sfp_master_load_events(str(pid), invocation, executable, start, mono, False, offset)
    sockets = sfp_sockets(identifier, entry, pid)
    before_inventory = sfp_inventory(identifier, pid, executable, cgroup)
    if files is None or events is None or sockets is None or before_inventory is None:
        return None
    base = f"/run/php-fpm/sites/{identifier}/{entry}"
    response = sfp_fcgi(fcgi_path, base + "/diagnostic/listen.sock")
    row: dict[str, object] = {
        "master_pid": pid,
        "identity": sfp_identity(),
        "response": response or "",
        "expected_executable": executable,
        "master_executable": os.path.realpath(f"/proc/{pid}/exe"),
        "socket_owned": True,
        "load_safe": True,
        "same_invocation": sfp_context(unit) == context,
    }
    values = live_values(row, version)
    if values is None or not master_identity(row):
        return None
    ini, opcache, extensions = values
    if not protected(ini, opcache, tuple(extensions)):
        return None
    inventory = sfp_inventory(identifier, pid, executable, cgroup)
    if (
        inventory is None
        or not sfp_same_application(before_inventory, inventory, pid)
        or not sfp_same_trees(sfp_files(identifier, entry, expected, start), files)
        or not sfp_same_trees(sfp_sockets(identifier, entry, pid), sockets)
        or sfp_context(unit) != context
        or sfp_master_load_events(str(pid), invocation, executable, start, mono, False, offset)
        != events
    ):
        return None
    return {
        "pid": pid,
        "invocation": invocation,
        "identity": row["identity"],
        "load": {"execution": context, "files": files, "events": events},
        "response": response,
        "protections": ini,
        "extensions": extensions,
        "app_pids": inventory["app_pids"],
        "inventory": inventory,
        "sockets": sockets,
        "executable": executable,
        "cgroup": cgroup,
        "fcgi_path": fcgi_path,
    }


def site_fpm_idle(identifier: str, entry: str, evidence: dict[str, object]) -> bool:
    if re.fullmatch(r"[a-z][a-z0-9]{2,23}", identifier) is None or entry not in ("php84", "php85"):
        return False
    pid, invocation = evidence.get("pid"), evidence.get("invocation")
    executable, cgroup, fcgi = (
        evidence.get("executable"),
        evidence.get("cgroup"),
        evidence.get("fcgi_path"),
    )
    load = evidence.get("load")
    if (
        type(pid) is not int
        or not all(isinstance(value, str) for value in (invocation, executable, cgroup, fcgi))
        or not isinstance(load, dict)
    ):
        return False
    if (
        not isinstance(invocation, str)
        or not isinstance(executable, str)
        or not isinstance(cgroup, str)
        or not isinstance(fcgi, str)
    ):
        return False
    unit = f"php-fpm-site-{entry}@{identifier}.service"
    context = sfp_context(unit)
    if context != load.get("execution") or context is None or not sfp_loaded_unchanged(load):
        return False
    before = sfp_inventory(identifier, pid, executable, cgroup)
    if before is None or before.get("app_pids") != evidence.get("app_pids"):
        return False
    pids = before.get("app_pids")
    if not isinstance(pids, list) or not all(type(value) is int for value in pids):
        return False
    response = sfp_fcgi(
        fcgi, f"/run/php-fpm/sites/{identifier}/{entry}/status/listen.sock", status=True
    )
    after = sfp_inventory(identifier, pid, executable, cgroup)
    return (
        response is not None
        and sfp_status_idle(response, identifier, pids)
        and after is not None
        and after.get("app_pids") == pids
        and sfp_context(unit) == context
        and sfp_loaded_unchanged(load)
        and sfp_same_trees(sfp_sockets(identifier, entry, pid), evidence.get("sockets"))
        and sfp_same_application(before, after, pid)
        and sfp_same_application(evidence.get("inventory"), after, pid)
    )


def sfp_same_application(before: object, after: object, master: int) -> bool:
    if not isinstance(before, dict) or not isinstance(after, dict):
        return False
    pids = before.get("app_pids")
    previous, current = before.get("processes"), after.get("processes")
    if (
        not isinstance(pids, list)
        or not isinstance(previous, list)
        or not isinstance(current, list)
    ):
        return False
    return all(
        process in current
        for process in previous
        if isinstance(process, dict) and process.get("pid") in [master, *pids]
    )


def sfp_same_metadata(before: object, after: object) -> bool:
    """Whether two samples describe the same native object (ADR 0038).

    A directory's ctime/mtime is not part of the authenticated identity: a shared ancestor
    such as ``/run`` changes whenever an unrelated entry appears, including from an operator
    SSH login. Owner, group, mode, type, device and inode must still match, as must every
    field of a non-directory sample, so no surviving file, symlink or listener may change.
    """
    if not isinstance(before, dict) or not isinstance(after, dict):
        return False
    if set(before) != set(after):
        return False
    if before.get("type") != stat.S_IFDIR:
        return before == after
    return all(
        before.get(key) == after.get(key)
        for key in ("uid", "gid", "mode", "type", "device", "inode")
    )


def sfp_same_trees(before: object, after: object) -> bool:
    """Whether two per-path metadata samples describe the same objects."""
    if not isinstance(before, dict) or not isinstance(after, dict) or set(before) != set(after):
        return False
    return all(sfp_same_metadata(before[path], after[path]) for path in before)


def sfp_loaded_unchanged(load: dict[str, object]) -> bool:
    files, context = load.get("files"), load.get("execution")
    if not isinstance(files, dict) or not isinstance(context, dict):
        return False
    return all(
        isinstance(path, str) and sfp_same_metadata(sfp_file(path), meta)
        for path, meta in files.items()
    )


def sfp_retained_shape(
    expected: dict[str, str],
    observed: dict[str, tuple[int, int, str, bytes]],
    active: bool,
) -> str:
    """Classify a runtime's surviving configuration directory (ADR 0038).

    ``expected`` maps every canonical file's absolute path to its exact text. ``observed``
    maps each surviving entry under the runtime directory to ``(uid, mode, kind, bytes)``
    with ``kind`` one of ``"dir"``, ``"file"`` or ``"other"``. The result is ``"complete"``
    when the whole canonical directory survives, ``"partial"`` when a non-empty proper
    subset survives while ``active`` is false, and ``"unsupported"`` for every other shape:
    an unknown entry, a symlink, a wrong owner, mode or kind, changed content, or a missing
    file while the service is active. Only ``"complete"`` and ``"partial"`` are recoverable.
    """
    if not expected:
        return "unsupported"
    base = os.path.commonpath(list(expected))
    directories = {base}
    for path in expected:
        parent = str(pathlib.PurePosixPath(path).parent)
        if parent.startswith(base + "/"):
            directories.add(parent)
    allowed = directories | set(expected)
    if any(path not in allowed for path in observed):
        return "unsupported"
    for path, (uid, mode, kind, contents) in observed.items():
        if path in directories:
            if kind != "dir" or uid != 0 or mode != 0o755:
                return "unsupported"
        elif kind != "file" or uid != 0 or mode != 0o644 or contents != expected[path].encode():
            return "unsupported"
    if directories <= observed.keys() and set(expected) <= observed.keys():
        return "complete"
    return "unsupported" if active else "partial"
