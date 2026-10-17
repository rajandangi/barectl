"""Authenticate one native HAProxy admission process and its upstream state (ADR 0038)."""

import csv
import grp
import hashlib
import io
import json
import os
import pathlib
import pwd
import re
import shlex
import socket
import stat
import struct
import subprocess
import tempfile
import time
from types import SimpleNamespace
from typing import TypedDict

from runtimes.bounded import bounded
from sites.configuration import SiteSettings
from sites.serving import HAPROXY_UNIT, haproxy_config

KNOWN_HAPROXY: dict[str, tuple[str, ...]] = {}
STATE_FIELDS = [
    "be_id",
    "be_name",
    "srv_id",
    "srv_name",
    "srv_addr",
    "srv_op_state",
    "srv_admin_state",
    "srv_uweight",
    "srv_iweight",
    "srv_time_since_last_change",
    "srv_check_status",
    "srv_check_result",
    "srv_check_health",
    "srv_check_state",
    "srv_agent_state",
    "bk_f_forced_id",
    "srv_f_forced_id",
    "srv_fqdn",
    "srv_port",
    "srvrecord",
    "srv_use_ssl",
    "srv_check_port",
    "srv_check_addr",
    "srv_agent_addr",
    "srv_agent_port",
]


class ProxyState(TypedDict):
    selection: str
    ready: list[str]
    persistent: str
    state: str
    process: dict[str, object]
    digest: str
    errors: dict[str, dict[str, int]]


def hap_run(argv: list[str]) -> str:
    status, output = bounded(shlex.join(argv) + " 2>/dev/null", limit=131072)
    if status:
        raise ValueError("Native proxy evidence failed or exceeded its bound.")
    return output.decode("utf-8", "strict")


def hap_safe(path: str, *, mode: int | None = None) -> os.stat_result:
    target = pathlib.Path(path)
    for parent in reversed((target, *target.parents)):
        value = parent.lstat()
        if stat.S_ISLNK(value.st_mode) or value.st_uid != 0 or value.st_mode & 0o022:
            raise ValueError("Unsafe proxy configuration ancestry.")
    value = target.stat()
    if mode is not None and stat.S_IMODE(value.st_mode) != mode:
        raise ValueError("Unsupported native file mode.")
    if not stat.S_ISDIR(value.st_mode) and value.st_nlink != 1:
        raise ValueError("Aliased native file.")
    return value


def state_rows(text: str) -> dict[str, list[str]]:
    if len(text) > 16384:
        raise ValueError("Native state is too large.")
    lines = text.splitlines()
    if len(lines) != 4 or lines[0] != "1" or lines[1].split() != ["#", *STATE_FIELDS]:
        raise ValueError("Unsupported native server-state format.")
    rows: dict[str, list[str]] = {}
    for line in lines[2:]:
        row = line.split()
        if len(row) != len(STATE_FIELDS) or row[3] not in ("php84", "php85") or row[3] in rows:
            raise ValueError("Unsupported native server inventory.")
        entry = row[3]
        fixed = {
            0: "2",
            1: "php",
            2: "1" if entry == "php84" else "2",
            4: "-",
            7: "1",
            8: "1",
            10: "1",
            11: "0",
            12: "0",
            13: "8",
            14: "0",
            15: "0",
            16: "1",
            17: "-",
            18: "0",
            19: "-",
            20: "0",
            21: "0",
            22: "-",
            23: "-",
            24: "0",
        }
        if (
            any(row[index] != value for index, value in fixed.items())
            or (row[5], row[6]) not in (("2", "4"), ("0", "5"))
            or not row[9].isdecimal()
        ):
            raise ValueError("Unsupported server state, address or maintenance flags.")
        rows[entry] = row
    if set(rows) != {"php84", "php85"}:
        raise ValueError("Incomplete native server inventory.")
    return rows


def state_selection(text: str) -> str:
    selected = [entry for entry, row in state_rows(text).items() if row[6] == "4"]
    if len(selected) != 1:
        raise ValueError("Native state does not select exactly one runtime.")
    return selected[0]


def hap_execution(identifier: str, argv: list[str], pid: int) -> tuple[dict[str, object], int]:
    path = "/org/freedesktop/systemd1/unit/haproxy_2dsite_40" + identifier + "_2eservice"
    names = (
        "ExecMainStartTimestamp",
        "ExecMainStartTimestampMonotonic",
        "ExecStart",
        "ExecReload",
        "Environment",
        "EnvironmentFiles",
        "PassEnvironment",
        "UnsetEnvironment",
    )
    bus = hap_run(
        [
            "busctl",
            "--json=short",
            "get-property",
            "org.freedesktop.systemd1",
            path,
            "org.freedesktop.systemd1.Service",
            *names,
        ]
    )
    records = [json.loads(line) for line in bus.splitlines()]
    signatures = ("t", "t", "a(sasbttttuii)", "a(sasbttttuii)", "as", "a(sb)", "as", "as")
    if len(records) != len(names):
        raise ValueError("Incomplete native execution evidence.")
    if any(
        not isinstance(item, dict) or set(item) != {"type", "data"} or item["type"] != signature
        for item, signature in zip(records, signatures, strict=True)
    ):
        raise ValueError("Malformed typed native execution evidence.")
    context = {name: item["data"] for name, item in zip(names, records, strict=True)}
    start, mono = context["ExecMainStartTimestamp"], context["ExecMainStartTimestampMonotonic"]
    commands = context["ExecStart"]
    if (
        type(start) is not int
        or type(mono) is not int
        or start <= 0
        or mono <= 0
        or abs(start - mono - (time.time_ns() // 1000 - time.monotonic_ns() // 1000)) > 1000000
        or not isinstance(commands, list)
        or len(commands) != 1
        or commands[0] != [argv[0], argv, False, start, mono, 0, 0, pid, 0, 0]
        or any(context[name] != [] for name in names[3:])
    ):
        raise ValueError("Unbound or foreign executed proxy command.")
    return context, start


def hap_validate(identifier: str) -> None:
    cfg = f"/etc/haproxy/sites/{identifier}.cfg"
    command = ["/nix/var/nix/profiles/barectl/haproxy/bin/haproxy", "-c", "-f", cfg]
    status, output = bounded(shlex.join(command) + " 2>&1", limit=16384)
    if status:
        raise ValueError("Native proxy configuration failed validation.")
    warnings = []
    state = f"/var/lib/haproxy/sites/{identifier}.state"
    continuation = {
        "   | While not properly invalid, you will certainly encounter various problems",
        "   | with such a configuration. To fix this, please ensure that all following",
        "   | timeouts are set to a non-zero value: 'client', 'connect', 'server'.",
    }
    for line in output.decode("utf-8", "strict").splitlines():
        match = re.fullmatch(
            r"\[WARNING\]\s+\([0-9]+\) : missing timeouts for "
            r"(frontend 'incoming'|backend 'php')\.",
            line,
        )
        if match:
            warnings.append(match[1])
        elif (
            line in continuation
            or line
            in (
                "Warnings were found.",
                "Configuration file is valid",
                "",
            )
            or re.fullmatch(
                r"\[NOTICE\]\s+\([0-9]+\) : haproxy version is 3\.3\.11[-A-Za-z0-9.]*", line
            )
            or re.fullmatch(
                r"\[NOTICE\]\s+\([0-9]+\) : path to executable is "
                r"/nix/var/nix/profiles/barectl/haproxy/bin/haproxy",
                line,
            )
            or (
                not pathlib.Path(state).exists()
                and line.endswith(
                    f"Can't open global server state file '{state}': No such file or directory"
                )
            )
        ):
            continue
        else:
            raise ValueError("Unexpected native proxy configuration warning or notice.")
    if sorted(warnings) != ["backend 'php'", "frontend 'incoming'"]:
        raise ValueError("Native proxy warning contract changed.")


def hap_sockets(identifier: str, pid: str) -> dict[str, list[int]]:
    base = f"/run/haproxy/{identifier}"
    hap_safe(base, mode=0o755)
    unix = [line.split() for line in pathlib.Path("/proc/net/unix").read_text().splitlines()[1:]]
    descriptors: set[str] = set()
    for descriptor in pathlib.Path(f"/proc/{pid}/fd").iterdir():
        try:
            descriptors.add(os.readlink(descriptor))
        except FileNotFoundError:
            continue
    caddy = pwd.getpwnam("caddy")
    records: dict[str, list[int]] = {}
    for name, uid, gid in (("admin.sock", 0, 0), ("http.sock", caddy.pw_uid, caddy.pw_gid)):
        path = base + "/" + name
        value = pathlib.Path(path).lstat()
        if not stat.S_ISSOCK(value.st_mode) or (
            value.st_uid,
            value.st_gid,
            stat.S_IMODE(value.st_mode),
            value.st_nlink,
        ) != (uid, gid, 0o600, 1):
            raise ValueError("Unsupported private proxy socket ownership.")
        matches = [
            row
            for row in unix
            if len(row) == 8
            and row[7] == path + "." + pid + ".tmp"
            and row[3:6] == ["00010000", "0001", "01"]
        ]
        if len(matches) != 1 or matches[0][3:6] != ["00010000", "0001", "01"]:
            raise ValueError("Private proxy socket is not a unique native listener.")
        if f"socket:[{matches[0][6]}]" not in descriptors:
            raise ValueError("Private listener does not belong to the authenticated process.")
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(1)
            client.connect(path)
            option = getattr(socket, "SO_PEERCRED", None)
            if type(option) is not int or struct.unpack(
                "3i", client.getsockopt(socket.SOL_SOCKET, option, 12)
            ) != (int(pid), 0, 0):
                raise ValueError("Private listener peer differs from its authenticated process.")
        records[path] = [value.st_dev, value.st_ino, value.st_ctime_ns, uid, gid, 0o600]
    return records


def hap_proxy_account(identifier: str) -> pwd.struct_passwd:
    proxy = pwd.getpwnam("p" + identifier)
    if (
        proxy.pw_uid <= 0
        or proxy.pw_gid <= 0
        or proxy.pw_dir != "/nonexistent"
        or proxy.pw_shell != "/usr/sbin/nologin"
        or proxy.pw_gid != grp.getgrnam(proxy.pw_name).gr_gid
        or os.getgrouplist(proxy.pw_name, proxy.pw_gid) != [proxy.pw_gid]
        or proxy.pw_uid in (pwd.getpwnam("caddy").pw_uid, pwd.getpwnam("s" + identifier).pw_uid)
    ):
        raise ValueError("Proxy account crosses a private admission boundary.")
    return proxy


def hap_process(identifier: str) -> dict[str, object]:
    unit = f"haproxy-site@{identifier}.service"
    report = hap_run(
        [
            "systemctl",
            "show",
            "--all",
            unit,
            "--property="
            + ",".join(
                (
                    "MainPID",
                    "InvocationID",
                    "ControlGroup",
                    "ActiveState",
                    "SubState",
                    "Type",
                    "ExecReload",
                    "CanReload",
                    "User",
                    "Group",
                    "FragmentPath",
                    "DropInPaths",
                    "ExecMainStartTimestampMonotonic",
                )
            ),
        ]
    )
    values = dict(line.split("=", 1) for line in report.splitlines() if "=" in line)
    pid = values.get("MainPID", "")
    if (
        not pid.isdecimal()
        or int(pid) <= 0
        or values.get("ActiveState") != "active"
        or values.get("SubState") != "running"
        or values.get("Type") != "simple"
        or values.get("CanReload") != "no"
        or values.get("User") != ""
        or values.get("Group") != ""
        or values.get("DropInPaths") != ""
        or values.get("FragmentPath") != "/etc/systemd/system/haproxy-site@.service"
    ):
        raise ValueError("Unsupported proxy service generation.")
    profile = os.path.realpath("/nix/var/nix/profiles/barectl/haproxy")
    if profile not in KNOWN_HAPROXY.get(os.uname().machine, ()):
        raise ValueError("Unknown proxy build.")
    executable = profile + "/bin/haproxy"
    cfg = f"/etc/haproxy/sites/{identifier}.cfg"
    argv = ["/nix/var/nix/profiles/barectl/haproxy/bin/haproxy", "-f", cfg]
    process = pathlib.Path("/proc") / pid
    proxy = hap_proxy_account(identifier)
    if (
        os.path.realpath(process / "exe") != executable
        or (process / "cmdline").read_bytes().split(b"\0")[:-1] != [a.encode() for a in argv]
        or sorted(p.name for p in (process / "task").iterdir()) != [pid]
    ):
        raise ValueError("Foreign proxy process or thread topology.")
    status = dict(line.split(":", 1) for line in (process / "status").read_text().splitlines())
    if (
        status["Uid"].split() != [str(proxy.pw_uid)] * 4
        or status["Gid"].split() != [str(proxy.pw_gid)] * 4
        or status["Groups"].split() != []
    ):
        raise ValueError("Proxy privilege drop differs from its site identity.")
    group = values["ControlGroup"]
    if group != f"/system.slice/{unit}" or (
        pathlib.Path("/sys/fs/cgroup") / group.lstrip("/") / "cgroup.procs"
    ).read_text().split() != [pid]:
        raise ValueError("Proxy service has another process generation.")
    env = (process / "environ").read_bytes().split(b"\0")
    if b"INVOCATION_ID=" + values["InvocationID"].encode() not in env:
        raise ValueError("Proxy process is not bound to its native invocation.")
    context, start = hap_execution(identifier, argv, int(pid))
    guarded = (cfg, "/etc/systemd/system/haproxy-site@.service")
    files: dict[str, object] = {}
    for name in guarded:
        item = hap_safe(name, mode=0o644 if name.endswith(".service") else 0o600)
        if max(item.st_ctime_ns, item.st_mtime_ns) >= start * 1000:
            raise ValueError("Proxy configuration changed after its loaded boundary.")
        files[name] = [
            item.st_ino,
            item.st_ctime_ns,
            item.st_mtime_ns,
            hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest(),
        ]
    if pathlib.Path(guarded[1]).read_text() != HAPROXY_UNIT:
        raise ValueError("Foreign proxy service template.")
    return {
        "pid": int(pid),
        "invocation": values["InvocationID"],
        "start": (process / "stat").read_text().rsplit(")", 1)[1].split()[19],
        "files": files,
        "execution": context,
        "sockets": hap_sockets(identifier, pid),
    }


def hap_inventory() -> list[str]:
    foreign: list[str] = []
    for process in pathlib.Path("/proc").iterdir():
        if not process.name.isdecimal():
            continue
        try:
            command = (process / "comm").read_text().strip()
            executable = pathlib.Path(os.readlink(process / "exe")).name
        except FileNotFoundError, ProcessLookupError:
            continue
        except PermissionError:
            raise ValueError("HAProxy process inventory is unreadable.") from None
        if command != "haproxy" and executable != "haproxy":
            continue
        try:
            group = (process / "cgroup").read_text().strip()
            match = re.fullmatch(
                r"0::/system.slice/haproxy-site@([a-z][a-z0-9]{2,23})\.service", group
            )
            if match is None:
                raise ValueError("Foreign HAProxy service ownership.")
            identifier = match[1]
            loaded = hap_process(identifier)
            if loaded["pid"] != int(process.name) or pathlib.Path(
                f"/etc/haproxy/sites/{identifier}.cfg"
            ).read_text() != haproxy_config(SimpleNamespace(identifier=identifier)):
                raise ValueError("Foreign HAProxy executable or serving configuration.")
        except OSError, ValueError, KeyError, subprocess.TimeoutExpired:
            foreign.append("Unrecognized HAProxy process " + process.name)
    return foreign


def hap_wait(identifier: str) -> None:
    """Wait for a just-started proxy to exec and bind its administrative socket.

    systemd reports a ``Type=simple`` unit running as soon as it forks, before the exec.
    """
    deadline = time.monotonic() + 10
    while True:
        try:
            hap_process(identifier)
            if stat.S_ISSOCK(pathlib.Path(f"/run/haproxy/{identifier}/admin.sock").lstat().st_mode):
                return
        except OSError, ValueError:
            pass
        if time.monotonic() >= deadline:
            raise ValueError("The site proxy did not become ready.")
        time.sleep(0.05)


def hap_api(identifier: str, command: str, *, seconds: float = 5) -> str:
    before = hap_process(identifier)
    path = f"/run/haproxy/{identifier}/admin.sock"
    value = pathlib.Path(path).lstat()
    if not stat.S_ISSOCK(value.st_mode) or (
        value.st_uid,
        value.st_gid,
        stat.S_IMODE(value.st_mode),
    ) != (0, 0, 0o600):
        raise ValueError("Foreign administrative socket.")
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(seconds + 1)
        client.connect(path)
        option = getattr(socket, "SO_PEERCRED", None)
        if type(option) is not int:
            raise ValueError("Native peer credentials are unavailable.")
        peer = struct.unpack("3i", client.getsockopt(socket.SOL_SOCKET, option, 12))
        if peer != (before["pid"], 0, 0):
            raise ValueError("Administrative API peer is not the authenticated process.")
        client.sendall((command + "\n").encode())
        if not command.startswith("wait "):
            client.shutdown(socket.SHUT_WR)
        output = bytearray()
        while part := client.recv(16384):
            output.extend(part)
            if len(output) > 131072:
                raise ValueError("Administrative API response exceeded its bound.")
    if hap_process(identifier) != before:
        raise ValueError("Proxy process changed during native API access.")
    return output.decode("ascii", "strict").strip()


def serving_errors(stats: list[dict[str, str | list[str] | None]]) -> dict[str, dict[str, int]]:
    errors: dict[str, dict[str, int]] = {}
    for row in stats:
        if row["svname"] not in ("php84", "php85"):
            continue
        counts: dict[str, int] = {}
        for name in ("econ", "eresp", "cli_abrt", "srv_abrt"):
            value = row.get(name)
            if not isinstance(value, str) or not value.isdecimal():
                raise ValueError("Native serving error evidence is unavailable.")
            counts[name] = int(value)
        errors[str(row["svname"])] = counts
    return errors


def haproxy_state(settings: SiteSettings | SimpleNamespace) -> ProxyState:
    identifier = settings.identifier
    process = hap_process(identifier)
    cfg = f"/etc/haproxy/sites/{identifier}.cfg"
    if pathlib.Path(cfg).read_text() != haproxy_config(settings):
        raise ValueError("Proxy ACL/configuration differs from its immutable convention.")
    info = dict(
        line.split(": ", 1)
        for line in hap_api(identifier, "show info").splitlines()
        if ": " in line
    )
    if (
        info.get("Nbthread") != "1"
        or info.get("Nbproc") != "1"
        or info.get("Pid") != str(process["pid"])
        or info.get("Maxconn") != "64"
    ):
        raise ValueError("Unsupported current proxy topology/capacity.")
    raw = hap_api(identifier, "show servers state") + "\n"
    rows = state_rows(raw)
    ready = [entry for entry, row in rows.items() if row[6] == "4"]
    stats = list(csv.DictReader(io.StringIO(hap_api(identifier, "show stat").removeprefix("# "))))
    if {row.get("svname") for row in stats} != {"php84", "php85", "FRONTEND", "BACKEND"} or len(
        stats
    ) != 4:
        raise ValueError("Foreign proxy server inventory.")
    for row in stats:
        if row["svname"] in ("php84", "php85") and (
            row.get("slim") != "2" or row.get("pxname") != "php"
        ):
            raise ValueError("Backend connection capacity changed.")
    errors = serving_errors(stats)
    state_path = f"/var/lib/haproxy/sites/{identifier}.state"
    hap_safe(state_path, mode=0o600)
    persistent = state_selection(pathlib.Path(state_path).read_text())
    if hap_process(identifier) != process:
        raise ValueError("Proxy identity changed during observation.")
    normalized = {entry: [*row[:9], "0", *row[10:]] for entry, row in rows.items()}
    selection = ready[0] if len(ready) == 1 else ""
    return {
        "errors": errors,
        "selection": selection,
        "ready": ready,
        "persistent": persistent,
        "state": raw,
        "process": process,
        "digest": hashlib.sha256(
            json.dumps([normalized, persistent, process], sort_keys=True).encode()
        ).hexdigest(),
    }


def persist_proxy_state(settings: SiteSettings | SimpleNamespace) -> str:
    raw = hap_api(settings.identifier, "show servers state") + "\n"
    selected = state_selection(raw)
    path = pathlib.Path(f"/var/lib/haproxy/sites/{settings.identifier}.state")
    hap_safe(str(path.parent), mode=0o755)
    if path.exists() or path.is_symlink():
        hap_safe(str(path), mode=0o600)
    descriptor, staged = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    temporary = pathlib.Path(staged)
    try:
        with os.fdopen(descriptor, "w") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        parent = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        temporary.unlink(missing_ok=True)
    if path.read_text() != raw:
        raise ValueError("Native state publication was not durable/current.")
    return selected
