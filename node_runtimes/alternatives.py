"""The ordinary Node command's native group (docs/node-runtimes-native-design.md)."""

import shlex

from . import catalog

LINK = "/usr/local/bin/node"
STATE = "/var/lib/dpkg/alternatives/node"
INDIRECT = "/etc/alternatives/node"

PROGRAM = r"""
import os, stat, subprocess, sys

selected = sys.argv[1]
paths = sys.argv[2:]

def safe(path, *, regular=False):
    s = os.lstat(path)
    if s.st_uid != 0 or s.st_gid != 0 or s.st_mode & 0o022:
        raise ValueError("unsafe alternatives state")
    if regular:
        if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1:
            raise ValueError("unsafe alternatives file")
    elif not stat.S_ISDIR(s.st_mode):
        raise ValueError("unsafe alternatives directory")

def stanza(text):
    result = {}
    for line in text.splitlines():
        if ":" not in line and not line.startswith(" "):
            raise ValueError("unexpected alternatives entry")
        if line.startswith(" "):
            if "Slaves" not in result or len(line.split()) != 2:
                raise ValueError("unexpected alternatives continuation")
            name, path = line.split()
            if name in result["Slaves"]:
                raise ValueError("duplicate slave")
            result["Slaves"][name] = path
            continue
        key, value = line.split(":", 1)
        if key in result:
            raise ValueError("duplicate alternatives entry")
        if key == "Slaves":
            if value.strip():
                raise ValueError("unexpected slave format")
            result[key] = {}
        else:
            result[key] = value.strip()
    return result

try:
    for directory in ("/", "/usr", "/usr/local", "/usr/local/bin", "/etc",
                      "/etc/alternatives", "/var", "/var/lib", "/var/lib/dpkg",
                      "/var/lib/dpkg/alternatives"):
        safe(directory)
    if any(os.path.lexists("/usr/bin/" + n) for n in ("node", "npm", "npx")):
        raise ValueError("distribution or unmanaged Node is present")
    link, indirect = "/usr/local/bin/node", "/etc/alternatives/node"
    state = "/var/lib/dpkg/alternatives/node"
    if any(os.path.lexists("/var/lib/dpkg/alternatives/" + n) for n in ("npm", "npx")):
        raise ValueError("independent npm alternatives group")
    commands = ("node", "npm", "npx")
    links = tuple("/usr/local/bin/" + n for n in commands)
    indirects = tuple("/etc/alternatives/" + n for n in commands)
    if not selected:
        if any(os.path.lexists(p) for p in (*links, *indirects, state)):
            raise ValueError("unmanaged Node alternatives")
    else:
        safe(state, regular=True)
        targets = tuple(selected[:-4] + n for n in commands)
        for path, target in (*zip(links, indirects), *zip(indirects, targets)):
            s = os.lstat(path)
            if not stat.S_ISLNK(s.st_mode) or s.st_uid or s.st_gid or os.readlink(path) != target:
                raise ValueError("Node command differs from selected runtime")
        result = subprocess.run(
            ["/usr/bin/update-alternatives", "--query", "node"],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10,
            env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"},
        )
        if result.returncode or len(result.stdout) > 16384 or len(result.stderr) > 8192:
            raise ValueError("Node alternatives unavailable")
        sections = result.stdout.strip().split("\n\n")
        head = stanza(sections[0])
        if set(head) not in ({"Name", "Link", "Status", "Best", "Value"},
                              {"Name", "Link", "Slaves", "Status", "Best", "Value"}):
            raise ValueError("unexpected Node alternatives fields")
        if (head["Name"], head["Link"], head.get("Slaves", {}), head["Status"], head["Value"]) != (
            "node", link, {"npm": links[1], "npx": links[2]}, "manual", selected
        ):
            raise ValueError("foreign Node alternatives")
        registered = {}
        for section in sections[1:]:
            item = stanza(section)
            if set(item) not in ({"Alternative", "Priority"},
                                  {"Alternative", "Priority", "Slaves"}):
                raise ValueError("foreign Node alternatives entry")
            path = item["Alternative"]
            if path not in paths or path in registered:
                raise ValueError("unreviewed Node alternative")
            if item.get("Slaves", {}) != {"npm": path[:-4] + "npm", "npx": path[:-4] + "npx"}:
                raise ValueError("unreviewed Node alternative")
            priority = path.split("/")[-3].split(".")[0]
            if item["Priority"] != priority or not os.path.isfile(path):
                raise ValueError("Node alternative priority or binary differs")
            registered[path] = int(priority)
        if selected not in registered or head["Best"] != max(registered, key=registered.get):
            raise ValueError("Node alternatives selection differs")
except (OSError, ValueError, subprocess.SubprocessError):
    sys.exit(31)
"""


def inspect_command() -> str:
    return (
        f'/usr/bin/python3 -I -c {shlex.quote(PROGRAM)} "$selected" '
        + shlex.join(catalog.executable(v) for v in catalog.VERSIONS)
        + " || exit 31"
    )


def select(version: str) -> str:
    executable = catalog.executable(version)
    priority = version.split(".")[0]
    return (
        f"/usr/bin/update-alternatives --install {LINK} node {executable} {priority} "
        f"--slave /usr/local/bin/npm npm {executable[:-4]}npm "
        f"--slave /usr/local/bin/npx npx {executable[:-4]}npx "
        f"&& /usr/bin/update-alternatives --set node {executable} || exit 34"
    )
