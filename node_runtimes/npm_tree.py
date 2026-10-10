"""Passive bundled npm integrity (docs/node-runtimes-native-design.md)."""

import shlex

from . import catalog

SHA256 = {
    "24.21.0": "f67abb034e1516900f810b227da48162b8d79950be4fc3b346e15a2a9ee3ce33",
    "22.23.3": "1a8717d78439dbee8c0d63a98bb619589bca70f6083e3c442d4ac9d82a836bb7",
}

PROGRAM = r"""
import hashlib, json, os, stat, sys

def owned(s):
    if s.st_uid or s.st_gid:
        raise ValueError("foreign npm ownership")
    if not stat.S_ISLNK(s.st_mode) and s.st_mode & 0o022:
        raise ValueError("writable npm content")

try:
    for spec in sys.argv[2:]:
        version, expected = spec.split(":")
        base = "/usr/local/share/mise/installs/http-node/" + version
        if not os.path.lexists(base):
            continue
        for p in (base, base + "/lib", base + "/lib/node_modules"):
            s = os.lstat(p)
            owned(s)
            if not stat.S_ISDIR(s.st_mode):
                raise ValueError("unsafe npm ancestry")
        for name in ("npm", "npx"):
            p = base + "/bin/" + name
            s = os.lstat(p)
            owned(s)
            target = "../lib/node_modules/npm/bin/" + name + "-cli.js"
            if not stat.S_ISLNK(s.st_mode) or os.readlink(p) != target:
                raise ValueError("foreign npm executable")
        root = base + "/lib/node_modules/npm"
        pending = [(root, "")]
        entries = []
        while pending:
            path, relative = pending.pop()
            s = os.lstat(path)
            owned(s)
            if stat.S_ISDIR(s.st_mode):
                kind, value = "d", ""
                pending.extend((path + "/" + n, relative + "/" + n if relative else n)
                               for n in os.listdir(path))
            elif stat.S_ISLNK(s.st_mode):
                kind, value = "l", os.readlink(path)
            elif stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and s.st_size <= 16777216:
                with open(path, "rb") as f:
                    kind, value = "f", hashlib.file_digest(f, "sha256").hexdigest()
            else:
                raise ValueError("unsupported npm content")
            entries.append((relative, kind, s.st_mode & 0o777, value))
            if len(entries) + len(pending) > 5000:
                raise ValueError("npm tree exceeds bound")
        encoded = json.dumps(sorted(entries), separators=(",", ":"), ensure_ascii=True).encode()
        digest = hashlib.sha256(encoded).hexdigest()
        if sys.argv[1] == "1" and digest != expected:
            raise ValueError("npm differs from authenticated archive")
        if sys.argv[1] == "0":
            print(version, digest)
except (OSError, ValueError):
    sys.exit(31)
"""


def command(*, verify: bool) -> str:
    return (
        f"/usr/bin/python3 -I -c {shlex.quote(PROGRAM)} {int(verify)} "
        + shlex.join(f"{v}:{SHA256[v]}" for v in catalog.VERSIONS)
        + " || exit 31"
    )
