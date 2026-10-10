"""Native PHP alternatives, read and changed through the existing SSH/unit adapter."""

import shlex

from . import native

PROGRAM = r"""
import hashlib, json, os, re, stat, subprocess


def run(argv: list[str], ok: tuple[int, ...] = (0,)) -> str:
    p = subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=20,
        env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"},
    )
    if p.returncode not in ok or len(p.stdout) > 32768 or len(p.stderr) > 8192:
        raise ValueError("native PHP evidence unavailable")
    return p.stdout


def safe(path: str) -> None:
    s = os.lstat(path)
    if (
        not stat.S_ISREG(s.st_mode)
        or s.st_uid != 0
        or s.st_gid != 0
        or s.st_mode & 0o022
        or s.st_nlink != 1
    ):
        raise ValueError("unsafe CLI executable")
    for directory in ("/", "/usr", "/usr/bin", "/etc", "/etc/alternatives"):
        d = os.lstat(directory)
        if not stat.S_ISDIR(d.st_mode) or d.st_uid != 0 or d.st_gid != 0 or d.st_mode & 0o022:
            raise ValueError("unsafe CLI directory")


states = run(
    [
        "/usr/bin/dpkg-query",
        "-W",
        "-f=${Package}|${Version}|${Architecture}|${db:Status-Abbrev}\n",
        "php[0-9]*-cli",
    ],
    (0, 1),
)
packages = []
for line in states.splitlines():
    name, version, architecture, status = line.split("|")
    if status.strip() == "ii":
        if (
            not re.fullmatch(r"php8\.[345]-cli", name)
            or not re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,100}", version)
            or architecture not in ("arm64", "amd64")
        ):
            raise ValueError("unsupported installed PHP CLI")
        path = "/usr/bin/php" + name[3:6]
        safe(path)
        if run(["/usr/bin/dpkg-query", "-S", path]).strip() != name + ": " + path:
            raise ValueError("CLI package ownership differs")
        sums = run(["/usr/bin/dpkg-query", "--control-show", name, "md5sums"])
        expected = [line.split()[0] for line in sums.splitlines()
                    if len(line.split()) == 2 and line.split()[1] == path.lstrip("/")]
        if len(expected) != 1 or not re.fullmatch(r"[0-9a-f]{32}", expected[0]):
            raise ValueError("CLI package checksum unavailable")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as executable:
            state = os.fstat(executable.fileno())
            if not 0 < state.st_size <= 32 * 1024 * 1024:
                raise ValueError("CLI executable exceeds evidence bound")
            if hashlib.file_digest(executable, "md5").hexdigest() != expected[0]:
                raise ValueError("CLI executable differs from its package")
        packages.append(
            {
                "branch": name[3:6],
                "path": path,
                "package": name,
                "version": version,
                "architecture": architecture,
            }
        )
if len(packages) > 3:
    raise ValueError("too many CLI branches")
query = subprocess.run(
    ["/usr/bin/update-alternatives", "--query", "php"],
    stdin=subprocess.DEVNULL,
    capture_output=True,
    text=True,
    timeout=20,
    env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"},
)
if len(query.stdout) > 16384 or len(query.stderr) > 8192:
    raise ValueError("alternatives query exceeds bound")
default = None
if query.returncode == 0:
    fields = {}
    for line in query.stdout.split("\n\n", 1)[0].splitlines():
        if ": " in line:
            key, value = line.split(": ", 1)
            if key in fields:
                raise ValueError("duplicate alternatives field")
            fields[key] = value
    if (
        fields.get("Name") != "php"
        or fields.get("Link") != "/usr/bin/php"
        or fields.get("Status") not in ("auto", "manual")
    ):
        raise ValueError("unsupported alternatives group")
    selected = [p for p in packages if p["path"] == fields.get("Value")]
    if (
        len(selected) != 1
        or os.path.realpath("/usr/bin/php") != fields["Value"]
        or not os.path.islink("/usr/bin/php")
        or os.readlink("/usr/bin/php") != "/etc/alternatives/php"
        or not os.path.islink("/etc/alternatives/php")
    ):
        raise ValueError("native default differs from registered CLI")
    for link in ("/usr/bin/php", "/etc/alternatives/php"):
        state = os.lstat(link)
        if not stat.S_ISLNK(state.st_mode) or state.st_uid or state.st_gid:
            raise ValueError("unsafe alternatives link")
    default = dict(selected[0], mode=fields["Status"])
elif (
    query.returncode != 2
    or packages
    or os.path.lexists("/usr/bin/php")
    or os.path.lexists("/etc/alternatives/php")
):
    raise ValueError("missing or broken PHP alternatives")
print(
    json.dumps(
        {"default": default, "packages": sorted(packages, key=lambda p: p["branch"])},
        sort_keys=True,
        separators=(",", ":"),
    )
)
"""
_READ_BODY = shlex.join(["/usr/bin/python3", "-I", "-c", PROGRAM])
READ = shlex.join(["/bin/sh", "-c", "; ".join(native.staged(_READ_BODY))])
DIGEST = f'value=$({READ}) || exit 1; printf "%s\\n" "$value" | sha256sum'


def set_default(branch: str) -> str:
    if branch not in ("8.3", "8.4", "8.5"):
        raise ValueError("Unsupported PHP branch.")
    return f"/usr/bin/update-alternatives --set php /usr/bin/php{branch}"


def change(
    unit: str,
    boot: str,
    deadline: int,
    *,
    digest: str,
    branch: str,
    preconditions: tuple[tuple[str, str], ...] = (),
) -> str:
    return "; ".join(
        (
            *native.admission(unit, boot, deadline),
            *native.digest_preconditions(((DIGEST, digest), *preconditions)),
            set_default(branch) + " || exit 40",
            f'test "$(readlink -f /usr/bin/php)" = /usr/bin/php{branch} || exit 40',
            "exit 0",
        )
    )
