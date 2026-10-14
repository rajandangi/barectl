import hashlib
import json
import os
import secrets
import shlex
import stat
import subprocess
import sys
from pathlib import Path

PROFILES = "/nix/var/nix/profiles/barectl"
WRAPPERS = "/usr/local/libexec/barectl/defaults"
KNOWN: dict[str, tuple[str, ...]] = {}
PHP = ("php84", "php85")
NODE = ("nodejs_22", "nodejs_24")
COMMANDS = {"php": ("php", "composer", "wp"), "node": ("node", "npm", "npx")}


def emit(text: str) -> None:
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


def render_wrapper(entry: str, name: str, helpers: tuple[str, ...]) -> str:
    if entry not in PHP or name not in ("composer", "wp"):
        raise ValueError("Unknown PHP command wrapper.")
    target = (
        f"{PROFILES}/composer/share/php/composer/bin/composer"
        if name == "composer"
        else f"{PROFILES}/wp-cli/share/wp-cli/wp-cli.phar"
    )
    path = ":".join((f"{PROFILES}/{entry}/bin", *helpers, "/usr/bin", "/bin"))
    return (
        "#!/bin/sh\n"
        "export PATH="
        + shlex.quote(path)
        + "\n"
        + "exec "
        + shlex.quote(f"{PROFILES}/{entry}/bin/php")
        + " "
        + shlex.quote(target)
        + ' "$@"\n'
    )


def metadata(path: str) -> dict[str, object] | None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    data: dict[str, object] = {
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": stat.S_IMODE(info.st_mode),
        "type": stat.S_IFMT(info.st_mode),
    }
    if stat.S_ISLNK(info.st_mode):
        data["target"] = os.readlink(path)
    elif stat.S_ISREG(info.st_mode):
        if info.st_size > 16384:
            data["content"] = "oversized"
        else:
            data["content"] = Path(path).read_bytes().hex()
    return data


def safe_directory(path: str, *, absent: bool = False) -> bool:
    value = metadata(path)
    return (value is None and absent) or (
        value is not None
        and value["type"] == stat.S_IFDIR
        and value["uid"] == 0
        and value["gid"] == 0
        and value["mode"] == 0o755
    )


def helper_paths(composer: str) -> tuple[str, ...]:
    result = subprocess.run(  # noqa: S603 - fixed Nix query against an identified catalog path
        ["/nix/var/nix/profiles/default/bin/nix-store", "--query", "--references", composer],
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    values = result.stdout.splitlines()
    if len(values) > 128 or any(
        not value.startswith("/nix/store/") or "/" in value[len("/nix/store/") :]
        for value in values
    ):
        raise ValueError("Invalid Composer closure references.")
    paths = tuple(sorted(value + "/bin" for value in values if os.path.isdir(value + "/bin")))
    if not all(
        any(os.access(path + "/" + name, os.X_OK) for path in paths)
        for name in ("git", "curl", "unzip", "xz", "7zz")
    ):
        raise ValueError("The pinned Composer helper tools are unavailable.")
    return paths


def current_selection(family: str, helpers: tuple[str, ...]) -> tuple[str, str]:
    entries = PHP if family == "php" else NODE
    names = COMMANDS[family]
    values = [metadata("/usr/local/bin/" + name) for name in names]
    if all(value is None for value in values):
        return "", ""
    for entry in entries:
        expected = targets(entry)
        if all(
            value is not None
            and value["type"] == stat.S_IFLNK
            and value["uid"] == 0
            and value["gid"] == 0
            and value.get("target") == expected[name]
            for name, value in zip(names, values, strict=True)
        ):
            if family == "php" and not wrappers_match(entry, helpers):
                break
            return entry, ""
    return "", f"The {'PHP' if family == 'php' else 'Node'} commands are set by the administrator."


def targets(entry: str) -> dict[str, str]:
    if entry in PHP:
        return {
            "php": f"{PROFILES}/{entry}/bin/php",
            "composer": f"{WRAPPERS}/{entry}/composer",
            "wp": f"{WRAPPERS}/{entry}/wp",
        }
    if entry in NODE:
        return {name: f"{PROFILES}/{entry}/bin/{name}" for name in COMMANDS["node"]}
    raise ValueError("Unknown default runtime.")


def wrappers_match(entry: str, helpers: tuple[str, ...]) -> bool:
    return all(
        metadata(f"{WRAPPERS}/{entry}/{name}")
        == {
            "uid": 0,
            "gid": 0,
            "mode": 0o755,
            "type": stat.S_IFREG,
            "content": render_wrapper(entry, name, helpers).encode().hex(),
        }
        for name in ("composer", "wp")
    )


def wrapper_problem(helpers: tuple[str, ...]) -> str:
    problem = ""
    for entry in PHP:
        directory = f"{WRAPPERS}/{entry}"
        if not safe_directory(directory, absent=True):
            problem = "The PHP wrapper directory is set by the administrator."
        for name in ("composer", "wp"):
            value = metadata(directory + "/" + name)
            if value is not None and value != {
                "uid": 0,
                "gid": 0,
                "mode": 0o755,
                "type": stat.S_IFREG,
                "content": render_wrapper(entry, name, helpers).encode().hex(),
            }:
                problem = "The PHP wrapper is set by the administrator."
    return problem


def state() -> dict[str, object]:
    paths = [
        "/usr",
        "/usr/local",
        "/usr/local/bin",
        "/usr/local/libexec",
        "/usr/local/libexec/barectl",
        WRAPPERS,
    ]
    paths.extend("/usr/local/bin/" + name for names in COMMANDS.values() for name in names)
    paths.extend(f"{WRAPPERS}/{entry}" for entry in PHP)
    paths.extend(f"{WRAPPERS}/{entry}/{name}" for entry in PHP for name in ("composer", "wp"))
    profiles = {}
    for entry, known in KNOWN.items():
        profile = f"{PROFILES}/{entry}"
        paths.append(profile)
        resolved = os.path.realpath(profile)
        if resolved in known and os.path.isdir(resolved):
            profiles[entry] = resolved
    helpers: tuple[str, ...] = ()
    helper_problem = ""
    if "composer" in profiles:
        try:
            helpers = helper_paths(profiles["composer"])
        except OSError, ValueError, subprocess.SubprocessError:
            helper_problem = "The installed Composer helper tools could not be verified."
    php, php_problem = current_selection("php", helpers)
    node, node_problem = current_selection("node", helpers)
    if php and php not in profiles:
        php_problem = "The selected default PHP profile is missing or unknown."
    if node and node not in profiles:
        node_problem = "The selected default Node profile is missing or unknown."
    if not all(safe_directory(path) for path in ("/usr", "/usr/local", "/usr/local/bin")):
        php_problem = node_problem = "The default command directory is outside supported settings."
    for path in ("/usr/local/libexec", "/usr/local/libexec/barectl", WRAPPERS):
        if not safe_directory(path, absent=True):
            php_problem = "The PHP wrapper directory is set by the administrator."
    php_problem = helper_problem or wrapper_problem(helpers) or php_problem
    evidence: dict[str, object] = {path: metadata(path) for path in paths}
    evidence["profiles"] = profiles
    evidence["helpers"] = list(helpers)
    return {
        "boot": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "uptime": int(float(Path("/proc/uptime").read_text().split()[0]) * 100),
        "digest": hashlib.sha256(json.dumps(evidence, sort_keys=True).encode()).hexdigest(),
        "profiles": profiles,
        "helpers": list(helpers),
        "php": php,
        "node": node,
        "php_problem": php_problem,
        "node_problem": node_problem,
    }


def install_wrappers(entry: str, raw_helpers: object) -> None:
    if not isinstance(raw_helpers, list):
        raise ValueError("Invalid native helper paths.")
    helpers = tuple(str(path) for path in raw_helpers)
    directory = f"{WRAPPERS}/{entry}"
    for parent in ("/usr/local/libexec", "/usr/local/libexec/barectl", WRAPPERS, directory):
        if not os.path.lexists(parent):
            os.mkdir(parent, mode=0o755)
            os.chmod(parent, 0o755)  # noqa: S103 - public root-owned command directory
    for name in ("composer", "wp"):
        path = directory + "/" + name
        if metadata(path) is None:
            with open(path, "x", encoding="utf-8") as output:
                output.write(render_wrapper(entry, name, helpers))
            os.chmod(path, 0o755)  # noqa: S103 - root-owned public executable configuration


def apply(document: dict[str, object]) -> None:
    current = state()
    entry = str(document["selection"])
    family = "php" if entry in PHP else "node"
    if current["digest"] != document["precondition_digest"] or current[family + "_problem"]:
        emit('barectl-result {"class":"refused","reason":"evidence"}')
        return
    profiles = current["profiles"]
    if not isinstance(profiles, dict) or profiles.get(entry) != document["path"]:
        emit('barectl-result {"class":"refused","reason":"evidence"}')
        return
    emit("barectl-stage preflight")
    changed = False
    try:
        if family == "php":
            changed = True
            install_wrappers(entry, current["helpers"])
        emit("barectl-stage commands")
        for name, target in targets(entry).items():
            destination = "/usr/local/bin/" + name
            if os.path.islink(destination) and os.readlink(destination) == target:
                continue
            temporary = "/usr/local/bin/.barectl-default-" + secrets.token_hex(16)
            try:
                os.symlink(target, temporary)
                changed = True
                os.replace(temporary, destination)
            finally:
                if os.path.lexists(temporary):
                    os.unlink(temporary)
        emit('barectl-result {"class":"succeeded"}')
    except OSError, ValueError:
        outcome = "partial" if changed else "refused"
        emit(
            "barectl-result " + json.dumps({"class": outcome, "reason": "runtime_config"}),
        )


if __name__ == "__main__":
    if len(sys.argv) > 2:
        KNOWN = {key: tuple(value) for key, value in json.loads(sys.argv[2]).items()}
    if sys.argv[1] == "read":
        emit(json.dumps(state()))
    else:
        apply(json.loads(sys.argv[1]))
