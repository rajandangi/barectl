"""The per-site logrotate file Barectl owns (docs/logs.md#rotation).

Barectl creates the PHP error and slow logs, and a WordPress site's debug log when it is
pointed into the site's log directory. Caddy rotates its own access log and Laravel's daily
channel rotates its own files, so neither appears here. This module is compiled into the
server-side site read and the rotation change body, so it imports nothing from Django.
"""

import os
import pathlib
import stat

LOGROTATE_DIRECTORY = "/etc/logrotate.d"
LOGROTATE_BINARIES = ("/usr/sbin/logrotate", "/usr/bin/logrotate")
# The only files Barectl creates in a site's log directory and therefore rotates.
LOGROTATE_PHP_FILES = ("php-error.log", "php-slow.log")
LOGROTATE_WORDPRESS_FILE = "wp-debug.log"
LOGROTATE_KNOWN_FILES = (*LOGROTATE_PHP_FILES, LOGROTATE_WORDPRESS_FILE)

LOGROTATE_HEADER = (
    "# Barectl rotates this site's own log files. Do not edit: anything outside this\n"
    "# file's supported shape is reported, and the reviewed Log rotation action restores it.\n"
    "# The log directory is caddy:site 0750, so root renames and recreates the files with\n"
    "# the site's ownership; the site account cannot rename inside its own log directory.\n"
)


def logrotate_directory(identifier: str) -> str:
    return f"/var/www/{identifier}/logs"


def logrotate_file(identifier: str) -> str:
    """The root-owned drop-in the distro's logrotate timer reads."""
    return f"{LOGROTATE_DIRECTORY}/barectl-site-{identifier}"


def logrotate_available() -> bool:
    """The package is installed: both its drop-in directory and its binary exist."""
    return pathlib.Path(LOGROTATE_DIRECTORY).is_dir() and any(
        pathlib.Path(path).is_file() for path in LOGROTATE_BINARIES
    )


def logrotate_present(identifier: str) -> tuple[str, ...]:
    """The known log files that exist in the site's log directory."""
    found: list[str] = []
    for name in LOGROTATE_KNOWN_FILES:
        path = pathlib.Path(logrotate_directory(identifier)) / name
        try:
            if path.is_file() and not path.is_symlink():
                found.append(name)
        except OSError:
            continue
    return tuple(found)


def logrotate_render(identifier: str, names: tuple[str, ...]) -> str:
    """The supported file for exactly ``names``, validated against the known set."""
    if not names or any(name not in LOGROTATE_KNOWN_FILES for name in names):
        raise ValueError("Not a supported set of site log files.")
    ordered = tuple(name for name in LOGROTATE_KNOWN_FILES if name in names)
    account = "s" + identifier
    rotated = " ".join(f"{logrotate_directory(identifier)}/{name}" for name in ordered)
    return (
        LOGROTATE_HEADER
        + rotated
        + " {\n"
        + "    daily\n"
        + "    maxsize 20M\n"
        + "    rotate 5\n"
        + "    maxage 14\n"
        + "    compress\n"
        + "    delaycompress\n"
        + "    missingok\n"
        + "    notifempty\n"
        + f"    create 0640 {account} {account}\n"
        + "}\n"
    )


def logrotate_parse(text: str, identifier: str) -> tuple[str, ...] | None:
    """The file names the text rotates, or ``None`` when it is outside the supported shape."""
    prefix = logrotate_directory(identifier) + "/"
    if not text.startswith(LOGROTATE_HEADER + prefix) or not text.endswith("}\n"):
        return None
    header, _, _body = text.partition(" {\n")
    paths = header[len(LOGROTATE_HEADER) :].split(" ")
    names: list[str] = []
    for path in paths:
        if not path.startswith(prefix) or path[len(prefix) :] not in LOGROTATE_KNOWN_FILES:
            return None
        names.append(path[len(prefix) :])
    if len(set(names)) != len(names) or not set(LOGROTATE_PHP_FILES) <= set(names):
        return None
    try:
        expected = logrotate_render(identifier, tuple(names))
    except ValueError:
        return None
    return tuple(names) if text == expected else None


def logrotate_state(identifier: str) -> tuple[str, str, tuple[str, ...]]:
    """The site's rotation state, a sanitized problem sentence, and the rotated file names.

    ``supported`` is a file matching the convention, ``partial`` one within the convention
    that does not cover every log present (a WordPress debug log enabled after the file was
    written), ``outside`` an edit Barectl does not interpret, ``missing`` no file at all, and
    ``unavailable`` a host without logrotate.
    """
    path = pathlib.Path(logrotate_file(identifier))
    if not logrotate_available():
        return "unavailable", "This server does not run logrotate.", ()
    if not path.exists() and not path.is_symlink():
        return "missing", "Log rotation is not set up for this site.", ()
    try:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            return "outside", "The site's log rotation file is not a regular file.", ()
        if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o644:
            return "outside", "The site's log rotation file is not owned by root.", ()
        names = logrotate_parse(path.read_text(), identifier)
    except OSError, UnicodeDecodeError:
        return "outside", "The site's log rotation file could not be read.", ()
    if names is None:
        return "outside", "The site's log rotation file is outside the supported settings.", ()
    if not set(logrotate_present(identifier)) <= set(names):
        return (
            "partial",
            "Log rotation does not yet cover every log in this site's log directory.",
            names,
        )
    return "supported", "", names


def logrotate_install(identifier: str, names: tuple[str, ...] | None = None) -> bool:
    """Write the supported file atomically; return whether this host has logrotate.

    Called from the site layout because every new site creates the PHP logs. A host without
    the logrotate package keeps its site: the file is absent and discovery says the server
    does not run logrotate.
    """
    if not logrotate_available():
        return False
    text = logrotate_render(identifier, names or LOGROTATE_PHP_FILES)
    path = pathlib.Path(logrotate_file(identifier))
    try:
        if (
            not path.is_symlink()
            and path.is_file()
            and path.stat().st_uid == 0
            and path.read_text() == text
        ):
            return True
    except OSError:
        pass
    temporary = path.with_name("." + path.name + ".barectl")
    descriptor = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(descriptor, "w") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(str(temporary), 0o644)
        os.replace(str(temporary), str(path))
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return True
