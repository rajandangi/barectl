"""The native bodies of a WordPress site's actions (Phase B #381).

Executed as root by the change engine's staged payload under the mutation lock. Both actions
run WP-CLI as the site user and report one bounded, sanitized result line; neither prints
WP-CLI's own output, and the administrator password travels only on standard input
(docs/wordpress.md, ADR 0032).

This module is also a complete Python module for the fast layer: it imports the site and
WordPress convention helpers it uses. When a body is assembled, those imports are stripped
and the helpers are inlined from ``sites.observation``'s ``COMMON_SOURCE`` and
``wordpress.convention``.
"""

import contextlib
import pathlib
import re
import socket
import ssl
import subprocess
import urllib.parse
from types import SimpleNamespace

from sites.bodies.common import NativeState, native_state, result, setting, stage
from wordpress.convention import ADMIN_USERNAME, public_root

WP_CLI = "bin/wp"
SECRET_PATH = re.compile(r"/run/barectl/secrets/[0-9a-f]{32}")
IDENTIFIER = re.compile(r"[a-z][a-z0-9]{2,23}")
VERSION_NAME = re.compile(r"[0-9A-Za-z.-]{1,40}")
DIGEST = re.compile(r"[0-9a-f]{64}")
# How much of WP-CLI's own output is kept in memory to classify the result; never stored.
OUTPUT_LIMIT = 65536
MISMATCH = "doesn't verify against checksums"


def user_run(
    settings: SimpleNamespace,
    argv: list[str],
    *,
    input_data: bytes | None = None,
    cwd: str | pathlib.Path | None = None,
    timeout: int = 300,
) -> subprocess.CompletedProcess[bytes]:
    environment = {
        "HOME": str(settings.directory),
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
    }
    return subprocess.run(  # noqa: S603 - fixed argv as the site's own user
        ["/usr/sbin/runuser", "-u", str(settings.account), "--", *argv],
        cwd=cwd,
        env=environment,
        input=input_data,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def _site(document: dict[str, object]) -> SimpleNamespace | None:
    """The reviewed site, or ``None`` when its native evidence changed."""
    identifier = str(document.get("identifier", ""))
    names = document.get("names")
    selection = document.get("selection")
    identity = document.get("identity")
    core_version = document.get("core_version")
    if (
        IDENTIFIER.fullmatch(identifier) is None
        or not isinstance(names, list)
        or not all(isinstance(name, str) for name in names)
        or not names
        or not isinstance(selection, str)
        or type(identity) is not int
        or not 1000 <= identity < 30000
        or not isinstance(core_version, str)
        or VERSION_NAME.fullmatch(core_version) is None
        or document.get("precondition_digest") is None
    ):
        return None
    try:
        state: NativeState = native_state("observed", "", protections=False)
    except ValueError, OSError, subprocess.TimeoutExpired:
        return None
    if state["digest"] != document["precondition_digest"]:
        return None
    site = next((row for row in state["sites"] if row["identifier"] == identifier), None)
    if (
        site is None
        or site["state"] != "complete"
        or site["application"] != "wordpress"
        or site["application_version"] != core_version
        or site["names"] != names
        or site["runtime"] != selection
        or site["account"] is None
        or site["account"][0] != identity
    ):
        return None
    return setting(identifier, list(names), selection, https=bool(site["https"]))


def _secret_path(document: dict[str, object]) -> str | None:
    value = document.get("secret_path")
    return value if isinstance(value, str) and SECRET_PATH.fullmatch(value) else None


def _wp(settings: SimpleNamespace) -> str:
    return str(settings.directory) + "/" + WP_CLI


def _user_field(settings: SimpleNamespace, username: str, field: str) -> str | None:
    completed = user_run(
        settings,
        [_wp(settings), "user", "get", username, f"--field={field}"],
        cwd=public_root(str(settings.identifier)),
        timeout=120,
    )
    if completed.returncode:
        return None
    value = completed.stdout.decode("utf-8", "replace").strip()
    return value or None


def _password_text(password: bytes) -> str | None:
    """The password WP-CLI's prompt reads as one line, or ``None`` when it cannot be one."""
    try:
        text = password.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text or len(password) > 4096 or any(mark in text for mark in ("\0", "\n", "\r")):
        return None
    return text


def _is_administrator(settings: SimpleNamespace, username: str) -> bool:
    roles = _user_field(settings, username, "roles")
    return roles is not None and "administrator" in {role.strip() for role in roles.split(",")}


def _signs_in(settings: SimpleNamespace, username: str, password: str) -> bool:
    """WordPress's own sign-in page accepts the new password, over the site's own address.

    The password is the request body, never an argument, and the loopback probe accepts the
    site's certificate like the installation's own verification does.
    """
    host = str(settings.names[0])
    scheme = "https" if settings.https else "http"
    body = urllib.parse.urlencode(
        {
            "log": username,
            "pwd": password,
            "wp-submit": "Log In",
            "redirect_to": f"{scheme}://{host}/wp-admin/",
            "testcookie": "1",
        }
    ).encode()
    request = (
        "POST /wp-login.php HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode()
    try:
        raw = socket.create_connection(("127.0.0.1", 443 if settings.https else 80), timeout=20)
        if settings.https:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            raw = context.wrap_socket(raw, server_hostname=host)
        with raw:
            raw.sendall(request + body)
            response = b""
            while b"\r\n\r\n" not in response and len(response) < 65536:
                chunk = raw.recv(65536 - len(response))
                if not chunk:
                    break
                response += chunk
    except OSError, ssl.SSLError:
        return False
    head = response.partition(b"\r\n\r\n")[0].decode("iso-8859-1", "replace")
    lines = head.splitlines()
    if not lines:
        return False
    status = lines[0].split(" ")[1] if len(lines[0].split(" ")) > 1 else ""
    cookies = "\n".join(line for line in lines if line.lower().startswith("set-cookie:"))
    return status in ("200", "302") and "wordpress_logged_in" in cookies


def _reset_values(document: dict[str, object]) -> tuple[str, str] | None:
    secret_path = _secret_path(document)
    username = document.get("admin_username")
    if (
        secret_path is None
        or not isinstance(username, str)
        or ADMIN_USERNAME.fullmatch(username) is None
    ):
        return None
    return secret_path, username


def _password_accepted(
    settings: SimpleNamespace, username: str, before: str | None, password: str
) -> bool:
    """The stored hash changed and WordPress's own sign-in page accepts the new value."""
    after = _user_field(settings, username, "user_pass")
    if before is None or after is None or before == after or not _is_password_hash(after):
        return False
    return _signs_in(settings, username, password)


def reset_password(document: dict[str, object]) -> None:
    """Set one administrator's password from the confidential channel and prove sign-in."""
    values = _reset_values(document)
    if values is None:
        result("refused", "evidence")
        return
    secret_path, username = values
    stage("preflight")
    settings = _site(document)
    if settings is None:
        result("refused", "evidence")
        return
    stage("password")
    path = pathlib.Path(secret_path)
    try:
        password = path.read_bytes()
    except OSError:
        result("refused", "wordpress_secret")
        return
    finally:
        with contextlib.suppress(OSError):
            path.unlink()
    text = _password_text(password)
    if text is None or not _is_administrator(settings, username):
        result("refused", "wordpress_password")
        return
    before = _user_field(settings, username, "user_pass")
    try:
        completed = user_run(
            settings,
            [_wp(settings), "user", "update", username, "--prompt=user_pass", "--skip-email"],
            input_data=password + b"\n",
            cwd=public_root(str(settings.identifier)),
        )
    except OSError, subprocess.TimeoutExpired:
        result("refused", "wordpress_password")
        return
    if completed.returncode:
        result("refused", "wordpress_password")
        return
    stage("verify")
    if not _password_accepted(settings, username, before, text):
        result("partial", "wordpress_password_unverified")
        return
    result("succeeded")


def _is_password_hash(value: str) -> bool:
    return value.startswith("$") and 34 <= len(value) <= 255 and " " not in value


def verify_core(document: dict[str, object]) -> None:
    """Compare the installed core with WordPress.org's official checksums for its version."""
    stage("preflight")
    settings = _site(document)
    if settings is None:
        result("refused", "evidence")
        return
    stage("checksums")
    version = str(document["core_version"])
    try:
        completed = user_run(
            settings,
            [
                _wp(settings),
                "core",
                "verify-checksums",
                f"--version={version}",
                "--locale=en_US",
            ],
            cwd=public_root(str(settings.identifier)),
        )
    except OSError, subprocess.TimeoutExpired:
        result("refused", "wordpress_checksums_unavailable")
        return
    output = (completed.stdout + completed.stderr)[-OUTPUT_LIMIT:].decode("utf-8", "replace")
    if completed.returncode == 0:
        result("succeeded")
    elif MISMATCH in output:
        result("refused", "wordpress_checksums")
    else:
        result("refused", "wordpress_checksums_unavailable")


if __name__ == "__main__":
    import base64
    import gzip
    import json
    import sys

    arguments = json.loads(gzip.decompress(base64.b64decode(sys.argv[1])))
    if arguments.get("action") == "password":
        reset_password(arguments)
    else:
        verify_core(arguments)
