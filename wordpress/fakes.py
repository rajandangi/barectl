"""WP-CLI setup preparation and apply against the simulated Ubuntu server.

The fake answers the fixed read-only WP-CLI scripts deterministically from a small
state, mirroring what the native payload does on a real server; it establishes nothing
about real GPG, curl or systemd behaviour.
"""

import hashlib
import shlex
from dataclasses import dataclass, field

from discovery.ssh import CommandResult
from sites import native as site_native

from . import setup_native

_MARKER = "/usr/local/lib/wp-cli"
_ANCESTRY = (
    ("directory", "root", "root", "755", "12", "/usr"),
    ("directory", "root", "root", "755", "10", "/usr/local"),
    ("directory", "root", "root", "755", "6", "/usr/local/lib"),
)
_GPG_VERSION = "gpg (GnuPG) 2.4.4"


def _reads() -> frozenset[str]:
    """The WP-CLI reads' exact command forms: plain, through sudo, and its listing."""
    argvs = (setup_native.wpcli_state(), setup_native.wpcli_digest_argv())
    plain = {shlex.join(argv) for argv in argvs}
    return frozenset(
        plain | {f"sudo -n {read}" for read in plain} | {f"sudo -n -l {read}" for read in plain}
    )


def wpcli_read_only(command: str) -> bool:
    return command in _reads()


def _inner_script(command: str) -> str | None:
    try:
        argv = shlex.split(command)
    except ValueError:
        return None
    if argv[:2] == [site_native.SHELL, "-c"] and len(argv) == 3:
        return argv[2]
    return None


@dataclass
class WpcliServer:
    """A server's WP-CLI installation state, as the fixed reads report it."""

    # "absent", "installed" (exact reviewed artifact) or "foreign" (other bytes or mode).
    phar: str = "absent"
    # "absent", "ok" (root:root 0755) or "foreign".
    directory: str = "absent"
    # Extra entries in the installation directory, by path.
    entries: tuple[str, ...] = ()
    # The native tools present, out of gpg and curl.
    tools: tuple[str, ...] = ("gpg", "curl")
    # The phar's digest when foreign, to make the mismatch observable.
    foreign_sha256: str = "0" * 64
    gpg_version: str = _GPG_VERSION
    ancestry: tuple[tuple[str, str, str, str, str, str], ...] = field(
        default_factory=lambda: _ANCESTRY
    )

    def state(self) -> str:
        """The fixed read's exact output for this state."""
        lines = [
            f"path {kind}|{user}|{group}|{mode}|{links}|{path}"
            for kind, user, group, mode, links, path in self.ancestry
        ]
        if self.directory == "absent":
            lines.append(f"absent {setup_native.DIRECTORY}")
        elif self.directory == "ok":
            lines.append(f"path directory|root|root|755|2|{setup_native.DIRECTORY}")
        else:
            lines.append(f"path directory|root|root|777|2|{setup_native.DIRECTORY}")
        entries: list[tuple[str, str, str, str, str]] = [
            ("f", "644", "0", "0", path) for path in self.entries
        ]
        if self.phar != "absent":
            mode = "644" if self.phar == "installed" else "755"
            entries.append(("f", mode, "0", "0", setup_native.PHAR))
        lines += [
            f"entry {kind} {mode} {user} {group} {path}"
            for kind, mode, user, group, path in sorted(entries, key=lambda entry: entry[4])
        ]
        if self.phar == "absent":
            lines.append(f"absent {setup_native.PHAR}")
        else:
            mode = "644" if self.phar == "installed" else "755"
            lines.append(f"path regular file|root|root|{mode}|1|{setup_native.PHAR}")
            digest = setup_native.SHA256 if self.phar == "installed" else self.foreign_sha256
            lines.append(f"sha {digest} {setup_native.PHAR}")
        lines += [
            f"tool {name} {'ok' if name in self.tools else 'missing'}" for name in ("gpg", "curl")
        ]
        if "gpg" in self.tools:
            lines.append(f"version {self.gpg_version}")
        return "\n".join(lines) + "\n"

    def answer(self, remote: object) -> None:
        answers = remote.answers  # type: ignore[attr-defined]
        if self._answer not in answers:
            answers.insert(0, self._answer)

    def install(self) -> None:
        """A successful run's effect, as the payload leaves it."""
        self.directory = "ok"
        self.phar = "installed"
        self.entries = ()

    def _answer(self, command: str) -> CommandResult | None:
        if command.startswith("sudo -n -l ") and _MARKER in command:
            return CommandResult(0, "")
        inner = command.removeprefix("sudo -n ")
        script = _inner_script(inner)
        if script is None or _MARKER not in script:
            return None
        state = self.state()
        if script.rstrip().endswith("sha256sum"):
            return CommandResult(0, f"{hashlib.sha256(state.encode()).hexdigest()}  -\n")
        return CommandResult(0, state)
