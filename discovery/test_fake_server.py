"""FakeServer answers the collectors' probe commands as a managed server's shell does.

The discovery tests trust FakeServer's emulation of ``test``, ``cat`` and ``ls``
(docs/adr/0002-keep-the-remote-shell-seam.md). Each scenario here describes a set of paths
once, builds it both as a FakeServer and as a real temporary tree, and runs every probe
form against both. The collectors only tell success from failure and read the output of
a success, so that is what must agree. ``ls`` output is compared as a set: FakeServer lists
entries in the order a test declares them.
"""

import os
import shlex
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from unittest import SkipTest, TestCase

from .fakes import FakeServer

TESTS = ("-e", "-r", "-x", "-L", "-d")
LISTINGS = ("ls -1b", "ls -1bA")


@dataclass
class Scenario:
    """Paths described as FakeServer describes them; every listed entry must exist."""

    files: dict[str, str] = field(default_factory=dict)
    directories: dict[str, list[str]] = field(default_factory=dict)
    # Files and directories whose mode refuses the SSH user.
    unreadable: set[str] = field(default_factory=set)
    # Directories the SSH user can list but not search.
    unsearchable: set[str] = field(default_factory=set)
    dead_links: set[str] = field(default_factory=set)
    # Paths to probe beyond the described ones, such as paths that do not exist.
    extra: tuple[str, ...] = ()

    @property
    def uses_permissions(self) -> bool:
        return bool(self.unreadable or self.unsearchable)

    def fake(self) -> FakeServer:
        return FakeServer(
            files=dict(self.files),
            directories={path: list(entries) for path, entries in self.directories.items()},
            unreadable=set(self.unreadable),
            unsearchable=set(self.unsearchable),
            dead_links=set(self.dead_links),
            base_directories=set(),
            results={},
        )

    def paths(self) -> list[str]:
        """Every described path, each ancestor, and the extra paths."""
        described = [
            *self.files,
            *self.directories,
            *self.unreadable,
            *self.unsearchable,
            *self.dead_links,
            *self.extra,
        ]
        found: set[str] = set()
        for path in described:
            found.add(path)
            found.update(str(parent) for parent in PurePosixPath(path).parents)
        return sorted(found)

    def is_directory(self, path: str) -> bool:
        prefix = path.rstrip("/") + "/"
        described = (*self.files, *self.directories, *self.unreadable, *self.dead_links)
        return path in self.directories or any(p.startswith(prefix) for p in described)

    def build(self, root: Path) -> None:
        """Create the described paths under ``root``; modes are applied last."""
        for directory in self.directories:
            _under(root, directory).mkdir(parents=True, exist_ok=True)
        for path, content in self.files.items():
            _parent_of(root, path).write_text(content, encoding="utf-8")
        for path in self.dead_links:
            _parent_of(root, path).symlink_to(root / "nonexistent-target")
        for path in self.unreadable:
            if not _under(root, path).exists():
                target = _parent_of(root, path)
                if self.is_directory(path):
                    target.mkdir()
                else:
                    target.write_text("", encoding="utf-8")
        self._check_listings(root)
        for path in self.unreadable:
            _under(root, path).chmod(0)
        for path in self.unsearchable:
            _under(root, path).chmod(0o644)

    def _check_listings(self, root: Path) -> None:
        for directory, entries in self.directories.items():
            for entry in entries:
                child = f"{directory.rstrip('/')}/{entry}"
                if not os.path.lexists(_under(root, child)):
                    msg = f"{child} is listed but not described"
                    raise AssertionError(msg)


def _under(root: Path, path: str) -> Path:
    return root / path.lstrip("/")


def _parent_of(root: Path, path: str) -> Path:
    """The path under ``root``, after creating its parent directories."""
    target = _under(root, path)
    target.parent.mkdir(parents=True, exist_ok=True)
    return target


def _restore_modes(root: Path) -> None:
    """Make the tree removable again after modes refused the owner."""
    for directory, names, _ in os.walk(root, topdown=True):
        for name in names:
            path = Path(directory, name)
            if not path.is_symlink():
                path.chmod(0o755)


def _shell(command: str) -> tuple[bool, str]:
    result = subprocess.run(  # noqa: S603
        ["/bin/sh", "-c", command],
        capture_output=True,
        check=False,
        env={"PATH": "/usr/local/bin:/usr/bin:/bin", "LC_ALL": "C"},
        text=True,
    )
    return result.returncode == 0, result.stdout


SCENARIOS = {
    "files, directories and missing paths": Scenario(
        files={
            "/etc/nginx/nginx.conf": "http {}\n",
            "/etc/nginx/sites-enabled/example.com": "server {}\n",
        },
        directories={"/etc/nginx/sites-enabled": ["example.com"]},
        extra=("/etc/nginx/sites-enabled/missing", "/etc/absent/site", "/etc/nginx/conf.d"),
    ),
    "names starting with a dot": Scenario(
        files={"/etc/postgresql/16/.hidden": "", "/etc/postgresql/16/main/postgresql.conf": ""},
        directories={"/etc/postgresql/16": [".hidden", "main"]},
    ),
    "a dead symlink": Scenario(
        directories={"/etc/postgresql/16": ["broken"]},
        dead_links={"/etc/postgresql/16/broken"},
    ),
    "an unreadable file": Scenario(
        files={"/etc/nginx/sites-enabled/public": "server {}\n"},
        directories={"/etc/nginx/sites-enabled": ["public", "private"]},
        unreadable={"/etc/nginx/sites-enabled/private"},
    ),
    "an unreadable directory": Scenario(
        files={"/etc/postgresql/16/main/postgresql.conf": ""},
        unreadable={"/etc/postgresql/16"},
        extra=("/etc/postgresql/16/main",),
    ),
    "a directory that can be listed but not searched": Scenario(
        files={"/etc/php/8.3/fpm/pool.d/www.conf": "[www]\n"},
        directories={"/etc/php/8.3/fpm/pool.d": ["www.conf"]},
        unsearchable={"/etc/php/8.3/fpm/pool.d"},
    ),
}


def _gnu_coreutils() -> bool:
    """Whether the local tools are GNU coreutils, as on the supported Debian and Ubuntu servers.

    BSD ``ls``, as on macOS, fails when it lists a directory it cannot search.
    """
    return _shell("ls --version")[0]


class FakeServerContractTests(TestCase):
    def test_probes_agree_with_a_posix_shell(self) -> None:
        if not _gnu_coreutils():
            msg = "Managed servers use GNU coreutils; run the contract where ls is GNU ls"
            raise SkipTest(msg)
        running_as_root = os.geteuid() == 0
        for name, scenario in SCENARIOS.items():
            with self.subTest(scenario=name):
                if scenario.uses_permissions and running_as_root:
                    msg = "Permissions do not restrict root, so the scenario cannot be built"
                    raise SkipTest(msg)
                self.assert_agrees(scenario)

    def assert_agrees(self, scenario: Scenario) -> None:
        fake = scenario.fake()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            scenario.build(root)
            try:
                for path in scenario.paths():
                    real = shlex.quote(str(_under(root, path)))
                    remote = shlex.quote(path)
                    forms = [(f"test {flag} {remote}", f"test {flag} {real}") for flag in TESTS]
                    if not scenario.is_directory(path):
                        forms.append((f"cat {remote}", f"cat {real}"))
                    else:
                        forms += [(f"{ls} {remote}", f"{ls} {real}") for ls in LISTINGS]
                    for command, local in forms:
                        with self.subTest(command=command):
                            self.assertEqual(self.fake_answer(fake, command), _shell(local))
            finally:
                _restore_modes(root)

    @staticmethod
    def fake_answer(fake: FakeServer, command: str) -> tuple[bool, str]:
        result = fake.run(command)
        succeeded = result.exit_status == 0
        if command.startswith("ls "):
            lines = sorted(result.stdout.splitlines())
            return succeeded, "".join(f"{line}\n" for line in lines)
        return succeeded, result.stdout
