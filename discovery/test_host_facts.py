"""The operating system and capacity observations, replayed from a real 26.04 server.

docs/quality.md#recorded-transcripts
"""

from . import ssh
from .fakes import FakeServer, ReplayObservationTestCase, observed
from .observations import (
    ARCH_COMMAND,
    CPU_COMMAND,
    FILESYSTEM_COMMAND,
    MEMINFO_PATH,
    OS_RELEASE_FILES,
)
from .recorded import load
from .snapshot import FilesystemSize, OsRelease

ETC_RELEASE, USR_RELEASE = OS_RELEASE_FILES


class PartialObservationTests(ReplayObservationTestCase):
    def test_unreadable_release_file_is_inaccessible_not_absent(self) -> None:
        self.filesystem = FakeServer(files={}, directories={}, results={})
        self.filesystem.unreadable = {ETC_RELEASE}
        collected = self.collect()
        self.assertEqual(collected.os.outcome, "inaccessible")
        self.assertIsNone(collected.os.value)
        self.assertIn(("Operating system", "inaccessible"), self.warned())
        self.assertEqual(
            collected.os.warning,
            "The SSH user cannot read /etc/os-release. Barectl does not use sudo.",
        )

    def test_missing_release_files_are_unsupported_not_absent(self) -> None:
        self.filesystem = FakeServer(files={}, directories={}, results={})
        collected = self.collect()
        self.assertEqual(collected.os.outcome, "unsupported")
        self.assertEqual(
            collected.os.warning,
            "The server has neither /etc/os-release nor /usr/lib/os-release, so Barectl "
            "cannot identify the operating system.",
        )

    def test_fallback_release_file_is_used(self) -> None:
        self.filesystem = FakeServer(
            files={USR_RELEASE: 'NAME="Debian GNU/Linux"\nID=debian\n'}, directories={}, results={}
        )
        collected = self.collect()
        self.assertEqual((collected.os.outcome, collected.os.source), ("observed", (USR_RELEASE,)))
        # Fields the file does not set are empty, not guessed.
        self.assertEqual(observed(collected.os), OsRelease("", "Debian GNU/Linux", "debian", ""))

    def test_unrecognized_content_is_unsupported(self) -> None:
        self.filesystem = FakeServer(
            files={ETC_RELEASE: "<html>not a release file</html>\nX=$(id)\n"},
            directories={},
            results={},
        )
        collected = self.collect()
        self.assertEqual(collected.os.outcome, "unsupported")
        self.assertIn(("Operating system", "unsupported"), self.warned())
        self.assert_not_kept("not a release file")

    def test_values_are_unquoted_bounded_and_never_executed(self) -> None:
        self.filesystem = FakeServer(
            files={
                ETC_RELEASE: (
                    "# comment\nNAME='Example $(touch /tmp/x)'\nID=example\n"
                    f'PRETTY_NAME="{"x" * 500}"\nVERSION_ID="1\\"2"\nBROKEN="unterminated\n'
                )
            },
            directories={},
            results={},
        )
        release = observed(self.collect().os)
        self.assertEqual(release.name, "Example $(touch /tmp/x)")
        self.assertEqual(len(release.pretty_name), 200)
        self.assertEqual(release.version_id, '1"2')


class CapacityTests(ReplayObservationTestCase):
    def test_capacity_is_replayed_from_the_recording(self) -> None:
        collected = self.collect()
        architecture, cpu_count = collected.architecture, collected.cpu_count
        self.assertEqual(
            (architecture.outcome, architecture.value, architecture.source),
            ("observed", self.recorded(ARCH_COMMAND).stdout.strip(), (ARCH_COMMAND,)),
        )
        self.assertEqual(
            (cpu_count.outcome, cpu_count.value, cpu_count.source),
            ("observed", int(self.recorded(CPU_COMMAND).stdout), (CPU_COMMAND,)),
        )
        meminfo = self.recorded(f"cat {MEMINFO_PATH}").stdout
        total = next(line for line in meminfo.splitlines() if line.startswith("MemTotal"))
        kilobytes = int(total.split()[1])
        memory = collected.memory_bytes
        self.assertEqual(
            (memory.outcome, memory.value, memory.source),
            ("observed", kilobytes * 1024, (MEMINFO_PATH,)),
        )
        size, avail, target = self.recorded(FILESYSTEM_COMMAND).stdout.splitlines()[1].split()
        self.assertEqual(target, "/")
        self.assertEqual(
            (collected.filesystem.outcome, collected.filesystem.value),
            ("observed", FilesystemSize(int(size), int(avail))),
        )
        self.assertEqual(observed(collected.os).pretty_name, "Ubuntu 26.04.1 LTS")
        # Only the needed fields are kept; other meminfo lines are discarded.
        memfree = next(line for line in meminfo.splitlines() if line.startswith("MemFree"))
        self.assert_not_kept(memfree.split()[1])

    def test_partial_capacity_shows_warnings_not_zero_values(self) -> None:
        self.override(ARCH_COMMAND, ssh.CommandResult(1, ""))
        self.override(CPU_COMMAND, ssh.CommandResult(0, "four\n"))
        self.override(
            FILESYSTEM_COMMAND,
            ssh.CommandResult(0, "Size Avail Target\nnot-a-number 123 /\n"),
        )
        self.filesystem = FakeServer(files=self.described_files(), directories={}, results={})
        self.filesystem.unreadable = {MEMINFO_PATH}
        collected = self.collect()
        self.assertEqual(collected.architecture.outcome, "unsupported")
        self.assertIsNone(collected.cpu_count.value)
        self.assertEqual(collected.cpu_count.outcome, "unsupported")
        self.assertEqual(collected.memory_bytes.outcome, "inaccessible")
        self.assertIsNone(collected.memory_bytes.value)
        self.assertEqual(collected.filesystem.outcome, "unsupported")
        self.assertIsNone(collected.filesystem.value)
        self.assertEqual(observed(collected.os).pretty_name, "Ubuntu 26.04.1 LTS")
        # Every capacity observation warns, before any later observation does.
        self.assertEqual(
            self.warned()[:4],
            [
                ("Architecture", "unsupported"),
                ("CPUs", "unsupported"),
                ("Memory", "inaccessible"),
                ("Root filesystem", "unsupported"),
            ],
        )
        self.assertEqual(
            collected.memory_bytes.warning,
            "The SSH user cannot read /proc/meminfo. Barectl does not use sudo.",
        )
        self.assert_not_kept("four")
        self.assertEqual([observation.value for observation in collected.capacity], [None] * 4)

    def test_missing_meminfo_is_unsupported_not_absent(self) -> None:
        files = self.described_files()
        del files[MEMINFO_PATH]
        self.filesystem = FakeServer(files=files, directories={}, results={})
        collected = self.collect()
        self.assertEqual(collected.memory_bytes.outcome, "unsupported")
        self.assertEqual(
            collected.memory_bytes.warning,
            "The server has no /proc/meminfo, so Barectl cannot report memory.",
        )

    def test_missing_and_unrunnable_commands_are_distinct(self) -> None:
        # POSIX shells exit 127 for a missing command and 126 for one they cannot run.
        self.override(ARCH_COMMAND, ssh.CommandResult(127, ""))
        self.override(CPU_COMMAND, ssh.CommandResult(126, ""))
        collected = self.collect()
        self.assertEqual(
            (collected.architecture.outcome, collected.cpu_count.outcome),
            ("unsupported", "inaccessible"),
        )
        self.assertEqual(
            collected.architecture.warning,
            "The server has no uname command, so Barectl cannot inspect this.",
        )
        self.assertEqual(
            collected.cpu_count.warning,
            "The SSH user cannot run nproc. Barectl does not use sudo.",
        )

    def test_truncated_capacity_output_is_unsupported(self) -> None:
        transcript = load(self.state)
        for command, entry in transcript.commands:
            self.override(
                command,
                ssh.CommandResult(
                    entry.result.exit_status,
                    entry.result.stdout,
                    truncated=True,
                ),
            )
        collected = self.collect()
        self.assertEqual(
            [observation.outcome for observation in collected.capacity],
            ["unsupported", "unsupported", "unsupported", "unsupported"],
        )
        for observation in (collected.architecture, collected.cpu_count, collected.filesystem):
            with self.subTest(source=observation.source):
                self.assertEqual(
                    observation.warning,
                    f"{observation.source[0]} wrote more output than expected. It was not read.",
                )
        self.assertIsNone(collected.memory_bytes.value)

    def test_unsupported_capacity_never_shows_raw_output(self) -> None:
        self.override(ARCH_COMMAND, ssh.CommandResult(0, "x86_64\nmalicious $(touch /tmp/x)"))
        self.override(CPU_COMMAND, ssh.CommandResult(0, "0\n"))
        self.override(FILESYSTEM_COMMAND, ssh.CommandResult(0, "Size Avail Target\n100 200 /\n"))
        files = self.described_files()
        files[MEMINFO_PATH] = "MemTotal: ² kB\n"
        self.filesystem = FakeServer(files=files, directories={}, results={})
        collected = self.collect()
        self.assertEqual(
            [observation.outcome for observation in collected.capacity],
            ["unsupported", "unsupported", "unsupported", "unsupported"],
        )
        self.assert_not_kept("malicious", "²")


class AttributeTests(ReplayObservationTestCase):
    """docs/ssh-connections.md#bounds-and-read-only-commands"""

    def test_a_server_without_inspection_tools_has_no_absent_attributes(self) -> None:
        # Every command is missing and every file is gone, with searchable parents.
        self.filesystem = FakeServer(files={}, directories={}, results={})
        for command, _ in load(self.state).commands:
            if not command.startswith("test "):
                self.override(command, ssh.CommandResult(127, ""))
        collected = self.collect()
        attributes = (collected.os, *collected.capacity)
        self.assertEqual(
            [attribute.outcome for attribute in attributes],
            ["unsupported"] * 5,
            [(attribute.source, attribute.warning) for attribute in attributes],
        )
        self.assertFalse([c for c in collected.components if c.package.outcome != "unsupported"])
        self.assert_nothing_absent()
