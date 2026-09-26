"""SSH configuration cases that the registration workflow tests cannot express clearly."""

import os
import tempfile
from pathlib import Path
from typing import override
from unittest import mock

from django.test import SimpleTestCase
from paramiko import SSHConfig

from .ssh_config import (
    AliasCatalog,
    AliasUnusable,
    ConnectionTarget,
    SkippedEntry,
    load_aliases,
    resolve_alias,
)


class AliasCatalogTests(SimpleTestCase):
    directory: Path

    @override
    def setUp(self) -> None:
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def write(self, name: str, text: str) -> Path:
        path = self.directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def load(self, text: str) -> AliasCatalog:
        return load_aliases(str(self.write("config", text)))

    def test_concrete_host_names_are_offered(self) -> None:
        catalog = self.load(
            "Host web db\n  HostName 203.0.113.10\n  User deploy\n"
            'Host "quoted-name"\n  Port 2222\n'
            "Host *\n  ServerAliveInterval 30\n"
        )
        self.assertEqual(catalog.aliases, ("db", "quoted-name", "web"))
        self.assertEqual(catalog.skipped, ())
        self.assertEqual(catalog.problem, "")
        self.assertIn("web", catalog)
        self.assertNotIn("*", catalog)

    def test_patterns_are_never_offered_as_servers(self) -> None:
        catalog = self.load(
            "Host web-* *.example.com db? !legacy web-1\n  User deploy\nHost legacy\n  User x\n"
        )
        self.assertEqual(catalog.aliases, ("web-1",))
        self.assertEqual(
            catalog.skipped,
            (
                SkippedEntry("!legacy", "A pattern, not a single server."),
                SkippedEntry("*.example.com", "A pattern, not a single server."),
                SkippedEntry("db?", "A pattern, not a single server."),
                # Barectl conservatively skips any name a negated pattern mentions.
                SkippedEntry("legacy", "Excluded by a negated Host pattern."),
                SkippedEntry("web-*", "A pattern, not a single server."),
            ),
        )

    def test_names_that_could_be_options_or_need_quoting_are_skipped(self) -> None:
        catalog = self.load('Host -oProxyCommand=x "a b" host;id ok\n  User deploy\n')
        self.assertEqual(catalog.aliases, ("ok",))
        self.assertEqual(
            {entry.name for entry in catalog.skipped}, {"-oProxyCommand=x", "a b", "host;id"}
        )

    def test_named_lookups_resolve_only_the_requested_entries(self) -> None:
        text = "Host web db bad\n  User deploy\nHost bad\n  Port ssh\nHost *.internal\n"
        path = str(self.write("config", text))
        with mock.patch.object(SSHConfig, "lookup", wraps=SSHConfig.lookup, autospec=True) as spy:
            catalog = load_aliases(path, {"web", "bad", "removed"})
        self.assertEqual(catalog.aliases, ("web",))
        self.assertEqual({entry.name for entry in catalog.skipped}, {"bad"})
        self.assertEqual(sorted(call.args[1] for call in spy.call_args_list), ["bad", "web"])

    def test_invalid_port_makes_an_alias_unusable(self) -> None:
        catalog = self.load("Host bad\n  Port ssh\nHost high\n  Port 70000\nHost ok\n  Port 22\n")
        self.assertEqual(catalog.aliases, ("ok",))
        reasons = {entry.name: entry.reason for entry in catalog.skipped}
        self.assertEqual(reasons["bad"], "Its Port setting is not a valid port number.")
        self.assertEqual(reasons["high"], "Its Port setting is not a valid port number.")

    def test_includes_expand_relative_to_the_including_file(self) -> None:
        self.write("conf.d/a.conf", "Host from-glob\n  User deploy\n")
        self.write("conf.d/nested/b.conf", "Host nested\n  User deploy\n")
        self.write("conf.d/c.conf", "Include nested/*.conf\n")
        absolute = self.write("elsewhere/extra", "Host absolute # inline comment\n")
        catalog = self.load(f"Include conf.d/*.conf\nInclude {absolute}\nInclude missing/*\n")
        self.assertEqual(catalog.aliases, ("absolute", "from-glob", "nested"))

    def test_include_loops_are_reported(self) -> None:
        self.write("loop", "Host looped\nInclude loop\n")
        catalog = self.load("Include loop\n")
        self.assertEqual(catalog.aliases, ())
        self.assertIn("includes the same file more than once", catalog.problem)

    def test_match_blocks_are_unsupported_and_never_executed(self) -> None:
        marker = self.directory / "executed"
        catalog = self.load(f"Host web\n  User deploy\nMatch exec \"touch '{marker}'\"\n  User x\n")
        self.assertEqual(catalog.aliases, ())
        self.assertIn("uses Match blocks, which Barectl does not support", catalog.problem)
        self.assertFalse(marker.exists())

    def test_problems_do_not_repeat_configuration_content(self) -> None:
        catalog = self.load("Host web\n  this-line-has-no-value\n")
        self.assertIn("contains a line Barectl cannot parse", catalog.problem)
        self.assertNotIn("this-line-has-no-value", catalog.problem)

    def test_missing_and_unreadable_files_are_explained(self) -> None:
        missing = load_aliases(str(self.directory / "absent"))
        self.assertEqual(missing.problem, f"No SSH configuration file exists at {missing.source}.")
        binary = self.directory / "binary"
        binary.write_bytes(b"Host \xff\n")
        self.assertIn("cannot read the SSH configuration", load_aliases(str(binary)).problem)
        if os.geteuid() != 0:  # root can read any file
            private = self.write("private", "Host web\n")
            private.chmod(0)
            self.assertIn("cannot read the SSH configuration", load_aliases(str(private)).problem)

    def test_reading_leaves_the_configuration_unchanged(self) -> None:
        path = self.write("config", "Host web\n  HostName 203.0.113.10\n")
        before = (path.read_bytes(), path.stat().st_mtime_ns)
        load_aliases(str(path))
        self.assertEqual((path.read_bytes(), path.stat().st_mtime_ns), before)
        self.assertEqual(sorted(p.name for p in self.directory.iterdir()), ["config"])


class ResolveAliasTests(SimpleTestCase):
    """Connection settings the worker reads for a registered alias."""

    directory: Path

    @override
    def setUp(self) -> None:
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def resolve(self, text: str, alias: str = "web") -> object:
        config = self.directory / "config"
        config.write_text(text, encoding="utf-8")
        return resolve_alias(str(config), alias)

    def test_connection_settings_are_resolved(self) -> None:
        target = self.resolve(
            "Host web\n  HostName 203.0.113.10\n  Port 2222\n  User deploy\n"
            "  IdentityFile ~/.ssh/web\n  IdentityFile /keys/%h\n"
            "  UserKnownHostsFile /trust/one ~/trust/two\n"
        )
        home = Path("~").expanduser()
        self.assertEqual(
            target,
            ConnectionTarget(
                alias="web",
                hostname="203.0.113.10",
                port=2222,
                user="deploy",
                identity_files=(home / ".ssh/web", Path("/keys/203.0.113.10")),
                known_hosts_files=(Path("/trust/one"), home / "trust/two"),
            ),
        )

    def test_openssh_defaults_apply_when_unset(self) -> None:
        target = self.resolve("Host web\n  ProxyJump none\n  IdentitiesOnly no\n")
        home = Path("~").expanduser()
        self.assertEqual(
            target,
            ConnectionTarget(
                alias="web",
                hostname="web",
                port=22,
                user=None,
                identity_files=(),
                known_hosts_files=(home / ".ssh/known_hosts", home / ".ssh/known_hosts2"),
            ),
        )

    def test_unimplemented_settings_are_refused_without_their_values(self) -> None:
        for setting in (
            "ProxyCommand ssh -W %h:%p secret-bastion",
            "HostKeyAlias secret-alias",
            "IdentitiesOnly yes",
            "UserKnownHostsFile /trust/%h",
        ):
            with self.subTest(setting=setting), self.assertRaises(AliasUnusable) as raised:
                self.resolve(f"Host web\n  {setting}\n")
            self.assertNotIn("secret", str(raised.exception))
            self.assertIn("The SSH alias web", str(raised.exception))

    def test_unusable_aliases_explain_why(self) -> None:
        cases = {
            "Host other\n": "It is no longer a Host entry.",
            "Host web\n  Port ssh\n": "Its Port setting is not a valid port number.",
            'Host web\nMatch exec "id"\n': "uses Match blocks",
        }
        for text, reason in cases.items():
            with self.subTest(reason=reason), self.assertRaises(AliasUnusable) as raised:
                self.resolve(text)
            self.assertIn(reason, str(raised.exception))
