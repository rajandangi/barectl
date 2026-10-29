"""The recorded Laravel create state, replayed at the ``RemoteShell`` seam (Phase B #382).

docs/quality.md#recorded-transcripts. The scenario ``LaravelCreateMariaDB`` records what a
fresh controller reconstructs from the server alone: the Laravel shape, the repository and
branch from the first release's Git metadata, the private environment's key names (never a
value) and the deploy key's public half.
"""

from typing import cast

from django.test import SimpleTestCase

from discovery import ssh
from discovery.recorded import Recorded, ReplayShell, Transcript, load
from laravel import observation

IDENTIFIER = "slcalpha"
REPOSITORY = "git@git:fixture.git"


class LaravelPendingMigrationTests(SimpleTestCase):
    """The Deploy review names pending migrations from the release and the table (#407)."""

    IDENTIFIER = "slcalpha"
    MIGRATION = "2026_10_19_000001_create_fixture_widgets"

    def test_the_pending_read_is_valid_python(self) -> None:
        compile(observation.PENDING_SOURCE, "pending.py", "exec")
        with self.assertRaises(ValueError):
            observation.pending_command("../escape")

    def test_a_recorded_pending_answer_binds_its_names(self) -> None:
        shell = ReplayShell(
            Transcript(
                "pending",
                {},
                "26.04",
                "x86_64",
                "ssh-ed25519 SHA256:x",
                (
                    ("id -u", Recorded(ssh.CommandResult(0, "0\n"))),
                    (
                        observation.pending_command(self.IDENTIFIER),
                        Recorded(
                            ssh.CommandResult(0, '["' + self.MIGRATION + '"]'),
                        ),
                    ),
                ),
            )
        )
        self.assertEqual(observation.pending(shell, self.IDENTIFIER), (self.MIGRATION,))

    def test_an_unreadable_answer_is_unknown_not_pending(self) -> None:
        shell = ReplayShell(
            Transcript(
                "pending",
                {},
                "26.04",
                "x86_64",
                "ssh-ed25519 SHA256:x",
                (
                    ("id -u", Recorded(ssh.CommandResult(0, "0\n"))),
                    (
                        observation.pending_command(self.IDENTIFIER),
                        Recorded(ssh.CommandResult(0, "null")),
                    ),
                ),
            )
        )
        self.assertIsNone(observation.pending(shell, self.IDENTIFIER))
        shell = ReplayShell(
            Transcript(
                "pending",
                {},
                "26.04",
                "x86_64",
                "ssh-ed25519 SHA256:x",
                (
                    ("id -u", Recorded(ssh.CommandResult(0, "0\n"))),
                    (
                        observation.pending_command(self.IDENTIFIER),
                        Recorded(ssh.CommandResult(0, '["..\\u0000bad"]')),
                    ),
                ),
            )
        )
        self.assertIsNone(observation.pending(shell, self.IDENTIFIER))


class LaravelCreateReconstructionTests(SimpleTestCase):
    def replay(self) -> dict[str, object]:
        value = observation.read(ReplayShell(load("laravel-create-26.04")))
        if value is None:
            raise AssertionError("The Laravel inventory was not read.")
        row = observation.site(value, IDENTIFIER)
        if row is None:
            raise AssertionError(f"The site was not reconstructed: {value}")
        return row

    def test_reconstructs_the_laravel_shape_repository_and_branch(self) -> None:
        row = self.replay()
        self.assertEqual(row["application"], "laravel")
        self.assertEqual(row["repository"], REPOSITORY)
        self.assertEqual(row["branch"], "main")
        self.assertTrue(all(cast(dict[str, bool], row["shared"]).values()))
        self.assertEqual(len(cast(list[object], row["releases"])), 1)

    def test_reconstructs_the_environment_key_names_but_no_value(self) -> None:
        row = self.replay()
        environment = cast(list[str], row["environment"])
        for key in ("APP_ENV", "APP_KEY", "APP_URL", "DB_CONNECTION", "LOG_CHANNEL"):
            self.assertIn(key, environment)
        self.assertNotIn("base64", str(environment))

    def test_reconstructs_the_deploy_key_public_half_and_host_keys(self) -> None:
        row = self.replay()
        self.assertTrue(str(row["deploy_key"]).startswith("ssh-ed25519 "))
        self.assertTrue(row["host_keys"])
