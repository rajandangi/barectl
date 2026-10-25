"""An environment change restarts the site's enabled queue workers, and nothing else."""

import hashlib
from contextlib import ExitStack
from unittest import mock

from django.test import SimpleTestCase

from automation.bodies import worker_env


class RestartEnabledWorkersTests(SimpleTestCase):
    def run_with(self, states: dict[str, str], *, failure: bool = False) -> list[str]:
        restarted: list[str] = []

        def completed(*_args: object, **_kwargs: object) -> object:
            return mock.Mock(returncode=1 if failure else 0, stdout="", stderr="")

        def run(argv: list[str], **_kwargs: object) -> object:
            if argv[1] == "show":
                return mock.Mock(returncode=0, stdout=states.get(argv[-1], ""), stderr="")
            if argv[1] == "restart":
                restarted.append(argv[-1])
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch("automation.bodies.worker_env.subprocess.run", run):
            enabled, ok = worker_env.restart_workers("shop")
        self.assertTrue(ok or failure)
        return restarted if enabled else []

    def test_only_enabled_processes_are_restarted(self) -> None:
        restarted = self.run_with(
            {
                "barectl-site-shop-queue1.service": "enabled\n",
                "barectl-site-shop-queue2.service": "disabled\n",
            }
        )
        self.assertEqual(restarted, ["barectl-site-shop-queue1.service"])

    def test_a_deliberate_stop_survives_an_environment_change(self) -> None:
        self.assertEqual(
            self.run_with(
                {
                    "barectl-site-shop-queue1.service": "disabled\n",
                    "barectl-site-shop-queue2.service": "disabled\n",
                }
            ),
            [],
        )

    def test_a_failed_restart_is_reported(self) -> None:
        restarted = self.run_with({"barectl-site-shop-queue1.service": "enabled\n"}, failure=True)
        self.assertEqual(restarted, ["barectl-site-shop-queue1.service"])


class EnvironmentBodyTests(SimpleTestCase):
    def test_the_environment_change_restarts_workers_between_config_and_verify(self) -> None:
        from laravel.bodies import settings as body

        order: list[str] = []

        def note(name: str) -> None:
            order.append(name)

        def config(_settings: object) -> bool:
            note("config")
            return True

        def workers(_identifier: str) -> tuple[bool, bool]:
            note("workers")
            return True, True

        def fence(*_args: object) -> bool:
            note("fence")
            return True

        def restore(*_args: object) -> bool:
            note("restore")
            return True

        document = {
            "identifier": "shop",
            "names": ["shop.example.com"],
            "selection": "php84",
            "https": True,
            "changes": [{"key": "QUEUE_CONNECTION", "action": "set", "digest": ""}],
            "secret_fields": [{"key": "QUEUE_CONNECTION", "secret": False}],
            "environment_digest": hashlib.sha256(b"QUEUE_CONNECTION=sync\n").hexdigest(),
            "secret_path": "/run/barectl/secrets/" + "a" * 32,
        }
        settings = mock.Mock(
            identifier="shop",
            names=["shop.example.com"],
            runtime="php84",
            https=True,
            account="sshop",
            directory="/var/www/shop",
        )
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(body, "fence", fence, create=True))
            stack.enter_context(mock.patch.object(body, "restore", restore, create=True))
            for name, value in {
                "setting": lambda *_args, **_kwargs: settings,
                "site_account": lambda _identifier: [1001, 1001, "/var/www/shop", ""],
                "environment_path": lambda _identifier: "/var/www/shop/private/laravel.env",
                "_private_file_ok": lambda *_args: True,
                "open_site_lock": lambda _identifier: 9,
                "read_environment": mock.Mock(
                    side_effect=["QUEUE_CONNECTION=sync\n", "QUEUE_CONNECTION=database\n"]
                ),
                "_changes": lambda _document: document["changes"],
                "_values": lambda *_args: {"QUEUE_CONNECTION": "database"},
                "apply_environment": lambda _before, _changes: "QUEUE_CONNECTION=database\n",
                "_write_as_site": lambda *_args: None,
                "_config": config,
                "restart_workers": workers,
                "stage": lambda name: order.append(f"stage:{name}"),
                "result": lambda outcome, reason="": order.append(f"result:{outcome}:{reason}"),
                "os": mock.MagicMock(close=lambda _fd: None),
            }.items():
                stack.enter_context(mock.patch.object(body, name, value))
            body.edit_environment(document)
        self.assertIn("fence", order, order)
        self.assertIn("config", order, order)
        self.assertIn("workers", order, order)
        self.assertIn("restore", order, order)
        self.assertLess(order.index("fence"), order.index("config"))
        self.assertLess(order.index("config"), order.index("workers"))
        self.assertLess(order.index("workers"), order.index("stage:verify"))
        self.assertLess(order.index("restore"), order.index("result:succeeded:"))
        self.assertIn("result:succeeded:", order)
