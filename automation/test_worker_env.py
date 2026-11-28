"""An environment change restarts the site's enabled queue workers, and nothing else."""

import hashlib
from contextlib import ExitStack
from typing import cast
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


class FencedWorkersTests(SimpleTestCase):
    def test_only_the_site_s_fenced_worker_services_count(self) -> None:
        plan: dict[str, object] = {
            "automation_fence": {
                "version": 1,
                "sites": [
                    {"identifier": "shop", "services": ["barectl-site-shop-queue1.service"]},
                    {"identifier": "blog", "services": ["barectl-site-blog-schedule.service"]},
                ],
            }
        }
        self.assertTrue(worker_env.fenced_workers(plan, "shop"))
        self.assertFalse(worker_env.fenced_workers(plan, "blog"))
        self.assertFalse(worker_env.fenced_workers(plan, "other"))
        self.assertFalse(worker_env.fenced_workers({}, "shop"))


QUEUE1 = "barectl-site-shop-queue1.service"
QUEUE2 = "barectl-site-shop-queue2.service"
OLD = "QUEUE_CONNECTION=sync\n"
NEW = "QUEUE_CONNECTION=database\n"


class FakeSite:
    """Queue1 enabled and running, queue2 deliberately stopped, under systemd's fence rules.

    A fenced unit keeps its loaded ``enabled`` state but refuses a manual start, as the
    fence's drop-in makes it do on a real server (automation/bodies/units.py).
    """

    def __init__(self) -> None:
        self.environment = OLD
        self.enabled = {QUEUE1: True, QUEUE2: False}
        self.running: dict[str, str | None] = {QUEUE1: OLD, QUEUE2: None}
        self.fenced = False
        self.order: list[str] = []

    def fence(self, document: dict[str, object], _identifier: str) -> bool:
        self.order.append("fence")
        if document.get("automation_fence"):
            self.fenced = True
            self.running = dict.fromkeys(self.running)
        return True

    def restore(self, document: dict[str, object], _identifier: str) -> bool:
        self.order.append("restore")
        if not document.get("automation_fence"):
            return True
        self.fenced = False
        plan = cast("dict[str, list[dict[str, list[str]]]]", document["automation_fence"])
        for name in plan["sites"][0]["resume"]:
            self.running[name] = self.environment
        return True

    def write(self, *_args: object) -> None:
        self.order.append("write")
        self.environment = NEW

    def config(self, _settings: object) -> bool:
        self.order.append("config")
        return True

    def read(self, _identifier: str) -> str:
        return self.environment

    def systemctl(self, argv: list[str], **_kwargs: object) -> object:
        name = argv[-1]
        if argv[1] == "show":
            state = "enabled" if self.enabled.get(name) else "disabled"
            return mock.Mock(returncode=0, stdout=state + "\n", stderr="")
        self.order.append(f"restart:{name}")
        if self.fenced:
            return mock.Mock(returncode=1, stdout="", stderr="Operation refused.")
        self.running[name] = self.environment
        return mock.Mock(returncode=0, stdout="", stderr="")


class EnvironmentBodyTests(SimpleTestCase):
    def edit(self, site: FakeSite, *, fenced: bool) -> list[str]:
        from laravel.bodies import settings as body

        document: dict[str, object] = {
            "identifier": "shop",
            "names": ["shop.example.com"],
            "selection": "php84",
            "https": True,
            "changes": [{"key": "QUEUE_CONNECTION", "action": "set", "digest": ""}],
            "secret_fields": [{"key": "QUEUE_CONNECTION", "secret": False}],
            "environment_digest": hashlib.sha256(OLD.encode()).hexdigest(),
            "secret_path": "/run/barectl/secrets/" + "a" * 32,
        }
        if fenced:
            document["automation_fence"] = {
                "version": 1,
                "sites": [{"identifier": "shop", "services": [QUEUE1, QUEUE2], "resume": [QUEUE1]}],
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
            stack.enter_context(mock.patch.object(body, "fence", site.fence, create=True))
            stack.enter_context(mock.patch.object(body, "restore", site.restore, create=True))
            stack.enter_context(
                mock.patch("automation.bodies.worker_env.subprocess.run", site.systemctl)
            )
            for name, value in {
                "setting": lambda *_args, **_kwargs: settings,
                "site_account": lambda _identifier: [1001, 1001, "/var/www/shop", ""],
                "environment_path": lambda _identifier: "/var/www/shop/private/laravel.env",
                "_private_file_ok": lambda *_args: True,
                "open_site_lock": lambda _identifier: 9,
                "read_environment": site.read,
                "_changes": lambda _document: document["changes"],
                "_values": lambda *_args: {"QUEUE_CONNECTION": "database"},
                "apply_environment": lambda _before, _changes: NEW,
                "_write_as_site": site.write,
                "_config": site.config,
                "stage": lambda name: site.order.append(f"stage:{name}"),
                "result": lambda outcome, reason="": site.order.append(
                    f"result:{outcome}:{reason}"
                ),
                "os": mock.MagicMock(close=lambda _fd: None),
            }.items():
                stack.enter_context(mock.patch.object(body, name, value))
            body.edit_environment(document)
        return site.order

    def test_fenced_running_workers_come_back_on_the_new_environment(self) -> None:
        """#587: a restart while the fence refuses manual starts would leave them stopped."""
        site = FakeSite()
        order = self.edit(site, fenced=True)
        self.assertEqual(order[-1], "result:succeeded:", order)
        self.assertNotIn(f"restart:{QUEUE1}", order)
        self.assertEqual(site.running, {QUEUE1: NEW, QUEUE2: None})
        self.assertFalse(site.fenced)

    def test_unfenced_workers_restart_between_config_and_verify(self) -> None:
        site = FakeSite()
        order = self.edit(site, fenced=False)
        self.assertEqual(order[-1], "result:succeeded:", order)
        self.assertLess(order.index("config"), order.index(f"restart:{QUEUE1}"))
        self.assertLess(order.index(f"restart:{QUEUE1}"), order.index("stage:verify"))
        self.assertNotIn(f"restart:{QUEUE2}", order)
        self.assertEqual(site.running, {QUEUE1: NEW, QUEUE2: None})
