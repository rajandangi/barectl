"""Journey 1: add a server in plain steps (docs/dashboard-workflows.md, #179)."""

import contextlib
import re
import tempfile
from pathlib import Path
from typing import override
from unittest import mock

from django.contrib.auth.models import Permission
from django.core.management import call_command
from django.test import override_settings, tag
from paramiko import ECDSAKey
from playwright.sync_api import expect

from dashboard.browser_testing import BrowserTestCase
from discovery.fakes import FakeServer, run_worker
from discovery.recorded import ReplayShell, load
from discovery.ssh import UnknownHostKey
from servers.models import Server
from servers.ssh_config import ConnectionTarget


@tag("browser")
class AddServerBrowserTests(BrowserTestCase):
    @classmethod
    @override
    def serve_assets(cls) -> None:
        static_root = cls.enterClassContext(tempfile.TemporaryDirectory())
        cls.enterClassContext(override_settings(STATIC_ROOT=static_root, VITE_DEV_SERVER_URL=""))
        known_hosts = Path(cls.enterClassContext(tempfile.TemporaryDirectory())) / "known_hosts"
        cls.enterClassContext(override_settings(SSH_KNOWN_HOSTS_PATH=str(known_hosts)))
        call_command("collectstatic", interactive=False, verbosity=0)

    def grant(self, *codenames: str) -> None:
        for codename in codenames:
            self.user.user_permissions.add(Permission.objects.get(codename=codename))

    def empty_inventory(self) -> None:
        Server.objects.all().delete()

    def add_server(self, *, name: str = "Cloud", address: str = "cloud.example") -> None:
        page = self.page
        page.get_by_role("link", name="Add server").click()
        page.get_by_role("textbox", name="Name", exact=True).fill(name)
        page.get_by_role("textbox", name="Address", exact=True).fill(address)
        page.get_by_role("button", name="Save and check").click()

    def test_add_a_server_in_three_activations(self) -> None:
        self.grant(
            "add_server",
            "add_discoveryattempt",
            "change_server",
            "change_shared",
        )
        self.empty_inventory()
        self.sign_in()
        page = self.page
        expect(page.get_by_role("heading", name="Add your first server")).to_be_visible()
        expect(page.get_by_role("link", name="Add server")).to_be_visible()
        expect(page.get_by_role("searchbox", name="Search servers")).to_have_count(0)

        self.add_server()
        expect(page.get_by_role("heading", name="Cloud", level=1)).to_be_visible()
        expect(page.get_by_text("Checking the connection…")).to_be_visible()

        key = ECDSAKey.generate()
        target = ConnectionTarget(
            alias="cloud.example",
            hostname="cloud.example",
            port=22,
            user="root",
            identity_files=(),
            known_hosts_files=(),
        )
        with mock.patch("discovery.ssh.connect_operation", side_effect=UnknownHostKey(target, key)):
            run_worker()
        expect(page.get_by_role("heading", name="Confirm this is your server")).to_be_visible(
            timeout=10_000
        )
        expect(page.get_by_text(key.fingerprint)).to_be_visible()
        page.get_by_label("Provider fingerprint").fill(key.fingerprint)
        page.get_by_role("button", name="Confirm and check").click()

        with mock.patch(
            "discovery.ssh.connect_operation",
            return_value=contextlib.nullcontext(ReplayShell(load("pristine-26.04"))),
        ):
            run_worker()
        expect(page.get_by_role("heading", name="Ready to set up")).to_be_visible(timeout=10_000)
        expect(page.get_by_role("button", name="Set up server")).to_be_visible()

    def test_more_options_hold_port_and_alias_and_focus_survives_polling(self) -> None:
        self.grant("add_server", "add_discoveryattempt")
        self.sign_in()
        page = self.page
        page.get_by_role("link", name="Add server").click()
        port = page.get_by_role("spinbutton", name="Port", exact=True)
        alias = page.get_by_role("combobox", name="SSH alias")
        expect(port).to_be_hidden()
        expect(alias).to_be_hidden()
        page.get_by_role("button", name="More options").click()
        expect(port).to_be_visible()
        expect(port).to_have_value("22")
        expect(alias).to_be_visible()

        port.fill("2222")
        page.get_by_role("textbox", name="Name", exact=True).fill("Cloud")
        page.get_by_role("textbox", name="Address", exact=True).fill("cloud.example")
        page.get_by_role("button", name="Save and check").click()
        expect(page.get_by_role("heading", name="Cloud", level=1)).to_be_visible()

        servers = page.get_by_role("navigation", name="Primary").get_by_role("link", name="Servers")
        servers.focus()
        page.wait_for_timeout(2500)
        expect(servers).to_be_focused()

    def test_connection_failed_shows_the_failure_and_its_actions(self) -> None:
        self.grant("add_server", "add_discoveryattempt", "change_server")
        self.sign_in()
        self.add_server()
        remote = FakeServer()
        with remote.substituted():
            remote.failure = "Barectl could not reach the SSH service configured for cloud.example."
            run_worker()
        page = self.page
        page.reload()
        expect(page.get_by_role("heading", name="Connection failed")).to_be_visible()
        expect(page.get_by_text("could not reach the SSH service")).to_be_visible()
        expect(page.get_by_role("button", name="Check again")).to_be_visible()
        expect(page.get_by_role("link", name="Edit connection")).to_be_visible()
        page.get_by_role("navigation", name="Server sections").get_by_role(
            "link", name="Advanced", exact=True
        ).click()
        expect(page.get_by_role("heading", name="Connection record")).to_be_visible()

    def test_cannot_be_managed_lists_one_line_per_reason(self) -> None:
        self.grant("add_server", "add_discoveryattempt")
        self.sign_in()
        self.add_server()
        with mock.patch(
            "discovery.ssh.connect_operation",
            return_value=contextlib.nullcontext(ReplayShell(load("nginx-26.04"))),
        ):
            run_worker()
        page = self.page
        page.reload()
        expect(
            page.get_by_role("heading", name="Barectl cannot manage this server")
        ).to_be_visible()
        reasons = page.locator("#next-action ul li")
        expect(reasons.first).to_contain_text("Another web stack is installed")
        page.get_by_role("navigation", name="Server sections").get_by_role(
            "link", name="Advanced", exact=True
        ).click()
        expect(page.get_by_text("Discovery evidence")).to_be_visible()

    def test_key_choice_reveals_the_chosen_public_half(self) -> None:
        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        key_file = directory / "private-key"
        key = ECDSAKey.generate()
        key.write_private_key_file(str(key_file))
        self.enterContext(override_settings(SSH_APPROVED_KEYS={"production": str(key_file)}))
        self.grant("add_server")
        self.sign_in()
        page = self.page
        page.get_by_role("link", name="Add server").click()
        public_half = page.get_by_label("Public key for production")
        expect(public_half).to_be_hidden()
        page.get_by_label("Key", exact=True).select_option("production")
        expect(public_half).to_be_visible()
        expect(public_half).to_have_value(f"{key.get_name()} {key.get_base64()}")
        self.assertNotIn(str(key_file), page.content())

    def test_narrow_layout_has_no_horizontal_scroll(self) -> None:
        self.grant("add_server")
        self.sign_in()
        page = self.page
        page.get_by_role("link", name="Add server").click()
        page.get_by_role("button", name="More options").click()
        page.set_viewport_size({"width": 320, "height": 740})
        overflow = page.evaluate(
            "document.documentElement.scrollWidth - document.documentElement.clientWidth"
        )
        self.assertEqual(overflow, 0)
        expect(page.get_by_label(re.compile("Name"))).to_be_visible()
