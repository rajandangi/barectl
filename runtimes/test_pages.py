from django.template.defaultfilters import filesizeformat

from discovery import ssh
from discovery.fakes import DiscoveryTestCase
from servers.models import Server

from .catalog import Architecture, load


class RuntimeCatalogPageTests(DiscoveryTestCase):
    def stack_page(self, machine: str) -> str:
        self.remote.results["uname -m"] = ssh.CommandResult(0, f"{machine}\n")
        self.discover()
        connections = len(self.remote.targets)
        page = self.client.get(f"/servers/{Server.objects.get().pk}/stack/")
        self.assertEqual(page.status_code, 200)
        self.assertEqual(len(self.remote.targets), connections, "The page connected over SSH.")
        self.assertContains(page, 'aria-current="page">Stack</a>')
        return page.content.decode()

    def assert_offers(self, machine: str, architecture: Architecture, other: Architecture) -> None:
        page = self.stack_page(machine)
        self.assertIn(f"<code>{architecture}</code>", page)
        for build in load().offered(architecture):
            self.assertIn(f"<code>{build.entry}</code>", page)
            self.assertIn(build.version, page)
            self.assertIn(filesizeformat(build.download_size), page)
        php84 = next(b for b in load().offered(other) if b.entry == "php84")
        self.assertNotIn(filesizeformat(php84.download_size), page)

    def test_an_amd64_server_is_offered_the_x86_64_builds_without_ssh(self) -> None:
        self.assert_offers("x86_64", Architecture.X86_64, Architecture.AARCH64)

    def test_an_arm64_server_is_offered_the_aarch64_builds_without_ssh(self) -> None:
        self.assert_offers("aarch64", Architecture.AARCH64, Architecture.X86_64)

    def test_an_architecture_without_builds_is_explained(self) -> None:
        page = self.stack_page("riscv64")
        self.assertIn("Barectl offers no runtimes for the riscv64 architecture.", page)
        self.assertNotIn("<code>php84</code>", page)

    def test_a_server_never_checked_is_asked_for_a_connection_check(self) -> None:
        self.sign_in_with("view_server")
        server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        page = self.client.get(f"/servers/{server.pk}/stack/")
        self.assertContains(page, "Check the connection first")
        self.assertEqual(self.remote.targets, [])

    def test_requires_the_server_view_permission(self) -> None:
        self.client.force_login(self.user)
        server = Server.objects.create(name="Web", ssh_alias="web.example.com")
        self.assertEqual(self.client.get(f"/servers/{server.pk}/stack/").status_code, 403)
