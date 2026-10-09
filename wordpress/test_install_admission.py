"""The installation review's pure decisions and input boundary.

docs/wordpress.md#installation-review
"""

from django.test import SimpleTestCase

from bootstrap.models import PlanRefusal
from bootstrap.releases import RELEASES
from sites.convention import Application, Stage

from . import core_native, inputs, install, setup_native
from .core_native import Unreadable

Reason = PlanRefusal.Reason
METADATA = inputs.Metadata("www.shop.example.com", "Shop", "owner", "owner@example.com")


def draft(version: str, php: str, supply: str = "ubuntu") -> install.InstallDraft:
    result = install.InstallDraft("shop", "0" * 32, METADATA, None, RELEASES[version])
    result.names = ("shop.example.com", "www.shop.example.com")
    result.php_version, result.php_supply = php, supply
    return result


class QualificationTests(SimpleTestCase):
    def reasons(self, result: install.InstallDraft) -> list[PlanRefusal.Reason]:
        return [reason for reason, _ in result.refusals]

    def test_the_releases_own_ubuntu_branch_on_a_qualified_architecture_is_admitted(self) -> None:
        for version, php in (("24.04", "8.3"), ("26.04", "8.5")):
            with self.subTest(version=version):
                result = draft(version, php)
                install._site(result, "arm64", Application.PHP, Stage.REDIRECT)
                self.assertEqual(result.refusals, [])

    def test_an_architecture_without_recorded_native_statuses_stays_disabled(self) -> None:
        for version, php in (("24.04", "8.3"), ("26.04", "8.5")):
            with self.subTest(version=version):
                result = draft(version, php)
                install._site(result, "amd64", Application.PHP, Stage.REDIRECT)
                self.assertEqual(self.reasons(result), [Reason.UNSUPPORTED_VERSION])
                self.assertIn("is not qualified", result.refusals[0][1])
                self.assertIn("stays disabled", result.refusals[0][1])

    def test_other_branches_sources_and_architectures_are_refused(self) -> None:
        for version, php, supply, architecture in (
            ("24.04", "8.4", "ubuntu", "amd64"),
            ("26.04", "8.3", "ubuntu", "arm64"),
            ("24.04", "8.3", "sury", "amd64"),
            ("24.04", "8.3", "ubuntu", "riscv64"),
        ):
            with self.subTest(version=version, php=php, supply=supply, arch=architecture):
                result = draft(version, php, supply)
                install._site(result, architecture, Application.PHP, Stage.REDIRECT)
                self.assertEqual(self.reasons(result), [Reason.UNSUPPORTED_VERSION])
                self.assertIn("has not completed Barectl's qualification", result.refusals[0][1])


class InputTests(SimpleTestCase):
    def test_a_bare_name_and_a_root_https_address_are_canonical(self) -> None:
        for text in (
            "WWW.Shop.Example.com",
            "https://www.shop.example.com",
            "https://www.shop.example.com/",
            " www.shop.example.com. ",
        ):
            with self.subTest(text=text):
                self.assertEqual(inputs.https_name(text), ("www.shop.example.com", ""))

    def test_unsafe_addresses_are_refused_not_trimmed(self) -> None:
        refused = {
            "http://shop.example.com": "HTTPS",
            "https://user:pw@shop.example.com": "credentials",
            "https://shop.example.com:8443": "port",
            "https://shop.example.com/blog": "path",
            "https://shop.example.com/?a=1": "query",
            "https://shop.example.com/#top": "fragment",
            "https://192.0.2.10": "IP addresses",
            "https://[2001:db8::1]": "IP addresses",
            "*.example.com": "wildcards",
            "shop example.com": "spaces",
            "ftp://shop.example.com": "HTTPS",
            "": "Enter",
            "https://localhost": "fully qualified",
        }
        for text, fragment in refused.items():
            with self.subTest(text=text):
                name, problem = inputs.https_name(text)
                self.assertEqual(name, "")
                self.assertIn(fragment, problem)

    def test_titles_logins_and_emails_are_bounded(self) -> None:
        self.assertEqual(inputs.title_problem("Bob's Café & Sons"), "")
        for title in ("", " Padded", "x" * 101, "a<b", "a\\b", "line\nbreak", "bell\x07"):
            with self.subTest(title=title):
                self.assertTrue(inputs.title_problem(title))
        for login in ("owner", "a.b-c_d9", "x" * 60):
            self.assertEqual(inputs.login_problem(login), "")
        for login in ("ab", "Owner", "-owner", "o wner", "x" * 61, "o;rm", "o'o"):
            with self.subTest(login=login):
                self.assertTrue(inputs.login_problem(login))
        self.assertEqual(inputs.email_problem("owner+shop@example.co.uk"), "")
        for email in (
            "",
            "owner",
            "a@b",
            "o@@example.com",
            "o wner@example.com",
            "o'x@example.com",
            "a" * 95 + "@x.co",
        ):
            with self.subTest(email=email):
                self.assertTrue(inputs.email_problem(email))

    def test_recorded_metadata_must_already_be_canonical(self) -> None:
        self.assertEqual(inputs.problems(METADATA), [])
        loud = inputs.Metadata("WWW.shop.example.com", "Shop", "owner", "owner@example.com")
        self.assertTrue(inputs.problems(loud))


class ReadTests(SimpleTestCase):
    def test_reads_are_fixed_scripts_for_a_checked_identifier(self) -> None:
        for build in (core_native.files_argv, core_native.database_argv):
            self.assertEqual(build("shop")[:2], ["/usr/bin/sh", "-c"])
            for bad in ("", "Shop", "sh;op", "a", "x" * 25, "shop; rm -rf /"):
                with (
                    self.subTest(build=build.__name__, identifier=bad),
                    self.assertRaises(ValueError),
                ):
                    build(bad)

    def test_nothing_in_the_reads_writes_or_runs_the_application(self) -> None:
        text = " ".join(
            argv[2]
            for argv in (
                core_native.files_argv("shop"),
                core_native.database_argv("shop"),
                core_native.supply_argv(),
            )
        )
        for word in (
            "rm ",
            "mv ",
            "chown",
            "chmod",
            "mkdir",
            "tee ",
            "> /",
            "php",
            "wp-cli",
            "INSERT",
            "UPDATE",
            "DROP",
            "CREATE",
            "ALTER",
            "DELETE",
        ):
            self.assertNotIn(word, text)
        self.assertIn("SET SESSION TRANSACTION READ ONLY", core_native.database_argv("shop")[2])
        self.assertNotIn(setup_native.PHAR, text)

    def test_the_files_read_parses_only_its_own_grammar(self) -> None:
        state = core_native.parse_files(
            "site d 750 1003 33 2 4096 public\nend site\n"
            "public f 640 1003 33 1 217 index.html\nend public\nend private\n"
            f"sha {'a' * 64}\n"
        )
        self.assertTrue(state.complete)
        self.assertEqual([entry.path for entry in state.public], ["index.html"])
        for hostile in (
            "public f 640 1003 33 1 217\n",
            "other thing\n",
            "sha xyz\n",
            "public f 640 a b c d e\n",
        ):
            with self.subTest(text=hostile), self.assertRaises(Unreadable):
                core_native.parse_files(hostile)
        self.assertFalse(core_native.parse_files("end site\nerror public\nend private\n").complete)

    def test_the_database_read_must_be_complete_and_unambiguous(self) -> None:
        good = "S\t1\nT\t0\nR\t0\nE\t0\nG\t0\n"
        self.assertTrue(core_native.parse_database(good).empty)
        self.assertFalse(
            core_native.parse_database(good.replace("T\t0", "T\t2") + "N\twp_a\n").empty
        )
        self.assertFalse(core_native.parse_database(good.replace("S\t1", "S\t0")).empty)
        for bad in (
            good.replace("G\t0\n", ""),
            good + "T\t1\n",
            good + "N\tbad name\n",
            "S\tone\n",
            "",
        ):
            with self.subTest(text=bad), self.assertRaises(Unreadable):
                core_native.parse_database(bad)

    def test_the_supply_read_must_be_complete(self) -> None:
        text = "tool curl ok\ntool tar ok\ntool sha256sum missing\nfree 100\narchive 200 35368461\n"
        supply = core_native.parse_supply(text)
        self.assertEqual(
            (supply.tools["sha256sum"], supply.free_bytes, supply.archive_bytes),
            (False, 100, 35368461),
        )
        self.assertEqual(core_native.parse_supply(text.replace(" 35368461", " ")).archive_bytes, 0)
        for bad in (
            text.replace("tool tar ok\n", ""),
            text.replace("free 100\n", ""),
            text + "extra\n",
        ):
            with self.subTest(text=bad), self.assertRaises(Unreadable):
                core_native.parse_supply(bad)

    def test_the_first_login_command_targets_the_site_user_and_selected_cli(self) -> None:
        self.assertEqual(
            install.password_command("shop", "8.5", "www.shop.example.com", "owner"),
            "sudo -u sshop /usr/bin/php8.5 /usr/local/lib/wp-cli/wp-cli-2.12.0.phar "
            "--path=/var/www/shop/public --url=https://www.shop.example.com "
            "user update owner --prompt=user_pass --skip-email",
        )
