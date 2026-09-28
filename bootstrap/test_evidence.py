"""Parsers for native evidence: exact shapes recorded from Ubuntu 24.04, nothing else."""

from django.test import SimpleTestCase

from discovery.ssh import CommandResult

from . import inspection
from .evidence import (
    Conffile,
    ConfigEntry,
    Transition,
    Unreadable,
    parse_apt_config,
    parse_conffiles,
    parse_digests,
    parse_index_targets,
    parse_listeners,
    parse_package_states,
    parse_simulation,
    parse_tree,
    parse_unit,
    parse_uptime,
)
from .fakes import NGINX_VERSION, UPDATES, WILDCARDS, PreparationTestCase
from .models import PlanRefusal

Reason = PlanRefusal.Reason
# Recorded from `apt-get -s install nginx` as an unprivileged user on Ubuntu 24.04 (arm64).
SIMULATION = f"""\
NOTE: This is only a simulation!
      apt-get needs root privileges for real execution.
      Keep also in mind that locking is deactivated,
      so don't depend on the relevance to the real current situation!
Reading package lists...
Building dependency tree...
Reading state information...
The following additional packages will be installed:
  nginx-common
Suggested packages:
  fcgiwrap nginx-doc ssl-cert
The following NEW packages will be installed:
  nginx nginx-common
0 upgraded, 2 newly installed, 0 to remove and 3 not upgraded.
Inst nginx-common ({NGINX_VERSION} {UPDATES} [all])
Inst nginx ({NGINX_VERSION} {UPDATES} [arm64])
Conf nginx-common ({NGINX_VERSION} {UPDATES} [all])
Conf nginx ({NGINX_VERSION} {UPDATES} [arm64])
"""
# An upgrade, as `apt-get -s install libaudit1` printed it on the same server.
UPGRADE = """\
1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
Inst libaudit1 [1:3.1.2-2.1build1.1] (1:3.1.2-2.1ubuntu0.1 Ubuntu:24.04/noble-updates [arm64])
Conf libaudit1 (1:3.1.2-2.1ubuntu0.1 Ubuntu:24.04/noble-updates [arm64])
"""


class SimulationParserTests(SimpleTestCase):
    def test_actions_are_read_with_versions_architectures_and_archives(self) -> None:
        simulation = parse_simulation(SIMULATION)
        self.assertEqual(simulation.problems, ())
        self.assertEqual(
            simulation.transitions[:2],
            (
                Transition(
                    "Inst",
                    "nginx-common",
                    "",
                    NGINX_VERSION,
                    "all",
                    ("Ubuntu:24.04/noble-updates", "Ubuntu:24.04/noble-security"),
                ),
                Transition(
                    "Inst",
                    "nginx",
                    "",
                    NGINX_VERSION,
                    "arm64",
                    ("Ubuntu:24.04/noble-updates", "Ubuntu:24.04/noble-security"),
                ),
            ),
        )
        self.assertEqual([t.action for t in simulation.transitions], ["Inst"] * 2 + ["Conf"] * 2)

    def test_upgrades_and_removals_keep_the_installed_version(self) -> None:
        (upgrade, _) = parse_simulation(UPGRADE).transitions
        self.assertEqual(
            (upgrade.previous, upgrade.version), ("1:3.1.2-2.1build1.1", "1:3.1.2-2.1ubuntu0.1")
        )
        removal = parse_simulation(
            "0 upgraded, 0 newly installed, 1 to remove and 0 not upgraded.\n"
            "Remv nginx [1.24.0-2ubuntu7.18]\n"
        ).transitions[0]
        self.assertEqual((removal.action, removal.previous), ("Remv", "1.24.0-2ubuntu7.18"))

    def test_action_lines_in_another_form_are_refused(self) -> None:
        for line in (
            "Inst nginx 1.24 [amd64]",
            "Inst nginx (1.24 Ubuntu:24.04/noble)",
            "Conf nginx (1.24 $(reboot) [amd64]",
            "Remv nginx",
            "Inst NGINX (1.24 Ubuntu:24.04/noble [amd64])",
        ):
            with self.subTest(line=line), self.assertRaises(Unreadable):
                parse_simulation(f"{line}\n")

    def test_errors_warnings_and_disagreeing_summaries_make_it_unusable(self) -> None:
        cases = {
            "error": "E: Unable to locate package nginx\n",
            "warning": "WARNING: The following packages cannot be authenticated!\n" + SIMULATION,
            "no summary": SIMULATION.replace("0 upgraded, 2 newly installed", "garbled"),
            "truncated": SIMULATION.rsplit("Inst nginx ", 1)[0],
            "two summaries": SIMULATION + "0 upgraded, 0 newly installed, 0 to remove and 0 not "
            "upgraded.\n",
        }
        for name, text in cases.items():
            with self.subTest(case=name):
                self.assertTrue(parse_simulation(text).problems)


class EvidenceParserTests(SimpleTestCase):
    def test_apt_configuration_lines(self) -> None:
        entries = parse_apt_config(
            'APT "";\nDPkg::Post-Invoke:: "test -x /usr/lib/x || true";\n'
            'Unattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}";\n'
        )
        self.assertEqual(
            entries[1], ConfigEntry("DPkg::Post-Invoke::", "test -x /usr/lib/x || true")
        )
        self.assertEqual(entries[1].name, "dpkg::post-invoke")
        for text in ('APT "unterminated;\n', "APT::Key value;\n", 'Key "a" "b";\n'):
            with self.subTest(text=text), self.assertRaises(Unreadable):
                parse_apt_config(text)

    def test_index_targets_drop_repository_credentials(self) -> None:
        (target,) = parse_index_targets(
            "Ubuntu\tnoble\tnoble\tyes\tmain\tamd64\thttp://user:secret@mirror.example:8080/ubuntu\n"
        )
        self.assertEqual(target.site, "http://mirror.example:8080/ubuntu")
        self.assertTrue(target.trusted)
        with self.assertRaises(Unreadable):
            parse_index_targets("Ubuntu\tnoble\tnoble\tmaybe\tmain\tamd64\thttp://x/\n")

    def test_package_states(self) -> None:
        states = parse_package_states(
            f"nginx\tamd64\t{NGINX_VERSION}\tii \nnginx-common\tall\t{NGINX_VERSION}\trc \n"
            "apache2\t\t\tun \nphp8.3-fpm\tamd64\t8.3.6\tiF \nlibc6\tamd64\t2.39\thi \n"
        )
        self.assertEqual(
            [(state.name, state.installed, state.absent) for state in states],
            [
                ("nginx", True, False),
                ("nginx-common", False, False),
                ("apache2", False, True),
                ("php8.3-fpm", False, False),
                ("libc6", True, False),
            ],
        )
        with self.assertRaises(Unreadable):
            parse_package_states("nginx amd64 1.24 ii\n")

    def test_conffiles_digests_and_trees(self) -> None:
        self.assertEqual(
            parse_conffiles(
                "nginx-common\n /etc/nginx/nginx.conf e5398edc0b51497dba606859fb13a86e\n"
                " /etc/nginx/old.conf 00000000000000000000000000000000 obsolete\n\nphp8.3-cli\n"
            ),
            (
                Conffile("/etc/nginx/nginx.conf", "e5398edc0b51497dba606859fb13a86e", False),
                Conffile("/etc/nginx/old.conf", "0" * 32, True),
            ),
        )
        with self.assertRaises(Unreadable):
            parse_digests(f"\\{'0' * 32}  /etc/nginx/new\\nline\n", 32)
        with self.assertRaises(Unreadable):
            parse_tree("f\t/etc/other/file\t\n", "/etc/nginx")
        with self.assertRaises(Unreadable):
            parse_tree("f\t/etc/nginx/a\tb\textra\n", "/etc/nginx")

    def test_units_listeners_and_uptime(self) -> None:
        unit = parse_unit(
            "Id=nginx.service\nLoadState=loaded\nActiveState=active\nSubState=running\n"
            "FragmentPath=/usr/lib/systemd/system/nginx.service\n"
            "DropInPaths=/etc/systemd/system/nginx.service.d/a.conf /run/x.conf\n"
            "UnitFileState=enabled\n",
            "nginx.service",
        )
        self.assertEqual(len(unit.drop_in_paths), 2)
        with self.assertRaises(Unreadable):
            parse_unit("Id=apache2.service\n", "nginx.service")
        listeners = parse_listeners(
            'LISTEN 0      511    0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=10,fd=5))\n'
            'LISTEN 0      511       [::]:80    [::]:* users:(("apache2",pid=11,fd=6))   \n',
            80,
            attributed=True,
        )
        self.assertEqual(
            [(item.address, item.processes) for item in listeners],
            [
                (WILDCARDS[0], ("nginx",)),
                ("[::]", ("apache2",)),
            ],
        )
        with self.assertRaises(Unreadable):
            parse_listeners("LISTEN 0 511 0.0.0.0:8080 0.0.0.0:*\n", 80, attributed=False)
        self.assertEqual(parse_uptime("5000.25 19822.11\n"), 500025)
        with self.assertRaises(Unreadable):
            parse_uptime("5000 19822\n")


class ReviewRuleTests(PreparationTestCase):
    """Rules that only a hand-written simulation or evidence can reach."""

    def test_unusual_simulated_transitions_are_refused(self) -> None:
        installs = f"Inst nginx ({NGINX_VERSION} Ubuntu:24.04/noble-updates [amd64])\n"
        configure = f"Conf nginx ({NGINX_VERSION} Ubuntu:24.04/noble-updates [amd64])\n"
        summary = "0 upgraded, {} newly installed, 0 to remove and 0 not upgraded.\n"
        cases = {
            "configure only": (
                summary.format(1)
                + installs
                + configure
                + "Conf libfoo (1.0 Ubuntu:24.04/noble [amd64])\n",
                Reason.SIMULATION,
            ),
            "unpack only": (summary.format(1) + installs, Reason.SIMULATION),
            "foreign architecture": (
                summary.format(1)
                + installs.replace("[amd64]", "[i386]")
                + configure.replace("[amd64]", "[i386]"),
                Reason.SIMULATION,
            ),
            "reinstall": (
                "0 upgraded, 0 newly installed, 1 reinstalled, 0 to remove and 0 not upgraded.\n"
                + installs.replace("nginx (", f"nginx [{NGINX_VERSION}] (")
                + configure,
                Reason.INSTALLED_PACKAGE_CHANGE,
            ),
            "missing root": (
                summary.format(1)
                + installs.replace("nginx (", "nginx-core (")
                + configure.replace("nginx (", "nginx-core ("),
                Reason.SIMULATION,
            ),
        }
        for name, (text, reason) in cases.items():
            with self.subTest(case=name):
                self.fresh_server()
                self.noble.simulation_text = text
                plan = self.plan("nginx")
                self.assertFalse(plan.eligible)
                self.assertIn(reason, self.reasons(plan))

    def test_unreadable_default_files_are_incomplete_evidence(self) -> None:
        self.noble.nginx = "installed"
        self.noble.answer(self.remote)
        digests = inspection.tree_digests("/etc/nginx")
        listing = self.remote.results[digests].stdout.splitlines()
        # md5sum could not read nginx.conf and exits 1.
        unread = "".join(f"{line}\n" for line in listing if "nginx.conf" not in line)
        self.noble.extra = {digests: CommandResult(1, unread)}
        plan = self.plan("nginx")
        self.assertEqual(self.reasons(plan), [Reason.INCOMPLETE])
        self.assertIn("cannot read /etc/nginx/nginx.conf", plan.refusals.get().text)

    def test_listeners_of_a_running_profile_must_be_its_own(self) -> None:
        self.noble.nginx = "installed"
        self.noble.other_listeners = ("127.0.0.1",)
        plan = self.plan("nginx")
        self.assertEqual(self.reasons(plan), [Reason.LISTENER])
        self.assertIn("127.0.0.1", plan.refusals.get().text)
