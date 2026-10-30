from django.test import SimpleTestCase

from discovery.models import ObservationOutcome
from discovery.ssh import CommandResult
from security import observation


class _Shell:
    host_key = "ssh-ed25519 SHA256:test"

    def __init__(self, root: bool) -> None:
        self.root = root

    def run(self, command: str, stdin: bytes | None = None) -> CommandResult:
        if command == "id -u":
            return CommandResult(0, "0\n" if self.root else "1000\n")
        if command.startswith("sudo -n -l "):
            return CommandResult(1, "")
        return CommandResult(127, "")


class RootAccessTests(SimpleTestCase):
    def test_without_root_every_check_says_why_it_could_not_be_read(self) -> None:
        observed = observation.collect(_Shell(root=False))
        self.assertTrue(observed.observed)
        self.assertIsNotNone(observed.value)
        for check in (
            observed.value.firewall,
            observed.value.listeners,
            observed.value.ssh,
            observed.value.auto_updates,
            observed.value.updates,
            observed.value.restart,
        ):
            self.assertEqual(check.status, ObservationOutcome.INACCESSIBLE)
            self.assertIn("root", check.warning)
            self.assertIsNone(check.value)


class ListenerTests(SimpleTestCase):
    SS = """\
tcp LISTEN 0      4096         0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=812,fd=3))
tcp LISTEN 0      511          0.0.0.0:80         0.0.0.0:*    users:(("caddy",pid=1200,fd=4))
tcp LISTEN 0      4096       127.0.0.1:5432       0.0.0.0:*    users:(("postgres",pid=900,fd=5))
tcp LISTEN 0      4096             [::]:443            [::]:*    users:(("caddy",pid=1200,fd=5))
udp UNCONN 0      0               0.0.0.0:443        0.0.0.0:*    users:(("caddy",pid=1200,fd=6))
"""

    def test_each_listener_keeps_its_process_and_public_exposure(self) -> None:
        rows = observation.parse_listeners(self.SS)
        self.assertIsNotNone(rows)
        self.assertEqual(
            [(row.process, row.port, row.protocol, row.public) for row in rows or ()],
            [
                ("sshd", 22, "tcp", True),
                ("caddy", 80, "tcp", True),
                ("postgres", 5432, "tcp", False),
                ("caddy", 443, "tcp", True),
                ("caddy", 443, "udp", True),
            ],
        )

    def test_malformed_output_is_not_a_guess(self) -> None:
        self.assertIsNone(observation.parse_listeners("nonsense\n"))


class FirewallParserTests(SimpleTestCase):
    STATUS = """\
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), deny (routed)
New profiles: skip
"""

    def test_status_reports_the_standard_defaults(self) -> None:
        enabled, defaults, logging = observation.parse_ufw_status(self.STATUS)
        self.assertTrue(enabled)
        self.assertEqual(defaults, ("deny", "allow", "deny"))
        self.assertEqual(logging, "on (low)")

    def test_rules_in_the_supported_shape_are_adopted_and_others_are_not(self) -> None:
        rules = observation.parse_ufw_added(
            """\
Added user rules (see 'ufw status' for running firewall):
ufw allow 22/tcp
ufw allow 443/udp
ufw allow proto tcp from 203.0.113.0/24 to any port 5432
ufw allow from 198.51.100.0/24 to any port 6379 proto tcp
ufw deny 3306/tcp
ufw allow in on eth0 to any port 8080
""",
            (22,),
        )
        self.assertEqual(
            [rule.kind for rule in rules],
            ["standard", "standard", "operator", "operator", "outside", "outside"],
        )
        self.assertEqual(rules[2].network, "203.0.113.0/24")
        self.assertEqual(rules[2].ports, "5432")
        self.assertEqual(rules[3].protocol, "tcp")
        self.assertEqual(rules[3].ports, "6379")


class SshParserTests(SimpleTestCase):
    SSHD = """\
port 22
port 2222
passwordauthentication no
kbdinteractiveauthentication no
permitrootlogin prohibit-password
persourcepenalties yes
"""

    def test_effective_settings_and_every_port(self) -> None:
        settings = observation.parse_sshd(self.SSHD)
        self.assertEqual(
            None
            if settings is None
            else (
                settings.password_authentication,
                settings.ports,
                settings.permit_root_login,
            ),
            ("no", (22, 2222), "prohibit-password"),
        )

    def test_accounts_with_a_login_shell_and_no_key_are_named(self) -> None:
        accounts = observation.parse_accounts_without_keys(
            """\
root:x:0:0:root:/root:/bin/bash
deploy:x:1000:1000::/home/deploy:/bin/bash
site:x:900:900::/var/www/site:/usr/sbin/nologin
unnamed:x:1001:1001::/home/unnamed:/bin/sh
""",
            "/root/.ssh/authorized_keys\n",
        )
        self.assertEqual(accounts, ("deploy", "unnamed"))

    def test_socket_listen_stream_ports(self) -> None:
        self.assertEqual(observation.parse_socket_ports("ListenStream=[::]:22\n"), (22,))


class UpdateParserTests(SimpleTestCase):
    SIMULATION = """\
NOTE: This is only a simulation!
The following packages will be upgraded:
  libssl3 libc6
Inst libssl3 [3.0.0] (3.0.1 Ubuntu:26.04/resolute-security [amd64])
Inst libc6 [2.39] (2.40 Ubuntu:26.04/resolute-updates [amd64])
The following packages have been kept back:
  openssl
"""

    def test_security_other_and_kept_back_are_separate(self) -> None:
        rows = observation.parse_upgrades(self.SIMULATION)
        self.assertEqual(
            rows,
            (
                ("libssl3", "3.0.0", "3.0.1"),
                ("libc6", "2.39", "2.40"),
                ("openssl", "", "kept"),
            ),
        )
        archives = observation.parse_apt_policy(
            """\
libssl3:
  Installed: 3.0.0
  Candidate: 3.0.1
  Version table:
     3.0.1 500
        500 http://archive.ubuntu.com/ubuntu resolute-security/main amd64 Packages
libc6:
  Installed: 2.39
  Candidate: 2.40
  Version table:
     2.40 500
        500 http://archive.ubuntu.com/ubuntu resolute-updates/main amd64 Packages
openssl:
  Installed: 3.0.0
  Candidate: 3.0.0
  Version table:
     3.0.0 100
        100 /var/lib/dpkg/status
"""
        )
        self.assertEqual(archives["libssl3"], "resolute-security/main")
        self.assertEqual(archives["libc6"], "resolute-updates/main")

    def test_apt_config_reports_the_effective_automatic_update_values(self) -> None:
        values = observation.parse_apt_config(
            """\
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Allowed-Origins:: "Ubuntu:resolute";
Unattended-Upgrade::Allowed-Origins:: "Ubuntu:resolute-security";
"""
        )
        self.assertEqual(values["APT::Periodic::Unattended-Upgrade"], "1")
        self.assertEqual(values["Unattended-Upgrade::Automatic-Reboot"], "false")

    def test_a_later_apt_file_wins_and_every_origin_is_kept(self) -> None:
        text = """\
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Unattended-Upgrade "0";
Unattended-Upgrade::Allowed-Origins:: "Ubuntu:resolute";
Unattended-Upgrade::Allowed-Origins:: "Ubuntu:resolute-security";
"""
        self.assertEqual(
            observation.parse_apt_config(text)["APT::Periodic::Unattended-Upgrade"], "0"
        )
        self.assertEqual(
            observation.parse_allowed_origins(text),
            ("Ubuntu:resolute", "Ubuntu:resolute-security"),
        )

    def test_timer_state_prefers_active_over_enabled(self) -> None:
        timers = observation.parse_timers(
            """\
Id=apt-daily.timer
UnitFileState=enabled
ActiveState=active

Id=apt-daily-upgrade.timer
UnitFileState=enabled
ActiveState=inactive
"""
        )
        self.assertEqual(timers["apt-daily.timer"], "active")
        self.assertEqual(timers["apt-daily-upgrade.timer"], "enabled")
