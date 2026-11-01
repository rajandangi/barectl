"""The firewall change kind: the one standard, operator ports and what refuses (Phase E #306)."""

from dataclasses import replace
from unittest import mock

from django.test import SimpleTestCase

from databases.packages import Simulation, Transition
from discovery.models import ObservationOutcome
from discovery.snapshot import Observation
from operations import revert
from operations.consent import Scope, consent_of
from operations.engine import BodyContext
from operations.inputs import PreparationInputs
from operations.models import Consent
from security import firewall
from security.observation import (
    Check,
    FirewallRule,
    FirewallState,
    Listener,
    SshState,
    parse_ufw_added,
)
from security.testing import check, ok_state

BOOT_ID = "0123456789abcdef0123456789abcdef"
DIGEST = "a" * 64
UNIT = "barectl-apply-" + "b" * 32 + ".service"
SSH_PORTS = (22,)


def _rules(*lines: str) -> tuple[FirewallRule, ...]:
    return parse_ufw_added("\n".join(lines), SSH_PORTS)


def _firewall(
    *,
    installed: bool = True,
    enabled: bool | None = True,
    ipv6: bool | None = True,
    rules: tuple[FirewallRule, ...] | None = None,
    outside: tuple[str, ...] = (),
) -> FirewallState:
    return FirewallState(
        installed,
        enabled,
        "deny",
        "allow",
        "deny",
        ipv6,
        "on (low)",
        rules
        if rules is not None
        else _rules("allow 22/tcp", "allow 80/tcp", "allow 443/tcp", "allow 443/udp"),
        outside,
        True,
    )


def _ssh(
    *, sshd_ports: tuple[int, ...] = SSH_PORTS, socket_ports: tuple[int, ...] = ()
) -> SshState:
    return SshState(
        "no",
        "no",
        "prohibit-password",
        sshd_ports,
        socket_ports,
        (),
        "yes",
        sshd_ports,
    )


def _evidence(
    state: FirewallState | None = None,
    ssh: SshState | None = None,
    *,
    connection_port: int = 22,
    docker: bool = False,
    simulation: Simulation | None = None,
    dry_run_error: str = "",
    listeners: tuple[Listener, ...] | None = None,
) -> firewall.FirewallEvidence:
    return firewall.FirewallEvidence(
        firewall=state or _firewall(),
        ssh=ssh or _ssh(),
        listeners=listeners
        if listeners is not None
        else (Listener("192.0.2.10", 22, "tcp", "sshd", True),),
        standing="Target stack",
        machine="x86_64",
        deb_arch="amd64",
        boot_id=BOOT_ID,
        uptime_centiseconds=500000,
        apt="apt 3.2.0 (amd64)",
        dpkg="Debian 'dpkg' package management program version 1.23.1 (amd64).",
        systemd="systemd 259 (259-1ubuntu1)",
        held=(),
        ufw_version="0.36.2-9build1",
        precondition_digest=DIGEST,
        dry_run_digest=DIGEST,
        dry_run_error=dry_run_error,
        docker_installed=docker,
        connection_port=connection_port,
        simulation=simulation,
        sites=("alpha", "beta"),
    )


def _simulation() -> Simulation:
    return Simulation(
        (
            Transition("Inst", "ufw", "", "0.36.2-9build1", "all", ("resolute/main",)),
            Transition("Conf", "ufw", "", "0.36.2-9build1", "all", ("resolute/main",)),
        ),
        (),
    )


def _on() -> PreparationInputs:
    return PreparationInputs("on", firewall=True)


def _add(port: str = "8080", protocol: str = "tcp", network: str = "") -> PreparationInputs:
    return PreparationInputs("add", firewall=True, port=port, protocol=protocol, network=network)


def _remove(port: str = "8080", protocol: str = "tcp", network: str = "") -> PreparationInputs:
    return PreparationInputs("remove", firewall=True, port=port, protocol=protocol, network=network)


class FirewallReviewTests(SimpleTestCase):
    def test_a_standard_firewall_needs_no_change(self) -> None:
        draft = firewall.review(_evidence(), _on())
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertFalse(draft.effects)
        self.assertIn("already follows the standard", str(draft.document["note"]))

    def test_turning_on_is_a_shared_server_change_naming_every_site(self) -> None:
        state = _firewall(enabled=False)
        draft = firewall.review(_evidence(state), _on())
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertEqual([effect.scope for effect in draft.effects], [Scope.SERVER])
        self.assertEqual(draft.effects[0].sites, ("alpha", "beta"))
        self.assertEqual(consent_of(draft.effects), Consent.SHARED)
        self.assertEqual(draft.current_sites, ("alpha", "beta"))
        self.assertTrue(draft.document["details"])
        text = str(draft.document["details"])
        self.assertIn(f"{revert.WINDOW_MINUTES} minutes", text)
        self.assertIn("80/tcp", text)
        self.assertIn("443/udp", text)
        self.assertIn("restart", text.lower())

    def test_a_missing_firewall_is_installed_through_one_exact_transaction(self) -> None:
        state = _firewall(installed=False, enabled=None, ipv6=None, rules=())
        draft = firewall.review(_evidence(state, simulation=_simulation()), _on())
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertTrue(draft.document["install"])
        self.assertEqual(draft.document["roots"], [["ufw", "0.36.2-9build1"]])
        actions = draft.document["actions"]
        self.assertIsInstance(actions, list)
        self.assertEqual(len(actions), 2)  # type: ignore[arg-type]
        native = firewall.body(draft.document, BodyContext(UNIT, BOOT_ID, 500000))
        self.assertIn("barectl_package_guard", native.arguments[3])
        self.assertEqual(native.arguments[-1], "b" * 32)

    def test_outside_settings_refuse_every_firewall_action(self) -> None:
        state = _firewall(outside=("Docker is active.",))
        for inputs in (_on(), _add(), _remove()):
            with self.subTest(action=inputs.selection):
                draft = firewall.review(_evidence(state), inputs)
                self.assertFalse(draft.eligible)
                self.assertTrue(
                    any("outside what Barectl supports" in item for item in draft.refusals)
                )

    def test_docker_installed_refuses(self) -> None:
        draft = firewall.review(_evidence(docker=True), _on())
        self.assertFalse(draft.eligible)
        self.assertTrue(any("Docker is installed" in item for item in draft.refusals))

    def test_ssh_sources_must_agree_and_include_the_connection_port(self) -> None:
        for ssh, port, reason in (
            (_ssh(sshd_ports=(22, 2222)), 22, "listeners do not agree"),
            (_ssh(socket_ports=(2222,)), 22, "socket"),
            (_ssh(sshd_ports=(2222,)), 22, "port this connection uses"),
        ):
            with self.subTest(reason=reason):
                listeners = tuple(
                    Listener("192.0.2.10", item, "tcp", "sshd", True)
                    for item in (ssh.sshd_ports if reason != "listeners do not agree" else (22,))
                )
                draft = firewall.review(
                    _evidence(
                        _firewall(enabled=False),
                        ssh,
                        connection_port=port,
                        listeners=listeners,
                    ),
                    _on(),
                )
                self.assertFalse(draft.eligible)
                self.assertTrue(any(reason in item for item in draft.refusals), draft.refusals)

    def test_one_operator_port_is_added_and_removed(self) -> None:
        added = firewall.review(_evidence(), _add("8080"))
        self.assertTrue(added.eligible, added.refusals)
        self.assertEqual([effect.scope for effect in added.effects], [Scope.SERVER])
        body = firewall.body(added.document, BodyContext(UNIT, BOOT_ID, 500000))
        self.assertEqual(body.arguments[0], "add")
        self.assertEqual(body.arguments[8:11], ("8080", "tcp", ""))
        self.assertEqual(body.arguments[7], "tcp:22,tcp:80,tcp:443,udp:443")

        state = replace(
            _firewall(),
            rules=_rules(
                "allow 22/tcp", "allow 80/tcp", "allow 443/tcp", "allow 443/udp", "allow 8080/tcp"
            ),
        )
        removed = firewall.review(_evidence(state), _remove("8080"))
        self.assertTrue(removed.eligible, removed.refusals)
        self.assertIn("Remove the allowance", removed.effects[0].text)

    def test_standard_rules_cannot_be_removed(self) -> None:
        state = _firewall()
        for port, protocol in (("22", "tcp"), ("80", "tcp"), ("443", "tcp"), ("443", "udp")):
            with self.subTest(port=port, protocol=protocol):
                draft = firewall.review(_evidence(state), _remove(port, protocol))
                self.assertFalse(draft.eligible)
                self.assertTrue(
                    any("does not remove the standard" in item for item in draft.refusals)
                )

    def test_an_equivalent_rule_needs_no_change(self) -> None:
        state = replace(
            _firewall(),
            rules=_rules(
                "allow 22/tcp", "allow 80/tcp", "allow 443/tcp", "allow 443/udp", "allow 8080/tcp"
            ),
        )
        draft = firewall.review(_evidence(state), _add("8080"))
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertFalse(draft.effects)
        self.assertIn("already allowed", str(draft.document["note"]))

    def test_an_unsupported_rule_refuses_only_firewall_actions(self) -> None:
        state = replace(
            _firewall(),
            rules=_rules(
                "allow 22/tcp",
                "allow 80/tcp",
                "allow 443/tcp",
                "allow 443/udp",
                "deny 3306/tcp",
            ),
            outside=("deny 3306/tcp",),
        )
        draft = firewall.review(_evidence(state, simulation=_simulation()), _on())
        self.assertFalse(draft.eligible)
        self.assertTrue(any("outside what Barectl supports" in item for item in draft.refusals))

    def test_an_invalid_port_or_network_refuses(self) -> None:
        for inputs, reason in (
            (_add("0"), "one port"),
            (_add("70000"), "1 to 65535"),
            (_add("65000:70000"), "1 to 65535"),
            (_add("9000:8000"), "first port"),
            (_add("8080", "sctp"), "TCP or UDP"),
            (_add("8080", "tcp", "203.0.113.5/24"), "one IPv4 or IPv6 network"),
            (_add("8080", "tcp", "not-a-network"), "one IPv4 or IPv6 network"),
        ):
            with self.subTest(port=inputs.port, network=inputs.network):
                draft = firewall.review(_evidence(), inputs)
                self.assertFalse(draft.eligible)
                self.assertTrue(any(reason in item for item in draft.refusals), draft.refusals)

    def test_a_rule_from_one_network_is_named_in_the_review(self) -> None:
        draft = firewall.review(_evidence(), _add("5432", "tcp", "203.0.113.0/24"))
        self.assertTrue(draft.eligible, draft.refusals)
        self.assertIn("from 203.0.113.0/24", draft.effects[0].text)

    def test_the_body_refuses_a_tampered_selection(self) -> None:
        draft = firewall.review(_evidence(), _add("8080"))
        document = dict(draft.document)
        document["action"] = "sideways"
        with self.assertRaises(ValueError):
            firewall.body(document, BodyContext(UNIT, BOOT_ID, 500000))


class DryRunTests(SimpleTestCase):
    def test_enable_is_not_dry_run_because_ufw_persists_it(self) -> None:
        from discovery.ssh import CommandResult

        shell = mock.Mock()
        with mock.patch(
            "security.firewall.run_root", return_value=CommandResult(0, "simulated")
        ) as run:
            digest, error = firewall._dry_run_digest(
                shell, [["default", "deny", "incoming"], ["--force", "enable"]]
            )
        self.assertNotEqual(digest, "")
        self.assertEqual(error, "")
        self.assertEqual(
            [call.args[1] for call in run.call_args_list],
            ["ufw --dry-run 'default' 'deny' 'incoming'"],
        )


class PacketFilterDetectionTests(SimpleTestCase):
    def test_ufws_own_chains_and_dockers_nat_rules_are_not_another_manager(self) -> None:
        from security.observation import _iptables_has_rules, _nft_has_foreign_rules

        ufw = "\n".join(
            (
                "*filter",
                ":INPUT ACCEPT [0:0]",
                ":ufw-user-input - [0:0]",
                "-A INPUT -j ufw-before-logging-input",
                "-A ufw-user-input -p tcp --dport 22 -j ACCEPT",
                "COMMIT",
                "*nat",
                ":DOCKER_OUTPUT - [0:0]",
                "-A OUTPUT -d 127.0.0.11/32 -j DOCKER_OUTPUT",
                "COMMIT",
            )
        )
        self.assertFalse(_iptables_has_rules(ufw))
        foreign = ufw.replace(
            "-A ufw-user-input -p tcp --dport 22 -j ACCEPT",
            "-A ufw-user-input -p tcp --dport 3306 -j ACCEPT\n"
            "-A INPUT -p tcp --dport 3306 -j ACCEPT",
        )
        self.assertTrue(_iptables_has_rules(foreign))
        nft = "table ip filter {\n  chain ufw-user-input {\n    tcp dport 22 accept\n  }\n}"
        self.assertFalse(_nft_has_foreign_rules(nft))
        self.assertTrue(
            _nft_has_foreign_rules(
                nft + "\ntable ip nat {\n  chain custom {\n    tcp dport 3306 accept\n  }\n}"
            )
        )


class FirewallVerifyTests(SimpleTestCase):
    def _verify(
        self, document: dict[str, object], state: FirewallState, ssh: SshState | None = None
    ) -> bool | None:
        checks = replace(
            ok_state(),
            firewall=Check(ObservationOutcome.OBSERVED, ("read",), "", state),
            ssh=Check(ObservationOutcome.OBSERVED, ("read",), "", ssh or _ssh()),
        )
        observed = Observation(ObservationOutcome.OBSERVED, ("read",), "", checks)
        stored = mock.Mock(document=document)
        with mock.patch("security.firewall.observation.collect", return_value=observed):
            return firewall.verify(mock.Mock(), stored)

    def test_standard_and_operator_rules_are_read_back(self) -> None:
        standard = _firewall()
        added = replace(
            standard,
            rules=_rules(
                "allow 22/tcp", "allow 80/tcp", "allow 443/tcp", "allow 443/udp", "allow 8080/tcp"
            ),
        )
        document = {
            "version": 1,
            "body_sha256": firewall.BODY_SHA256,
            "action": "add",
            "install": False,
            "package_installed": True,
            "package_version": "0.36.2-9build1",
            "architecture": "x86_64",
            "deb_arch": "amd64",
            "precondition_digest": DIGEST,
            "dry_run_digest": DIGEST,
            "ssh_ports": [22],
            "connection_port": 22,
            "port": "8080",
            "protocol": "tcp",
            "network": "",
            "roots": [],
            "actions": [],
            "details": [],
        }
        # The read of the installed version is a fixed command, not the observation.
        with mock.patch.object(firewall, "_installed_version", return_value="0.36.2-9build1"):
            self.assertTrue(self._verify(document, added))
            self.assertFalse(self._verify(document, standard))
            removed = dict(document, action="remove")
            self.assertTrue(self._verify(removed, standard))


class FirewallPanelTests(SimpleTestCase):
    def test_the_panel_states_the_shared_window_length(self) -> None:
        from operations import revert
        from security.presentation import firewall_panel

        state = replace(
            ok_state(),
            firewall=check(_firewall()),
            ssh=check(_ssh()),
        )
        panel = firewall_panel(state, prepare_url="/prepare/", can_change=True)
        if panel is None:
            self.fail("The standard firewall offered no extra-port panel.")
        self.assertEqual(panel.window_minutes, revert.WINDOW_MINUTES)
        self.assertEqual([rule.label for rule in panel.rules], [])
