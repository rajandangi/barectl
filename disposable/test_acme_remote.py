"""The ACME and DNS fixtures work: docs/ssh-connections.md#acme-and-dns-fixtures

They need the disposable server and the fixture containers ``run-tests.sh`` starts, named by
``BARECTL_SSH_TEST_CONTAINER`` and ``BARECTL_ACME_TEST_*``.
"""

import json
import os
import subprocess
from datetime import timedelta
from typing import override
from unittest import skipIf, skipUnless

from cryptography import x509
from django.test import SimpleTestCase, tag

from . import acme

NAME = "fixture.barectl.test"
# systemd 255 rejects --search=no for record queries, and ignores --json for them.
RESOLVECTL = (
    "resolvectl query --legend=no --cache=no --synthesize=no --zone=no --trust-anchor=no "
    "{options}-t {type} {name}"
)
# The system trust store, with the fixtures' roots, verifies each directory's certificate.
DIRECTORY_CHECK = """
import json, socket, sys, urllib.request
family = {"4": socket.AF_INET, "6": socket.AF_INET6}[sys.argv[1]]
resolve = socket.getaddrinfo
socket.getaddrinfo = lambda *a, **k: [r for r in resolve(*a, **k) if r[0] == family]
with urllib.request.urlopen(sys.argv[2], timeout=10) as response:
    print(response.status, sorted(json.load(response)))
"""


def resolvectl(record: str, name: str, options: str = "") -> tuple[int, str, str]:
    """resolvectl's exit status, output and errors, run as an unprivileged user."""
    result = subprocess.run(  # noqa: S603 - the tests' own commands
        [  # noqa: S607 - Docker on PATH
            "docker",
            "exec",
            "-u",
            "observer",
            os.environ["BARECTL_SSH_TEST_CONTAINER"],
            "sh",
            "-c",
            RESOLVECTL.format(options=options, type=record, name=name),
        ],
        capture_output=True,
        timeout=60,
        check=False,
    )
    return result.returncode, result.stdout.decode(), result.stderr.decode().strip()


def resolve(record: str, name: str) -> tuple[int, list[tuple[str, str, str]], str]:
    """The exit status, each answer's owner, type and data, and the last error line.

    Answers read ``<owner> IN <type> <data>`` padded before ``-- link: <interface>``.
    """
    status, output, errors = resolvectl(record, name)
    answers = []
    for line in output.splitlines():
        owner, klass, rtype, *data = line.partition("-- link:")[0].split()
        if klass != "IN":
            raise AssertionError(line)
        answers.append((owner, rtype, " ".join(data)))
    return status, answers, errors.splitlines()[-1] if errors else ""


@tag("ssh")
@skipUnless(acme.CONFIGURED, "Set BARECTL_SSH_TEST_CONTAINER and BARECTL_ACME_TEST_*")
class AcmeFixtureTests(SimpleTestCase):
    @classmethod
    @override
    def setUpClass(cls) -> None:
        super().setUpClass()
        acme.install_trust_and_resolver(cls)

    def test_resolvectl_answers_from_challtestsrv(self) -> None:
        acme.add_a(self, NAME, ["192.0.2.10", "192.0.2.11"])
        acme.add_aaaa(self, NAME, ["2001:db8::10"])
        acme.set_cname(self, f"www.{NAME}", f"cdn.{NAME}")
        acme.set_cname(self, f"cdn.{NAME}", NAME)
        acme.add_caa(
            self, "barectl.test", [("issue", "letsencrypt.org"), ("iodef", "mailto:a@b.c")]
        )
        acme.set_servfail(self, f"broken.{NAME}")
        acme.set_nxdomain(self, f"missing.{NAME}")
        failed = f"resolve call failed: Name '{NAME}'"

        addresses = [(NAME, "A", "192.0.2.10"), (NAME, "A", "192.0.2.11")]
        self.assertEqual(resolve("A", NAME), (0, addresses, ""))
        self.assertEqual(resolve("AAAA", NAME), (0, [(NAME, "AAAA", "2001:db8::10")], ""))
        # Through a CNAME chain, only the final records show, under the final name.
        self.assertEqual(resolve("A", f"www.{NAME}"), (0, addresses, ""))
        self.assertEqual(
            resolve("CNAME", f"www.{NAME}"), (0, [(f"www.{NAME}", "CNAME", f"cdn.{NAME}")], "")
        )
        status, answers, _ = resolve("CAA", "barectl.test")
        self.assertEqual(
            (status, answers),
            (
                0,
                [
                    ("barectl.test", "CAA", '0 issue "letsencrypt.org"'),
                    ("barectl.test", "CAA", '0 iodef "mailto:a@b.c"'),
                ],
            ),
        )
        # No data, NXDOMAIN and SERVFAIL share one exit status and differ only in the message.
        self.assertEqual(
            resolve("CAA", NAME),
            (1, [], f"{NAME}: {failed} does not have any RR of the requested type"),
        )
        self.assertEqual(
            resolve("A", f"missing.{NAME}"),
            (1, [], f"missing.{NAME}: resolve call failed: Name 'missing.{NAME}' not found"),
        )
        separator = ":" if os.environ.get("BARECTL_SSH_TEST_RELEASE") == "26.04" else ""
        servfail = (
            f"broken.{NAME}: resolve call failed: Could not resolve 'broken.{NAME}', server or "
            f"network returned error{separator} SERVFAIL"
        )
        self.assertEqual(resolve("A", f"broken.{NAME}"), (1, [], servfail))

    def test_resolvectl_json_output_per_release(self) -> None:
        acme.add_a(self, NAME, ["192.0.2.10"])
        status, output, _ = resolvectl("A", NAME, "--json=short ")
        if os.environ.get("BARECTL_SSH_TEST_RELEASE") == "26.04":
            record = {"key": {"class": 1, "type": 1, "name": NAME}, "address": [192, 0, 2, 10]}
            self.assertEqual((status, json.loads(output)), (0, record))
        else:
            self.assertEqual((status, output), resolvectl("A", NAME)[:2])
        status, _, errors = resolvectl("A", NAME, "--search=no ")
        if os.environ.get("BARECTL_SSH_TEST_RELEASE") == "26.04":
            self.assertEqual(status, 0)
        else:
            self.assertEqual(
                (status, errors), (1, f"{NAME}: resolve call failed: Invalid flags parameter")
            )

    def test_server_reaches_acme_directories_over_ipv4(self) -> None:
        self.assert_directories_reachable("4")

    @skipIf(acme.IPV6_UNAVAILABLE, acme.IPV6_UNAVAILABLE)
    def test_server_reaches_acme_directories_over_ipv6(self) -> None:
        self.assert_directories_reachable("6")

    def assert_directories_reachable(self, family: str) -> None:
        for directory in (acme.DIRECTORY, acme.SHORT_DIRECTORY, acme.FAULT_DIRECTORY):
            with self.subTest(directory=directory):
                output = acme.on_server(
                    f"python3 -I -c '{DIRECTORY_CHECK}' {family} {directory}", user="observer"
                )
                self.assertIn(
                    "200 ['keyChange', 'meta', 'newAccount', 'newNonce', 'newOrder'", output
                )

    def test_pebble_validates_http01_on_port_80_over_ipv4(self) -> None:
        acme.add_a(self, NAME, [acme.server_addresses().ipv4])
        issued, clients = self.issue(acme.setting("PEBBLE_SHORT"))
        self.assertEqual(clients, {acme.addresses(acme.setting("PEBBLE_SHORT")).ipv4})
        certificate = issued.certificate
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        self.assertEqual(names.value.get_values_for_type(x509.DNSName), [NAME])
        self.assertLessEqual(
            certificate.not_valid_after_utc - certificate.not_valid_before_utc,
            timedelta(seconds=600),
        )

    @skipIf(acme.IPV6_UNAVAILABLE, acme.IPV6_UNAVAILABLE)
    def test_pebble_validates_http01_on_port_80_over_ipv6(self) -> None:
        acme.add_aaaa(self, NAME, [acme.server_addresses().ipv6])
        issued, clients = self.issue(acme.setting("PEBBLE"))
        self.assertEqual(clients, {acme.addresses(acme.setting("PEBBLE")).ipv6})
        self.assertGreater(
            issued.certificate.not_valid_after_utc - issued.certificate.not_valid_before_utc,
            timedelta(days=89),
        )

    def issue(self, pebble: str) -> tuple[acme.Issued, set[str]]:
        """Issue a certificate for NAME, and return the addresses that fetched its token.

        Pebble's challenge objects carry no validation record, so the responder's log shows
        which address, and so which family, Pebble validated from.
        """
        responder = acme.Responder(self)
        client = acme.AcmeClient(pebble)
        client.register()
        issued = client.issue([NAME], responder.publish)
        (authorization,) = issued.authorizations
        (challenge,) = [
            item for item in acme.objects(authorization, "challenges") if item["type"] == "http-01"
        ]
        self.assertEqual(challenge["status"], "valid")
        self.assertNotIn("validationRecord", challenge)
        return issued, responder.clients(acme.text(challenge, "token"))

    def test_fault_proxy_injects_problem_documents(self) -> None:
        client = acme.AcmeClient(acme.setting("FAULT_PROXY"))
        acme.inject_fault(self, "newAccount", "badNonce")
        rejected = client.post(
            acme.text(client.directory, "newAccount"), {"termsOfServiceAgreed": True}
        )
        self.assertEqual(
            (rejected.status, rejected.document()["type"]),
            (400, "urn:ietf:params:acme:error:badNonce"),
        )
        # The problem's fresh nonce lets the client retry at once.
        self.assertTrue(client.nonce)
        client.register()

        acme.inject_fault(self, "newOrder", "rateLimited", retry_after="3600")
        limited = client.new_order([NAME])
        self.assertEqual(
            (
                limited.status,
                limited.headers["content-type"],
                limited.headers["retry-after"],
                limited.document()["type"],
            ),
            (429, "application/problem+json", "3600", "urn:ietf:params:acme:error:rateLimited"),
        )
        order = client.new_order([NAME])
        self.assertEqual(order.status, 201)

        acme.inject_fault(self, "finalize", "caa")
        denied = client.post(acme.text(order.document(), "finalize"), {"csr": ""})
        self.assertEqual(
            (denied.status, denied.document()["type"]), (403, "urn:ietf:params:acme:error:caa")
        )
        self.assertEqual(
            [fault["type"] for fault in acme.served_faults() if isinstance(fault, dict)],
            ["badNonce", "rateLimited", "caa"],
        )
