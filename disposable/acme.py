"""ACME and DNS fixtures for the native suites: docs/ssh-connections.md#acme-and-dns-fixtures

Tests only. Everything here changes the disposable server through ``docker exec`` as its
administrator would, or talks to the fixture containers ``run-tests.sh`` starts beside it.
"""

import base64
import hashlib
import json
import os
import ssl
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from unittest import TestCase

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

SETTINGS = ("NETWORK", "ROOT", "PEBBLE", "PEBBLE_SHORT", "CHALLTESTSRV", "FAULT_PROXY")
CONFIGURED = bool(os.environ.get("BARECTL_SSH_TEST_CONTAINER")) and all(
    os.environ.get(f"BARECTL_ACME_TEST_{name}") for name in SETTINGS
)
IPV6_UNAVAILABLE = os.environ.get("BARECTL_ACME_TEST_IPV6_UNAVAILABLE", "")

# The directories as the disposable server reaches them, through Docker's resolver.
DIRECTORY = "https://pebble:14000/dir"
SHORT_DIRECTORY = "https://pebble-short:14000/dir"
FAULT_DIRECTORY = "https://acme-fault-proxy:14000/dir"
ANCHORS = "/usr/local/share/ca-certificates"
RESOLVED_DROPIN = "/run/systemd/resolved.conf.d/barectl-test.conf"
RESPONDER_ROOT = "/run/barectl-test-http01"
RESPONDER_UNIT = "barectl-test-http01"


def setting(name: str) -> str:
    return os.environ[f"BARECTL_ACME_TEST_{name}"]


def docker(*arguments: str, stdin: bytes | None = None) -> str:
    result = subprocess.run(  # noqa: S603 - the fixtures' own commands
        ["docker", *arguments],  # noqa: S607 - Docker on PATH
        input=stdin,
        capture_output=True,
        timeout=120,
        check=True,
    )
    return result.stdout.decode()


def on_server(script: str, *, user: str = "root", stdin: bytes | None = None) -> str:
    """Run a script on the disposable server through ``docker exec``; it must succeed."""
    container = os.environ["BARECTL_SSH_TEST_CONTAINER"]
    return docker("exec", "-i", "-u", user, container, "sh", "-c", script, stdin=stdin)


@dataclass(frozen=True)
class Addresses:
    ipv4: str
    ipv6: str


def addresses(container: str) -> Addresses:
    """A container's addresses on the test network, read fresh: a restart may change them."""
    networks: object = json.loads(
        docker("inspect", "-f", "{{json .NetworkSettings.Networks}}", container)
    )
    entry = networks.get(setting("NETWORK")) if isinstance(networks, dict) else None
    if not isinstance(entry, dict):
        raise AssertionError(f"{container} is not on the test network")
    ipv4, ipv6 = entry.get("IPAddress"), entry.get("GlobalIPv6Address")
    if not isinstance(ipv4, str) or not isinstance(ipv6, str):
        raise AssertionError(f"{container} has no addresses")
    return Addresses(ipv4, ipv6)


def server_addresses() -> Addresses:
    return addresses(os.environ["BARECTL_SSH_TEST_CONTAINER"])


def published(container: str, port: int) -> str:
    """The controller's loopback address and port for a fixture container's port."""
    return docker("port", container, f"{port}/tcp").splitlines()[0]


def trust() -> ssl.SSLContext:
    return ssl.create_default_context(cafile=setting("ROOT"))


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict[str, str]
    body: bytes

    def document(self) -> dict[str, object]:
        value: object = json.loads(self.body)
        if not isinstance(value, dict):
            raise AssertionError(f"not a JSON object: {self.body!r}")
        return {str(key): item for key, item in value.items()}


def fetch(
    url: str,
    *,
    method: str = "GET",
    body: bytes | None = None,
    content_type: str = "application/json",
    context: ssl.SSLContext | None = None,
) -> Response:
    request = urllib.request.Request(  # noqa: S310 - fixture URLs
        url, data=body, method=method, headers={"Content-Type": content_type}
    )
    try:
        with urllib.request.urlopen(request, context=context, timeout=30) as reply:  # noqa: S310
            return Response(
                reply.status, {k.lower(): v for k, v in reply.headers.items()}, reply.read()
            )
    except urllib.error.HTTPError as error:
        with error:
            return Response(
                error.code, {k.lower(): v for k, v in error.headers.items()}, error.read()
            )


def wait_until_serving(url: str, context: ssl.SSLContext | None = None) -> None:
    deadline = time.monotonic() + 60
    while True:
        try:
            fetch(url, context=context)
        except OSError:
            if time.monotonic() > deadline:
                raise
            time.sleep(0.5)
        else:
            return


def pebble_root(container: str) -> bytes:
    """The root Pebble generated at start, which signs every certificate it issues."""
    url = f"https://{published(container, 15000)}/roots/0"
    wait_until_serving(url, trust())
    return fetch(url, context=trust()).body


def install_trust_and_resolver(test: type[TestCase]) -> None:
    """Trust the fixtures' roots and resolve through the fault proxy, until the class ends.

    Pebble's test roots are fit only for a disposable server's trust store. resolved's global
    server is the fault proxy, which relays to challtestsrv and can answer NXDOMAIN; glibc keeps
    Docker's resolver, so the fixtures' own names still resolve.
    """
    anchors = {
        "barectl-test-pebble-minica.crt": Path(setting("ROOT")).read_bytes(),
        "barectl-test-pebble-root.crt": pebble_root(setting("PEBBLE")),
        "barectl-test-pebble-short-root.crt": pebble_root(setting("PEBBLE_SHORT")),
    }
    for filename, certificate in anchors.items():
        on_server(f"cat >{ANCHORS}/{filename}", stdin=certificate)
    dns = addresses(setting("FAULT_PROXY")).ipv4
    on_server(
        "update-ca-certificates >/dev/null && mkdir -p /run/systemd/resolved.conf.d && "
        f"printf '[Resolve]\\nDNS={dns}:8053\\nDomains=~.\\n' >{RESOLVED_DROPIN} && "
        "systemctl restart systemd-resolved"
    )
    names = " ".join(f"{ANCHORS}/{filename}" for filename in anchors)
    test.addClassCleanup(
        on_server,
        f"rm -f {names} {RESOLVED_DROPIN} && update-ca-certificates >/dev/null && "
        "systemctl restart systemd-resolved",
    )


def challtestsrv(test: TestCase, endpoint: str, document: dict[str, object], clear: str) -> None:
    base = f"http://{published(setting('CHALLTESTSRV'), 8055)}"
    response = fetch(f"{base}/{endpoint}", method="POST", body=json.dumps(document).encode())
    test.assertEqual(response.status, 200, response.body)
    host = document["host"]
    test.addCleanup(
        fetch, f"{base}/{clear}", method="POST", body=json.dumps({"host": host}).encode()
    )


def fqdn(name: str) -> str:
    return name.rstrip(".") + "."


def add_a(test: TestCase, name: str, values: Iterable[str]) -> None:
    challtestsrv(test, "add-a", {"host": fqdn(name), "addresses": list(values)}, "clear-a")


def add_aaaa(test: TestCase, name: str, values: Iterable[str]) -> None:
    challtestsrv(test, "add-aaaa", {"host": fqdn(name), "addresses": list(values)}, "clear-aaaa")


def set_cname(test: TestCase, name: str, target: str) -> None:
    challtestsrv(test, "set-cname", {"host": fqdn(name), "target": fqdn(target)}, "clear-cname")


def add_caa(test: TestCase, name: str, policies: Iterable[tuple[str, str]]) -> None:
    records = [{"tag": tag, "value": value} for tag, value in policies]
    challtestsrv(test, "add-caa", {"host": fqdn(name), "policies": records}, "clear-caa")


def set_servfail(test: TestCase, name: str) -> None:
    challtestsrv(test, "set-servfail", {"host": fqdn(name)}, "clear-servfail")


def fault_proxy_control() -> str:
    return f"http://{published(setting('FAULT_PROXY'), 8080)}"


def set_nxdomain(test: TestCase, name: str) -> None:
    """Answer NXDOMAIN for a name without records, instead of challtestsrv's empty answer."""
    base = fault_proxy_control()
    response = fetch(f"{base}/nxdomain", method="POST", body=json.dumps({"host": name}).encode())
    test.assertEqual(response.status, 200, response.body)
    test.addCleanup(fetch, f"{base}/nxdomain", method="DELETE")


def inject_fault(
    test: TestCase, resource: str, problem: str, *, retry_after: str = "", count: int = 1
) -> None:
    """Fail the next ``count`` requests to an ACME resource through the fault proxy."""
    base = fault_proxy_control()
    fault = {"resource": resource, "type": problem, "retryAfter": retry_after, "count": count}
    response = fetch(f"{base}/faults", method="POST", body=json.dumps(fault).encode())
    test.assertEqual(response.status, 200, response.body)
    test.addCleanup(fetch, f"{base}/faults", method="DELETE")


def served_faults() -> list[object]:
    served = fetch(fault_proxy_control()).document()["served"]
    return served if isinstance(served, list) else []


class Responder:
    """HTTP-01 responses on the server's port 80, for any name and both families.

    It runs until the test ends. Nginx is stopped meanwhile, and started again afterwards if it
    was active.
    """

    def __init__(self, test: TestCase) -> None:
        on_server(
            f"install -d {RESPONDER_ROOT}/.well-known/acme-challenge && "
            "if systemctl is-active --quiet nginx; then "
            "touch /run/barectl-test-nginx-was-active; systemctl stop nginx; fi && "
            f"systemd-run --quiet --unit {RESPONDER_UNIT} python3 -m http.server 80 --bind :: "
            f"--directory {RESPONDER_ROOT} && "
            "for i in $(seq 50); do ss -Hltn 'sport = :80' | grep -q . && exit 0; sleep 0.2; done; "
            "exit 1"
        )
        test.addCleanup(
            on_server,
            f"systemctl stop {RESPONDER_UNIT}; rm -rf {RESPONDER_ROOT}; "
            "if [ -e /run/barectl-test-nginx-was-active ]; then "
            "rm /run/barectl-test-nginx-was-active; systemctl start nginx; fi",
        )

    def publish(self, token: str, key_authorization: str) -> None:
        on_server(
            f"cat >{RESPONDER_ROOT}/.well-known/acme-challenge/{token}",
            stdin=key_authorization.encode(),
        )

    def clients(self, token: str) -> set[str]:
        """The addresses that fetched a token, IPv4 ones without their mapped prefix."""
        request = f'"GET /.well-known/acme-challenge/{token} HTTP/1.1" 200'
        deadline = time.monotonic() + 10
        while True:
            log = on_server(f"journalctl -q -u {RESPONDER_UNIT} -o cat --no-pager")
            found = {
                line.split()[0].removeprefix("::ffff:")
                for line in log.splitlines()
                if request in line
            }
            if found or time.monotonic() > deadline:
                return found
            time.sleep(0.5)


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def text(document: dict[str, object], key: str) -> str:
    value = document.get(key)
    if not isinstance(value, str):
        raise AssertionError(f"{key} is not a string in {document}")
    return value


def objects(document: dict[str, object], key: str) -> list[dict[str, object]]:
    value = document.get(key)
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise AssertionError(f"{key} is not a list of objects in {document}")
    return [{str(k): v for k, v in item.items()} for item in value]


@dataclass(frozen=True)
class Issued:
    authorizations: list[dict[str, object]]
    certificate: x509.Certificate


class AcmeClient:
    """A minimal RFC 8555 client, so a test can drive Pebble without Certbot on the server.

    It runs on the controller against a fixture's published port, and trusts only the test root.
    """

    def __init__(self, container: str) -> None:
        self.context = trust()
        self.key = ec.generate_private_key(ec.SECP256R1())
        numbers = self.key.public_key().public_numbers()
        self.jwk = {
            "crv": "P-256",
            "kty": "EC",
            "x": b64(numbers.x.to_bytes(32, "big")),
            "y": b64(numbers.y.to_bytes(32, "big")),
        }
        canonical = json.dumps(self.jwk, sort_keys=True, separators=(",", ":")).encode()
        self.thumbprint = b64(hashlib.sha256(canonical).digest())
        url = f"https://{published(container, 14000)}/dir"
        wait_until_serving(url, self.context)
        self.directory = fetch(url, context=self.context).document()
        self.nonce = ""
        self.account = ""

    def post(self, url: str, payload: dict[str, object] | None) -> Response:
        if not self.nonce:
            nonce = fetch(text(self.directory, "newNonce"), method="HEAD", context=self.context)
            self.nonce = nonce.headers["replay-nonce"]
        protected: dict[str, object] = {"alg": "ES256", "nonce": self.nonce, "url": url}
        if self.account:
            protected["kid"] = self.account
        else:
            protected["jwk"] = self.jwk
        header = b64(json.dumps(protected).encode())
        body = "" if payload is None else b64(json.dumps(payload).encode())
        r, s = decode_dss_signature(
            self.key.sign(f"{header}.{body}".encode(), ec.ECDSA(hashes.SHA256()))
        )
        jws = {
            "protected": header,
            "payload": body,
            "signature": b64(r.to_bytes(32, "big") + s.to_bytes(32, "big")),
        }
        response = fetch(
            url,
            method="POST",
            body=json.dumps(jws).encode(),
            content_type="application/jose+json",
            context=self.context,
        )
        self.nonce = response.headers.get("replay-nonce", "")
        return response

    def register(self) -> None:
        response = self.post(text(self.directory, "newAccount"), {"termsOfServiceAgreed": True})
        if response.status not in {200, 201}:
            raise AssertionError(response.body)
        self.account = response.headers["location"]

    def new_order(self, names: Iterable[str]) -> Response:
        identifiers = [{"type": "dns", "value": name} for name in names]
        return self.post(text(self.directory, "newOrder"), {"identifiers": identifiers})

    def poll(self, url: str, final: set[str]) -> dict[str, object]:
        deadline = time.monotonic() + 60
        while True:
            document = self.post(url, None).document()
            if text(document, "status") in final or time.monotonic() > deadline:
                return document
            time.sleep(0.5)

    def issue(self, names: list[str], publish: Callable[[str, str], None]) -> Issued:
        """Order a certificate for the names and answer each HTTP-01 challenge through publish."""
        order = self.new_order(names)
        if order.status != 201:
            raise AssertionError(order.body)
        document = order.document()
        authorizations = []
        urls = document.get("authorizations")
        for url in urls if isinstance(urls, list) else []:
            authorization = self.post(str(url), None).document()
            challenge = next(
                item for item in objects(authorization, "challenges") if item["type"] == "http-01"
            )
            token = text(challenge, "token")
            publish(token, f"{token}.{self.thumbprint}")
            self.post(text(challenge, "url"), {})
            authorizations.append(self.poll(str(url), {"valid", "invalid"}))
        if any(text(item, "status") != "valid" for item in authorizations):
            raise AssertionError(f"validation failed: {authorizations}")
        key = ec.generate_private_key(ec.SECP256R1())
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), False)
            .sign(key, hashes.SHA256())
        )
        der = csr.public_bytes(serialization.Encoding.DER)
        self.post(text(document, "finalize"), {"csr": b64(der)})
        final = self.poll(order.headers["location"], {"valid", "invalid"})
        pem = self.post(text(final, "certificate"), None).body
        return Issued(authorizations, x509.load_pem_x509_certificates(pem)[0])
