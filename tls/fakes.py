"""Challenge route preparation against the simulated site server (sites.fakes)."""

import json
import re
import shlex
from dataclasses import dataclass, field

from django.http import HttpResponseBase

from discovery.ssh import CommandResult
from sites import native
from sites.fakes import SiteServer, SiteTestCase

TLS_PERMISSIONS = ("view_server", "view_tlsplan", "prepare_tlsplan")
NAMES = ("shop.example.com", "www.shop.example.com")


class TlsTestCase(SiteTestCase):
    """TLS preparation through requests and the worker, against a simulated server."""

    def prepare_challenge(
        self, identifier: str = "shop", *, perms: tuple[str, ...] = TLS_PERMISSIONS
    ) -> HttpResponseBase:
        """Request a challenge route preparation as an operator with ``perms``."""
        self.sign_in_with(*perms)
        self.site.answer(self.remote)
        response = self.client.post(
            f"/servers/{self.server.pk}/tls/challenge/prepare/", {"identifier": identifier}
        )
        self.run_worker()
        return response


@dataclass
class TlsServer:
    """A site server that also answers TLS readiness's external reads and Certbot."""

    site: SiteServer
    # Per name: its A and AAAA records, its CNAME target and its CAA entries, as the
    # server's resolver answers them.
    dns: dict[str, DnsRecords] = field(default_factory=dict)
    # The server's own global addresses, split by family.
    ipv4: tuple[str, ...] = ("203.0.113.10",)
    ipv6: tuple[str, ...] = ("2001:db8::10",)
    ntp: bool = True
    # The directory's answer body, or a connection failure when empty.
    directory: str = (
        '{"newNonce":"https://acme/test/nonce","newAccount":"https://acme/test/account"}'
    )
    # The installed Certbot's version, or None when it is absent.
    certbot_version: str | None = "2.9.0"
    # The staged certificate openssl reads, or empty when no staging lineage exists.
    staged: str = ""

    def answer(self, remote: object) -> None:
        self.site.answer(remote)
        answers = remote.answers  # type: ignore[attr-defined]
        if self._answer not in answers:
            answers.insert(0, self._answer)

    def set_records(
        self,
        name: str,
        *,
        a: tuple[str, ...] = (),
        aaaa: tuple[str, ...] = (),
        cname: str = "",
        caa: tuple[str, ...] = (),
    ) -> None:
        self.dns[name] = DnsRecords(a=a, aaaa=aaaa, cname=cname, caa=caa)

    def _answer(self, command: str) -> CommandResult | None:
        # The staged certificate's read is privileged, like the site reads beside it.
        script = _inner_script(command.removeprefix("sudo -n "))
        if script is None:
            return None
        if "resolvectl query" in script:
            return self._dns(script)
        if "ip -j address" in script:
            return CommandResult(0, _addresses_json(self.ipv4, self.ipv6))
        if "timedatectl show -p NTPSynchronized" in script:
            return CommandResult(0, "yes\n" if self.ntp else "no\n")
        if "openssl s_client" in script:
            return CommandResult(0, self.directory + "\n")
        if "certbot --version" in script:
            if self.certbot_version is None:
                return CommandResult(1, "certbot: command not found\n")
            return CommandResult(0, f"certbot {self.certbot_version}\n")
        if "openssl x509" in script:
            if self.staged:
                return CommandResult(0, self.staged)
            return CommandResult(1, "Can't open the staged certificate for reading\n")
        return None

    def _dns(self, script: str) -> CommandResult:
        found = _DNS_QUERY.search(script)
        if found is None:
            return CommandResult(1, "rc=1\n")
        kind = found[1]
        name = found[2].rstrip(".")
        records = self.dns.get(name)
        if records is None:
            return CommandResult(1, self._empty_answer(name))
        if kind == "CNAME":
            if not records.cname:
                return CommandResult(1, self._empty_answer(name))
            return CommandResult(0, f"{name}.  IN  CNAME  {records.cname}  -- link: eth0\nrc=0\n")
        values = records.a if kind == "A" else records.aaaa if kind == "AAAA" else records.caa
        body = "".join(f"{name}.  IN  {kind}  {value}  -- link: eth0\n" for value in values)
        if body:
            return CommandResult(0, f"{body}rc=0\n")
        return CommandResult(1, self._empty_answer(name))

    @staticmethod
    def _empty_answer(name: str) -> str:
        """A name with none of this type: challtestsrv answers an empty NOERROR, which
        resolvectl reports as missing records of the type, not as a failure."""
        return (
            f"{name}: resolve call failed: Name '{name}' does not have any RR of "
            "the requested type\nrc=1\n"
        )


_DNS_QUERY = re.compile(r"-t (AAAA|CNAME|CAA|A) (\S+) 2>&1; echo rc=")


@dataclass
class DnsRecords:
    """One name's records, as the tests set them."""

    a: tuple[str, ...] = ()
    aaaa: tuple[str, ...] = ()
    cname: str = ""
    caa: tuple[str, ...] = ()


def _inner_script(command: str) -> str | None:
    try:
        argv = shlex.split(command)
    except ValueError:
        return None
    if argv[:2] == [native.SHELL, "-c"] and len(argv) == 3:
        return argv[2]
    return None


def _addresses_json(ipv4: tuple[str, ...], ipv6: tuple[str, ...]) -> str:
    interfaces = [
        {"addr_info": [{"family": family, "scope": "global", "local": address}]}
        for family, addresses in (("inet", ipv4), ("inet6", ipv6))
        for address in addresses
    ]
    return json.dumps(interfaces)
