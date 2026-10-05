"""Challenge route preparation against the simulated site server (sites.fakes)."""

import hashlib
import json
import re
import shlex
from dataclasses import dataclass, field

from django.http import HttpResponseBase
from django.utils import timezone

from bootstrap import native as bootstrap_native
from bootstrap.models import ApplyRun, PlanPreparation, Verification
from discovery.ssh import CommandResult
from sites import native
from sites.convention import Stage, render_site
from sites.fakes import SiteServer, SiteTestCase

from .installation import STAGES
from .models import CertificateInstallation, CertificateInstallationStep

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


def record_step(
    installation: CertificateInstallation,
    position: int,
    status: str = "succeeded",
    verification: str = Verification.PASSED,
) -> ApplyRun:
    """Record an installation stage's prepared plan and run as the worker would leave them."""
    server = installation.server
    user = installation.requested_by
    if server is None or user is None:
        raise ValueError("The installation needs its server and requesting account.")
    preparation = PlanPreparation.objects.create(
        server=server,
        ssh_alias=server.ssh_alias,
        status="succeeded",
        action=STAGES[position],
        requested_by=user,
        finished_at=timezone.now(),
    )
    finished = status in ("succeeded", "failed")
    run = ApplyRun.objects.create(
        server=server,
        ssh_alias=server.ssh_alias,
        status=status,
        plan_number=preparation.pk + 1000,
        requested_by=user,
        requested_by_name=user.get_username(),
        server_name=server.name,
        action=STAGES[position],
        intent="",
        profile_revision=1,
        reviewed_host_key="ssh-ed25519 SHA256:test",
        boot_id="boot",
        admission_deadline_centiseconds=1,
        admission_expires_at=timezone.now(),
        effects="",
        unit_name=bootstrap_native.new_unit_name(),
        verification=verification,
        dispatched_at=timezone.now(),
        finished_at=timezone.now() if finished else None,
    )
    CertificateInstallationStep.objects.create(
        installation=installation, position=position, preparation=preparation, run=run
    )
    return run


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
    # The production lineage's openssl read, or empty when none exists.
    production: str = ""
    # The production account registrations, as Certbot's regr.json documents.
    accounts: tuple[str, ...] = ()
    # The shared default TLS rejection server's state, and competing 443 defaults.
    default_reject: bool = False
    competing_defaults: int = 0
    # The activation's observable results.
    redirect_status: str = "301"
    challenge_status: str = "404"
    unknown_served: bool = False
    host_served: bool = False

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

    def production_fingerprint(self) -> str:
        found = re.search(r"^sha256 Fingerprint=([0-9A-Fa-f:]+)$", self.production, re.MULTILINE)
        return found[1].replace(":", "").lower() if found else ""

    def state(self) -> str:
        """The production lineage and account state, as the preparation reads it."""
        lines = ["lineage=yes" if self.production else "lineage=no"]
        if self.production:
            lines.append(self.production)
        lines += [f"account={document}" for document in self.accounts]
        return "\n".join(lines) + "\n"

    def _answer(self, command: str) -> CommandResult | None:
        # The staged certificate's read is privileged, like the site reads beside it.
        script = _inner_script(command.removeprefix("sudo -n "))
        if script is None:
            return None
        digest = self._digest(script)
        if digest is not None:
            return digest
        if "tls-default-reject.conf" in script:
            return self._activation(script)
        if "regr.json" in script:
            return CommandResult(0, self.state())
        if "resolvectl query" in script:
            return self._dns(script)
        return self._read(script)

    def _read(self, script: str) -> CommandResult | None:
        """The server's own platform, directory and Certbot reads."""
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
            return self._certificate(script)
        return None

    def _digest(self, script: str) -> CommandResult | None:
        """The preparation digests, which the fake answers deterministically."""
        if not script.rstrip().endswith("sha256sum"):
            return None
        if "certbot.service" in script:
            return CommandResult(0, f"{'f' * 64}  -\n")
        if "openssl x509" in script:
            return CommandResult(0, f"{hashlib.sha256(self.production.encode()).hexdigest()}  -\n")
        if "regr.json" in script:
            return CommandResult(0, f"{hashlib.sha256(self.state().encode()).hexdigest()}  -\n")
        if "resolvectl query" in script:
            return CommandResult(0, f"{hashlib.sha256(script.encode()).hexdigest()}  -\n")
        return None

    def _activation(self, script: str) -> CommandResult:
        """The shared rejection server's state or the activated site's verification read."""
        from . import activation_native

        if "nginx -T" in script:
            lines = (
                ["absent"]
                if not self.default_reject
                else [
                    "path regular file root root 644 1 /etc/nginx/conf.d/tls-default-reject.conf",
                    "sha "
                    + hashlib.sha256(activation_native.DEFAULT_CONTENT.encode()).hexdigest()
                    + " /etc/nginx/conf.d/tls-default-reject.conf",
                ]
            )
            lines += ["listen 443 ssl default_server;"] * (
                self.competing_defaults + (2 if self.default_reject else 0)
            )
            return CommandResult(0, "\n".join(lines) + "\n")
        found = re.search(r"/etc/nginx/sites-available/([a-z0-9]+)\.conf", script)
        identifier = found[1] if found else ""
        names, ipv6, _ = self.site.sites[identifier]
        stage = self.site.stages.get(identifier, Stage.CHALLENGE)
        source = render_site(identifier, names, ipv6=ipv6, stage=stage)
        preimage = render_site(identifier, names, ipv6=ipv6, stage=Stage.CHALLENGE)
        default_sha = hashlib.sha256(activation_native.DEFAULT_CONTENT.encode()).hexdigest()
        source_path = f"/etc/nginx/sites-available/{identifier}.conf"
        backup = re.search(r"/var/backups/nginx/\S+", script)
        backup_path = backup[0] if backup else ""
        lines = [
            f"path regular file root root 644 1 {source_path}",
            f"path regular file root root 600 1 {backup_path}",
            "path regular file root root 644 1 /etc/nginx/conf.d/tls-default-reject.conf",
            f"sha {hashlib.sha256(source.encode()).hexdigest()} {source_path}",
            f"sha {hashlib.sha256(preimage.encode()).hexdigest()} {backup_path}",
            f"sha {default_sha} /etc/nginx/conf.d/tls-default-reject.conf",
            "nginx valid",
        ]
        fingerprint = self.production_fingerprint()
        lines += [f"served {name} {fingerprint}" for name in names]
        lines += [
            "served verified",
            "unknown served" if self.unknown_served else "unknown rejected",
            "host served" if self.host_served else "host not served",
            f"redirect {self.redirect_status} challenge {self.challenge_status}",
        ]
        return CommandResult(0, "\n".join(lines) + "\n")

    def _certificate(self, script: str) -> CommandResult:
        if "-serial" in script:
            if self.production:
                return CommandResult(0, self.production)
            return CommandResult(1, "Can't open the production certificate for reading\n")
        if self.staged:
            return CommandResult(0, self.staged)
        return CommandResult(1, "Can't open the staged certificate for reading\n")

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
