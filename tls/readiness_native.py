"""The fixed, unprivileged external reads of TLS readiness: DNS from the server's own
resolver, the server's addresses, its clock and the authority directory's reachability.

docs/tls.md#readiness. None of them escalates: resolvectl, ip, timedatectl and openssl
answer to any account, so no sudo authorization is added for them. Everything else a
readiness or staging review reads runs through the site inspection's privilege machinery
(docs/ssh-connections.md#site-preparation).
"""

import shlex
from urllib.parse import urlsplit

from sites import native as site_native

ENV = "export LC_ALL=C PATH=/usr/sbin:/usr/bin"

# docs/ssh-connections.md#acme-and-dns-fixtures: both releases' resolvectl answers A, AAAA,
# CNAME and CAA records as text lines `<owner> IN <type> <data>` with --legend=no, and every
# failure exits 1 with its reason on standard error. The flags ask the configured servers
# anew: no cache, no synthesis, no local zone and no trust anchor, so only DNS answers.
_RECORD = (
    "resolvectl query --legend=no --cache=no --synthesize=no --zone=no --trust-anchor=no "
    "-t {kind} {name} 2>&1; echo rc=$?"
)


def dns_command(name: str, kind: str) -> str:
    """One fixed DNS read of ``name`` for ``kind`` (A, AAAA, CNAME or CAA)."""
    return _wrapped(f"{ENV}; {_RECORD.format(name=shlex.quote(_fqdn(name)), kind=kind)}")


def _fqdn(name: str) -> str:
    # The trailing dot keeps the server's search list out of the answer.
    return name.rstrip(".") + "."


def addresses_command() -> str:
    return _wrapped(f"{ENV}; ip -j address")


def clock_command() -> str:
    return _wrapped(f"{ENV}; timedatectl show -p NTPSynchronized --value")


def certbot_version_command() -> str:
    return _wrapped(f"{ENV}; certbot --version 2>&1")


def _wrapped(text: str) -> str:
    """One fixed read, as one ``sh -c`` command line, like the privileged reads."""
    return shlex.join(site_native.script(text))


def directory_command(directory: str, family: str) -> str:
    """One fixed reachability read: a plain HTTP/1.0 GET of the ACME directory over the
    system trust store, restricted to ``family`` (``-4`` or ``-6``)."""
    parts = urlsplit(directory)
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError("Not an https directory URL.")
    port = parts.port or 443
    # printf turns the two-character escapes into the request's real line endings, and
    # the quoted one-liner survives shlex the same way every fixed read does.
    host = parts.hostname or ""
    # Pebble answers 400 without a User-Agent header; printf turns the two-character
    # escapes into the request's real line endings.
    request = shlex.quote(
        f"GET {parts.path or '/'} HTTP/1.0\\r\\nHost: {host}\\r\\n"
        "User-Agent: barectl-readiness\\r\\n\\r\\n"
    )
    connect = shlex.quote(f"{host}:{port}")
    name = shlex.quote(host)
    return _wrapped(
        f"{ENV}; printf {request} | openssl s_client -quiet {family} -connect {connect} "
        f"-servername {name} 2>/dev/null | tr -d '\\r' | head -c 2000"
    )
