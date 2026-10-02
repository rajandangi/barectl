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
    return _wrapped(_record_text(name, kind))


def _record_text(name: str, kind: str) -> str:
    return f"{ENV}; {_RECORD.format(name=shlex.quote(_fqdn(name)), kind=kind)}"


def readiness_digest(names: tuple[str, ...], directory: str) -> str:
    """One read of every fact a certificate order stands on, hashed whole.

    docs/tls.md#issuance: preparation records this digest and the order's payload repeats
    the same reads, so fresh DNS, addresses, clock and directory reachability are rechecked
    before the authority is contacted.
    """
    reads = [_record_text(name, kind) for name in names for kind in ("A", "AAAA", "CNAME", "CAA")]
    reads += [
        f"{ENV}; ip -j address",
        f"{ENV}; timedatectl show -p NTPSynchronized --value",
        _directory_text(directory, "-4"),
        _directory_text(directory, "-6"),
    ]
    return "{ " + "; ".join(reads) + "; } 2>&1 | sha256sum"


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
    return _wrapped(_directory_text(directory, family))


def _directory_text(directory: str, family: str) -> str:
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
    # The Date header changes with every request, so it is dropped: the read's stable
    # bytes are the document itself, and the digest rechecks it before applying.
    return (
        f"{ENV}; printf {request} | openssl s_client -quiet {family} -connect {connect} "
        f"-servername {name} 2>/dev/null | tr -d '\\r' | grep -v '^Date: ' | head -c 2000"
    )
