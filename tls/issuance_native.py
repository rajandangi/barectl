"""Applying a reviewed production certificate order: its payload and lineage reads.

docs/tls.md#issuance. The order runs Certbot's ordinary lineage under ``/etc/letsencrypt``
with the site's challenge webroot, rechecks the reviewed readiness, the site's challenge
route and the guarded renewal setup before it contacts the authority, and proves the
issued lineage's public identity afterwards. A lost answer is reconciled from the unit
alone; Barectl never orders twice.
"""

import shlex

from bootstrap import native as bootstrap_native
from sites import native as site_native
from sites.convention import SitePaths

from . import readiness_native, setup_native, staging_native

DRIFT = bootstrap_native.Exit.DRIFT
# The order's own boundaries, shared with the staging order's wording (docs/tls.md#staging).
DNS = staging_native.DNS
AUTHORITY_CAA = staging_native.AUTHORITY_CAA
RATE_LIMITED = staging_native.RATE_LIMITED
ACCOUNT = staging_native.ACCOUNT
ORDER_FAILED = staging_native.ORDER_FAILED

_FAILURES = {
    DNS: (
        "The authority could not validate the challenge for at least one name, which is a "
        "DNS or routing problem: the names' addresses, the challenge route's serving or "
        "port 80's reachability from outside differ from what the review read. Working HTTP "
        "is unchanged and no lineage was created. Readiness again names what differs "
        "(docs/tls.md#issuance)."
    ),
    AUTHORITY_CAA: (
        "The authority refused the order under the names' CAA records. Working HTTP is "
        "unchanged and no lineage was created. Change the CAA records or choose an authority "
        "they name, then prepare again."
    ),
    RATE_LIMITED: (
        "The authority rate-limited the order and asked for a retry later; Barectl never "
        "retries automatically. Working HTTP is unchanged and no lineage was created. Read "
        "the authority's advice and prepare again afterwards."
    ),
    ACCOUNT: (
        "The authority refused the production account's registration. Working HTTP is "
        "unchanged and no lineage was created. Check the recorded contact address and the "
        "authority's terms, then prepare again."
    ),
    ORDER_FAILED: (
        "The order failed for another reason, or the lineage it wrote does not match the "
        "reviewed names and key policy. The unit's journal holds Certbot's bounded output "
        "for inspection. Working HTTP is unchanged; an issued certificate, if one exists, "
        "is left in place and a fresh activation-only review can reference it."
    ),
}

# Certbot 2.x issues SAN-only certificates, so the subject line exists but may be empty.
_SUBJECT = r"^subject=(.*)$"


def lineage_dir(identifier: str) -> str:
    return f"/etc/letsencrypt/live/{identifier}"


def lineage_cert(identifier: str) -> str:
    return f"{lineage_dir(identifier)}/cert.pem"


def lineage_key(identifier: str) -> str:
    return f"{lineage_dir(identifier)}/privkey.pem"


def renewal_conf(identifier: str) -> str:
    return f"/etc/letsencrypt/renewal/{identifier}.conf"


def lineage_text(identifier: str) -> str:
    """The issued certificate's subject, dates, names, serial, fingerprint, key identity,
    curve and renewal configuration, as the verification reads them."""
    cert = shlex.quote(lineage_cert(identifier))
    key = shlex.quote(lineage_key(identifier))
    renewal = shlex.quote(renewal_conf(identifier))
    return "; ".join(
        (
            "export LC_ALL=C PATH=/usr/sbin:/usr/bin",
            (
                "openssl x509 -noout -subject -startdate -enddate -ext subjectAltName "
                f"-serial -fingerprint -sha256 -in {cert} 2>/dev/null"
            ),
            (
                "printf 'pubkey_cert='; "
                f"openssl x509 -noout -pubkey -in {cert} 2>/dev/null "
                '| sha256sum | cut -d" " -f1'
            ),
            (
                "printf 'pubkey_key='; "
                f"openssl pkey -in {key} -pubout 2>/dev/null "
                '| sha256sum | cut -d" " -f1'
            ),
            (
                "printf 'curve='; "
                f"openssl x509 -noout -text -in {cert} 2>/dev/null "
                "| sed -n 's/.*ASN1 OID: //p' | head -1"
            ),
            f"printf 'renewal='; [ -f {renewal} ] && echo yes || echo no",
        )
    )


def lineage_argv(identifier: str) -> list[str]:
    return site_native.script(lineage_text(identifier))


def lineage_digest(identifier: str) -> str:
    """The lineage's public facts, hashed whole, for the payload's recheck."""
    return "{ " + lineage_text(identifier) + "; } 2>&1 | sha256sum"


def state_text(identifier: str) -> str:
    """The production lineage and account state a review reads and applying rechecks."""
    directory = shlex.quote(lineage_dir(identifier))
    return "; ".join(
        (
            "export LC_ALL=C PATH=/usr/sbin:/usr/bin",
            f"if [ -e {directory} ]; then echo lineage=yes; else echo lineage=no; fi",
            lineage_text(identifier),
            (
                "for r in /etc/letsencrypt/accounts/*/*/*/regr.json; do "
                '[ -f "$r" ] || continue; '
                "printf 'account='; tr -d '\\n' <\"$r\"; echo; done"
            ),
        )
    )


def state_argv(identifier: str) -> list[str]:
    return site_native.script(state_text(identifier))


def state_digest(identifier: str) -> str:
    """The lineage and account state, hashed whole, for the payload's recheck."""
    return "{ " + state_text(identifier) + "; } 2>&1 | sha256sum"


def steps(
    unit: str,
    boot_id: str,
    deadline: int,
    *,
    identifier: str,
    php_version: str,
    webroot: str,
    names: tuple[str, ...],
    email: str,
    directory: str,
    site_digest: str,
    renewal_digest: str,
    readiness_digest: str,
    lineage_digest: str,
) -> list[site_native.Step]:
    """docs/tls.md#issuance: each named fragment of the payload, in order."""
    paths = SitePaths(identifier, php_version)
    cert = shlex.quote(lineage_cert(identifier))
    key = shlex.quote(lineage_key(identifier))
    renewal = shlex.quote(renewal_conf(identifier))
    requested = " ".join(f"-d {shlex.quote(name)}" for name in names)
    order = (
        f"o=$(certbot certonly -n --server {shlex.quote(directory)} --webroot -w "
        f"{shlex.quote(webroot)} {requested} --cert-name {shlex.quote(identifier)} "
        f"--email {shlex.quote(email)} --agree-tos --no-eff-email --key-type ecdsa "
        "--elliptic-curve secp256r1 --no-directory-hooks 2>&1); s=$?"
    )
    cases = "; ".join(
        f'case "$o" in *{shlex.quote(marker)}*) exit {code};; esac'
        for code, marker in staging_native._CLASSIFIERS
    )
    reviewed = site_native.site_digest(paths)

    def drift(name: str) -> str:
        return f"|| {{ echo 'barectl-tls: drift: {name}'; exit {DRIFT}; }}"

    return [
        site_native.Step(
            "admission", "; ".join(bootstrap_native.admission(unit, boot_id, deadline))
        ),
        site_native.Step(
            "revalidation",
            "; ".join(
                (
                    "export PATH=/usr/sbin:/usr/bin",
                    (
                        f'[ "$({reviewed} | cut -d" " -f1)" = {shlex.quote(site_digest)} ] '
                        f"{drift('site')}"
                    ),
                    (
                        f'[ "$({setup_native.renewal_digest()} | cut -d" " -f1)" = '
                        f"{shlex.quote(renewal_digest)} ] {drift('renewal')}"
                    ),
                    (
                        f'[ "$({readiness_native.readiness_digest(names, directory)}'
                        f' | cut -d" " -f1)" = {shlex.quote(readiness_digest)} ] '
                        f"|| {{ echo 'barectl-tls: drift: readiness'; exit {DNS}; }}"
                    ),
                    (
                        f'[ "$({state_digest(identifier)} | cut -d" " -f1)" = '
                        f"{shlex.quote(lineage_digest)} ] {drift('lineage')}"
                    ),
                    f"certbot --version >/dev/null 2>&1 {drift('certbot')}",
                )
            ),
        ),
        site_native.Step("order", order),
        site_native.Step(
            "boundary",
            "; ".join(
                (
                    (
                        f'[ "$s" -eq 0 ] || {{ printf \'%s\\n\' "$o" | tail -c '
                        f"{bootstrap_native.MAX_JOURNAL_OUTPUT}; {cases}; "
                        f"exit {ORDER_FAILED}; }}"
                    ),
                    f"[ -f {cert} ] || exit {ORDER_FAILED}",
                    f"[ -f {key} ] || exit {ORDER_FAILED}",
                    f"[ -f {renewal} ] || exit {ORDER_FAILED}",
                    (
                        "openssl x509 -noout -ext subjectAltName "
                        f"-in {cert} 2>/dev/null | tr -d ' \\n' | "
                        + " ".join(f"grep -qiF {shlex.quote(f'DNS:{name}')} &&" for name in names)
                        + " true"
                    ),
                    (
                        "a=$(openssl x509 -noout -pubkey "
                        f'-in {cert} 2>/dev/null | sha256sum | cut -d" " -f1); '
                        "b=$(openssl pkey -in " + key + " -pubout 2>/dev/null "
                        '| sha256sum | cut -d" " -f1); [ -n "$a" ] && [ "$a" = "$b" ] '
                        f"|| exit {ORDER_FAILED}"
                    ),
                    (
                        "openssl x509 -noout -text "
                        f"-in {cert} 2>/dev/null | grep -q 'ASN1 OID: prime256v1' "
                        f"|| exit {ORDER_FAILED}"
                    ),
                    # No site digest here: the order's own lineage legitimately changes the
                    # certificate paths the digest covers, and revalidation proved the site
                    # before Certbot ran.
                    f"exit {bootstrap_native.Exit.SUCCESS}",
                )
            ),
        ),
    ]


def payload(
    unit: str,
    boot_id: str,
    deadline: int,
    *,
    identifier: str,
    php_version: str,
    webroot: str,
    names: tuple[str, ...],
    email: str,
    directory: str,
    site_digest: str,
    renewal_digest: str,
    readiness_digest: str,
    lineage_digest: str,
) -> str:
    return "; ".join(
        step.text
        for step in steps(
            unit,
            boot_id,
            deadline,
            identifier=identifier,
            php_version=php_version,
            webroot=webroot,
            names=names,
            email=email,
            directory=directory,
            site_digest=site_digest,
            renewal_digest=renewal_digest,
            readiness_digest=readiness_digest,
            lineage_digest=lineage_digest,
        )
    )
