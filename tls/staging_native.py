"""Applying a reviewed staging certificate order: its payload, outcome and verification.

docs/tls.md#staging. The order runs Certbot against the reviewed staging authority with
the site's challenge webroot, into isolated configuration, work and log directories, and
never touches the production Certbot state or Nginx. Every failure leaves the site's HTTP
serving exactly as it was.
"""

import shlex

from bootstrap import native as bootstrap_native
from sites import native as site_native
from sites.convention import SitePaths

# docs/tls.md#staging: the boundaries after admission. Nothing but the staging
# directories and the order's own artifacts can exist after any of them, and the site's
# HTTP serving is unchanged throughout.
DRIFT = bootstrap_native.Exit.DRIFT
DNS = 95
AUTHORITY_CAA = 96
RATE_LIMITED = 97
ACCOUNT = 98
ORDER_FAILED = 99

_FAILURES = {
    DNS: (
        "The authority could not validate the challenge for at least one name, which is a "
        "DNS or routing problem: the names' addresses, the challenge route's serving or "
        "port 80's reachability from outside differ from what the review read. Working HTTP "
        "is unchanged; nothing was created but the staging directories. Readiness again "
        "names what differs (docs/tls.md#staging)."
    ),
    AUTHORITY_CAA: (
        "The authority refused the order under the names' CAA records. Working HTTP is "
        "unchanged. Change the CAA records or choose an authority they name, then prepare "
        "again."
    ),
    RATE_LIMITED: (
        "The authority rate-limited the order and asked for a retry later; Barectl never "
        "retries automatically. Working HTTP is unchanged. Read the authority's advice and "
        "prepare again afterwards."
    ),
    ACCOUNT: (
        "The authority refused the staging account's registration. Working HTTP is "
        "unchanged. Check the recorded contact address and the authority's terms, then "
        "prepare again."
    ),
    ORDER_FAILED: (
        "The order failed for another reason; the unit's journal holds Certbot's bounded "
        "output for inspection. Working HTTP is unchanged and nothing was created but the "
        "staging directories."
    ),
}


def config_dir(identifier: str) -> str:
    return f"/etc/letsencrypt-staging/{identifier}"


def work_dir(identifier: str) -> str:
    return f"/var/lib/letsencrypt-staging/{identifier}"


def logs_dir(identifier: str) -> str:
    return f"/var/log/letsencrypt-staging/{identifier}"


def lineage_cert(identifier: str) -> str:
    return f"{config_dir(identifier)}/live/s{identifier}/cert.pem"


def lineage_argv(identifier: str) -> list[str]:
    """The staged certificate's subject, dates and names, as the verification reads them."""
    cert = shlex.quote(lineage_cert(identifier))
    return site_native.script(
        "; ".join(
            (
                "export LC_ALL=C PATH=/usr/sbin:/usr/bin",
                (
                    f"openssl x509 -noout -subject -startdate -enddate "
                    f"-ext subjectAltName -in {cert} 2>/dev/null"
                ),
            )
        )
    )


# Certbot's own failure words, most specific first; the first match names the boundary.
# Certbot 2.9's challenge failures all start with "Certbot failed to authenticate some
# domains"; older releases say "Failed authorization procedure". "Account registered."
# also appears on orders that fail later, so the account markers only match registration
# failures, never the success line.
_CLASSIFIERS = (
    (DNS, "Certbot failed to authenticate some domains"),
    (DNS, "Failed authorization procedure"),
    (DNS, "Timeout during"),
    (DNS, "Invalid response from"),
    (DNS, "Error getting validation data"),
    (DNS, "Connection refused"),
    (DNS, "DNS problem"),
    (AUTHORITY_CAA, "CAA"),
    (AUTHORITY_CAA, "caa"),
    (RATE_LIMITED, "rateLimited"),
    (RATE_LIMITED, "too many"),
    (ACCOUNT, "Unable to register"),
    (ACCOUNT, "Error creating new account"),
)


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
) -> list[site_native.Step]:
    """docs/tls.md#staging: each named fragment of the payload, in order."""
    paths = SitePaths(identifier, php_version)
    config, work, logs = config_dir(identifier), work_dir(identifier), logs_dir(identifier)
    cert = shlex.quote(lineage_cert(identifier))
    requested = " ".join(f"-d {shlex.quote(name)}" for name in names)
    order = (
        f"o=$(certbot certonly -n --server {shlex.quote(directory)} --webroot -w "
        f"{shlex.quote(webroot)} {requested} --cert-name "
        f"{shlex.quote(f's{identifier}')} --email {shlex.quote(email)} --agree-tos "
        "--no-eff-email --key-type ecdsa --elliptic-curve secp256r1 --no-directory-hooks "
        f"--config-dir {shlex.quote(config)} --work-dir {shlex.quote(work)} "
        f"--logs-dir {shlex.quote(logs)} 2>&1); s=$?"
    )
    cases = "; ".join(
        f'case "$o" in *{shlex.quote(marker)}*) exit {code};; esac' for code, marker in _CLASSIFIERS
    )
    reviewed = site_native.site_digest(paths)
    sans = (
        "openssl x509 -noout -ext subjectAltName -in "
        f"{cert} | grep -qiF {shlex.quote(f'DNS:{names[0]}')}"
    )
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
                        f"|| exit {bootstrap_native.Exit.DRIFT}"
                    ),
                    f"certbot --version >/dev/null 2>&1 || exit {DRIFT}",
                )
            ),
        ),
        site_native.Step(
            "staging-directories",
            "; ".join(
                (
                    "export PATH=/usr/sbin:/usr/bin; umask 077",
                    (
                        f"for d in {shlex.quote(config)} {shlex.quote(work)} "
                        f'{shlex.quote(logs)}; do mkdir -p -- "$d" || exit {DRIFT}; done'
                    ),
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
                    f"{sans} || exit {ORDER_FAILED}",
                    (
                        f'[ "$({reviewed} | cut -d" " -f1)" = {shlex.quote(site_digest)} ] '
                        f"|| exit {bootstrap_native.Exit.DRIFT}"
                    ),
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
        )
    )
