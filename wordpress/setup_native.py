"""WP-CLI tool setup's fixed reads, payload and verification read (docs/wordpress.md).

The tool state is one fixed root script. Its output is parsed for admission and
verification; its SHA-256 is the digest a plan records and its payload recomputes under
the mutation lock. The payload acquires the pinned official PHAR and its detached
signature, authenticates both with native GPG against the approved primary signing
identity, and only then installs the artifact. No downloaded PHP ever executes.
"""

import re
import shlex
from typing import Final

from bootstrap import native as bootstrap_native
from sites import native as site_native

_ENV = "export LC_ALL=C PATH=/usr/sbin:/usr/bin"
_DIGEST = re.compile(r"[0-9a-f]{64}")
# docs/wordpress-native-design.md#compatibility-and-supply: the reviewed release pins.
VERSION: Final = "2.12.0"
# The official release artifacts, as the pinned release publishes them.
PHAR_URL: Final = (
    f"https://github.com/wp-cli/wp-cli/releases/download/v{VERSION}/wp-cli-{VERSION}.phar"
)
SIGNATURE_URL: Final = f"{PHAR_URL}.asc"
# The release signing key's published location and its approved primary fingerprint, from
# WP-CLI's verification guide; the fingerprint, not the URL, is the trust anchor.
KEY_URL: Final = "https://raw.githubusercontent.com/wp-cli/builds/gh-pages/wp-cli.pgp"
FINGERPRINT: Final = "63AF7AA15067C05616FDDD88A3A2E8F226F0BC06"
# The authenticated artifact's reviewed digest, as GitHub also records it.
SHA256: Final = "ce34ddd838f7351d6759068d09793f26755463b4a4610a5a5c0a97b68220d85c"
DIRECTORY: Final = "/usr/local/lib/wp-cli"
PHAR: Final = f"{DIRECTORY}/wp-cli-{VERSION}.phar"
# The root-owned, non-writable ancestry the protected installation requires.
PATHS: Final = ("/usr", "/usr/local", "/usr/local/lib", DIRECTORY, PHAR)
# Bound on one download; the reviewed digest binds the exact bytes.
MAX_DOWNLOAD: Final = 256 * 1024 * 1024
DOWNLOAD_TIMEOUT: Final = 300
# GPG's colon format: the primary key's validity and fingerprint, every bound key's
# fingerprint, and the signature status line's actual signer.
_PRIMARY_AWK: Final = 'awk -F: \'$1=="pub"{v=$2} $1=="fpr"{print v ":" $10; exit}\''
_BOUND_AWK: Final = "awk -F: '$1==\"fpr\"{print $10}'"
# GPG's status lines are prefixed "[GNUPG:] ", so the signer is the field after the tag.
_SIGNER_AWK: Final = "awk '$2==\"VALIDSIG\"{print $3; exit}'"


def _curl(url: str, output: str) -> str:
    return (
        "curl --fail --location --silent --show-error --proto =https "
        f"--connect-timeout 10 --max-time {DOWNLOAD_TIMEOUT} --max-filesize {MAX_DOWNLOAD} "
        f"--output {output} {shlex.quote(url)}"
    )


def _state_lines() -> list[str]:
    """Each fact on its own line, prefixed by its kind; all of it stable."""
    quoted = " ".join(shlex.quote(path) for path in PATHS)
    return [
        _ENV,
        (
            f'for p in {quoted}; do if [ -e "$p" ] || [ -L "$p" ]; then '
            'stat -c \'path %F|%U|%G|%a|%h|%n\' -- "$p"; else echo "absent $p"; fi; done'
        ),
        (
            f"[ ! -L {PHAR} ] && [ -f {PHAR} ] && "
            f"echo \"sha $(sha256sum <{PHAR} | cut -d' ' -f1) {PHAR}\""
        ),
        (
            f"find {DIRECTORY} -mindepth 1 -maxdepth 1 -printf 'entry %y %m %U %G %p\\n' "
            "2>/dev/null | sort"
        ),
        (
            'for t in gpg curl; do [ -x /usr/bin/$t ] && echo "tool $t ok" || '
            'echo "tool $t missing"; done'
        ),
        "/usr/bin/gpg --version 2>/dev/null | sed -n '1s/^/version /p'",
        "true",
    ]


def wpcli_digest() -> str:
    """docs/wordpress.md#wp-cli-setup: what the payload rechecks, as root."""
    return "{ " + "; ".join(_state_lines()) + "; } 2>/dev/null | sha256sum"


def wpcli_state() -> list[str]:
    """Every fact admission and verification read, as root."""
    return site_native.script("; ".join(_state_lines()))


def wpcli_digest_argv() -> list[str]:
    return site_native.script(wpcli_digest())


class Exit:
    """docs/wordpress.md#recovering-a-partial-tool-setup: the payload's own boundaries."""

    DRIFT = bootstrap_native.Exit.DRIFT
    TOOLS = 31
    KEY = 32
    SIGNATURE = 33
    DOWNLOAD = 34
    FILE = 35


def setup_steps(
    unit: str,
    boot_id: str,
    deadline: int,
    *,
    digest: str,
) -> list[site_native.Step]:
    """docs/wordpress.md#applying-a-wp-cli-setup: each named fragment, in order."""
    if not _DIGEST.fullmatch(digest):
        raise ValueError("Not a valid digest.")
    suffix = unit.removeprefix(bootstrap_native.UNIT_PREFIX).removesuffix(".service")
    staged = f"{DIRECTORY}/.{VERSION}.phar.{suffix}"
    private = f"/run/barectl-wpcli-{suffix}"
    key_file = '"$k/key.pgp"'
    signature_file = '"$k/phar.asc"'
    status_file = '"$k/status"'
    gnupg = f"GNUPGHOME={private}/gnupg /usr/bin/gpg --batch --yes"
    return [
        site_native.Step(
            "admission", "; ".join(bootstrap_native.admission(unit, boot_id, deadline))
        ),
        site_native.Step(
            "helpers",
            "; ".join(("export PATH=/usr/sbin:/usr/bin; umask 022; set -C", site_native.ANCESTORS)),
        ),
        site_native.Step(
            "revalidation",
            "; ".join(bootstrap_native.digest_preconditions(((wpcli_digest(), digest),))),
        ),
        site_native.Step(
            "tools",
            (
                "[ -x /usr/bin/gpg ] && [ -x /usr/bin/curl ] "
                f"|| exit {Exit.TOOLS}; /usr/bin/gpg --version >/dev/null 2>&1 "
                f"|| exit {Exit.TOOLS}"
            ),
        ),
        site_native.Step(
            "keyring",
            "; ".join(
                (
                    f"k={private}",
                    f'[ ! -L "$k" ] && [ ! -e "$k" ] || exit {Exit.KEY}',
                    f'mkdir -m 0700 -- "$k" || exit {Exit.KEY}',
                    f"trap 'rm -rf -- \"$k\"; rm -f -- {staged} 2>/dev/null' EXIT",
                    f'mkdir -m 0700 -- "$k/gnupg" || exit {Exit.KEY}',
                    f"{_curl(KEY_URL, key_file)} || exit {Exit.DOWNLOAD}",
                    f'{gnupg} --import "$k/key.pgp" >/dev/null 2>&1 || exit {Exit.KEY}',
                    # Exactly one key, whose primary fingerprint is the approved one.
                    (
                        f"[ \"$({gnupg} --with-colons --list-keys | grep -c '^pub:')\" = 1 ] "
                        f"|| exit {Exit.KEY}"
                    ),
                    f"p=$({gnupg} --with-colons --list-keys | {_PRIMARY_AWK})",
                    f'[ "${{p#*:}}" = {FINGERPRINT} ] || exit {Exit.KEY}',
                    f"case $p in r:*|e:*) exit {Exit.KEY};; esac",
                )
            ),
        ),
        site_native.Step(
            "download",
            "; ".join(
                (
                    f"[ -d {DIRECTORY} ] || mkdir -m 0755 -- {DIRECTORY} || exit {Exit.FILE}",
                    f"a {DIRECTORY} || exit {Exit.FILE}",
                    f"[ ! -e {staged} ] && [ ! -L {staged} ] || exit {Exit.FILE}",
                    f"{_curl(PHAR_URL, staged)} || exit {Exit.DOWNLOAD}",
                    f"{_curl(SIGNATURE_URL, signature_file)} || exit {Exit.DOWNLOAD}",
                )
            ),
        ),
        site_native.Step(
            "verify",
            "; ".join(
                (
                    (
                        f"{gnupg} --status-file {status_file} --verify {signature_file} "
                        f"{staged} >/dev/null 2>&1 || exit {Exit.SIGNATURE}"
                    ),
                    (
                        "grep -qE '^\\[GNUPG:\\] "
                        "(KEYREVOKED|REVKEYSIG|EXPKEYSIG|EXPSIG|BADSIG|ERRSIG)' "
                        f"{status_file} && exit {Exit.SIGNATURE}"
                    ),
                    (
                        # The actual signer must be the approved primary or one of the
                        # bound subkeys of the one key this run's keyring holds.
                        f"s=$({gnupg} --with-colons --list-keys | {_BOUND_AWK} | grep -xF "
                        f'"$({_SIGNER_AWK} {status_file})")'
                    ),
                    f'[ -n "$s" ] || exit {Exit.SIGNATURE}',
                    (
                        f"[ \"$(sha256sum <{staged} | cut -d' ' -f1)\" = {SHA256} ] "
                        f"|| exit {Exit.SIGNATURE}"
                    ),
                )
            ),
        ),
        site_native.Step(
            "install",
            "; ".join(
                (
                    f"a {DIRECTORY} || exit {Exit.FILE}",
                    f"[ ! -e {PHAR} ] && [ ! -L {PHAR} ] || exit {Exit.FILE}",
                    f"chown root:root -- {staged} || exit {Exit.FILE}",
                    f"chmod 0644 -- {staged} || exit {Exit.FILE}",
                    f"ln -T -- {staged} {PHAR} || exit {Exit.FILE}",
                    f"sync -- {PHAR}",
                    f"rm -f -- {staged}",
                )
            ),
        ),
        site_native.Step(
            "check",
            "; ".join(
                (
                    (
                        f"[ \"$(stat -c '%F %U %G %a' -- {PHAR})\" = "
                        f"'regular file root root 644' ] "
                        f"|| exit {bootstrap_native.Exit.VALIDATION_FAILED}"
                    ),
                    (
                        f"[ \"$(sha256sum <{PHAR} | cut -d' ' -f1)\" = {SHA256} ] "
                        f"|| exit {bootstrap_native.Exit.VALIDATION_FAILED}"
                    ),
                    f'echo "barectl-wpcli: verified {VERSION} signed by $s"; exit 0',
                )
            ),
        ),
    ]


def setup_payload(unit: str, boot_id: str, deadline: int, **reviewed: object) -> str:
    steps = setup_steps(unit, boot_id, deadline, **reviewed)  # type: ignore[arg-type]
    return "; ".join(step.text for step in steps)
