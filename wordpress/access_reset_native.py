"""Explicit browser recovery.

docs/adr/0026-encrypt-wordpress-first-access-for-the-requesting-browser.md
"""

import hashlib
import re
import shlex
from dataclasses import dataclass

from bootstrap import native as bootstrap_native
from sites import native as site_native

from . import convention, execution, first_access, inputs, inspection_native
from .access_reset_models import AccessReview

COMMAND_SECONDS = 120
COMMAND_FAILED = 71
_DIGEST = re.compile(r"[0-9a-f]{64}")
_ROLE = 'a:1:{s:13:"administrator";b:1;}'
_ACCOUNT_FORMAT = r'%s {"account_digest":"%s"}\n'


@dataclass(frozen=True)
class Account:
    account_id: int
    login: str
    email: str
    first_name: str
    password_digest: str
    digest: str

    def identity(self) -> tuple[int, str, str, str]:
        return self.account_id, self.login, self.email, self.first_name


def account_script(identifier: str, login: str) -> str:
    if not convention.IDENTIFIER.fullmatch(identifier) or not inputs.LOGIN.fullmatch(login):
        raise ValueError("Not a supported site or exact administrator login.")
    database = f"s{identifier}"
    query = (
        "SELECT u.ID, HEX(LEFT(u.user_login,61)), HEX(LEFT(u.user_email,101)), "  # noqa: S608 - strict identifier and hex-encoded validated login
        "HEX(LEFT(c.meta_value,256)), SHA2(u.user_pass,256), "
        "IF(f.umeta_id IS NULL,'-',HEX(LEFT(f.meta_value,101))) "
        f"FROM {database}.wp_users u "
        f"JOIN {database}.wp_usermeta c ON c.user_id=u.ID AND c.meta_key='wp_capabilities' "
        f"LEFT JOIN {database}.wp_usermeta f ON f.user_id=u.ID AND f.meta_key='first_name' "
        f"WHERE BINARY u.user_login=0x{login.encode().hex()} ORDER BY u.ID LIMIT 2"
    )
    return (
        f"export LC_ALL=C PATH=/usr/sbin:/usr/bin; {convention.MARIADB_CLIENT} {shlex.quote(query)}"
    )


def account_argv(identifier: str, login: str) -> list[str]:
    return site_native.script(account_script(identifier, login))


def parse_account(text: str, login: str) -> Account:
    lines = text.splitlines()
    if len(lines) != 1 or len(text) > 2048:
        raise ValueError("The exact administrator account is absent or ambiguous.")
    values = lines[0].split("\t")
    if len(values) != 6 or not re.fullmatch(r"[1-9][0-9]{0,18}", values[0]):
        raise ValueError("The account evidence is not in its expected form.")
    if int(values[0]) > 2**63 - 1 or any(
        not re.fullmatch(r"(?:[0-9A-F]{2})*", value)
        for value in (*values[1:4], *((values[5],) if values[5] != "-" else ()))
    ):
        raise ValueError("The account metadata is not canonical native evidence.")
    try:
        found_login, email, role = [bytes.fromhex(value).decode("utf-8") for value in values[1:4]]
        name = "" if values[5] == "-" else bytes.fromhex(values[5]).decode("utf-8")
    except ValueError, UnicodeDecodeError:
        raise ValueError("The account metadata is unreadable.") from None
    if (
        not inputs.LOGIN.fullmatch(login)
        or found_login != login
        or len(email) > inputs.MAX_EMAIL
        or not inputs.EMAIL.fullmatch(email)
        or role != _ROLE
        or not _DIGEST.fullmatch(values[4])
        or len(name) > 100
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
    ):
        raise ValueError("The account is not one exact supported administrator.")
    return Account(
        int(values[0]),
        found_login,
        email,
        name,
        values[4],
        hashlib.sha256(text.encode()).hexdigest(),
    )


def body(row: AccessReview, evidence: inspection_native.Evidence) -> str:
    evidence.checked()
    if (row.site_digest, row.wpcli_digest, row.state_digest) != (
        evidence.site,
        evidence.wpcli,
        evidence.state,
    ):
        raise ValueError("The retained native bindings differ from the reviewed evidence.")
    target = inspection_native.target_of(row)
    first_access.validate_key(row.first_access_spki)
    if row.account_id <= 0 or not _DIGEST.fullmatch(row.account_digest):
        raise ValueError("The administrator review is incomplete.")
    query = account_script(row.identifier, row.admin_login)
    encrypted = first_access.install_script(row.first_access_spki)
    return "; ".join(
        (
            execution.helpers(target, command_seconds=COMMAND_SECONDS),
            execution.tools(target),
            f"[ -x /usr/bin/openssl ] || exit {execution.Exit.TOOLS}",
            execution.revalidation(
                site=evidence.site,
                wpcli=evidence.wpcli,
                state_script=inspection_native.state_script(row.identifier),
                state=evidence.state,
                target=target,
            ),
            (
                f"[ \"$({query} | sha256sum | cut -d' ' -f1)\" = {row.account_digest} ] "
                f"|| exit {execution.Exit.DRIFT}"
            ),
            (
                f'[ "$(date +%s)" -lt {int(row.first_access_expires_at.timestamp())} ] '
                f"|| exit {bootstrap_native.Exit.EXPIRED}"
            ),
            execution.stage(),
            (
                f"c=$(s /usr/bin/timeout --kill-after=5 {COMMAND_SECONDS} /usr/bin/sh -c "
                f'{shlex.quote(encrypted)} sh "/usr/bin/php$php" "$phar" --no-color '
                f'--skip-packages --skip-plugins --skip-themes "--path=$pub" "--url=$url" '
                f"user update {row.account_id} --prompt=user_pass --skip-email) "
                f"|| exit {COMMAND_FAILED}"
            ),
            f'[ "${{#c}}" -eq 684 ] || exit {execution.Exit.PROJECTION}',
            f'case "$c" in *[!A-Za-z0-9+/=]*) exit {execution.Exit.PROJECTION};; esac',
            f"a=$({query} | sha256sum | cut -d' ' -f1)",
            f'[ "${{#a}}" -eq 64 ] || exit {execution.Exit.PROJECTION}',
            f'case "$a" in *[!0-9a-f]*) exit {execution.Exit.PROJECTION};; esac',
            f'printf {shlex.quote(_ACCOUNT_FORMAT)} {execution.RECORD_MARKER} "$a"',
            (
                f'printf "%s %s %s\\n" {first_access.MARKER} '
                f'{first_access.key_digest(row.first_access_spki)} "$c"'
            ),
            "unset c",
        )
    )
