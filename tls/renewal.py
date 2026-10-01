"""The guarded renewal's files, exactly as setup publishes them (docs/site-conventions.md).

The wrapper takes the mutation lock with the apply payloads' own steps
(``bootstrap.native.lock_steps``), so the two cannot drift apart.
"""

import hashlib
from dataclasses import dataclass
from enum import IntEnum
from typing import Final

from bootstrap import native as bootstrap_native
from bootstrap.profiles import CERTBOT_DROP_IN

from .models import RenewalFile as RenewalFileRecord

Role = RenewalFileRecord.Role

WRAPPER: Final = "/usr/local/sbin/barectl-certbot-renew"
DEPLOY_HOOK: Final = "/usr/local/sbin/barectl-certbot-deploy"
DROP_IN: Final = CERTBOT_DROP_IN
DROP_IN_DIRECTORY: Final = CERTBOT_DROP_IN.rpartition("/")[0]
SOURCE: Final = (
    "https://github.com/rajandangi/barectl/blob/main/docs/site-conventions.md#guarded-renewal"
)
# The packaged timer's schedule, the same on both releases (docs/tls.md#certbot-renewal-setup).
TIMER_CALENDAR: Final = "*-*-* 00,12:00:00"
TIMER_RANDOMIZED_DELAY: Final = "12h"


class Outcome(IntEnum):
    """docs/tls.md#renewal-outcomes: certbot.service's exit statuses besides Certbot's own."""

    UNSAFE_LOCK = 71
    LOCK_HELD = 75
    APPLY_ACTIVE = 76
    NOT_DEPLOYED = 80


# For each lineage that renewed: the certificate Nginx serves on 127.0.0.1:443 for each of
# its names must be the one on disk; the system trust store validates the chain.
_VERIFY = (
    "import hashlib,socket,ssl,sys,time\n"
    "from cryptography import x509\n"
    "from cryptography.hazmat.primitives.serialization import Encoding\n"
    "ok=True\n"
    "for d in sys.argv[1:]:\n"
    '    c=x509.load_pem_x509_certificate(open(d+"/cert.pem","rb").read())\n'
    "    want=hashlib.sha256(c.public_bytes(Encoding.DER)).hexdigest()\n"
    "    names=c.extensions.get_extension_for_class(x509.SubjectAlternativeName)"
    ".value.get_values_for_type(x509.DNSName)\n"
    "    end=time.monotonic()+10\n"
    "    while True:\n"
    "        good=bool(names)\n"
    "        for n in names:\n"
    "            try:\n"
    '                with socket.create_connection(("127.0.0.1",443),5) as s:\n'
    "                    with ssl.create_default_context().wrap_socket(s,server_hostname=n) as t:\n"
    "                        good=good and hashlib.sha256(t.getpeercert(True)).hexdigest()==want\n"
    "            except OSError:\n"
    "                good=False\n"
    "        if good or time.monotonic()>end:\n"
    "            break\n"
    "        time.sleep(1)\n"
    '    print("barectl-renew: %s %s"%("deployed" if good else "not deployed",d))\n'
    "    ok=ok and good\n"
    "sys.exit(0 if ok else 1)\n"
)


def wrapper() -> str:
    lock = bootstrap_native.lock_steps(
        f"{{ echo 'barectl-renew: unsafe lock'; exit {Outcome.UNSAFE_LOCK}; }}",
        (
            "{ echo 'barectl-renew: skipped: another change holds the mutation lock'; "
            f"exit {Outcome.LOCK_HELD}; }}"
        ),
    )
    lines = [
        "#!/bin/sh",
        f"# Barectl guarded Certbot renewal: {SOURCE}",
        lock[0] + " PATH=/usr/sbin:/usr/bin",
        *lock[1:],
        (
            f"for e in /sys/fs/cgroup/system.slice/{bootstrap_native.UNIT_PREFIX}*.service/"
            "cgroup.events; do"
        ),
        '\t[ -e "$e" ] || continue',
        (
            '\tgrep -qx \'populated 1\' "$e" && { echo "barectl-renew: skipped: '
            f'${{e%/cgroup.events}} has processes"; exit {Outcome.APPLY_ACTIVE}; }}'
        ),
        "done",
        (
            'live() { for c in /etc/letsencrypt/live/*/cert.pem; do [ -L "$c" ] && '
            'printf \'%s %s\\n\' "${c%/cert.pem}" "$(readlink -- "$c")"; done; }'
        ),
        "b=$(live)",
        (
            "certbot -q renew --no-random-sleep-on-renew --no-directory-hooks "
            f"--deploy-hook {DEPLOY_HOOK}"
        ),
        "s=$?",
        "a=$(live)",
        "n=$(printf '%s\\n' \"$a\" | grep -vxF -e \"$b\" | cut -d' ' -f1)",
        '[ -n "$n" ] || exit "$s"',
        f"python3 -I -c '{_VERIFY}' $n || exit {Outcome.NOT_DEPLOYED}",
        'exit "$s"',
    ]
    return "\n".join(lines) + "\n"


def deploy_hook() -> str:
    return (
        "#!/bin/sh\n"
        f"# Barectl deploy hook, run under barectl-certbot-renew's mutation lock: {SOURCE}\n"
        "export LC_ALL=C PATH=/usr/sbin:/usr/bin\n"
        # Certbot keeps a hook's output in its own log; the journal gets it too.
        'f() { logger -t barectl-deploy -- "$1; $RENEWED_LINEAGE not deployed"; exit 1; }\n'
        'nginx -t -q || f "barectl-deploy: nginx -t refused the configuration"\n'
        'systemctl reload nginx.service || f "barectl-deploy: reloading nginx failed"\n'
    )


def drop_in() -> str:
    return (
        f"# Barectl guarded Certbot renewal: {SOURCE}\n"
        "[Service]\n"
        "ExecStart=\n"
        f"ExecStart=/usr/bin/sh {WRAPPER}\n"
        f"SuccessExitStatus={Outcome.LOCK_HELD} {Outcome.APPLY_ACTIVE}\n"
        "TimeoutStartSec=30min\n"
        "TimeoutStopSec=60\n"
        "KillMode=control-group\n"
    )


@dataclass(frozen=True)
class RenewalFile:
    role: str
    path: str
    mode: str
    content: str

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.content.encode()).hexdigest()

    @property
    def directory(self) -> str:
        return self.path.rpartition("/")[0]

    @property
    def name(self) -> str:
        return self.path.rpartition("/")[2]


def files() -> tuple[RenewalFile, ...]:
    """In publication order: the drop-in names the wrapper, which runs the hook."""
    return (
        RenewalFile(Role.DEPLOY_HOOK, DEPLOY_HOOK, "0755", deploy_hook()),
        RenewalFile(Role.RENEW_WRAPPER, WRAPPER, "0755", wrapper()),
        RenewalFile(Role.DROP_IN, DROP_IN, "0644", drop_in()),
    )
