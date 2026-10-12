"""Record the transcript of a plain server state (docs/quality.md#recorded-transcripts).

    uv run --env-file .env python -m disposable.record pristine-26.04

The server is built from the pinned base image, a known secret is seeded on it, and
discovery runs through the recording shell as root, the default SSH user.
"""

import argparse
import os
import secrets
import shlex
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from disposable import runner

if TYPE_CHECKING:
    from discovery.recorded import Transcript

# Each plain state and the release whose pinned base image it is built from.
STATES = {"pristine-26.04": "26.04"}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("state", choices=sorted(STATES))
    state = parser.parse_args(argv).state
    runner.setup_django()
    from discovery import recorded

    release = STATES[state]
    image = f"{runner.IMAGE}:recording-{release}"
    pins = recorded.current_pins()
    runner.build_server(
        release, image, "--target", "server", "--build-arg", f"BASE={pins[f'ubuntu-{release}']}"
    )
    with tempfile.TemporaryDirectory() as work:
        server = runner.Server.boot(
            image, network=None, name=f"{runner.IMAGE}-{state}-{secrets.token_hex(4)}"
        )
        try:
            transcript = _record(server, Path(work), state, release, pins)
        finally:
            server.remove()
    path = recorded.TRANSCRIPTS / f"{state}.json"
    path.parent.mkdir(exist_ok=True)
    path.write_text(transcript.dumps(), encoding="utf-8")
    sys.stdout.write(f"Recorded {len(transcript.commands)} commands in {path}\n")
    return 0


def _record(
    server: runner.Server, work: Path, state: str, release: str, pins: dict[str, str]
) -> Transcript:
    from discovery import recorded, ssh
    from discovery.observations import collect
    from servers.ssh_config import ConnectionTarget

    keys = runner.controller_keys(work)
    secret = shlex.quote(recorded.SEEDED_SECRET)
    server.exec(
        f"printf %s {shlex.quote(Path(f'{keys.first}.pub').read_text(encoding='utf-8'))}"
        " >/root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys"
        f" && install -d -m 700 /run/barectl/secrets && printf %s {secret}"
        " >/run/barectl/secrets/seeded"
    )
    known_hosts = work / "known_hosts"
    host_key = server.exec("cut -d' ' -f1-2 /etc/ssh/ssh_host_ed25519_key.pub").strip()
    known_hosts.write_text(f"[127.0.0.1]:{server.port} {host_key}\n", encoding="utf-8")
    target = ConnectionTarget(
        alias=state,
        hostname="127.0.0.1",
        port=server.port,
        user="root",
        identity_files=(keys.first,),
        known_hosts_files=(known_hosts,),
    )
    # Only the generated key is offered, never the developer's agent keys.
    os.environ["SSH_AUTH_SOCK"] = ""
    with ssh.connect(target) as shell:
        recording = recorded.RecordingShell(shell, state, secrets=(recorded.SEEDED_SECRET,))
        collect(recording)
    return recording.transcript(
        pins=pins, release=release, architecture=server.exec("uname -m").strip()
    )


if __name__ == "__main__":
    sys.exit(main())
