"""Relay one QEMU guestfwd connection from stdio to a host TCP service.

docs/quality.md#the-cloud-image-vm-lane. QEMU spawns this command for every TCP connection
the guest makes to the virtual address. Its stdin and stdout are the connection, so the
guest stays on ``restrict=on`` networking and reaches only the services the lane exposes.
"""

import argparse
import contextlib
import os
import select
import signal
import socket
import sys
from collections.abc import Sequence

BUFFER = 64 * 1024


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def _pump(input_fd: int, output_fd: int, upstream: socket.socket) -> None:
    """Copy both directions until either side closes or the idle deadline expires."""
    while True:
        readable, _, _ = select.select([input_fd, upstream], [], [], 300)  # type: ignore[type-var]
        if not readable:
            return
        for source in readable:
            if source == input_fd:
                data = os.read(input_fd, BUFFER)
                if not data:
                    return
                upstream.sendall(data)
            else:
                data = upstream.recv(BUFFER)
                if not data:
                    return
                _write_all(output_fd, data)


def _close(_signal: int, _frame: object) -> None:
    raise SystemExit(0)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--connect", required=True, metavar="HOST:PORT")
    # QEMU may append the guest address and port; they name nothing this proxy needs.
    options, _ = parser.parse_known_args(sys.argv[1:] if argv is None else argv)
    host, _, port = options.connect.rpartition(":")
    if not host or not port.isdigit():
        parser.error("--connect takes HOST:PORT")
    signal.signal(signal.SIGTERM, _close)
    try:
        upstream = socket.create_connection((host, int(port)), timeout=30)
    except OSError as error:
        sys.stderr.write(f"guestfwd: could not reach {options.connect}: {error}\n")
        return 1
    with upstream, contextlib.suppress(OSError):
        _pump(0, 1, upstream)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
