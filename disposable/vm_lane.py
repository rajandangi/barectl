"""Run the ``vm``-tagged tests against a booted cloud image (docs/quality.md).

The lane boots the pinned Ubuntu cloud image with :mod:`disposable.vm`, exports the same
``BARECTL_SSH_TEST_*`` contract the native scenarios use, runs ``manage.py test --tag vm``,
and always tears the guest down. It is scheduled and dispatchable, never part of the merge
build, and can run locally on a host with QEMU.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from . import vm

REPOSITORY = Path(__file__).resolve().parent.parent
TEST_MODULE = "disposable.test_vm_lane"
VM_TAG = "vm"


def arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="vm_lane", description=__doc__.splitlines()[0])
    parser.add_argument(
        "labels",
        nargs="*",
        default=[TEST_MODULE],
        help="test labels to run inside the lane",
    )
    parser.add_argument("--keep", action="store_true", help="keep the work directory and logs")
    parser.add_argument("--image", type=Path, help="use this base image instead of the pin")
    parser.add_argument("--arch", choices=("amd64", "arm64"), help="guest architecture")
    parser.add_argument("--ssh-port", type=int, default=0, help="host SSH port (default: free)")
    parser.add_argument("--seed-port", type=int, default=0, help="NoCloud seed port")
    parser.add_argument("--mirror-port", type=int, default=0, help="local mirror HTTPS port")
    parser.add_argument("--work-dir", type=Path, help="work directory (default: temporary)")
    parser.add_argument("--timeout", type=float, default=vm.BOOT_TIMEOUT, metavar="SECONDS")
    parser.add_argument("--tag", default=VM_TAG, help="test tag to run")
    parser.add_argument(
        "--boot-only",
        action="store_true",
        help="boot once and print diagnostics without running the vm tests",
    )
    options = parser.parse_args(sys.argv[1:] if argv is None else argv)
    if options.timeout <= 0:
        parser.error("--timeout must be positive")
    return options


def environment(machine: vm.Vm) -> dict[str, str]:
    return os.environ | {
        "BARECTL_SSH_TEST_HOST": "127.0.0.1",
        "BARECTL_SSH_TEST_PORT": str(machine.ssh_port),
        "BARECTL_SSH_TEST_USER": vm.SSH_USER,
        "BARECTL_SSH_TEST_KEY": str(machine.key),
        "BARECTL_SSH_TEST_KNOWN_HOSTS": str(machine.known_hosts),
        "BARECTL_SSH_TEST_CONTAINER": "",
        "BARECTL_SCENARIO_PREFIX": "vm",
        "BARECTL_SCENARIO_RECORD": "",
        "BARECTL_SCENARIO_ARCH": "aarch64" if machine.architecture == "arm64" else "x86_64",
        "BARECTL_SCENARIO_RELEASE": vm.RELEASE,
        "BARECTL_VM_LANE": "1",
    }


def main(argv: Sequence[str] | None = None, output: TextIO | None = None) -> int:
    options = arguments(argv)
    stream = output or sys.stdout
    work = options.work_dir or Path(tempfile.mkdtemp(prefix="barectl-vm-"))
    work.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    machine: vm.Vm | None = None
    status = 1
    try:
        machine = vm.Vm.boot(
            work=work,
            image=options.image,
            architecture=options.arch,
            ssh_port=options.ssh_port,
            seed_port=options.seed_port,
            mirror_port=options.mirror_port,
            output=stream,
            timeout=options.timeout,
        )
        env = environment(machine)
        (work / "environment.json").write_text(
            json.dumps(
                {
                    key: value
                    for key, value in env.items()
                    if key.startswith(("BARECTL_SSH_TEST_", "BARECTL_SCENARIO_", "BARECTL_VM"))
                },
                indent=1,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        if options.boot_only:
            _diagnostics(machine, stream)
            status = 0
            return status
        command = [
            sys.executable,
            "manage.py",
            "test",
            "--tag",
            options.tag,
            "--verbosity",
            "2",
            "--durations",
            "10",
            *options.labels,
        ]
        log = work / "logs" / "tests.log"
        with log.open("wb") as destination:
            completed = subprocess.run(  # noqa: S603 - this repository's own test command
                command,
                cwd=REPOSITORY,
                env=env,
                stdout=destination,
                stderr=subprocess.STDOUT,
                check=False,
            )
        status = completed.returncode
        elapsed = time.monotonic() - started
        stream.write(f"vm: tests finished in {elapsed:.0f} s with exit {status}\n")
        if status != 0:
            stream.write(_tail(log))
        stream.flush()
        return status
    except vm.VmError as error:
        stream.write(f"vm: {error}\n")
        stream.flush()
        return 1
    finally:
        if machine is not None:
            machine.stop()
        try:
            vm.keep_logs(work, stream)
        except OSError as error:
            stream.write(f"vm: could not keep logs: {error}\n")
        if status == 0 and not (options.keep or options.boot_only):
            shutil.rmtree(work, ignore_errors=True)
        else:
            stream.write(f"vm: kept the work directory at {work}\n")
        stream.flush()


_DIAGNOSTICS = (
    ("cloud-init", "cloud-init status --long 2>&1 || true"),
    ("listeners", "ss -Hlnptu"),
    ("failed units", "systemctl --failed --no-pager 2>&1 || true"),
    ("addresses", "ip -br addr"),
    ("hosts", "cat /etc/hosts"),
    ("journal", "journalctl --no-pager -n 100 2>&1 || true"),
)


def _diagnostics(machine: vm.Vm, output: TextIO) -> None:
    for label, command in _DIAGNOSTICS:
        code, stdout, stderr = machine.run(command, timeout=120)
        output.write(f"### {label} (exit {code})\n{stdout}{stderr}\n")
    output.flush()


def _tail(path: Path, lines: int = 80) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return "\n".join(text.splitlines()[-lines:]) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
