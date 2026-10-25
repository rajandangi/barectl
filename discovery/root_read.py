"""Bounded target-stack reads using the existing native privilege adapter."""

from operations import native

from .ssh import CommandResult, RemoteShell


def run_root(shell: RemoteShell, command: str) -> CommandResult:
    """Authorize this exact fixed read without prompting or changing SSH integration."""
    root = native.is_root(shell)
    if root is True:
        return shell.run(command)
    if root is None:
        return CommandResult(1, "")
    argv = ["/usr/bin/sh", "-c", command]
    authorized = shell.run(native.authorization(argv))
    # ``sudo -l`` echoes the whole command. A long fixed read can exceed the SSH answer
    # bound, but the probe runs nothing: the exit status is the answer, and truncation of
    # the echoed command does not change it.
    if authorized.exit_status != 0:
        return CommandResult(1, "")
    return shell.run(native.privileged(argv, root=False))
