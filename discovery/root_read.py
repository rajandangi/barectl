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
    if authorized.exit_status != 0 or authorized.truncated:
        return CommandResult(1, "")
    return shell.run(native.privileged(argv, root=False))
