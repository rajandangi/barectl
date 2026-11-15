"""Bounded target-stack reads using the existing native privilege adapter."""

import shlex

from operations import native

from .ssh import MAX_OUTPUT, CommandResult, RemoteShell


def read_command(command: str) -> str:
    """Check fresh identity and authorize the exact read in the same SSH execution."""
    argv = ["/usr/bin/sh", "-c"]
    return (
        f"set -- {shlex.quote(command)}; "
        "barectl_read_uid=$(id -u && printf .) || exit 1; "
        f'[ "${{#barectl_read_uid}}" -le {MAX_OUTPUT + 1} ] || exit 1; '
        "barectl_read_uid=$(printf %s \"${barectl_read_uid%.}\" | tr -d '[:space:]') || exit 1; "
        'if [ "$barectl_read_uid" = 0 ]; then '
        'sh -c "$1"; else '
        f'{native.authorization(argv)} "$1" >/dev/null 2>&1 || exit 1; '
        f'{native.privileged(argv, root=False)} "$1"; fi'
    )


def run_root(shell: RemoteShell, command: str) -> CommandResult:
    """Authorize this exact fixed read without prompting or changing SSH integration."""
    return shell.run(read_command(command))
