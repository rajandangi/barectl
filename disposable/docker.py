"""The Docker CLI as the native harness drives it (docs/quality.md#native-layer)."""

import subprocess


class DockerError(Exception):
    """A Docker command the harness needs could not be completed."""


def docker(*arguments: str, timeout: float = 300, stdin: str | None = None) -> str:
    try:
        completed = subprocess.run(  # noqa: S603 - the harness's own Docker commands
            ["docker", *arguments],  # noqa: S607 - Docker on PATH
            input=stdin,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise DockerError(f"docker {arguments[0]} timed out after {timeout:.0f} s") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise DockerError(f"docker {' '.join(arguments[:2])}: {detail}")
    return completed.stdout


def quietly(*arguments: str) -> None:
    subprocess.run(  # noqa: S603 - the harness's own Docker commands
        ["docker", *arguments],  # noqa: S607 - Docker on PATH
        capture_output=True,
        timeout=120,
        check=False,
    )
