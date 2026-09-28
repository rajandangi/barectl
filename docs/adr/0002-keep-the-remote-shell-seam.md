# Keep the remote shell as the discovery seam

Collectors reach a managed server through `RemoteShell.run(command)` in `discovery/ssh.py`, and decide observation outcomes themselves from the exit status and output of fixed read-only commands: whether a path is missing or hidden by a directory the SSH user cannot search, whether a file is unreadable, and whether a command is missing or cannot run. Barectl keeps that seam rather than a deeper probe interface that would return already classified file reads and listings. The seam has several implementations: pyinfra's SSH connector in production, `FakeServer` for the discovery tests, an in-process SSH server running the local shell for transport and worker tests, and a disposable Ubuntu server for acceptance. Keeping classification in the collectors keeps it within reach of the discovery tests.

`FakeServer` emulates the probe commands the collectors run (`test`, `cat` and `ls`) over a small described filesystem. `discovery/test_fake_server.py` builds each described filesystem both as a `FakeServer` and as a real directory tree and requires the same success and output from both, using GNU coreutils as the supported Debian and Ubuntu servers do.

## Consequences

- A change to a probe command, or a new one, is emulated in `FakeServer` and covered by a scenario in the contract test.
- Fixed commands such as `dpkg-query` and `systemctl show` are replayed from recorded results, not emulated, so the contract test does not cover them; the acceptance tests against a disposable server do.
- The contract test skips where `ls` is not GNU ls, and skips its permission scenarios when run as root.
