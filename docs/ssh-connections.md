# SSH connections and discovery

Barectl connects to a managed server only from its discovery worker, using the SSH alias the server was registered with (`docs/ssh-aliases.md`). Credentials, connection settings and host trust stay on the controller host. Barectl reads them and never writes SSH configuration, known_hosts files or key files.

## Workflow

1. Registering a server, choosing a new alias for it, or pressing **Verify connection**, **Refresh observations** or **Retry connection check** queues a discovery attempt. The request returns immediately; it does not connect.
2. The worker claims the attempt and marks it running. It reads the SSH configuration again and resolves the alias.
3. It connects, verifies the server's host key against the controller's known_hosts files, then authenticates.
4. It reads the operating system release, architecture, CPU count, memory and root filesystem capacity and publishes a snapshot and the attempt's outcome in one transaction. A successful refresh replaces the current snapshot; earlier attempts remain as history.

The server page polls while an attempt is queued or running and announces changes in a live region. **Verify connection** appears before the first check, **Refresh observations** after a success, and **Retry connection check** after a failure or interruption.

Attempts are stored separately from registrations and snapshots, with the states queued, running, succeeded and failed. The database allows one queued or running attempt per server, so repeated or concurrent requests share the active attempt. A failed or interrupted attempt does not remove earlier snapshots; the page shows the latest attempt and the latest snapshot separately, each with its alias and time, and notes that the snapshot may be out of date. The alias cannot be changed while an attempt is active. Forcing the worker to stop mid-task marks its attempt as interrupted. An attempt abandoned any other way, such as by killing the worker, is recovered as interrupted once it has been active for ten minutes; viewing the server list or page, polling, requesting a check and the worker's next task all perform this recovery. Recovery keeps any previous snapshot, and the operator retries manually. Finishing filters on still-running attempts, so a stale worker cannot overwrite the recovery or a newer result. There is no automatic retry, scheduled discovery or live monitoring.

## Running the worker

The worker is a separate process from the same application, using the Django tasks framework with the database backend from `django-tasks-db`. Queued work is stored in the application database and survives the request that created it.

```bash
uv run --env-file .env python manage.py db_worker
```

Run it as the controller account whose SSH configuration, keys and agent Barectl should use. If authentication relies on an agent, start the worker with that agent's `SSH_AUTH_SOCK`. Without a running worker, attempts stay queued and the server page says so.

## Host trust

Barectl reads the files named by the alias's `UserKnownHostsFile`, or `~/.ssh/known_hosts` and `~/.ssh/known_hosts2`. Missing files are ignored. The host name looked up is the resolved `HostName`, written as `[host]:port` when the port is not 22, as OpenSSH records it.

- Supported: plain and hashed host names, several key types per host, and `@revoked` lines. A revoked key is refused for every host, even when another line lists it.
- A key that is not listed is **unknown**: the connection is refused before authentication and the key is not recorded.
- A listed host that presents a different key is **changed**: the connection is refused before authentication.
- Not supported, so such servers are treated as unknown: `@cert-authority` host certificates, host patterns with wildcards or negation, `GlobalKnownHostsFile` and `/etc/ssh/ssh_known_hosts`, and `CheckHostIP`.
- `StrictHostKeyChecking` is ignored. Barectl always refuses unknown and changed keys and offers no bypass.

Establish trust outside Barectl, for example by comparing the key fingerprint with one obtained from the server's console or provider, then adding it to known_hosts on the controller host.

## Authentication

Barectl uses only public-key authentication, with no password or keyboard-interactive prompts.

- Keys in the SSH agent named by the worker's `SSH_AUTH_SOCK`.
- The alias's `IdentityFile` keys, or when it names none, the default `~/.ssh/id_rsa`, `~/.ssh/id_ecdsa` and `~/.ssh/id_ed25519`.
- A key file with a passphrase works only when the key is loaded in the agent. Barectl never asks for or stores a passphrase.
- The user is the alias's `User`, or the worker account's name.

An alias that uses any of these settings is not offered for registration, and a registered alias that gains one is refused when connecting, because Barectl's connection does not implement them: `ProxyJump`, `ProxyCommand`, `HostKeyAlias`, `IdentityAgent`, `IdentitiesOnly yes`, `CertificateFile`, `PKCS11Provider` and `SecurityKeyProvider`. Values that select OpenSSH's default behavior, such as `ProxyJump none`, are accepted. `UserKnownHostsFile` paths must not contain `%` tokens. Hardware-backed keys have not been verified.

## Bounds and read-only commands

Connecting, the SSH handshake and authentication each time out after 10 seconds, and each command must finish within 15 seconds, however steadily it writes output. Command output is read up to 64 KiB. Commands run without a terminal, environment variables or `sudo`, with the SSH user's own permissions. Discovery installs nothing and writes nothing on the server.

The operating system observation runs `cat /etc/os-release`, falling back to `/usr/lib/os-release` as the [os-release specification](https://www.freedesktop.org/software/systemd/man/latest/os-release.html) describes. When `cat` fails, `test -e` and `test -r` distinguish a missing file from an unreadable one, whatever the server's language. Only `PRETTY_NAME`, `NAME`, `ID` and `VERSION_ID` are kept, unquoted with Python's `shlex` and length-limited. The snapshot records the file read and the collection time.

Capacity observations use the same bounds and permissions:

- `uname -m` reports the machine hardware name, such as `x86_64` ([uname invocation](https://www.gnu.org/software/coreutils/manual/html_node/uname-invocation.html)).
- `nproc` reports the available processing units ([nproc invocation](https://www.gnu.org/software/coreutils/manual/html_node/nproc-invocation.html)).
- `cat /proc/meminfo` reports memory; only `MemTotal` in `kB` is kept and stored in bytes ([proc filesystem](https://docs.kernel.org/filesystems/proc.html)). When `cat` fails, `test -e` and `test -r` distinguish a missing file from an unreadable one.
- `df -B1 --output=size,avail,target /` reports the root filesystem in bytes; only its size and available space are kept ([df invocation](https://www.gnu.org/software/coreutils/manual/html_node/df-invocation.html)).

No new dependencies were selected for these observations. They rely on the Linux proc filesystem, GNU coreutils (`nproc`, `df`), and the standard `uname` interface already present on supported Ubuntu servers, within the existing paramiko transport. These are maintainer documentation sources, not Django endorsements. The snapshot records each observation's source, collection time, and explicit units; memory and filesystem sizes are stored in bytes and shown with human-readable units plus byte counts. Command failures, including permission failures for `uname`, `nproc` and `df`, are reported as unsupported with a warning, while file-based observations distinguish inaccessible files; no missing observation is stored as zero.

| Outcome | Meaning |
| --- | --- |
| Observed | The command or file reported the observation in a supported format. |
| Inaccessible | The file exists but the SSH user cannot read it. |
| Absent | The expected file does not exist. |
| Unsupported | The command could not be read or did not report a supported format. |

A completed attempt with an inaccessible, absent or unsupported observation still succeeds; the snapshot shows the warning. Missing observations never appear as zero values.

## Failures and logs

Failures are shown as fixed explanations that name the alias and the next step. They never include exception text, remote output, host names, user names or key paths. An unexpected error is recorded as such, and the worker log names only its type. paramiko's own logging is limited to critical messages because it can quote server-supplied data.

## Components

| Component | Version | Source consulted |
| --- | --- | --- |
| Django tasks framework | Django 6.1.1 | [Background tasks](https://docs.djangoproject.com/en/6.1/topics/tasks/) |
| `django-tasks-db` | 0.13.0 | [README](https://github.com/RealOrangeOne/django-tasks-db), [CI matrix](https://github.com/RealOrangeOne/django-tasks-db/blob/master/.github/workflows/ci.yml), [Django community ecosystem](https://www.djangoproject.com/community/ecosystem/) |
| `paramiko` | 5.0.0 | [SSHClient](https://docs.paramiko.org/en/stable/api/client.html), [host keys](https://docs.paramiko.org/en/stable/api/keys.html#module-paramiko.hostkeys), [agent](https://docs.paramiko.org/en/stable/api/agent.html) |

Django's own task backends are for development and testing; the documentation directs production use to third-party backends. `django-tasks-db` is listed in Django's community ecosystem, not endorsed by Django. The selection and the transport decision are recorded in [#4](https://github.com/rajandangi/barectl/issues/4#issuecomment-5845273176).

## Acceptance against a real server

`discovery/test_remote.py` registers a server and runs the worker against a disposable Ubuntu 24.04 server. It checks a trusted connection with a key file and with an agent, rejection of unknown and changed host keys, and that `/etc`, the SSH user's home directory and the package database are unchanged. The tests are tagged `ssh` and skip unless these variables are set: `BARECTL_SSH_TEST_HOST`, `BARECTL_SSH_TEST_PORT`, `BARECTL_SSH_TEST_USER`, `BARECTL_SSH_TEST_KEY` (a key file without a passphrase) and `BARECTL_SSH_TEST_KNOWN_HOSTS`.

One way to create the server locally with Docker, from an empty directory:

```bash
ssh-keygen -q -t ed25519 -N "" -f id
cat > Dockerfile <<'EOF'
FROM ubuntu:24.04
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd \
 && useradd --create-home --shell /bin/bash deploy \
 && install -d -m 700 -o deploy -g deploy /home/deploy/.ssh
COPY --chown=deploy:deploy --chmod=600 id.pub /home/deploy/.ssh/authorized_keys
CMD ["/usr/sbin/sshd", "-D", "-e"]
EOF
docker build -t barectl-ubuntu-ssh .
docker run -d --rm --name barectl-ssh -p 127.0.0.1:2222:22 barectl-ubuntu-ssh
echo "[127.0.0.1]:2222 $(docker exec barectl-ssh cut -d' ' -f1-2 /etc/ssh/ssh_host_ed25519_key.pub)" > known_hosts
```

The host key is read through `docker exec`, a trusted channel, rather than by scanning the network. Then, from the Barectl repository:

```bash
BARECTL_SSH_TEST_HOST=127.0.0.1 BARECTL_SSH_TEST_PORT=2222 BARECTL_SSH_TEST_USER=deploy \
BARECTL_SSH_TEST_KEY=/path/to/id BARECTL_SSH_TEST_KNOWN_HOSTS=/path/to/known_hosts \
uv run --env-file .env python manage.py test --tag ssh
```

Routine tests do not need a server. `discovery/tests.py` runs the request, worker and persistence workflow with remote execution substituted, and `discovery/test_ssh.py` exercises host-key checks, authentication, agents and error handling against an in-process SSH server.
