# SSH connections and discovery

Barectl connects to a managed server only from its worker, for discovery, for [change preparation](#change-preparation) and for [applying reviewed changes](#applying-reviewed-changes). A server is registered with a [saved connection](saved-server-connections.md), an address, SSH user, port and either this computer's SSH agent or an approved key file, or with an advanced SSH alias from the controller's SSH configuration ([SSH aliases](ssh-aliases.md)). Alias targets keep their supported configuration and also consult the controller-owned trust file, so revocation cannot be bypassed by choosing an alias. Credentials, connection settings and host trust stay on the controller host. Barectl never writes SSH configuration or credential key files. Saved-address fingerprint confirmation writes only the configured Barectl-owned trust file. Alias registration never writes trust.

Discovery attempts and their history belong to this Barectl application database. They are not native server history and are not written to the server. Another device can establish authorized SSH access and rediscover supported configuration with its own database; it cannot recover this installation's private attempt records. Future native history inspection, background server operations, and coordination across devices follow the [architecture requirements](architecture.md#state-and-discovery).

## Workflow

1. Registering a server, choosing a new alias for it, or pressing **Verify connection**, **Refresh observations** or **Retry connection check** queues a discovery attempt. The request returns immediately; it does not connect.
2. The worker claims the attempt and marks it running. It rechecks the captured connection definition, and for an alias resolves the SSH configuration again.
3. It connects, verifies the server's host key against the controller's trust files, then authenticates.
4. It reads the operating system release, architecture, CPU count, memory, root filesystem capacity, the [component observations](#component-observations) and the [host standing](bootstrap.md#host-standing). On a Target stack host it also reads the runtimes, the server defaults and the [sites](#site-observations). It publishes a snapshot and the attempt's outcome in one transaction. A successful refresh replaces the current snapshot; earlier attempts remain as history.

The server page polls while an attempt is queued or running and announces changes in a live region. **Verify connection** appears before the first check, **Refresh observations** after a success, and **Retry connection check** after a failure or interruption.

Attempts are stored separately from registrations and snapshots, with the states queued, running, succeeded and failed. Each attempt is a remote operation of the discovery kind: within one Barectl database, a server has at most one queued, running or reconciling remote operation of any kind, so repeated or concurrent requests share the active attempt, and a check cannot start while a change preparation runs (the page says another remote operation is running and offers the check when it finishes). This constraint does not coordinate independent devices with separate databases. A failed or interrupted attempt does not remove earlier snapshots; the page shows the latest attempt and the latest snapshot separately, each with its alias and time, and notes that the snapshot may be out of date. Every registration edit and removal is refused while any remote operation is active. A connection correction creates an immutable revision and invalidates current verification and reviews immediately; older observations remain labelled history of their original target and revision, excluded from current inventory and actions. A failed correction check retains that correction. Name-only saves queue no SSH work. Edit revisions prevent conflicting forms from overwriting each other. Forcing the worker to stop mid-task marks its attempt as interrupted. An attempt abandoned any other way, such as by killing the worker, is recovered as interrupted once it has been active for ten minutes; every read of attempts performs this recovery first (the server list and page, polling, the Activity page and the removal page), as do requesting a check and the worker's next task. Recovery keeps any previous snapshot, and the operator retries manually. Finishing filters on still-running attempts, so a stale worker cannot overwrite the recovery or a newer result. There is no automatic retry, scheduled discovery or live monitoring.

## Server removal

An operator with the `servers.view_server` and `servers.delete_server` permissions removes a server from its page. **Remove** opens a confirmation page, and only its CSRF-protected **Remove server** button deletes anything.

- Removal deletes the server's registration, its discovery attempts and snapshots, its change preparations and unapplied reviews, and the worker's task records for those operations, all from the Barectl database. Finished runs are kept as audit with the server detached, with their reviews, and stay listed in Activity. The removal page counts change preparations only for accounts that may view changes. A task record that a running worker claimed within the last ten minutes is kept, since that worker saves it when it finishes.
- It never connects to the server and never touches the controller's SSH configuration, keys, agent or known_hosts. The alias can be registered again.
- It is refused while a remote operation of any kind is queued, running or reconciling. Operations protect their server in the database, so a request that queues discovery while removal is in progress makes the removal fail and roll back, and a request that queues discovery after removal finds the server gone. Abandoned attempts are recovered first, so they do not block removal.
- An edit submitted after removal is refused rather than registering the server again.

## Running the worker

The worker is a separate process from the same application, using the Django tasks framework with the database backend from `django-tasks-db`. Queued work is stored in the application database and survives the request that created it. Discovery requires this controller worker and does not continue as a background server job if the controller stops.

```bash
uv run --env-file .env python manage.py db_worker
```

Run it as the controller account whose SSH configuration, keys and agent Barectl should use. If authentication relies on an agent, start the worker with that agent's `SSH_AUTH_SOCK`. Without a running worker, attempts stay queued and the server page says so.

## Host trust

A saved connection is checked against the Barectl-owned trust file named by `BARECTL_SSH_KNOWN_HOSTS`. An alias is checked against that file and the files named by the alias's `UserKnownHostsFile`, or `~/.ssh/known_hosts` and `~/.ssh/known_hosts2`. Missing files are ignored. The host name looked up is the resolved `HostName`, written as `[host]:port` when the port is not 22, as OpenSSH records it.

- Supported: plain and hashed host names, several key types per host, and `@revoked` lines. A revoked key is refused for every host, even when another line lists it.
- A key that is not listed is **unknown**: the connection is refused before authentication and the key is not recorded.
- A listed host that presents a different key is **changed**: the connection is refused before authentication.
- Not supported, so such servers are treated as unknown: `@cert-authority` host certificates, host patterns with wildcards or negation, `GlobalKnownHostsFile` and `/etc/ssh/ssh_known_hosts`, and `CheckHostIP`.
- `StrictHostKeyChecking` is ignored. Barectl always refuses unknown and changed keys and offers no bypass.

For an SSH alias, establish trust outside Barectl by comparing the key fingerprint with the server's console or provider before adding it to a configured trust file.

### Confirming a fresh saved-address host

An unknown host stops the worker check before authentication. Overview shows the captured key type and SHA256 fingerprint. Read the fingerprint independently from the provider console, serial console output, or provider web shell. For example, `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` prints the ED25519 host key fingerprint. Select the host key file for the displayed key type. Copy only its `SHA256:...` fingerprint into **Provider host key fingerprint**, then choose **Confirm fingerprint and check**.

The input must match exactly. A malformed value, another key's fingerprint or surrounding whitespace records nothing. The confirmation requires `servers.view_server`, `servers.change_server` and `discovery.add_discoveryattempt`, a CSRF-protected POST and the current saved connection revision. Browser input cannot supply the endpoint, public key or trust-file path. The failed attempt stores those public key facts and its immutable connection definition.

Confirmation serializes updates with an adjacent controller file lock, rereads trust under that lock and atomically replaces only the Barectl-owned file while preserving unrelated entries. A changed or revoked key refuses confirmation. A matching existing entry needs no write. Registration changes and active operations refuse confirmation. The queued follow-up captures the confirmed public key. At dispatch it rereads current trust and revocations, requires that exact key to remain trusted, and gives the strict connector a private trust copy containing only the confirmed identity for the endpoint. Replacing both the server key and trust-file entry still refuses authentication. Each controller confirms independently. Removing a registration leaves trust untouched.

The fast layer proves this path through real in-process SSH negotiation and Django requests, and the native S1 scenario follows it on a real server.

## Authentication

Barectl uses only public-key authentication, with no password or keyboard-interactive prompts. Saved connections select the controller agent or an [approved key-file reference](saved-server-connections.md#approved-key-files). File mode binds its selected public and file identity and disables agent and default-key search. The following credential rules apply to advanced aliases.

- Keys in the SSH agent named by the worker's `SSH_AUTH_SOCK`.
- The alias's `IdentityFile` keys, or when it names none, the default `~/.ssh/id_rsa`, `~/.ssh/id_ecdsa` and `~/.ssh/id_ed25519`.
- A key file with a passphrase works only when the key is loaded in the agent. Barectl never asks for or stores a passphrase.
- The user is the alias's `User`, or the worker account's name.

An alias that uses any of these settings is not offered for registration, and a registered alias that gains one is refused when connecting, because Barectl's connection does not implement them: `ProxyJump`, `ProxyCommand`, `HostKeyAlias`, `IdentityAgent`, `IdentitiesOnly yes`, `CertificateFile`, `PKCS11Provider` and `SecurityKeyProvider`. Values that select OpenSSH's default behavior, such as `ProxyJump none`, are accepted. `UserKnownHostsFile` paths must not contain `%` tokens. Hardware-backed keys have not been verified.

## Bounds and read-only commands

Connecting, the SSH handshake and authentication each time out after 10 seconds, and each command must finish within 15 seconds, however steadily it writes output. All commands on one connection must finish within 5 minutes, so an attempt ends well before recovery would treat it as abandoned; a longer one fails, keeping any previous snapshot. Command output is read up to 64 KiB. Commands run without a terminal, environment variables or `sudo`, with the SSH user's own permissions. Discovery installs nothing and writes nothing on the server.

A target-stack site observation reads each site's live PHP protection evidence in its own bounded command, because one verification is far below the 15-second limit while several bundled into one command are not. The target-stack site read therefore runs one inventory command for the whole convention and one command per site that has a serving master, and reports a site whose per-site read fails as outside supported settings rather than as healthy.

The target-stack readers of sites, runtimes, server defaults and site runtime selections take the native mutation lock shared and without waiting ([`flock -s -n`](https://raw.githubusercontent.com/util-linux/util-linux/v2.39.3/sys-utils/flock.1.adoc)). A change holds it exclusively, so a read never sees a change half-applied and a change is refused while a read is in progress, but two controllers discovering the same server at once do not refuse each other.

The operating system observation runs `cat /etc/os-release`, falling back to `/usr/lib/os-release` as the [os-release specification](https://www.freedesktop.org/software/systemd/man/latest/os-release.html) describes. When `cat` fails, `test -e` and `test -r` distinguish a missing file from an unreadable one, whatever the server's language. Only `PRETTY_NAME`, `NAME`, `ID` and `VERSION_ID` are kept, unquoted with Python's `shlex` and length-limited. The snapshot records the file read and the collection time.

Capacity observations use the same bounds and permissions:

- `uname -m` reports the machine hardware name, such as `x86_64` ([uname invocation](https://www.gnu.org/software/coreutils/manual/html_node/uname-invocation.html)).
- `nproc` reports the processing units available to the SSH session, which can be fewer than the server has; the page labels them as available ([nproc invocation](https://www.gnu.org/software/coreutils/manual/html_node/nproc-invocation.html)).
- `cat /proc/meminfo` reports memory; only `MemTotal` in `kB` is kept and stored in bytes ([proc filesystem](https://docs.kernel.org/filesystems/proc.html)). When `cat` fails, `test -e` and `test -r` distinguish a missing file from an unreadable one.
- `df -B1 --output=size,avail,target /` reports the root filesystem in bytes; only its size and available space are kept ([df invocation](https://www.gnu.org/software/coreutils/manual/html_node/df-invocation.html)).

Observation outcomes are defined in the [glossary](../GLOSSARY.md). The snapshot records each observation's source and the collection time. A source is the commands or files whose results decided the observation's outcome, in the order they were read; the page shows each one. Memory and filesystem sizes are stored in bytes and shown with human-readable units plus byte counts. A command the shell cannot find (exit status 127) is unsupported and one it cannot run (126) is inaccessible, as the [POSIX shell](https://pubs.opengroup.org/onlinepubs/9799919799/utilities/V3_chap02.html#tag_19_08_02) defines; any other failure is unsupported. A missing inspection command or file is never a finding that something does not exist.

Every server has an operating system, an architecture, CPUs, memory and a root filesystem, so these observations are never absent; the database refuses a snapshot that records one as absent.

| Outcome | Meaning |
| --- | --- |
| Observed | The file or command reported the observation in a supported format. |
| Inaccessible | The file exists but the SSH user cannot read it, or the command exists but the SSH user cannot run it. |
| Unsupported | The file or command does not exist on the server, could not be read, or did not report a supported format. |

A completed attempt with an inaccessible or unsupported observation still succeeds; the snapshot shows the warning. Missing observations never appear as zero values.

## Component observations

For each distribution web-stack component, Nginx, PHP-FPM, MariaDB, PostgreSQL and Certbot, the snapshot records a component observation: the installed package versions from the server's dpkg database and the state of its systemd service units. None of them belongs to the target stack, so on a target-stack server they are normally absent; an installed Nginx or APT PHP makes the host Not manageable ([host standing](bootstrap.md#host-standing)). Each installed package is compared with the release's distribution package names, and a versioned or variant package, PostgreSQL major or cluster outside them is named. Both observations use fixed read-only commands with the SSH user's own permissions: no sudo, no package installation, no service restarts, no configuration writes, and no database credentials or application secrets. The observation commands are bounded by the same timeouts and output limits as every other discovery command.

Versions come from one dpkg database query of those exact package names. On Ubuntu 26.04 it is:

```text
dpkg-query -W -f='${Package} ${Version} ${db:Status-Abbrev}\n' 'certbot' 'mariadb-server' 'mariadb-server-core' 'nginx' 'php8.5-fpm' 'postgresql' 'postgresql-18'
```

A second bounded dpkg inventory query reads only installed names and states to name conflicting variants. It never obtains their versions, queries their units, or reads their configuration. Service states come from one `systemctl show` query per component, reading `Id`, `LoadState`, `ActiveState`, `SubState` and `UnitFileState` for its units. A missing systemd unit is reported as `not found`; a loaded unit is shown as `active (running)`, `inactive (dead)` and so on, with the unit file state such as `enabled` when systemd reports one.

These installation formats and service names are supported, based on the parsers and the transport results recorded from Ubuntu 26.04:

| Component | Installed packages match | Service units queried |
| --- | --- | --- |
| Nginx | `nginx` | `nginx.service` |
| PHP-FPM | The release default profile, `php8.5-fpm` | Only the release default unit, `php8.5-fpm.service` |
| MariaDB | `mariadb-server` and `mariadb-server-core` | `mariadb.service` |
| PostgreSQL | the release default major's packages, `postgresql` and `postgresql-18` | `postgresql.service`, then the release default major's `main` cluster: `postgresql@18-main.service` |
| Certbot | `certbot` | `certbot.timer` |

Behavior on other servers:

- Only dpkg installations are supported. When `dpkg-query` is missing or its output cannot be parsed, every component's package observation is **unsupported**, never absent: Barectl cannot know whether the software is installed. When the SSH user cannot run `dpkg-query` (exit status 126), the observations are **inaccessible**.
- A package counts as installed when its dpkg state is installed: status `ii`, `hi` for a package held with `apt-mark hold`, or either with the `R` reinstall-required flag. Packages that apt merely knows about, such as the `php-fpm` metapackage on a server that installed `php8.5-fpm`, and packages removed with only configuration files left (`rc`) are never reported as installed.
- A matching package in an unfinished dpkg state, such as unpacked (`iU`) or half-configured (`iF`), makes the component's package and service observations **unsupported**: the software may be partly present, so it is neither reported as installed nor as absent.
- Installed packages are compared with the release's exact distribution package names; a versioned or variant package outside them, such as `php8.1-fpm`, is named as a deviation. Its version, unit and configuration are not read. An unsupported release queries the supported release's finite names; that inventory does not qualify the server release.
- When `systemctl` is missing, fails (for example `System has not been booted with systemd`), or reports unknown state tokens, the service observation is **unsupported**, never absent. Querying it requires systemd's D-Bus interface, which stock servers provide and unprivileged accounts may read.
- Units are queried only for components with an installed package. Otherwise the service observation takes the package observation's outcome, with the dpkg query as its source and the same warning: **absent** when no package is installed, and unsupported or inaccessible when the dpkg database cannot be read.
- A missing unit appears as `not found`. A unit whose reported states do not match the supported tokens, or that systemd reports under a name other than the one queried (an alias resolving to another unit), makes the service observation **unsupported** rather than showing invented states.
- PHP-FPM discovery queries only the release-default unit. Other PHP package names are conflict evidence only; their units and pool trees are not inspected.
- PostgreSQL's units are found as the next section describes.

Package and service observations are stored per component with their own outcome, source commands and warnings, and the collection time of the snapshot. A component can report versions while its service state is unsupported, and the other way around. A service observation stores each service unit's name, load state, active state, sub-state and unit-file state as systemd reports them; the page shows them as one line per unit, such as `nginx.service active (running), enabled`.

## PostgreSQL clusters

On Debian and Ubuntu, `postgresql.service` is an umbrella unit. It stays `active (exited)` while the clusters it started run or stop. Each cluster runs as an instance of the `postgresql@.service` template named after its version and cluster name, such as `postgresql@18-main.service`. Barectl supports only the server release's default major and its `main` cluster. When the dpkg database shows PostgreSQL installed, it lists the configuration layout, reports any other major or cluster as not following the profile, and queries the umbrella unit and the release default major's `main` cluster's unit after it, in the same `systemctl show` query, so a stopped cluster appears as `postgresql@18-main.service inactive (dead), enabled-runtime` under an `active (exited)` umbrella. No other major's or cluster's directory is read and no other cluster's unit is queried.

What upstream defines:

- postgresql-common keeps each cluster's configuration in `/etc/postgresql/<version>/<cluster>/`. A cluster is such a directory holding `postgresql.conf`, as an existing file or a dead symlink. Version directories are named like `16` or `9.6`; other entries of `/etc/postgresql` are not versions. The `postgresql-common` package installs `/etc/postgresql` itself ([`PgCommon.pm`](https://salsa.debian.org/postgresql/postgresql-common/-/blob/master/PgCommon.pm), [`postgresql-common.dirs`](https://salsa.debian.org/postgresql/postgresql-common/-/blob/master/debian/postgresql-common.dirs)).
- `pg_createcluster` accepts cluster names made of word characters, `.` and `-`, and advises against `-` because it breaks the template's `%I` path in systemd ([pg_createcluster](https://manpages.debian.org/stable/postgresql-common/pg_createcluster.1.en.html)).
- Its systemd generator adds each cluster whose `start.conf` says `auto` to the umbrella unit's wants, so systemd loads those clusters' units. `manual` and `disabled` clusters are not wanted and stay unloaded until something names them ([`README.systemd`](https://salsa.debian.org/postgresql/postgresql-common/-/blob/master/systemd/README.systemd), [`postgresql-generator`](https://salsa.debian.org/postgresql/postgresql-common/-/blob/master/systemd/system-generators/postgresql-generator)).
- A literal unit name refers to exactly one unit, while a glob such as `postgresql@*` matches only units currently in memory ([systemctl](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html)). On Ubuntu 26.04, `systemctl show` with the name of an unloaded cluster's unit reports it, such as `inactive (dead), disabled` for a `manual` cluster.
- `pg_lsclusters` lists clusters from the same directories, but it skips a directory it cannot open without reporting an error, and its status column reads the cluster's socket and data directory ([pg_lsclusters](https://manpages.debian.org/stable/postgresql-common/pg_lsclusters.1.en.html)).

What Barectl does, with the SSH user's own permissions and no database connection, credentials or data directory access:

```text
ls -1b /etc/postgresql
ls -1bA /etc/postgresql/<release major>
test -e /etc/postgresql/<release major>/main/postgresql.conf
```

Barectl lists the configuration directories itself and does not run `pg_lsclusters`; a directory it cannot read is reported, never treated as empty. It lists `/etc/postgresql` to name other majors and the release default major's directory to name other clusters, but it never lists another major's directory below that. The release default major's directory is listed with `-A`, as postgresql-common reads names starting with `.` too. The `main` cluster's unit is named in the query, loaded or not, as the generator names it: `postgresql@<release major>-main.service`. When `postgresql.conf` is not found, `test -L` accepts a dead symlink. Entries of `/etc/postgresql` not named like a version are ignored, as postgresql-common ignores them. The service observation's source records the listing commands, then the unit query.

Supported cluster names are 1 to 64 ASCII letters, digits, `_`, `.` and `-`. Version directories follow postgresql-common's pattern, at least two digits with an optional dot between them, such as `16` or `9.6`, bounded to four digits on each side of the dot. Other names are never used in a command, a unit name or a warning; unknown cluster names are skipped and counted, and a supported name other than `main`, and every version other than the release default major, is reported as not following the profile.

| Outcome | Meaning |
| --- | --- |
| Observed | `/etc/postgresql` and the release default major's directory were listed and the `main` cluster checked. The umbrella unit and, when `main` exists, its unit are shown. Another major or cluster is reported as a deviation, not scanned. |
| Inaccessible | The SSH user cannot list `/etc/postgresql` or the release default major's directory. The umbrella unit is still shown. |
| Unsupported | `/etc/postgresql` does not exist or a listing could not be read. The umbrella unit is still shown. |

A listing Barectl could not complete is never absent: Barectl cannot tell whether other clusters exist. A cluster whose unit systemd reports as `not found` is shown as `not found`. The cluster unit is checked like every other unit: a record under another name, or in an unsupported format, makes the observation unsupported. When systemd cannot be queried, the observation is unsupported or inaccessible as for other components, and its warning also names the listing problem.

## Site observations

On a Target stack host, discovery reads the [site convention](site-conventions.md) as root, or through noninteractive sudo of each fixed read. It reads every file in `/etc/caddy/sites/` through `caddy adapt` and compares the adapted JSON with the convention rendered for the same identifier and names, then reads each site's accounts, directory metadata, wrappers and links, PHP-FPM and HAProxy configuration, services, HAProxy API state and persisted server state. Then it reads each site's live PHP protection evidence in its own bounded command. On any other standing, sites are reported absent, with the reason that Barectl reads sites only on a Target stack host.

Each site observation carries one state:

| State | Meaning |
| --- | --- |
| Managed | Every convention resource exists and matches, within the [supported settings](site-conventions.md#supported-configuration-grammar). A hand-made site that follows the convention is managed. |
| Partly applied | Every existing resource matches and some are absent. A new review creates only what is missing ([creating a PHP site](sites.md#applying)). |
| Not following the convention | A resource differs from the convention or holds a setting outside the supported ones. The observation names it, and only the changes that depend on it are blocked. |

A site's names, its runtime selection, its Node selection and any incomplete PHP switch are reconstructed from native evidence alone, so a fresh controller with authorized access sees the same sites. Discovery never requests a site over HTTP and never runs application PHP. Site observations are shown only to accounts with `discovery.view_siteobservation`.

## Change preparation

Every change goes through the change engine of [ADR 0035](adr/0035-one-change-engine-with-effect-derived-consent.md). Preparing a change is a remote operation that runs the change kind's fixed reads on the server, as root or through noninteractive sudo of each exact read, and stores one immutable review. Without the privilege a review is refused. Preparation installs nothing, starts or reloads no service and writes nothing outside private scratch directories, which it removes; validators such as `caddy validate` and `php-fpm -t` run against scratch copies. The review is bound to the server's boot ID and a deadline 15 minutes ahead on its uptime clock, and to a digest of the evidence the native body rechecks under the lock.

The worker rechecks, before it connects, that the requesting account is active and still allowed to prepare changes, and that the server's connection revision is the one the request captured.

## Applying reviewed changes

Applying is a remote operation of its own, queued from the review's page, never from a view. The worker rechecks the account, the consent the review needs, the reviewed host key, and that root or sudo authorizes the exact submission. It stages the kind's fixed body as `/run/lock/barectl/body-<32 hex>.sh` and submits it with `systemd-run` as a transient unit, `barectl-apply-<32 hex>.service`, with a 30-minute limit, no restart and its output in the journal ([ADR 0006](adr/0006-use-native-bootstrap-execution.md)). The body takes `/run/lock/barectl/mutation.lock` with `flock -n`, without waiting, then checks the boot, the deadline and the reviewed evidence and refuses on any difference. It prints a `barectl-stage <name>` line per stage and ends with one `barectl-result` line; its exit status is 0 for success, 1 for a refusal before any change, 2 for a partial change, 3 for a failure and 10 when the lock is busy.

systemd unloads the unit when it ends, so the run records its execution outcome from the unit's state while it runs and from its result line in the journal afterwards, then verifies the change with fresh reads. A run succeeds only when both hold. After a verified run that changes what discovery reads, the engine queues discovery. An uncertain submission leaves the run reconciling; **Check outcome** inspects the same unit with a new connection and never submits it again.

### Clearing finished runs

Change runs unload when they end, but a Barectl unit something keeps loaded is retained, and new changes are refused while 100 are retained. The server's **Changes** page prepares **Clear finished barectl runs**: it lists every retained `barectl-apply-*` unit that finished, has no processes and shows an invocation, and leaves the others in place. The review explains that systemd then forgets the units, that journal entries stay as long as the server's retention keeps them, that another controller still establishing one of these runs can then only close it as outcome unknown, and that Barectl's own records are kept. Clearing stays available up to 110 retained units. Under the lock the body refuses the whole cleanup if any listed unit shows another invocation, has not finished or has processes. Discovery never clears anything.

### Durability and its limits

Accepted work survives the controller: closing the browser, losing SSH, stopping the worker or losing the controller and its database leaves the transient unit running under systemd, and Check outcome establishes its outcome later. A server reboot is different: transient units and the lock directory are gone after it, nothing resumes, and a run caught by it can only be closed as outcome unknown. The journal is persistent on a target-stack host but may be rotated or vacuumed; a run whose result line is gone before Barectl read it stays unknown.

## pyinfra connection

Discovery, preparation and apply connect through pyinfra's SSH connector. Barectl uses pyinfra for SSH transport and command execution only, not its facts or operations.

- Each connection builds a new one-host pyinfra inventory and state from the resolved alias, so nothing carries over between attempts or servers. pyinfra never reads the controller's SSH configuration (`ssh_config_file` is the null device), so `Match` blocks and settings Barectl refuses have no effect.
- Host keys are checked with `ssh_strict_host_key_checking` set to `yes` against a private temporary copy of the alias's known_hosts entries, with revoked keys removed. pyinfra never adds a key, and the copy is deleted when the connection closes. The presented key decides which refusal is reported.
- Barectl opens the TCP connection and passes it, with the timeouts and credentials above, through `ssh_paramiko_connect_kwargs`, pyinfra's documented override for paramiko's `SSHClient.connect`. Its `transport_factory` argument keeps the SSH transport, which reports the verified host key and is closed at each deadline.
- pyinfra reports a command's success as a boolean and reads output as text lines without a limit, so each command runs in a POSIX `sh` wrapper. The wrapper runs the command in its own shell with its error output discarded, keeps at most 64 KiB and one byte of its output with `head -c`, encodes it with `base64`, and ends with a line holding the command's exit status and the encoder's. base64 contains no spaces, so remote output cannot imitate that line, and the wrapper always exits 0, so pyinfra never retries a command. The exact output bytes and exit status are recovered from that; anything else is refused as an unreadable result. On the controller, the connection stops receiving once more than 256 KiB arrive while connecting or during one command, so a server that ignores the wrapper cannot make the worker hold unbounded output. The wrapper uses only the shell and coreutils, and writes nothing on the server.
- A command may receive optional bytes on standard input. The connector passes them through pyinfra's `_stdin` channel, base64-encodes the bytes on the controller, and decodes them inside the remote wrapper before the fixed command reads them. The bytes are never part of argv, the pyinfra command log, or `RemoteShell`'s command transcript. This uses pyinfra 3.10.0's SSH connector standard-input implementation ([version-matched source](https://github.com/pyinfra-dev/pyinfra/blob/v3.10.0/src/pyinfra/connectors/ssh.py#L363-L430)); the in-process SSH test exercises the channel end to end.
- pyinfra waits for command output without a limit Barectl can rely on, so a timer closes the SSH transport at the command or connection deadline. A stalled or slowly writing command, a dropped connection and an unreadable result all fail the attempt with a fixed explanation; incomplete output is never returned as a result. The TCP connection, transport and trust copy are released on success, failure, truncation, timeout and when the worker is forced to stop, and nothing more is sent on a connection that was closed.
- The worker process is not changed by the integration: Barectl does not apply gevent's monkey-patching, so threads, sockets and the database driver behave as before. pyinfra reads command output in gevent greenlets on the worker's own thread. When connecting, pyinfra's connector replaces paramiko's key-type lookup for agent keys with the behavior of upstream paramiko's fix for security-key agent keys ([pyinfra connector source](https://github.com/pyinfra-dev/pyinfra/blob/v3.10.0/src/pyinfra/connectors/ssh_util.py)); this applies to every paramiko client in the process. pyinfra also keeps the host keys it loaded from each trust copy for the life of the worker process, a few kilobytes per attempt; the copy's file is deleted, and a restart of the worker releases them.

## Failures and logs

Failures are shown as fixed explanations that name the alias and the next step. They never include exception text, remote output, host names, user names or key paths. An unexpected error is recorded as such, and the worker log names only its type. pyinfra's and paramiko's own logging is discarded because it can quote host names, commands and server-supplied data.

## Components

| Component | Version | Source consulted |
| --- | --- | --- |
| Django tasks framework | Django 6.1.1 | [Background tasks](https://docs.djangoproject.com/en/6.1/topics/tasks/) |
| `django-tasks-db` | 0.13.0 | [README](https://github.com/RealOrangeOne/django-tasks-db), [CI matrix](https://github.com/RealOrangeOne/django-tasks-db/blob/master/.github/workflows/ci.yml), [Django community ecosystem](https://www.djangoproject.com/community/ecosystem/) |
| `pyinfra` | 3.10.0 | [Python API](https://docs.pyinfra.com/en/3.x/api/index.html), [Host API](https://docs.pyinfra.com/en/3.x/apidoc/pyinfra.api.host.html), [SSH connector](https://docs.pyinfra.com/en/3.x/connectors/ssh.html), [compatibility](https://docs.pyinfra.com/en/3.x/compatibility.html) |
| `paramiko` | 5.0.0 | [SSHClient](https://docs.paramiko.org/en/stable/api/client.html), [host keys](https://docs.paramiko.org/en/stable/api/keys.html#module-paramiko.hostkeys), [agent](https://docs.paramiko.org/en/stable/api/agent.html) |

Django's own task backends are for development and testing; the documentation directs production use to third-party backends. `django-tasks-db` is listed in Django's community ecosystem, not endorsed by Django. pyinfra is Barectl's choice, not a Django recommendation. pyinfra 3.10.0 declares `paramiko<5`; its maintainers raised that bound to `<6` on the 3.x branch ([pyinfra#1743](https://github.com/pyinfra-dev/pyinfra/pull/1743)) because paramiko 4.0.0 is affected by CVE-2026-44405, so `pyproject.toml` overrides the bound until a pyinfra release carries it, and the tests exercise the combination.

## Target foundation reads and privilege

The target foundation on Ubuntu 26.04 accepts root or authorized passwordless sudo. Only its fixed foundation read, privilege check and privileged listener read use `discovery/root_read.py`. It reuses `operations/native.py` to check root, authorize the exact fixed argv without prompting, and run that argv on the existing `RemoteShell` from pyinfra. A denied or truncated authorization produces unavailable evidence, never guessed absence. This bounded reuse and the owning requirements are recorded on [#336](https://github.com/rajandangi/barectl/issues/336#issuecomment-6171527420).
