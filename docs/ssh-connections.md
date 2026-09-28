# SSH connections and discovery

In the current release, Barectl connects to a managed server only from its discovery worker, using the SSH alias the server was registered with (`docs/ssh-aliases.md`). Credentials, connection settings and host trust stay on the controller host. Barectl reads them and never writes SSH configuration, known_hosts files or key files.

Discovery attempts and their history belong to this Barectl application database. They are not native server history and are not written to the server. Another device can establish authorized SSH access and rediscover supported configuration with its own database; it cannot recover this installation's private attempt records. Future native history inspection, background server operations, and coordination across devices follow the [architecture requirements](architecture.md#state-and-discovery).

## Workflow

1. Registering a server, choosing a new alias for it, or pressing **Verify connection**, **Refresh observations** or **Retry connection check** queues a discovery attempt. The request returns immediately; it does not connect.
2. The worker claims the attempt and marks it running. It reads the SSH configuration again and resolves the alias.
3. It connects, verifies the server's host key against the controller's known_hosts files, then authenticates.
4. It reads the operating system release, architecture, CPU count, memory, root filesystem capacity, the component observations and the Nginx site file and PHP-FPM pool observations it can read, and publishes a snapshot and the attempt's outcome in one transaction. A successful refresh replaces the current snapshot; earlier attempts remain as history.

The server page polls while an attempt is queued or running and announces changes in a live region. **Verify connection** appears before the first check, **Refresh observations** after a success, and **Retry connection check** after a failure or interruption.

Attempts are stored separately from registrations and snapshots, with the states queued, running, succeeded and failed. Within one Barectl database, there is at most one queued or running attempt per server, so repeated or concurrent requests share the active attempt. This constraint does not coordinate independent devices with separate databases. A failed or interrupted attempt does not remove earlier snapshots; the page shows the latest attempt and the latest snapshot separately, each with its alias and time, and notes that the snapshot may be out of date. The alias cannot be changed while an attempt is active. Forcing the worker to stop mid-task marks its attempt as interrupted. An attempt abandoned any other way, such as by killing the worker, is recovered as interrupted once it has been active for ten minutes; every read of attempts performs this recovery first (the server list and page, polling, the Activity page and the removal page), as do requesting a check and the worker's next task. Recovery keeps any previous snapshot, and the operator retries manually. Finishing filters on still-running attempts, so a stale worker cannot overwrite the recovery or a newer result. There is no automatic retry, scheduled discovery or live monitoring.

## Server removal

An operator with the `servers.view_server` and `servers.delete_server` permissions removes a server from its page. **Remove** opens a confirmation page, and only its CSRF-protected **Remove server** button deletes anything.

- Removal deletes the server's registration, its discovery attempts and snapshots, and the worker's task records for those attempts, all from the Barectl database. A task record that a running worker claimed within the last ten minutes is kept, since that worker saves it when it finishes.
- It never connects to the server and never touches the controller's SSH configuration, keys, agent or known_hosts. The alias can be registered again.
- It is refused while an attempt is queued or running. Attempts protect their server in the database, so a request that queues discovery while removal is in progress makes the removal fail and roll back, and a request that queues discovery after removal finds the server gone. Abandoned attempts are recovered first, so they do not block removal.
- An edit submitted after removal is refused rather than registering the server again.

## Running the worker

The worker is a separate process from the same application, using the Django tasks framework with the database backend from `django-tasks-db`. Queued work is stored in the application database and survives the request that created it. Discovery requires this controller worker and does not continue as a background server job if the controller stops.

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

Connecting, the SSH handshake and authentication each time out after 10 seconds, and each command must finish within 15 seconds, however steadily it writes output. All commands on one connection must finish within 5 minutes, so an attempt ends well before recovery would treat it as abandoned; a longer one fails, keeping any previous snapshot. Command output is read up to 64 KiB. Commands run without a terminal, environment variables or `sudo`, with the SSH user's own permissions. Discovery installs nothing and writes nothing on the server.

The operating system observation runs `cat /etc/os-release`, falling back to `/usr/lib/os-release` as the [os-release specification](https://www.freedesktop.org/software/systemd/man/latest/os-release.html) describes. When `cat` fails, `test -e` and `test -r` distinguish a missing file from an unreadable one, whatever the server's language. Only `PRETTY_NAME`, `NAME`, `ID` and `VERSION_ID` are kept, unquoted with Python's `shlex` and length-limited. The snapshot records the file read and the collection time.

Capacity observations use the same bounds and permissions:

- `uname -m` reports the machine hardware name, such as `x86_64` ([uname invocation](https://www.gnu.org/software/coreutils/manual/html_node/uname-invocation.html)).
- `nproc` reports the processing units available to the SSH session, which can be fewer than the server has; the page labels them as available ([nproc invocation](https://www.gnu.org/software/coreutils/manual/html_node/nproc-invocation.html)).
- `cat /proc/meminfo` reports memory; only `MemTotal` in `kB` is kept and stored in bytes ([proc filesystem](https://docs.kernel.org/filesystems/proc.html)). When `cat` fails, `test -e` and `test -r` distinguish a missing file from an unreadable one.
- `df -B1 --output=size,avail,target /` reports the root filesystem in bytes; only its size and available space are kept ([df invocation](https://www.gnu.org/software/coreutils/manual/html_node/df-invocation.html)).

Observation outcomes are defined in the [glossary](../CONTEXT.md). The snapshot records each observation's source and the collection time. A source is the commands or files whose results decided the observation's outcome, in the order they were read; the page shows each one. Memory and filesystem sizes are stored in bytes and shown with human-readable units plus byte counts. A command the shell cannot find (exit status 127) is unsupported and one it cannot run (126) is inaccessible, as the [POSIX shell](https://pubs.opengroup.org/onlinepubs/9799919799/utilities/V3_chap02.html#tag_19_08_02) defines; any other failure is unsupported. A missing inspection command or file is never a finding that something does not exist.

Every server has an operating system, an architecture, CPUs, memory and a root filesystem, so these observations are never absent; the database refuses a snapshot that records one as absent.

| Outcome | Meaning |
| --- | --- |
| Observed | The file or command reported the observation in a supported format. |
| Inaccessible | The file exists but the SSH user cannot read it, or the command exists but the SSH user cannot run it. |
| Unsupported | The file or command does not exist on the server, could not be read, or did not report a supported format. |

A completed attempt with an inaccessible or unsupported observation still succeeds; the snapshot shows the warning. Missing observations never appear as zero values.

## Component observations

For each supported web-stack component — Nginx, PHP-FPM, MariaDB and PostgreSQL — the snapshot records a component observation: the installed package versions from the server's dpkg database and the state of its systemd service units. Both observations use fixed read-only commands with the SSH user's own permissions: no sudo, no package installation, no service restarts, no configuration writes, and no database credentials or application secrets. The observation commands are bounded by the same timeouts and output limits as every other discovery command.

Versions come from one dpkg database query:

```text
dpkg-query -W -f='${Package} ${Version} ${db:Status-Abbrev}\n' 'nginx' 'php*-fpm' 'mariadb-server*' 'postgresql' 'postgresql-[0-9]*'
```

Service states come from one `systemctl show` query per component, reading `Id`, `LoadState`, `ActiveState`, `SubState` and `UnitFileState` for its units. A missing systemd unit is reported as `not found`; a loaded unit is shown as `active (running)`, `inactive (dead)` and so on, with the unit file state such as `enabled` when systemd reports one.

These installation formats and service names are supported, based on the parsers and the transport results recorded from Ubuntu 24.04:

| Component | Installed packages match | Service units queried |
| --- | --- | --- |
| Nginx | `nginx` | `nginx.service` |
| PHP-FPM | `php*-fpm`, such as `php8.3-fpm` | One per installed package, named after it: `php8.3-fpm.service` |
| MariaDB | `mariadb-server*` | `mariadb.service` |
| PostgreSQL | `postgresql` and `postgresql-[0-9]*`, such as `postgresql-16` | `postgresql.service`, then one per cluster: `postgresql@16-main.service` |

Behavior on other servers:

- Only dpkg installations are supported. When `dpkg-query` is missing or its output cannot be parsed, every component's package observation is **unsupported**, never absent: Barectl cannot know whether the software is installed. When the SSH user cannot run `dpkg-query` (exit status 126), the observations are **inaccessible**.
- A package counts as installed when its dpkg state is installed: status `ii`, `hi` for a package held with `apt-mark hold`, or either with the `R` reinstall-required flag. Packages that apt merely knows about, such as the `php-fpm` metapackage on a server that installed `php8.3-fpm`, and packages removed with only configuration files left (`rc`) are never reported as installed.
- A matching package in an unfinished dpkg state, such as unpacked (`iU`) or half-configured (`iF`), makes the component's package and service observations **unsupported**: the software may be partly present, so it is neither reported as installed nor as absent.
- When `systemctl` is missing, fails (for example `System has not been booted with systemd`), or reports unknown state tokens, the service observation is **unsupported**, never absent. Querying it requires systemd's D-Bus interface, which stock servers provide and unprivileged accounts may read.
- Units are queried only for components with an installed package. Otherwise the service observation takes the package observation's outcome, with the dpkg query as its source and the same warning: **absent** when no package is installed, and unsupported or inaccessible when the dpkg database cannot be read.
- A missing unit appears as `not found`. A unit whose reported states do not match the supported tokens, or that systemd reports under a name other than the one queried (an alias resolving to another unit), makes the service observation **unsupported** rather than showing invented states.
- One query covers every PHP-FPM unit of a server with several PHP versions; systemctl separates their records with an empty line.
- PostgreSQL's units are found as the next section describes.

Package and service observations are stored per component with their own outcome, source commands and warnings, and the collection time of the snapshot. A component can report versions while its service state is unsupported, and the other way around. A service observation stores each service unit's name, load state, active state, sub-state and unit-file state as systemd reports them; the page shows them as one line per unit, such as `nginx.service active (running), enabled`.

## PostgreSQL clusters

On Debian and Ubuntu, `postgresql.service` is an umbrella unit. It stays `active (exited)` while the clusters it started run or stop. Each cluster runs as an instance of the `postgresql@.service` template named after its version and cluster name, such as `postgresql@16-main.service`. When the dpkg database shows PostgreSQL installed, Barectl finds the server's clusters and queries each cluster's unit after the umbrella unit, in the same `systemctl show` query, so a stopped cluster appears as `postgresql@16-main.service inactive (dead), enabled-runtime` under an `active (exited)` umbrella.

What upstream defines:

- postgresql-common keeps each cluster's configuration in `/etc/postgresql/<version>/<cluster>/`. A cluster is such a directory holding `postgresql.conf`, as an existing file or a dead symlink. Version directories are named like `16` or `9.6`; other entries of `/etc/postgresql` are not versions. The `postgresql-common` package installs `/etc/postgresql` itself ([`PgCommon.pm`](https://salsa.debian.org/postgresql/postgresql-common/-/blob/master/PgCommon.pm), [`postgresql-common.dirs`](https://salsa.debian.org/postgresql/postgresql-common/-/blob/master/debian/postgresql-common.dirs)).
- `pg_createcluster` accepts cluster names made of word characters, `.` and `-`, and advises against `-` because it breaks the template's `%I` path in systemd ([pg_createcluster](https://manpages.debian.org/stable/postgresql-common/pg_createcluster.1.en.html)).
- Its systemd generator adds each cluster whose `start.conf` says `auto` to the umbrella unit's wants, so systemd loads those clusters' units. `manual` and `disabled` clusters are not wanted and stay unloaded until something names them ([`README.systemd`](https://salsa.debian.org/postgresql/postgresql-common/-/blob/master/systemd/README.systemd), [`postgresql-generator`](https://salsa.debian.org/postgresql/postgresql-common/-/blob/master/systemd/system-generators/postgresql-generator)).
- A literal unit name refers to exactly one unit, while a glob such as `postgresql@*` matches only units currently in memory ([systemctl](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html)). On Ubuntu 24.04, `systemctl show` with the name of an unloaded cluster's unit reports it, such as `inactive (dead), disabled` for a `manual` cluster.
- `pg_lsclusters` lists clusters from the same directories, but it skips a directory it cannot open without reporting an error, and its status column reads the cluster's socket and data directory ([pg_lsclusters](https://manpages.debian.org/stable/postgresql-common/pg_lsclusters.1.en.html)).

What Barectl does, with the SSH user's own permissions and no database connection, credentials or data directory access:

```text
ls -1b /etc/postgresql
ls -1bA /etc/postgresql/<version>
test -e /etc/postgresql/<version>/<cluster>/postgresql.conf
```

Barectl lists the configuration directories itself and does not run `pg_lsclusters`; a directory it cannot read is reported, never treated as empty. Version directories are listed with `-A`, as postgresql-common reads names starting with `.` too. Every cluster's unit is named in the query, loaded or not, as the generator names them: `postgresql@<version>-<cluster>.service`, including cluster names with dashes. Entries of `/etc/postgresql` not named like a version are ignored, as postgresql-common ignores them. When `postgresql.conf` is not found, `test -L` accepts a dead symlink, and `test -d`, `test -x` and `test -e` tell an entry that is not a cluster (a file, or a searchable directory without `postgresql.conf`) from a directory the SSH user cannot search. The service observation's source records the listing commands, then the unit query.

Supported cluster names are 1 to 64 ASCII letters, digits, `_`, `.` and `-`. Version directories follow postgresql-common's pattern, at least two digits with an optional dot between them, such as `16` or `9.6`, bounded to four digits on each side of the dot. Other names are never used in a command, a unit name or a warning; they are skipped and counted. At most 20 version directories and 100 cluster directory entries are inspected.

| Outcome | Meaning |
| --- | --- |
| Observed | Every version directory was listed and every entry checked. The umbrella unit and each cluster's unit are shown. When no cluster was found, the observation says so and shows only the umbrella unit. |
| Inaccessible | The SSH user cannot list `/etc/postgresql` or a version directory, or cannot search a cluster directory. The units that were found are still shown. |
| Unsupported | `/etc/postgresql` does not exist, a listing could not be read or is larger than supported, a version directory lists names outside the supported ones, or there are more versions or entries than Barectl inspects. The units that were found are still shown. |

A listing Barectl could not complete is never absent: Barectl cannot tell whether other clusters exist. A cluster whose unit systemd reports as `not found` is shown as `not found`. Cluster units are checked like every other unit: a record under another name, or in an unsupported format, makes the observation unsupported. When systemd cannot be queried, the observation is unsupported or inaccessible as for other components, and its warning also names any listing problem.

## Nginx site file and PHP-FPM pool observations

Alongside the component observations, the snapshot records the Nginx site files and PHP-FPM pools it can read, with the snapshot's collection time, the paths each observation was read from and explicit warnings.

These observations depend on the component's package observation, as the service observation does ([ADR 0001](adr/0001-configuration-observations-depend-on-package-observation.md)). Nginx site files are read only when the dpkg database shows Nginx installed, and PHP-FPM pools only for the PHP versions of installed `php<version>-fpm` packages. When the package observation is absent, unsupported or inaccessible, the site file or pool observation takes the same outcome, with the dpkg query as its source and the same warning, and nothing is read. Configuration left behind by a removed package (`rc`) is therefore not reported. Discovery never adopts or changes this configuration, and it never links Nginx site files to PHP-FPM pools: it does not interpret a site file's `fastcgi_pass`, so an observed Nginx site file is never attributed to an observed pool.

Nginx site files are read from the Debian and Ubuntu layout only, and only when `/etc/nginx/nginx.conf` loads it with `include /etc/nginx/sites-enabled/*;` directly inside its `http` block, as the stock file does:

```text
cat /etc/nginx/nginx.conf
ls -1b /etc/nginx/sites-enabled
cat /etc/nginx/sites-enabled/<entry>
```

nginx includes every entry of that directory, so every listing entry is read. From each readable file, only the `server_name` and `listen` directives of its `server` blocks are kept, and only in these supported forms:

- Server names: plain names, wildcards (`*.example.com`) and the quoted or unquoted forms around them. Regex names such as `~^www\d\.` and variables such as `$hostname` are server data Barectl does not interpret, so a file using them is unsupported.
- Listen addresses: a port (`80`), an address and port (`127.0.0.1:8080`, `[::]:80`, `*:80`) or a `unix:` socket path. Flags such as `ssl` and `default_server` are not kept.

PHP-FPM pools are read from the same layout PHP-FPM's own pool include uses, for each installed PHP-FPM version whose `php-fpm.conf` declares `include=/etc/php/<version>/fpm/pool.d/*.conf`, as the stock file does:

```text
cat /etc/php/<version>/fpm/php-fpm.conf
ls -1b /etc/php/<version>/fpm/pool.d
cat /etc/php/<version>/fpm/pool.d/<file>.conf
```

The PHP-FPM pool observation's source is each `php-fpm.conf` whose include could not be confirmed, each pool directory Barectl tried to list, and each listed pool file that could not be read as a pool configuration. The Nginx site file observation's source is `nginx.conf` when its include cannot be confirmed, otherwise the site directory.

Only `*.conf` entries are read, as PHP-FPM only loads those. From each readable file only the pool section names and their `listen` values are kept. Quoted `listen` values are unquoted and `$pool` is expanded to the pool's name, as PHP-FPM does. A `[global]` section, matched case-insensitively like PHP-FPM, is not a pool. Everything else in every file is discarded before anything is stored: no credentials, no secret environment values (`env[...]`), no `php_value[...]` settings and no unfiltered configuration dumps are ever persisted, logged or shown.

The supported configuration forms end there. A file is **unsupported**, with a warning, when it cannot be tokenized as supported nginx syntax (unclosed blocks, unterminated quotes, directives without a semicolon), when its `server_name` or `listen` values fall outside the forms above, when it defines no `server` block at all, or when a pool file cannot be parsed as supported INI-style pool configuration. PHP-FPM merges repeated pool sections, matching names case-insensitively; Barectl does not merge them. A pool repeated within one file makes that file unsupported, and a pool declared in files of the same PHP version is recorded once as unsupported, without a listen address. A pool without a `listen` value is also unsupported.

Only the include that loads the Debian directory is looked for in `nginx.conf` and `php-fpm.conf`; nothing else in them is kept, and other files they include, such as `/etc/nginx/conf.d/*.conf`, are not read. Barectl does not run `nginx -T` or `php-fpm -tt`, which print the whole effective configuration. The include path must match exactly: a relative path, another directory or an include that is commented out makes the observation unsupported and the directory is not read.

Files named by `include` inside site and pool files are not read. A site file that includes others outside its `location` blocks, where server blocks, server names or listen addresses may be declared, and a pool file that includes others, are still observed, with a warning that what the included files declare is not shown.

Values are validated and length-limited, and listings are bounded: a directory listing more than 1000 entries is unsupported and not read, and at most 200 Nginx site files, 20 PHP-FPM versions, 200 pools per snapshot and 50 pools per file are read. Listings use `ls -b`, which escapes newlines and other nongraphic characters, so each entry is one line. Entries whose names fall outside the supported characters, including escaped names, are skipped and counted in a warning, never read. Names reported by the server are validated before they appear in a command and are shell-quoted there.

Outcomes follow the [glossary](../CONTEXT.md), as for every other observation:

| Outcome | Meaning |
| --- | --- |
| Observed | At least one Nginx site file or PHP-FPM pool was read in a supported form; the other entries keep their own outcomes as partial results. A listed directory holding no Nginx site files or pool files is observed, with an explicit warning. |
| Inaccessible | The component's package observation is inaccessible, the SSH user cannot read `nginx.conf` or `php-fpm.conf`, or nothing was observed because the SSH user's permissions refused it: the directory cannot be listed, or every entry that could hold configuration cannot be read, including entries of a directory that can be listed but not searched. Barectl does not use sudo. |
| Absent | The dpkg database shows the component not installed, or every listed Nginx site file entry no longer exists. |
| Unsupported | The component's package observation is unsupported; the component is installed but `/etc/nginx/nginx.conf` or an installed version's `php-fpm.conf` does not exist, cannot be parsed, or does not include the Debian directory, or that directory does not exist, since Barectl reads only the Debian layout; the dpkg database lists no PHP-FPM package for a specific PHP version; or nothing was observed and at least one entry could not be interpreted: a file or pool outside the supported forms, or a listing larger than supported. |

Partial results are preserved: a site directory that lists but cannot be read per file still records the readable Nginx site files, and one version's unreadable or missing pool directory does not hide another version's pools. Each Nginx site file row carries the entry's name, status, server names, listen addresses, the file it was read from and its warning; each PHP-FPM pool row carries the pool name, its PHP version, its listen address, the file and its warning. A broken `sites-enabled` symlink is recorded as absent for that entry.

## pyinfra connection

Barectl is moving discovery onto pyinfra's SSH connector, which future provisioning will also use. `discovery.ssh.connect_with_pyinfra` implements the same `RemoteShell` contract as the paramiko connection and meets every rule on this page; it is a candidate that the worker does not use yet. Discovery switches to it once failure recovery and reconstruction from independent controllers are qualified through it ([#101](https://github.com/rajandangi/barectl/issues/101)).

- Each connection builds a new one-host pyinfra inventory and state from the resolved alias. pyinfra never reads the controller's SSH configuration (`ssh_config_file` is the null device), so `Match` blocks and settings Barectl refuses have no effect.
- Host keys are checked with `ssh_strict_host_key_checking` set to `yes` against a private temporary copy of the alias's known_hosts entries, with revoked keys removed. pyinfra never adds a key, and the copy is deleted when the connection closes. The presented key decides which refusal is reported.
- Barectl opens the TCP connection and passes it, with the timeouts and credentials above, through `ssh_paramiko_connect_kwargs`, pyinfra's documented override for paramiko's `SSHClient.connect`. Its `transport_factory` argument keeps the SSH transport, which reports the verified host key and is closed at each deadline.
- pyinfra reports a command's success as a boolean and reads output as text lines without a limit, so each command runs in a POSIX `sh` wrapper. The wrapper runs the command in its own shell with its error output discarded, keeps at most 64 KiB and one byte of its output with `head -c`, encodes it with `base64`, and ends with a line holding the command's exit status and the encoder's. The exact output bytes and exit status are recovered from that; anything else is refused as an unreadable result. The wrapper uses only the shell and coreutils, and writes nothing on the server.
- pyinfra waits for command output without a limit Barectl can rely on, so a timer closes the SSH transport at the command or connection deadline. A stalled or slowly writing command, a dropped connection and an unreadable result all fail the attempt with a fixed explanation; incomplete output is never returned as a result. The TCP connection, transport and trust copy are released on success, failure, truncation, timeout and when the worker is forced to stop, and nothing more is sent on a connection that was closed.

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

## Acceptance against a real server

`discovery/test_remote.py` registers a server and runs the worker against a disposable Ubuntu 24.04 server. It checks a trusted connection with a key file and with an agent, rejection of unknown and changed host keys, and that the persisted component, Nginx site file and PHP-FPM pool observations agree with read-only ground truth read through the controller's OpenSSH client, independently of Barectl's connection, including each PostgreSQL cluster's unit state. After every test, `/etc`, the SSH user's home directory, the package database and each running service's main process must be unchanged. A site file the SSH user cannot read is recorded as inaccessible, with its warning on the server page and in Activity, while the rest of the snapshot is still observed. After removing every record Barectl holds about the server, including the worker's task records, discovery reconstructs the same observations, apart from Barectl's own identifiers and times and the root filesystem's free space. A second discovery replaces site and pool rows without duplicates. `PyinfraDisposableServerTests` repeats every test with discovery connecting through `connect_with_pyinfra`. The tests are tagged `ssh` and skip unless these variables are set: `BARECTL_SSH_TEST_HOST`, `BARECTL_SSH_TEST_PORT`, `BARECTL_SSH_TEST_USER`, `BARECTL_SSH_TEST_KEY` (a key file without a passphrase) and `BARECTL_SSH_TEST_KNOWN_HOSTS`.

`docker/disposable-server/run-tests.sh` creates that server in Docker and runs the tests against it, locally and in CI's `disposable-server` job. It builds an Ubuntu 24.04 image that boots systemd, with the SSH user `deploy` and a throwaway key. `provision.sh` then installs `nginx`, `php8.3-fpm` and `postgresql`, adds a stopped `archive` cluster and an unloaded `reports` cluster beside the running `16/main` one, and enables a site file only root can read beside the stock `default` site, so installed and running observations, PostgreSQL clusters and limited permissions are all exercised. The host key is read through `docker exec`, a trusted channel, rather than by scanning the network. The container and key are removed when the script exits. The service observation test compares the cluster units with `pg_lsclusters` and with each unit's own `systemctl show` result.

From the Barectl repository, with Docker running:

```bash
docker/disposable-server/run-tests.sh --env-file .env
```

The script's arguments are passed to `uv run`. Each run has its own container on a free local port chosen by Docker, so concurrent runs do not interfere; set `BARECTL_SSH_TEST_PORT` to fix the port. To run the tests against another disposable server, set the `BARECTL_SSH_TEST_*` variables yourself and run `uv run --env-file .env python manage.py test --tag ssh`.

Routine tests do not need a server. `discovery/test_host_facts.py`, `discovery/test_components.py` and `discovery/test_configuration.py` test observation rules through `discovery.observations.collect`, and `discovery/test_lifecycle.py` runs the request, worker and persistence workflow, all with remote execution substituted by `FakeServer` from `discovery/fakes.py`, whose `test`, `cat` and `ls` answers `discovery/test_fake_server.py` checks against GNU coreutils on a real directory tree ([ADR 0002](adr/0002-keep-the-remote-shell-seam.md)), `discovery/test_snapshot_page.py` checks how the server page renders each kind of stored observation, `discovery/test_transport_workflow.py` runs registration, the worker and the pages through the pyinfra connection against that in-process server: a stalled refresh, a dropped connection, refused host keys and credentials and a forced worker stop each fail or interrupt the attempt, keep the previous snapshot as possibly out of date, wait for an explicit retry and release the connection, and no log, output, stored failure or page reveals connection details or remote output; and `discovery/test_ssh.py` exercises host-key checks, authentication, agents, exit statuses, output bounds, deadlines and error handling for both connections against an in-process SSH server that runs each command with the local `/bin/sh`.
