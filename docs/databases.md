# Site databases

A site's optional database binding follows the [database convention](site-conventions.md#database-convention): a MariaDB or PostgreSQL principal and database named like the site user, authenticated by the site's Linux identity. Discovery reconstructs bindings from the catalogs ([site database observations](ssh-connections.md#site-database-observations)). Before a site's PHP can connect, PHP-FPM needs the distribution's driver for the engine; a **PHP driver plan** reviews and installs it. A **database plan** then creates one site's MariaDB database and principal, and a **privileged inspection** reads every binding with privilege when ordinary discovery cannot. The accepted specification is [v0.3](v0.3.md#database-bootstrap-and-site-access); the evidence is in the qualification record for the [drivers](v0.3-qualification.md#php-database-drivers) and [MariaDB site databases](v0.3-qualification.md#mariadb-site-database).

## Permissions

Database plans have their own permissions, separate from bootstrap's and sites':

| Stage | Permissions |
| --- | --- |
| View database plans and their preparations | `servers.view_server` and `databases.view_databaseplan` |
| Prepare a database plan | the above and `databases.prepare_databaseplan` |
| Apply a database plan, and close a run whose outcome is unknown | the above and `databases.apply_databaseplan` |

Bootstrap and site permissions grant none of these, and database permissions grant no bootstrap or site plan. An account that may not view database plans never sees the **Database plans** section, a database plan, its preparation or its line in Activity. The worker checks again, before it connects and before it submits a run, that the requesting account is active and still holds these permissions.

## Preparing a database plan

Open the server and use **Database plans**. **Prepare PHP MariaDB driver plan** and **Prepare PHP PostgreSQL driver plan** queue a driver plan's preparation; **Inspect catalogs** queues a privileged inspection. For a database plan, enter the **site identifier** and press **Prepare MariaDB database plan**; an invalid identifier is refused before anything is queued. The page follows the preparation and shows the review when the worker finishes.

## PHP database drivers

A driver plan installs the release's default PHP version's driver package from the release's own archive through the [exact package transaction](adr/0007-admit-exact-package-transactions-with-an-inline-apt-guard.md) every bootstrap profile uses:

| Plan | Package | Modules, as `phpenmod` links them in each SAPI's `conf.d` |
| --- | --- | --- |
| PHP MariaDB driver | `php8.3-mysql` on Ubuntu 24.04, `php8.5-mysql` on 26.04 | `10-mysqlnd.ini`, `20-mysqli.ini`, `20-pdo_mysql.ini` |
| PHP PostgreSQL driver | `php8.3-pgsql` or `php8.5-pgsql`, with `libpq5` when it is missing | `20-pgsql.ini`, `20-pdo_pgsql.ini` |

The review lists every package at its exact version, like any bootstrap profile, and refuses what the PHP profile refuses: other PHP releases, held or unhealthy packages, other sources, and the other checks of [bootstrapping a server](bootstrap.md). It also requires:

- the PHP profile's FPM and CLI to be installed; a driver plan never installs PHP, and a stopped PHP-FPM is refused rather than started;
- an installed driver to have its modules linked from both SAPIs to the distribution's module files and listed by `php-fpm<version> -m`; such a driver is a plan without changes, and one whose modules an administrator disabled is refused, naming `phpenmod`.

### Site-aware readiness

The stock PHP profile refuses a PHP-FPM tree that holds a site pool, since it only adopts the distribution's configuration. A driver plan judges `/etc/php/<version>/fpm` by the [site grammar](sites.md#admission) instead: the distribution's unmodified files and links, and pool files that are byte for byte a site convention pool, root's with mode 0644 and one link. Anything else there, such as an administrator's own pool or `conf.d` file, refuses the plan, since the driver's reload would load it into every pool. `/etc/php/<version>/cli` and `mods-available` keep the distribution-only rule. Reading pool files takes root, as a site plan's preparation does: root, or noninteractive sudo of the same fixed read-only scripts, which is equivalent to a root shell; without it the plan is refused for privilege. Preparation compares that listing with the unprivileged listing the package digest covers and refuses when they differ.

The review records the tree's entries, owners, modes and file digests as its PHP-FPM configuration evidence, with the recognized pools, and lists each pool the reload restarts, with its user and socket: the distribution's `www` and every site pool. Earlier site and database plans are invalidated, since the configuration they were reviewed against changes.

### Installed PHP versions

Each driver package depends on its PHP release's `php<version>-common` at exactly the same version. An installation therefore requests the driver at the installed `php<version>-common` version, so it never upgrades PHP. When no configured source offers the driver at that version, as happens once the release's `-updates` and `-security` suites move on, since they keep only their newest version, the plan is refused and names the upgrade: `sudo apt-get install --only-upgrade php<version>-common php<version>-cli php<version>-fpm`, then prepare again. Barectl never upgrades PHP itself.

### Applying a driver plan

The run is a package run ([applying package profiles](ssh-connections.md#applying-package-profiles)): under the mutation lock it rechecks the APT and package digests, installs exactly the reviewed transaction through the guard, and runs `php-fpm<version> -t` as root. While dpkg runs, the driver's maintainer scripts enable its modules with `phpenmod` and PHP-FPM's dpkg trigger restarts `php<version>-fpm.service`; needrestart may restart other services. After a passing check the run reloads `php<version>-fpm.service` and waits up to 5 seconds for every reviewed pool's socket to listen again, as `ss -Hlx src <socket>` shows. A reload restarts every pool's workers; a request a worker is serving can fail.

| Exit | Meaning | Recovery |
| --- | --- | --- |
| 15 | The APT configuration, packages, marks, indexes, units, PHP configuration or sockets changed after review; nothing was installed. | Prepare a new plan. |
| 20, 21, 23 | As for any package run: dpkg changed packages without completing, the guard refused APT's transaction, or APT failed before dpkg. | As [bootstrapping a server](bootstrap.md) describes. |
| 24 | The driver was installed, but `php-fpm<version> -t` rejected the configuration; PHP-FPM was not reloaded. | Repair the configuration through ordinary administration, then prepare again. |
| 26 | The driver was installed and the check passed, but `systemctl reload` failed or a pool's socket did not listen again. | Inspect `systemctl status` and `journalctl` for the PHP-FPM unit, repair it, then prepare again. |

Verification then reads, unprivileged: the packages at their reviewed versions with `dpkg --audit` empty, the marks, `php<version>-fpm.service` active and running, the default pool's socket, each module's `conf.d` link in both SAPIs resolving to its module file, `php-fpm<version> -m` listing every module, and every reviewed pool's socket listening. `php-fpm -m` reads PHP-FPM's configuration and writes nothing. That the running workers loaded the driver is proven later, when a site's database binding connects through its pool.

## Database bindings

A database plan gives one complete convention site its own MariaDB database. Everything is derived from the site identifier `<id>`: the principal and the database are both `s<id>`, the site's Linux user, since unix_socket authentication without a mapping requires the names to match. Identifiers are always quoted in statements, so a name such as `sselect` is never a keyword.

### Preparation

Preparation reads the server as root, or through noninteractive sudo of Barectl's fixed read-only scripts, which is equivalent to a root shell; without it the plan is refused for privilege. It reads:

- the site, as a site plan's preparation does ([site preparation](ssh-connections.md#site-preparation)): the site must be complete, its review a plan without changes, and its account supplies the UID and GID the pool runs as;
- the engine, as its bootstrap profile's preparation does, including the administrator's readiness check: MariaDB must be established, its review a plan without changes;
- the PHP MariaDB driver, as its driver plan's preparation does: installed, linked and loaded by PHP-FPM, its review a plan without changes;
- whether PostgreSQL is installed, from dpkg;
- the catalog read: MariaDB's rows under `s<id>`, as [discovery reads them](ssh-connections.md#site-database-observations), and, when PostgreSQL is installed, whether it holds a role or database named `s<id>`;
- whether the probe's path exists.

A missing site, engine or driver is refused as a prerequisite, naming the plan to prepare first. The catalog decides the rest:

| Catalog under `s<id>` | Plan |
| --- | --- |
| Nothing, in either engine | The statements below. |
| Exactly the convention's rows | No changes: the binding is complete. |
| The convention's first statements, in order, and nothing else | Refused as a partial binding, naming what exists and the statements that remain. |
| Anything else, such as a password, another host, a grant of the principal on other databases, another collation or a data directory entry | Refused as a collision; it is never adopted. |
| Another account's grant that reaches the name, such as a database pattern like `s%` | Refused as a collision, since the database would not be the site's alone. |
| A role or database in PostgreSQL | Refused as an existing binding: one binding per site, and no switching engines. |

The plan records the site's revalidation digest, the engine's package digest, the driver's version, the SHA-256 of the catalog read, and the SHA-256 of the catalog read's text once every statement took effect, predicted from the read and the convention's rows. The catalog read's text itself is never stored.

### What a database plan reviews

- the statements, in order, each run in its own client invocation as MariaDB's `root@localhost` through `/run/mysqld/mysqld.sock`, without a password or option files:

  ```sql
  CREATE USER `s<id>`@`localhost` IDENTIFIED VIA unix_socket
  CREATE DATABASE `s<id>` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
  GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, DROP, REFERENCES, CREATE TEMPORARY TABLES, LOCK TABLES ON `s<id>`.* TO `s<id>`@`localhost`
  ```

  None is conditional (`IF NOT EXISTS`, `OR REPLACE`), none maps another Linux user, and nothing is ever dropped.
- the temporary probe's path, owner, mode and complete bytes ([the probe](#the-probe));
- the connection instructions ([connecting](#connecting));
- the engine's and driver's versions, the site's UID and GID, and the admission deadline.

### The probe

The probe `/var/www/<id>/dbprobe-<32 hex digits>.php` is root's, readable by the site's group, mode 0640. It is published in the root-owned site directory, never the document root, which the site user owns ([ADR 0012](adr/0012-publish-site-files-without-replacing-them.md#publication)). The run sends it FastCGI requests as root directly to the site's pool socket, not over HTTP, with the PHP CLI's own FastCGI client. With the query `pre` it reports the pool's effective UID and GID and whether `mysqlnd`, `mysqli` and `pdo_mysql` are loaded; otherwise it connects as `s<id>` through the socket with PDO, creates, fills, reads and drops a table `barectl_<token>`, lists the databases it sees, tries `CREATE DATABASE`, `CREATE USER` and a read of `mysql.global_priv`, connects with `mysqli` through the socket, and tries a password-less TCP login to `127.0.0.1`. The report must be exactly `barectl-db <token> <uid> s<id>@localhost 7 information_schema,s<id> 1044 1227 1142 1 1698`: its own identity and data, only its own database, the three refusals, `mysqli`, and TCP refused.

### Applying a binding plan

A binding plan is applied with `databases.apply_databaseplan`, under the mutation lock of [ADR 0006](adr/0006-use-native-bootstrap-execution.md), statement by statement ([ADR 0013](adr/0013-create-a-database-binding-statement-by-statement.md)):

1. the admission of ADR 0006;
2. revalidation: the site digest, the engine's package digest, the driver installed at its reviewed version, the catalog read's digest, the probe's path absent and `/var/www/<id>` and every directory above it root's and writable by no one else (exit 15);
3. the probe is published (exit 64 when that fails);
4. the probe's `pre` request must report the site user's UID and GID and every driver module (exit 32 otherwise, after removing the probe);
5. the catalog read's digest again, immediately before the first statement (exit 15);
6. the principal: a duplicate (`ERROR 1396`) exits 33; another failure exits 34 when the catalog is unchanged and 56 when it changed;
7. the database: a duplicate (`ERROR 1007`) exits 57, another failure 58;
8. the privileges (exit 59);
9. the catalog read's digest must equal the predicted one (exit 61);
10. the full probe report must be exactly the expected one (exit 62);
11. the probe is removed (exit 63 when it changed or cannot be removed), and the run succeeds.

After a failing statement the run prints the catalog read, bounded to 16 KiB, to the unit's journal for inspection. Every failure after the probe was published removes the probe while its bytes still match. Verification then reads, as root: the catalog read, which must hold exactly the convention's rows and nothing under the name in PostgreSQL; the administrator's readiness check's exact output; the probe's absence; MariaDB's and PHP-FPM's units active and running; and the pool's socket listening. The run records the principal, its authentication, privileges, character set and collation, and whether the probe is absent, then queues discovery.

### Recovering a partial binding

| Exit | Outcome | What exists, and how to recover |
| --- | --- | --- |
| 15 | Refused | Something reviewed changed; nothing was created. Prepare again. |
| 32 | Refused | The site's pool did not run the probe as the site user with the driver loaded; nothing was created and the probe was removed. Check PHP-FPM and the driver. |
| 33 | Refused | The principal already existed: another administrator created it after the last check. Nothing was created. |
| 34 | Refused | The engine rejected the first statement and the catalog is unchanged. |
| 56 | Partial | The first statement failed, but a principal exists whose origin is unknown. |
| 57 | Partial | The principal exists; a database `s<id>` already existed and was not adopted. |
| 58 | Partial | The principal exists; creating the database failed, and it may exist. |
| 59 | Partial | The principal and database exist; the grant failed. |
| 61 | Partial | Every statement succeeded, but the catalog differs from the review, as when another administrator added a grant meanwhile. |
| 62 | Partial | The binding exists, but the pool could not use it as reviewed; a table `barectl_<token>` may remain. The probe was removed. |
| 63 | Partial | The probe changed or could not be removed; verification is incomplete. Remove it by hand. |
| 64 | Partial | Publishing the probe failed before any statement; a stage `.dbprobe-<token>.php.<unit>` may remain in `/var/www/<id>`. |

Barectl never drops, replaces, resumes or retries anything. A new database plan shows what exists: it is refused as a partial binding or a collision until ordinary administration completes or removes it, for example with the remaining statements its refusal names, or `DROP DATABASE` and `DROP USER` as MariaDB's administrator once nothing uses them. A timeout, termination or reboot leaves the boundary unknown; a new review shows the current state.

### Connecting

The site connects through the socket `/run/mysqld/mysqld.sock` to the database `s<id>` as the user `s<id>`, with no password: with PDO, the DSN `mysql:unix_socket=/run/mysqld/mysqld.sock;dbname=s<id>` and a null password. TCP logins are refused, by design. The site may drop and recreate its own database, since it holds `DROP` and `CREATE` on it; discovery then reports whether the result still follows the convention.

## Privileged inspection

Ordinary discovery never escalates, so an SSH identity other than root sees catalogs as inaccessible. **Inspect catalogs** prepares a read-only inspection that repeats discovery's reads as root, through noninteractive sudo of each read under `/usr/bin/sh -c` when the SSH user is not root, and keeps each site candidate's binding with the plan: its engine, outcome, principal, authentication, privileges, character set, collation and owner, and why it does not follow the convention. Without root or that authorization it is refused for privilege and reads nothing more. It distinguishes inaccessible catalogs, when an engine's service is not running, from absent bindings. An inspection is never applied, never updates discovery and is never used in its place; only accounts allowed to view database plans see it, its preparation or its line in Activity, with the account, alias and time that prepared it.
