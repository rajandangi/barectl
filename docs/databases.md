# Site databases

A site's optional database binding follows the [database convention](site-conventions.md#database-convention): a MariaDB or PostgreSQL principal and database named like the site user, authenticated by the site's Linux identity. Discovery reconstructs bindings from the catalogs ([site database observations](ssh-connections.md#site-database-observations)). Before a site's PHP can connect, PHP-FPM needs the distribution's driver for the engine; a **PHP driver plan** reviews and installs it. The accepted specification is [v0.3](v0.3.md#database-bootstrap-and-site-access); the evidence is in the [qualification record](v0.3-qualification.md#php-database-drivers).

## Permissions

Database plans have their own permissions, separate from bootstrap's and sites':

| Stage | Permissions |
| --- | --- |
| View database plans and their preparations | `servers.view_server` and `databases.view_databaseplan` |
| Prepare a database plan | the above and `databases.prepare_databaseplan` |
| Apply a database plan, and close a run whose outcome is unknown | the above and `databases.apply_databaseplan` |

Bootstrap and site permissions grant none of these, and database permissions grant no bootstrap or site plan. An account that may not view database plans never sees the **Database plans** section, a database plan, its preparation or its line in Activity. The worker checks again, before it connects and before it submits a run, that the requesting account is active and still holds these permissions.

## Preparing a database plan

Open the server and use **Database plans**. **Prepare PHP MariaDB driver plan** and **Prepare PHP PostgreSQL driver plan** queue a preparation; the page follows it and shows the review when the worker finishes.

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
