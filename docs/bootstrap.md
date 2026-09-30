# Bootstrapping a server

Barectl can prepare an Ubuntu 24.04 or 26.04 LTS server with the distribution's Nginx, with the FPM and CLI of the release's default PHP version, PHP 8.3 on 24.04 and PHP 8.5 on 26.04, or with the release's MariaDB server, MariaDB 10.11 on 24.04 and 11.8 on 26.04, after you review the exact change. It can also refresh the server's package metadata and clear the records of finished bootstrap runs, each as its own reviewed action. This page describes what the current implementation does and what it requires. The design and its rationale are in [v0.2: reviewed bootstrap](v0.2.md); the evidence behind these claims, including what has not been tested, is in the [v0.2 qualification record](v0.2-qualification.md), and for MariaDB in the [v0.3 qualification record](v0.3-qualification.md#mariadb-profile). Technical details of each read and payload are in [SSH connections and discovery](ssh-connections.md#plan-preparation).

Bootstrap installs ordinary Ubuntu packages with their default configuration. It installs no Barectl agent and writes no Barectl records on the server. After a run, the server is managed with the usual tools, `apt`, `dpkg`, `systemctl` and `journalctl`, whether Barectl is still installed or not.

## Prerequisites

The server:

- Runs Ubuntu 24.04 LTS or Ubuntu 26.04 LTS with systemd as its init system, and APT and dpkg as its package manager, on amd64 or arm64, with the release's own APT and systemd: apt 2.8 and systemd 255 on 24.04, apt 3.2 and systemd 259 on 26.04. The qualification record lists the revisions and architectures that were tested. Any other release, including an interim one, is refused before anything but its platform is read.
- Has authenticated package indexes of its own release's three suites, including their `main` component: `noble`, `noble-updates` and `noble-security` on 24.04, or `resolute`, `resolute-updates` and `resolute-security` on 26.04, from archives reached over `http` or `https`, and none of their Release files has expired. Nginx comes from `main`; PHP, and MariaDB on 24.04, come partly from `universe`, which Ubuntu's server installations and cloud images enable by default, and their installations are refused without the authenticated `universe` indexes of the three suites; MariaDB on 26.04 comes from `main`. Each installed version must be offered by the release's archive from a component its profile installs from. Other authenticated sources, such as the release's backports, a PPA or a hosting provider's own repository, may stay configured. The release's backports may offer anything but never supplies a package. Any other source must not offer any package a plan would install, at any version, even one APT would not choose: such a plan is refused and names the source and the package. An unauthenticated source refuses every installation, and a plan is also refused when its transaction would take a package from any other suite or archive, including another Ubuntu release's, a local repository or removable media. A server never receives another release's packages. The review lists the sources other than the release's own archive.
- Has no APT configuration that weakens authentication, overrides package selection or changes how dpkg runs, and only the APT hooks that its release's own `debconf`, `needrestart`, `update-notifier-common`, `apt`, `command-not-found`, `ubuntu-pro-client`, `packagekit`, `appstream` and `snapd` packages install, and on Ubuntu 26.04 `ubuntu-helper-virt-hwe`, which hosting providers' images include. Any other hook refuses every plan: hooks run as root during package changes.
- Has a healthy package database (`dpkg --audit` reports nothing) and no held package that the change would touch.
- Is reachable over SSH from the controller as root, or as a user with noninteractive sudo (`NOPASSWD`). On Ubuntu 26.04, `sudo` is sudo-rs by default, and the original sudo, `sudo.ws`, works the same way here. Barectl checks with `sudo -n -l` that sudo authorizes the exact command it runs: `/usr/bin/systemd-run` for each run, `ss` for the listener query and, for MariaDB, the [readiness](#readiness) check while preparing a plan, and `/usr/bin/sh` for the probe that closes an unknown outcome. It never prompts for a password and never installs a sudo policy.

**Root-equivalent access.** Authorizing an account to run `systemd-run` or a shell through sudo gives it full control of the server. Barectl's own permissions decide who may ask for a change; they do not limit what the SSH account can do. Use a dedicated account, keep its key on the controller host, and treat the controller and anyone who can use its keys as having root on the server. Ordinary discovery never uses sudo.

The controller: register the server by its SSH alias and run the worker (`manage.py db_worker`) as the account whose SSH configuration, keys and known_hosts Barectl should use, as the [README](../README.md#run-locally) describes.

Barectl permissions, granted per account on the controller host:

| Permission | Allows |
| --- | --- |
| `servers.view_server` | Seeing the inventory. Alone, it shows no plans, runs or their audit. |
| `bootstrap.view_configurationplan` | Reviewing plans, preparations and apply runs, and pressing **Check outcome**. |
| `bootstrap.prepare_configurationplan` | Preparing plans, with the permission above. |
| `bootstrap.apply_configurationplan` | Applying metadata refresh, Nginx, PHP and MariaDB plans, and closing their runs as outcome unknown. |
| `bootstrap.clear_native_results` | Applying and closing cleanups of finished bootstrap runs. |

## Review, apply and check

1. On the server's page, choose **Nginx profile**, **PHP profile (FPM and CLI)**, **MariaDB profile**, **Package metadata refresh** or **Clear finished bootstrap runs**, and press **Prepare plan**. The worker reads the server without changing it; preparing never runs `apt-get update` or installs anything.
2. Review the plan. It names the server's release and, for PHP and MariaDB, the version it installs, the packages at exact versions with every dependency APT would install, the service effects and exposure, the evidence it was derived from, and every reason it is refused, each with what ordinary administration resolves it. A refused plan cannot be applied. A profile that is already installed and healthy is a plan with no changes, even when newer versions are available; bootstrap never upgrades.
3. Press **Apply plan** within 15 minutes of preparation. The confirmation names the server, alias, plan and deadline. A plan is applied at most once: repeating the request shows the same run.
4. The run's page follows it. **Execution** is what the server's systemd recorded; **Verification** is a separate check with fresh reads that the packages, marks, service, listeners and, for MariaDB, the data directory are as reviewed. A run succeeds only when both hold. Afterwards Barectl refreshes discovery, so the server page shows the native state.

The run is refused before it changes anything when the server restarted since the review, the deadline passed, another bootstrap run is active, the reviewed evidence changed, or the package manager is busy; Barectl never waits for the package manager, even when the server's APT configuration sets a lock timeout. Each refusal needs a new plan; Barectl never retries or waits to apply an old plan.

When the answer from the server is lost, or the controller stops, the run shows **Outcome not established** and keeps the server's active slot. Press **Check outcome** later, from the same controller or after restarting it; it inspects the same systemd unit and never submits the run again.

## What the profiles install

- **Nginx**: `nginx` and its dependencies, without recommended packages. The distribution's default site serves HTTP on port 80 on every IPv4 and IPv6 address as soon as the package starts Nginx.
- **PHP**: the release's default version, `php8.3-fpm` and `php8.3-cli` on Ubuntu 24.04 or `php8.5-fpm` and `php8.5-cli` on Ubuntu 26.04, and their dependencies, without recommended packages. No web server is installed, and Nginx is not required. The default `www` pool listens only on the local socket `/run/php/php8.3-fpm.sock`, or `/run/php/php8.5-fpm.sock`; when the service starts, it registers that socket as the `/run/php/php-fpm.sock` alternative. Only missing packages are named to APT: a CLI package that another package already pulled in keeps its automatic mark.
- **MariaDB**: `mariadb-server` and its dependencies, without recommended packages, as the [MariaDB section](#mariadb) describes. It is offered independently of any site and creates no database, database user or password, and installs no PHP driver.

Bootstrap keeps the distribution's defaults and does not create sites, pools, users, databases or certificates. It refuses rather than adopts a server that already has something else: changed or additional configuration files, leftover configuration of removed packages, unit overrides, masked or failed units, another service on port 80 or on the pool's socket, or, for PHP, any other PHP version's packages or directories under `/etc/php`. An installed profile whose service is only stopped or disabled gets a plan that enables and starts it, without APT.

## Effects to expect while a run installs

- Package maintainer scripts enable and start the service before Barectl validates anything. Nginx's default site is reachable on port 80 from that moment.
- The release's `needrestart` runs after dpkg and may restart other services that use updated libraries.
- APT downloads the archives into `/var/cache/apt/archives` and debconf records default answers for the new packages before Barectl's guard compares the transaction, so both remain even when the guard then stops APT before dpkg changes anything.
- A metadata refresh runs `apt-get update` for every configured source, including third-party ones, which the review lists; each must authenticate and update without errors or warnings, or the refresh fails. It runs the distribution's update hooks, which refresh caches such as the command-not-found database and the login message's update count. It makes every earlier package plan of the server stale.

Barectl never rolls back or repairs. A run that fails can leave packages installed, partly configured, or a service stopped.

## Recovering with ordinary tools

The run's page says whether dpkg changed anything. When it did and the run failed, or a reboot interrupted it:

```bash
sudo dpkg --audit                 # packages left unfinished
sudo dpkg --configure -a          # finish configuring unpacked packages
sudo apt-get install --reinstall <package> # one dpkg --audit says to reinstall
sudo apt-get install -f           # complete an interrupted installation
systemctl status nginx php8.5-fpm mariadb # see whether a service failed (php8.3-fpm on 24.04)
sudo systemctl reset-failed nginx # clear a failed state once its cause is fixed
journalctl -u 'barectl-apply-*'   # the runs' own output, while the journal keeps it
```

Until root completes an interrupted change, dpkg refuses to let other accounts read its database, so a review prepared through a sudo account says that Barectl could not read dpkg's audit and asks for `sudo dpkg --configure -a`. Then prepare a new plan. It reviews the server as it is now: a completed profile has no changes, a stopped service gets a start plan, and anything else is refused with its reason.

## MariaDB

The **MariaDB profile** installs the release's MariaDB server from its own archive: MariaDB 10.11 from `noble`'s `main` and `universe` components on Ubuntu 24.04, and MariaDB 11.8 from `resolute`'s `main` on Ubuntu 26.04, with the dependency closure APT resolves without recommended packages. The review lists every package at its exact version, like any other profile, and the same guard admits only that transaction. Every package must be offered by the release's archive from one of those components. The revisions it is qualified on are in the [v0.3 qualification record](v0.3-qualification.md#mariadb-profile).

The server package's maintainer scripts initialize the engine while dpkg runs: they create the data directory, `/var/lib/mysql` on 24.04 and `/var/lib/mariadb` on 26.04, owned by `mysql` and holding the system tables, create `root@localhost` without a usable password, authenticated by the Unix identity of the local root user through the `unix_socket` plugin, write `/etc/mysql/debian.cnf`, readable by root only, point the `my.cnf` alternative at `/etc/mysql/mariadb.cnf`, and then enable and start `mariadb.service`. The distribution's configuration makes MariaDB listen on the local socket `/run/mysqld/mysqld.sock` and on `127.0.0.1` port 3306 only. The review shows these effects. Barectl changes none of them and never passes a database password in a plan, a command or a log.

### Readiness

MariaDB is ready when root administers it through the local socket as the distribution set it up. Barectl checks this with one fixed, read-only command run as root, without a password and without reading option files:

```text
/usr/bin/mariadb --no-defaults --protocol=socket --socket=/run/mysqld/mysqld.sock --user=root -N -B -e "SELECT CURRENT_USER(); SHOW CREATE USER 'root'@'localhost'; SELECT COUNT(*) FROM mysql.global_priv WHERE User = '' OR (User = 'root' AND Host <> 'localhost')"
```

Its output must be exactly `root@localhost`, then ``CREATE USER `root`@`localhost` IDENTIFIED VIA mysql_native_password USING 'invalid' OR unix_socket``, then `0`: root authenticates only by `unix_socket`, the password entry cannot be used, and there is no anonymous or remote root account.

- **Preparing a plan.** When MariaDB is installed and running, preparation runs the check as root, or through `sudo -n` when `sudo -n -l` lists that exact command as authorized without a password. A review is a plan with no changes only when the check ran and printed that output. Without that privilege it is refused as *administrative socket readiness unverified*; with another output or a failed connection it is refused as not the distribution's administration. Run the review as root or authorize the exact command, or restore the distribution's accounts through ordinary administration. A stopped engine is not checked; its start plan checks it after starting.
- **Applying.** Every run ends with the same check as root, and fails with the configuration check's execution outcome when the output differs.
- **Verifying.** Verification then reads, without privilege, that every reviewed package is installed with the marks kept as for any profile, that `mariadb.service` is the distribution's unit, enabled and running, that the data directory and its `mysql` system-table directory exist and belong to `mysql`, that port 3306 listens at `127.0.0.1` and nowhere else, that a socket listens at `/run/mysqld/mysqld.sock`, that `/etc/mysql/my.cnf` resolves to `/etc/mysql/mariadb.cnf`, that `/etc/my.cnf` does not exist, that `mariadbd --print-defaults` reports the release's qualified options, and that `mariadbd --version` names the installed `mariadb-server` version.

An installed package or a running process alone is never reported ready.

### What is refused

An established engine is a plan with no changes, and its databases are left alone. A stopped or disabled one gets a plan that enables and starts it. Everything else is refused, without erasing, migrating or adopting anything:

- another database server's packages installed or left configured: `mysql-server*`, `mysql-client*`, `mysql-community-*`, `mysql-router*`, `default-mysql-server*`, `default-mysql-client*`, `percona-*`, or a versioned `mariadb-server-*`, `mariadb-server-core-*`, `mariadb-client-*` or `mariadb-client-core-*` package;
- data the installed packages do not account for: the data directory or `/var/log/mysql` while `mariadb-server` is not installed, such as what a purge leaves behind by default, another release's data directory, MySQL's `/var/lib/mysql-files`, or `/etc/my.cnf`. A dangling symbolic link counts as present;
- an installed engine whose data directory is not a `mysql`-owned directory holding its `mysql` system tables;
- leftover configuration of a removed MariaDB package, or anything under `/etc/mysql` that is not the packages' default: changed or additional files, such as another listener or authentication setting, or a changed `debian.cnf` when the SSH user is root and can read it;
- a `my.cnf` alternative set manually before installation, or one that does not resolve to `/etc/mysql/mariadb.cnf` once installed, and `mariadbd --print-defaults` options other than the release's;
- an installed, running engine whose [readiness](#readiness) is unverified or not the distribution's;
- another service on port 3306 or on the socket while MariaDB is not running, or a running MariaDB that listens anywhere besides `127.0.0.1`;
- a masked, failed, overridden or changing `mariadb.service`.
- an installed `mariadb-server` version that the release's own archive does not offer;

After completing an interrupted MariaDB installation with the tools above, check the service with `systemctl status mariadb` and root's access with `sudo mariadb -e 'SELECT CURRENT_USER()'`. Removing MariaDB is ordinary administration; `apt-get purge` keeps the data directory by default, and a later review refuses it until you move or remove it. An installed engine is established only when the release's archive offers its `mariadb-server` version from the profile's components, as `apt-cache madison` lists it; one installed from another repository, such as MariaDB's own, is refused, as is a version the archive no longer lists. When the installed version follows Ubuntu's [version conventions for updates](https://ubuntu.com/project/docs/how-ubuntu-is-made/concepts/version-strings/), which always name `ubuntu`, and the archive offers a newer version of the same package, the refusal names it as an update the archive has superseded and asks you to upgrade it, such as with `sudo apt-get install --only-upgrade mariadb-server`, then prepare again; any other version is refused as possibly from another repository.

## Authorizing readiness checks

A database profile's review runs its readiness check with privilege. When the SSH user is not root, sudo must authorize the exact command without a password. With the original sudo, which Ubuntu 24.04 uses and Ubuntu 26.04 provides as `sudo.ws`, a rule such as the following, for an SSH user named `deploy` and in a file under `/etc/sudoers.d`, authorizes `systemd-run` and the MariaDB check and nothing else. The backslashes escape the characters sudoers treats as separators; the check's arguments contain no wildcard characters, so the rule matches only the exact command:

```text
deploy ALL=(root) NOPASSWD: /usr/bin/systemd-run
deploy ALL=(root) NOPASSWD: /usr/bin/mariadb --no-defaults --protocol\=socket --socket\=/run/mysqld/mysqld.sock --user\=root -N -B -e SELECT CURRENT_USER(); SHOW CREATE USER 'root'@'localhost'; SELECT COUNT(User) FROM mysql.global_priv WHERE User \= '' OR (User \= 'root' AND Host <> 'localhost')
```

Ubuntu 26.04's default sudo, sudo-rs, splits a rule's arguments at spaces and cannot express one argument that contains spaces, such as the check's query, so no rule for the exact command matches. With sudo-rs, run the review as root, grant the SSH user a rule that authorizes every command, or select the original sudo with `update-alternatives --set sudo /usr/bin/sudo.ws`. Without the authorization, an installed engine is refused as unverified, never reviewed as established.

## Native records and their limits

Each run is a transient systemd service named `barectl-apply-<32 hex digits>.service`. systemd keeps it after it ends, so `systemctl list-units --all 'barectl-apply-*'` lists the runs on the server, from every controller. Their output is in the system journal only as long as the server's own journal retention keeps it; Barectl's outcomes rest on the unit state, not on the journal. The only other thing Barectl uses on the server is the empty lock file `/run/lock/barectl/mutation.lock`, which excludes concurrent runs from every controller and alias and disappears at reboot.

New runs are refused while 100 finished units are retained. **Clear finished bootstrap runs** reviews and clears finished units with no processes, including other controllers' runs; it never stops a running one, keeps journal entries, and keeps Barectl's own audit. Another controller that was still establishing the outcome of a cleared run can then only close it as outcome unknown.

## Losing the controller versus rebooting the server

Accepted work belongs to the server's systemd. Closing the browser, losing the network, stopping the worker, or destroying the controller and its database leave a running installation to finish. Check outcome from the same or a restarted controller records its outcome. Another installation, with its own database and access, sees the server's current packages, services and finished units, but none of the first controller's accounts, plans, approvals or history.

A reboot is different. It stops a running bootstrap unit, and transient units and the lock directory do not survive it. Nothing resumes the run, and an installation it interrupted can leave packages unfinished for the recovery above. Barectl then shows **Outcome unknown so far**. An operator allowed to apply that action can acknowledge it and press **Close as outcome unknown**; Barectl closes the run only after it takes the mutation lock and proves that the server restarted or the deadline passed and that no bootstrap run is active. The run then shows **Outcome unknown: this run may have changed the server**, never that nothing changed. A submission still in transit when the server rebooted is refused by the server when it arrives, before any change.

## Removing a registration

Removing a server deletes its registration, discovery history and plans from Barectl, and keeps finished apply runs as audit, marked as belonging to a removed registration, each with its requester, reviewed effects and exact reviewed changes: every package at its version, or every unit a cleanup cleared. It is refused while any run is queued, running or being reconciled. Removal never connects to the server: its packages, services and retained units stay as they are.
