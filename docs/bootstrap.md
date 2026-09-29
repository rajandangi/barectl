# Bootstrapping a server

Barectl can prepare an Ubuntu 24.04 or 26.04 LTS server with the distribution's Nginx, or with the FPM and CLI of the release's default PHP version, PHP 8.3 on 24.04 and PHP 8.5 on 26.04, after you review the exact change. It can also refresh the server's package metadata and clear the records of finished bootstrap runs, each as its own reviewed action. This page describes what the current implementation does and what it requires. The design and its rationale are in [v0.2: reviewed bootstrap](v0.2.md); the evidence behind these claims, including what has not been tested, is in the [v0.2 qualification record](v0.2-qualification.md). Technical details of each read and payload are in [SSH connections and discovery](ssh-connections.md#plan-preparation).

Bootstrap installs ordinary Ubuntu packages with their default configuration. It installs no Barectl agent and writes no Barectl records on the server. After a run, the server is managed with the usual tools, `apt`, `dpkg`, `systemctl` and `journalctl`, whether Barectl is still installed or not.

## Prerequisites

The server:

- Runs Ubuntu 24.04 LTS or Ubuntu 26.04 LTS with systemd as its init system, and APT and dpkg as its package manager, on amd64 or arm64, with the release's own APT and systemd: apt 2.8 and systemd 255 on 24.04, apt 3.2 and systemd 259 on 26.04. The qualification record lists the revisions and architectures that were tested. Any other release, including an interim one, is refused before anything but its platform is read.
- Has authenticated package indexes of its own release's three suites, including their `main` component: `noble`, `noble-updates` and `noble-security` on 24.04, or `resolute`, `resolute-updates` and `resolute-security` on 26.04, from archives reached over `http` or `https`, and none of their Release files has expired. Nginx comes from `main`; PHP comes partly from `universe`, which Ubuntu's server installations and cloud images enable by default. Other sources, such as the release's backports or a PPA, may stay configured, but a plan is refused when its transaction would take a package from any other suite or archive, including another Ubuntu release's, a PPA, a local repository or removable media. A server never receives another release's packages.
- Has no APT configuration that weakens authentication, overrides package selection or changes how dpkg runs, and only the APT hooks that its release's own `debconf`, `needrestart`, `update-notifier-common`, `apt`, `command-not-found`, `ubuntu-pro-client`, `packagekit`, `appstream` and `snapd` packages install. Any other hook refuses every plan: hooks run as root during package changes.
- Has a healthy package database (`dpkg --audit` reports nothing) and no held package that the change would touch.
- Is reachable over SSH from the controller as root, or as a user with noninteractive sudo (`NOPASSWD`). On Ubuntu 26.04, `sudo` is sudo-rs by default, and the original sudo, `sudo.ws`, works the same way here. Barectl checks with `sudo -n -l` that sudo authorizes the exact command it runs: `/usr/bin/systemd-run` for each run, `ss` for the listener query while preparing a plan, and `/usr/bin/sh` for the probe that closes an unknown outcome. It never prompts for a password and never installs a sudo policy.

**Root-equivalent access.** Authorizing an account to run `systemd-run` or a shell through sudo gives it full control of the server. Barectl's own permissions decide who may ask for a change; they do not limit what the SSH account can do. Use a dedicated account, keep its key on the controller host, and treat the controller and anyone who can use its keys as having root on the server. Ordinary discovery never uses sudo.

The controller: register the server by its SSH alias and run the worker (`manage.py db_worker`) as the account whose SSH configuration, keys and known_hosts Barectl should use, as the [README](../README.md#run-locally) describes.

Barectl permissions, granted per account on the controller host:

| Permission | Allows |
| --- | --- |
| `servers.view_server` | Seeing the inventory. Alone, it shows no plans, runs or their audit. |
| `bootstrap.view_configurationplan` | Reviewing plans, preparations and apply runs, and pressing **Check outcome**. |
| `bootstrap.prepare_configurationplan` | Preparing plans, with the permission above. |
| `bootstrap.apply_configurationplan` | Applying metadata refresh, Nginx and PHP plans, and closing their runs as outcome unknown. |
| `bootstrap.clear_native_results` | Applying and closing cleanups of finished bootstrap runs. |

## Review, apply and check

1. On the server's page, choose **Nginx profile**, **PHP profile (FPM and CLI)**, **Package metadata refresh** or **Clear finished bootstrap runs**, and press **Prepare plan**. The worker reads the server without changing it; preparing never runs `apt-get update` or installs anything.
2. Review the plan. It names the server's release and, for PHP, the version it installs, the packages at exact versions with every dependency APT would install, the service effects and exposure, the evidence it was derived from, and every reason it is refused, each with what ordinary administration resolves it. A refused plan cannot be applied. A profile that is already installed and healthy is a plan with no changes, even when newer versions are available; bootstrap never upgrades.
3. Press **Apply plan** within 15 minutes of preparation. The confirmation names the server, alias, plan and deadline. A plan is applied at most once: repeating the request shows the same run.
4. The run's page follows it. **Execution** is what the server's systemd recorded; **Verification** is a separate check with fresh reads that the packages, marks, service and listeners are as reviewed. A run succeeds only when both hold. Afterwards Barectl refreshes discovery, so the server page shows the native state.

The run is refused before it changes anything when the server restarted since the review, the deadline passed, another bootstrap run is active, the reviewed evidence changed, or the package manager is busy. Each refusal needs a new plan; Barectl never retries or waits to apply an old plan.

When the answer from the server is lost, or the controller stops, the run shows **Outcome not established** and keeps the server's active slot. Press **Check outcome** later, from the same controller or after restarting it; it inspects the same systemd unit and never submits the run again.

## What the profiles install

- **Nginx**: `nginx` and its dependencies, without recommended packages. The distribution's default site serves HTTP on port 80 on every IPv4 and IPv6 address as soon as the package starts Nginx.
- **PHP**: the release's default version, `php8.3-fpm` and `php8.3-cli` on Ubuntu 24.04 or `php8.5-fpm` and `php8.5-cli` on Ubuntu 26.04, and their dependencies, without recommended packages. No web server is installed, and Nginx is not required. The default `www` pool listens only on the local socket `/run/php/php8.3-fpm.sock`, or `/run/php/php8.5-fpm.sock`; when the service starts, it registers that socket as the `/run/php/php-fpm.sock` alternative. Only missing packages are named to APT: a CLI package that another package already pulled in keeps its automatic mark.

Bootstrap keeps the distribution's defaults and does not create sites, pools, users, databases or certificates. It refuses rather than adopts a server that already has something else: changed or additional configuration files, leftover configuration of removed packages, unit overrides, masked or failed units, another service on port 80 or on the pool's socket, or, for PHP, any other PHP version's packages or directories under `/etc/php`. An installed profile whose service is only stopped or disabled gets a plan that enables and starts it, without APT.

## Effects to expect while a run installs

- Package maintainer scripts enable and start the service before Barectl validates anything. Nginx's default site is reachable on port 80 from that moment.
- The release's `needrestart` runs after dpkg and may restart other services that use updated libraries.
- APT downloads the archives into `/var/cache/apt/archives` and debconf records default answers for the new packages before Barectl's guard compares the transaction, so both remain even when the guard then stops APT before dpkg changes anything.
- A metadata refresh runs `apt-get update` and the distribution's update hooks, which refresh caches such as the command-not-found database and the login message's update count. It makes every earlier package plan of the server stale.

Barectl never rolls back or repairs. A run that fails can leave packages installed, partly configured, or a service stopped.

## Recovering with ordinary tools

The run's page says whether dpkg changed anything. When it did and the run failed, or a reboot interrupted it:

```bash
sudo dpkg --audit                 # packages left unfinished
sudo dpkg --configure -a          # finish configuring unpacked packages
sudo apt-get install -f           # complete an interrupted installation
systemctl status nginx php8.5-fpm # see whether a service failed (php8.3-fpm on 24.04)
sudo systemctl reset-failed nginx # clear a failed state once its cause is fixed
journalctl -u 'barectl-apply-*'   # the runs' own output, while the journal keeps it
```

Until root completes an interrupted change, dpkg refuses to let other accounts read its database, so a review prepared through a sudo account says that Barectl could not read dpkg's audit and asks for `sudo dpkg --configure -a`. Then prepare a new plan. It reviews the server as it is now: a completed profile has no changes, a stopped service gets a start plan, and anything else is refused with its reason.

## Native records and their limits

Each run is a transient systemd service named `barectl-apply-<32 hex digits>.service`. systemd keeps it after it ends, so `systemctl list-units --all 'barectl-apply-*'` lists the runs on the server, from every controller. Their output is in the system journal only as long as the server's own journal retention keeps it; Barectl's outcomes rest on the unit state, not on the journal. The only other thing Barectl uses on the server is the empty lock file `/run/lock/barectl/mutation.lock`, which excludes concurrent runs from every controller and alias and disappears at reboot.

New runs are refused while 100 finished units are retained. **Clear finished bootstrap runs** reviews and clears finished units with no processes, including other controllers' runs; it never stops a running one, keeps journal entries, and keeps Barectl's own audit. Another controller that was still establishing the outcome of a cleared run can then only close it as outcome unknown.

## Losing the controller versus rebooting the server

Accepted work belongs to the server's systemd. Closing the browser, losing the network, stopping the worker, or destroying the controller and its database leave a running installation to finish. Check outcome from the same or a restarted controller records its outcome. Another installation, with its own database and access, sees the server's current packages, services and finished units, but none of the first controller's accounts, plans, approvals or history.

A reboot is different. It stops a running bootstrap unit, and transient units and the lock directory do not survive it. Nothing resumes the run, and an installation it interrupted can leave packages unfinished for the recovery above. Barectl then shows **Outcome unknown so far**. An operator allowed to apply that action can acknowledge it and press **Close as outcome unknown**; Barectl closes the run only after it takes the mutation lock and proves that the server restarted or the deadline passed and that no bootstrap run is active. The run then shows **Outcome unknown: this run may have changed the server**, never that nothing changed. A submission still in transit when the server rebooted is refused by the server when it arrives, before any change.

## Removing a registration

Removing a server deletes its registration, discovery history and plans from Barectl, and keeps finished apply runs as audit, marked as belonging to a removed registration, each with its requester, reviewed effects and exact reviewed changes: every package at its version, or every unit a cleanup cleared. It is refused while any run is queued, running or being reconciled. Removal never connects to the server: its packages, services and retained units stay as they are.
