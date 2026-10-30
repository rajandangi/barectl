# Setting up a server

**Set up server** turns a Fresh host into a Target stack host: it installs the pinned Nix, realises Caddy and the foundation's tools from the [runtime catalog](runtimes.md), configures Caddy and makes the journal persistent. Runtimes and sites are added afterwards. This page describes what the setup does, what it requires and how to recover from it. The decisions behind it are [ADR 0026](adr/0026-manage-fresh-hosts-on-one-target-stack.md), [ADR 0027](adr/0027-serve-sites-and-https-with-caddy.md) and [ADR 0028](adr/0028-supply-runtimes-and-tools-from-pinned-nix.md).

Setup writes no Barectl inventory or marker on the server. Afterwards the server is managed with ordinary tools, `systemctl`, `journalctl`, `caddy` and `nix-store`, whether Barectl is still installed or not.

## Host standing

Every discovery and every review judges the server's standing from native evidence ([host standing](target-architecture.md#host-standing)):

- **Fresh host**: Ubuntu 26.04 LTS on amd64 or arm64, with nothing of the target stack and nothing foreign. Setup is offered.
- **Incomplete foundation**: part of the foundation is present in its supported form, as after an interrupted setup. Setup continues from what exists.
- **Target stack**: the whole foundation is present. Runtimes and sites can be added.
- **Not manageable**: another release or architecture, missing privilege, a web server installed from APT (Apache, Nginx, Lighttpd, Caddy, HAProxy or OpenLiteSpeed), APT PHP packages, HAProxy processes outside the site convention, a hosting panel's directories, a Nix installation that is not Barectl's, Nix build-user IDs already taken, or another listener on ports 80 or 443. A server set up by an earlier Barectl build has Nginx and APT PHP, and is reported as such. Barectl shows each reason and offers no changes; resolve them through ordinary administration and run discovery again.

Overview shows the standing, its named reasons and each foundation stage. A clock that NTP has not synchronized is a warning, not a refusal.

## Prerequisites

The server:

- runs Ubuntu 26.04 LTS with its own apt 3.2, dpkg 1.23 and systemd 259, on amd64 or arm64;
- is reachable over SSH from the controller as root, or as a user with noninteractive sudo (`NOPASSWD`). Barectl checks with `sudo -n -l` that sudo authorizes each exact command it runs and never prompts for a password;
- has at least 4 GiB free disk and 900 MiB available memory. These are provisional admission thresholds, not a qualified minimum host size;
- is not running `apt-daily` or `apt-daily-upgrade`. A fresh cloud host often runs them during its first minutes; wait and prepare again.

**Root-equivalent access.** Authorizing an account to run `systemd-run` or a shell through sudo gives it full control of the server. Barectl's permissions decide who may ask for a change; they do not limit what the SSH account can do. Treat the controller, and anyone who can use its keys, as having root on the server.

## Host foundation

Open the server's **Setup** section, or follow **Set up server** from Overview, and prepare the review. The steps are Connect, Check host, Review, Apply and verify. Opening setup, review or Stack pages reads stored evidence and makes no SSH connection.

The review lists every effect: the Nix release and its installer's SHA-256, the shell profile files the installer edits, the 32 build users at UIDs 30001 to 30032, the catalog store paths with their download and unpacked sizes, the Caddy unit and main configuration, the per-site service templates, the journald setting and the network destinations (`releases.nixos.org` and `cache.nixos.org` over HTTPS). Its effects are server-wide, so applying needs Shared consent: an Administrator, or the `operations.change_shared` permission.

The run is one transient systemd unit under the shared mutation lock. It reports the stages `preflight`, `Nix`, `catalog`, `Caddy`, `journald` and `verify`; missing progress lines do not mean failure.

1. **Preflight** rechecks the boot, the deadline, the reviewed evidence, privilege, release, architecture, disk and memory, foreign packages and listeners, reserved user IDs and running package-maintenance units, and refuses before any change.
2. **Nix** downloads the official multi-user installer for Nix 2.35.2, checks it against the SHA-256 in the catalog lock before extracting or running it, and runs it with `--daemon --yes --no-channel-add`. `/etc/nix/nix.conf` admits and trusts only root, uses `cache.nixos.org` alone with its published key, and sets `max-jobs = 0` and `fallback = false`, so a server never compiles.
3. **Catalog** realises the exact store paths of Caddy, Composer, WP-CLI and HAProxy with `nix-store --realise` and sets each as a profile under `/nix/var/nix/profiles/barectl/`. Nothing is evaluated on the server.
4. **Caddy** creates the `caddy` system user, `/etc/caddy/Caddyfile`, the `/etc/caddy/sites/` directory and `caddy.service`, and installs the per-site templates `haproxy-site@.service`, `php-fpm-site-php84@.service` and `php-fpm-site-php85@.service`.
5. **journald** writes `/etc/systemd/journald.conf.d/50-barectl.conf` with `Storage=persistent`.
6. **Verify** checks each stage against its supported form: the daemon active and admitting only root, Caddy running its configuration, the admin socket private, no listener on port 2019, unknown hosts answered with 404, and persistent journal storage.

`caddy.service` follows upstream's unit: it runs `/nix/var/nix/profiles/barectl/caddy/bin/caddy run` as the `caddy` user with `Type=notify`, reloads through `caddy reload`, and keeps its state in `/var/lib/caddy`. The main configuration sets the admin endpoint to the Unix socket `/run/caddy/admin.sock` (mode 0600 in a 0700 runtime directory), so it never listens on TCP; leaves automatic HTTPS on and adds the optional certificate contact email when one is set ([HTTPS](tls.md#certificate-contact-email)); enables strict SNI host matching; imports `/etc/caddy/sites/*.caddy`; and answers 404 on port 80 for any host no site claims.

After a verified run Barectl queues discovery. A repeated review on a finished host proposes no changes, and a fresh controller with its own credentials and trust recognizes the same Target stack.

A Nix installation that is incomplete or not Barectl's is refused as **Nix installation incomplete**, with the [official Nix 2.35 uninstall instructions](https://nix.dev/manual/nix/2.35/installation/uninstall.html). Barectl never removes it. A setup that stopped partway is an Incomplete foundation: the next review keeps the stages that exist in their supported form and proposes the rest.

Sources: the [Nix 2.35 installation manual](https://nix.dev/manual/nix/2.35/installation/installing-binary.html), [daemon settings](https://nix.dev/manual/nix/2.35/command-ref/conf-file.html), [profiles](https://nix.dev/manual/nix/2.35/command-ref/nix-env/set.html), [Caddy global options](https://caddyserver.com/docs/caddyfile/options), [Caddy's command line](https://caddyserver.com/docs/command-line) and [upstream's Caddy unit](https://raw.githubusercontent.com/caddyserver/dist/master/init/caddy.service). The fixed payload composes these native tools because pyinfra operations would run outside the reviewed single-unit admission, as recorded on [#336](https://github.com/rajandangi/barectl/issues/336#issuecomment-6168831648).

## Native records and their limits

Each run of any change is a transient systemd service named `barectl-apply-<32 hex digits>.service`, from every controller alike. systemd unloads it when it ends, and its output stays in the journal: `journalctl -u barectl-apply-<32 hex digits>` shows its stage lines and its one `barectl-result` line, which records the outcome Barectl reads ([ADR 0006](adr/0006-use-native-bootstrap-execution.md)). While a run is active, `systemctl list-units 'barectl-apply-*'` shows it. The other Barectl files on the server are the empty lock file `/run/lock/barectl/mutation.lock`, which excludes concurrent changes from every controller, and a run's staged body in the same directory while it runs; both disappear at reboot.

New changes are refused while 100 finished Barectl units are retained, which happens only when something keeps them loaded. The server's **Changes** page offers a reviewed cleanup that clears finished units with no processes, including other controllers'. It never stops a running unit, and it keeps the journal and Barectl's own records.

## Losing the controller versus rebooting the server

Accepted work belongs to the server's systemd. Closing the browser, losing the network, stopping the worker, or losing the controller and its database leave a running change to finish. **Check outcome** from the same or a restarted controller establishes its result from the same unit and its journal and never submits it again. Another controller sees the server's current state and retained units, but none of the first controller's accounts, reviews or history.

A reboot stops a running unit, and transient units and the lock directory do not survive it. Nothing resumes the run, and the run shows **Outcome unknown so far**. An operator allowed to apply that change can acknowledge it; Barectl closes the run only after it takes the lock and proves that the server restarted or the deadline passed and that no change is running. The run then says it may have changed the server, never that nothing changed. Run discovery and prepare a new review, which proposes only what is missing. See [native recovery](recovery.md).

## Removing a registration

Removing a server deletes its registration, discovery history and unapplied reviews from this controller, and keeps finished runs with their reviews as audit, marked as belonging to a removed registration. It is refused while any operation is queued, running or being reconciled. Removal never connects to the server.
