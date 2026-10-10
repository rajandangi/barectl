# Target architecture

Accepted direction for [#323](https://github.com/rajandangi/barectl/issues/323). Nothing in this document is implemented. It replaces the planned Nginx, Certbot, APT-PHP and rclone stack for new servers; the released v0.2 and v0.3 behavior described in the [README](../README.md#current-status) and [architecture](architecture.md) remains what the code does until Phase A lands and is qualified. Sources were read on 2026-10-10.

Barectl is a portable, local-first, agentless control plane for fresh Ubuntu 26.04 LTS servers. Ubuntu 24.04 is not supported on the target stack; a later LTS is added only by its own reviewed release policy and qualification. Mature native components own hosting mechanics. Barectl owns the operator experience, review, admission, reconciliation and recovery, through the existing pyinfra SSH connection and the detached native execution of [ADR 0006](adr/0006-use-native-bootstrap-execution.md). The [core philosophy](../README.md#core-philosophy) is unchanged: the server is the source of truth, and a new controller with authorized SSH access reconstructs supported state without the previous controller's database.

## Stack

| Area | Target | Supply | Decision |
|---|---|---|---|
| Operating system and native services | Ubuntu LTS, MariaDB and/or PostgreSQL, Valkey | Ubuntu archive through reviewed APT transactions ([ADR 0007](adr/0007-admit-exact-package-transactions-with-an-inline-apt-guard.md)) | [ADR 0026](adr/0026-manage-fresh-hosts-on-one-target-stack.md) |
| Adding a server | Saved connection, host key confirmed against the provider's fingerprint | none | [ADR 0034](adr/0034-trust-a-fresh-host-by-confirming-its-fingerprint.md) |
| Changes | One change engine, consent derived from declared effects | none | [ADR 0035](adr/0035-one-change-engine-with-effect-derived-consent.md) |
| Web serving and HTTPS | Caddy | Nix | [ADR 0027](adr/0027-serve-sites-and-https-with-caddy.md) |
| Language runtimes and tools | PHP CLI and FPM, Composer, WP-CLI, Node.js, Python, uv, restic, Caddy | One multi-user Nix installation, exact store paths from a catalog lock | [ADR 0028](adr/0028-supply-runtimes-and-tools-from-pinned-nix.md) |
| PHP serving | One PHP-FPM master per runtime, one pool per site | Nix | [ADR 0029](adr/0029-share-one-php-fpm-master-per-runtime.md) |
| Object cache | One Valkey instance per site that enables it | Ubuntu archive | [ADR 0030](adr/0030-give-each-site-its-own-valkey-instance.md) |
| Backups | restic, per-site repositories onsite plus optional S3-compatible offsite | Nix | [ADR 0031](adr/0031-back-up-with-restic.md), [ADR 0037](adr/0037-capture-scheduled-backups-live.md) |
| Settings and secrets | Private native files written through confidential SSH input | none | [ADR 0032](adr/0032-keep-secrets-in-private-native-files.md) |
| Build and tests | Two test layers, 10-minute target, 15-minute limit | none | [ADR 0033](adr/0033-prove-real-behavior-in-two-test-layers.md) |
| Background work | Persistent systemd services and timers in per-site slices | Ubuntu | [ADR 0036](adr/0036-run-site-automation-in-per-site-slices-without-the-global-lock.md) |
| Logs | journald, Caddy file logs, application logs | Ubuntu, Caddy | this document |

APT keeps owning the operating system and native services. Nix owns Barectl's language runtimes and the tools that need a newer or pinned version than the archive offers. No server mixes APT PHP and Nix PHP for managed sites.

## Host standing

V1 provisions and manages fresh, qualified Ubuntu 26.04 LTS hosts. Each architecture (amd64, arm64) is supported only after its own qualification. See [ADR 0026](adr/0026-manage-fresh-hosts-on-one-target-stack.md).

Every discovery and every review judges the host's standing from native evidence, with no marker file on the server:

| Standing | Meaning |
|---|---|
| Fresh host | A supported release and architecture with nothing of the target stack and nothing foreign |
| Incomplete foundation | Part of the host foundation is present in its supported shape, and nothing foreign is present |
| Target stack | The whole host foundation is present in its supported shape |
| Not manageable | A wrong release or architecture, missing privilege, or another web stack, PHP installation, panel or Nix installation that is not Barectl's |

Discovery and review share one pure judgment over the evidence, so resuming after a failure or from a second controller needs no extra mechanism. Servers set up by earlier Barectl builds and other panels' servers are Not manageable: Barectl reads them and shows why, and never rewrites them.

On a target-stack host, discovery reads Caddy, Nix, FPM, systemd, database, Valkey and restic evidence and adopts administrator changes that stay within the supported settings, instead of requiring byte-exact files. A resource with a setting Barectl does not interpret is Outside supported settings: it is reported once, and only the changes that depend on it are blocked.

## Adding a server

Phase A adds servers through a saved connection: address, user (root by default), port and a key reference, either this computer's SSH agent or an approved key file. The connection never stores a private key. A fresh cloud host gets new host keys at first boot, so Barectl does not ask the operator to edit SSH files first. The operator pastes the fingerprint the provider shows for the new host; Barectl connects, accepts the presented key only on an exact match and records it in a Barectl-owned known_hosts file on the controller. A changed or revoked key is refused, and no key is trusted on first use. The check result shows the host's standing and, for a Fresh host, the next action, Set up server. See [ADR 0034](adr/0034-trust-a-fresh-host-by-confirming-its-fingerprint.md).

## Host foundation

Setting up a Fresh host is one reviewed plan, executed as one transient unit under the shared lock ([ADR 0006](adr/0006-use-native-bootstrap-execution.md)). Its stages run in order and each reports its own result:

1. Preflight: Ubuntu 26.04, a qualified architecture, root or the exact sudo authorization, disk and memory headroom, no other web stack, PHP or panel, and neither `apt-daily` nor `unattended-upgrades` running. A host that fails any check is refused cleanly, before anything changes.
2. Nix: install the pinned release and write `nix.conf` ([Nix](#nix)).
3. Catalog realisation: Caddy and the tools from the catalog lock.
4. Caddy: the unit, the `caddy` user and the main configuration ([Caddy](#caddy)).
5. journald: a drop-in for persistent storage.
6. Verify: each stage's result is checked against its supported shape.

Runtimes and FPM masters are not part of the foundation. A runtime is added when a site first selects it, so small hosts do not run idle masters.

## Changes and consent

One change engine owns every change: prepare, review, apply natively, verify and reconcile. Each kind of change supplies its inspection, a pure review, a native body and its verification; a run refers to the one stored review it applies. The review declares the change's effects, and its consent level follows from them: Read, Site, Shared or Destructive. A Shared change lists every affected site, and that list is rechecked under the lock before apply. See [ADR 0035](adr/0035-one-change-engine-with-effect-derived-consent.md).

## Scope and non-goals

The trust model is one owner or a trusted team hosting their own applications. Sites are separated by Unix accounts, private directories, FPM pools, database principals and their own cache instances; they share the kernel, Caddy, PHP-FPM masters and SQL engines, which is not container or VM isolation. V1 offers no hostile multi-tenancy, container orchestration, billing, DNS hosting or email hosting, and no arbitrary Caddyfile or system editing. A site's SSH user is not a confined shell; SFTP-only chroot is offered where suitable. Metrics are on demand (CPU, memory, disk, services, FPM pool status, web checks); persistent charts need a later server-side sampler.

Public exposure is limited to SSH, 80/tcp, 443/tcp and 443/udp; the firewall standard (Phase E) allows exactly these. Reviewed package updates cover the Ubuntu archive only; Caddy and the runtimes are updated through catalog updates.

## Caddy

Caddy comes from the pinned Nix catalog: nixos-26.05 packages 2.11.7, the current upstream release, while Ubuntu 26.04 ships only [2.6.2](https://packages.ubuntu.com/search?keywords=caddy&searchon=names&suite=all&section=all) in universe, without the 2026 fixes in [2.11.3](https://github.com/caddyserver/caddy/releases/tag/v2.11.3) and later. Upstream's [documented APT repository](https://caddyserver.com/docs/install) answered `402 Payment Required` for its index to a real `apt update` on Ubuntu 26.04 on 2026-10-10. Barectl owns the systemd unit, modeled on [upstream's](https://raw.githubusercontent.com/caddyserver/dist/master/init/caddy.service) (`caddy` user, `Type=notify`, reload through `caddy reload`, state in `/var/lib/caddy`), and the `caddy` system user. No APT package is installed or masked.

Layout: `/etc/caddy/Caddyfile` imports `/etc/caddy/sites/*.caddy`, one file per site. The main file holds only the admin socket, an optional ACME email, `strict_sni_host`, the sites import and a final `:80` catch-all that answers 404 for unknown hosts. The admin endpoint is a Unix socket with mode 0600 in the unit's `RuntimeDirectory`, which site users cannot reach. `caddy reload` reads the admin address from the configuration it loads, so the unit needs no reload override. [The API docs](https://caddyserver.com/docs/api) advise against a TCP admin endpoint where untrusted code runs, and `admin off` would prevent reloads.

A site change runs one step: validate a copy of the whole tree with the candidate swapped in, replace the live file only if it still has the reviewed bytes, reload, verify that the running configuration equals the configuration on disk, and restore the previous file if the reload fails. A failed reload [keeps the running configuration](https://caddyserver.com/docs/api). The previous file is kept only in the plan and run, not in a backup directory on the server. Discovery reads site files through `caddy adapt` on the server, which is upstream's own parser, so Barectl has no Caddyfile parser. Operators change sites through a small catalog of tested settings (primary domain, aliases, redirects, compression), not a free Caddyfile editor.

PHP sites use [`php_fastcgi`](https://caddyserver.com/docs/caddyfile/directives/php_fastcgi) to the site's FPM socket plus `file_server`. Caddy documents no default deny for dotfiles, `wp-config.php` or PHP under uploads, and [`hide` is not a security boundary](https://caddyserver.com/docs/caddyfile/directives/file_server), so every site file carries explicit deny rules that native tests prove: dotfiles except `/.well-known/`, `wp-config.php`, and PHP under uploads including path-info forms. The document root `public/` is owned by the site user with group `caddy` and mode 2750. Domain names have no Barectl length limit beyond DNS's own.

In Phase A a site serves HTTP only: its file uses explicit `http://` addresses, so Caddy starts no automatic HTTPS. Phase B adds the HTTPS workflow, in which [automatic HTTPS](https://caddyserver.com/docs/automatic-https) issues and renews certificates. Caddy offers no certificate status command or endpoint, so discovery reports certificate state from the stored certificate files, a TLS probe and journald. Native tests point Caddy at a local ACME server through `acme_ca` and `acme_ca_root`.

Each site has a JSON access log through the [`log` directive](https://caddyserver.com/docs/caddyfile/directives/log), rotated by Caddy at 20 MiB with 5 files kept for 14 days; sensitive headers are redacted by default.

## Nix

Install multi-user Nix 2.35.2 with the [official installer](https://nix.dev/manual/nix/latest/installation/installing-binary) tarball, whose sha256 is pinned in Barectl's source, run as `install --daemon --yes --no-channel-add`. Ubuntu 26.04's [`nix-bin`](https://packages.ubuntu.com/search?keywords=nix-bin&searchon=names&suite=all&section=all) is 2.34.3, in universe without updates. The installer creates the `nixbld` group and [build users](https://nix.dev/manual/nix/latest/installation/multi-user) from UID 30001, which site accounts must avoid; preflight refuses a host where those IDs are taken.

`nix.conf` sets:

| Setting | Value | Reason |
|---|---|---|
| [`allowed-users`](https://nix.dev/manual/nix/latest/command-ref/conf-file#conf-allowed-users) | `root` | Only root talks to the daemon; there is no operator group. Discovery reads world-readable files and needs no daemon access |
| `trusted-users` | `root` | The manual describes a trusted user as equivalent to root |
| `substituters` | `https://cache.nixos.org` only, with its published key | Nothing comes from another cache |
| `max-jobs` | `0` | The server never builds; a path missing from the cache fails fast |
| `fallback` | `false` | A failed download never turns into a local build |

Servers never evaluate nixpkgs. Barectl's source holds a catalog lock, generated by a CI job from one pinned nixpkgs commit: for each entry and architecture, the exact output store paths and closure size. A server runs [`nix-store --realise`](https://nix.dev/manual/nix/latest/command-ref/nix-store/realise) on exactly those paths and refuses anything else, the Nix counterpart of the exact APT transactions in [ADR 0007](adr/0007-admit-exact-package-transactions-with-an-inline-apt-guard.md). Flakes remain [experimental](https://nix.dev/manual/nix/latest/development/experimental-features) and are not used. Phase A's entries are php84 and php85 (their default builds), Caddy, Composer, WP-CLI, nodejs_22, nodejs_24 and restic. php83 waits until its extensions are checked; extension variants such as phpredis wait for a Phase C spike.

Each runtime is a [profile](https://nix.dev/manual/nix/latest/command-ref/files/profiles) under `/nix/var/nix/profiles/barectl/`, set with [`nix-env --set`](https://nix.dev/manual/nix/latest/command-ref/nix-env/set). Generations are the rollback candidates and garbage-collection roots; collection never uses `-d` and keeps the active and previous generation. Discovery reads the profiles, matches their store paths to the catalog lock, and reads references and closure sizes with `nix-store -q`, not the experimental `nix path-info`. The store is world-readable, so no configuration, credential or user data passes through Nix.

## Runtimes

A runtime is a PHP branch and extension set with a name, such as `php84`. Its exact build changes over time: each catalog update becomes a new profile generation, and the previous generation stays for rollback. Sites select a runtime; identical builds are shared, never copied per site.

Security fixes for PHP, Caddy and the other catalog entries reach servers through a reviewed in-branch catalog update shipped with a Barectl release. Applying it restarts each affected runtime once, after review. This is a stated limitation: a fix published in nixpkgs reaches servers only when Barectl ships a catalog release containing it. The nixpkgs branch itself moves about every six months, when a stable branch ends, as a reviewed change.

The server's default PHP and Node.js commands are links in `/usr/local/bin`. Each site has a root-owned `/var/www/<id>/bin` with `php`, `node`, `composer` and `wp` bound to the site's runtime, which its workers and timers use. Changing the server default never changes existing sites.

## PHP-FPM

Each runtime has one FPM master, run by the template unit `php-fpm@<runtime>` with its configuration under `/etc/php-fpm/<runtime>/`, and one pool per site under the site's own user. The [NixOS module](https://github.com/NixOS/nixpkgs/blob/nixos-26.05/nixos/modules/services/web-servers/phpfpm/default.nix) is the reference for the unit (`Type=notify`, `php-fpm -y`); the unit must not set `PHP_INI_SCAN_DIR`, which the nixpkgs wrapper uses to load extensions. Sockets are keyed by runtime, `/run/php-fpm/<runtime>/<site>.sock`, and reachable only by Caddy. Switching a site's PHP adds a pool on the new runtime, points Caddy at it, then removes the old pool, so requests are not dropped.

[OPcache](https://www.php.net/manual/en/opcache.configuration.php) is one shared cache per master. Its protections are off by default, so every master sets `opcache.validate_permission=1`, `opcache.validate_root=1` and a root-only `opcache.restrict_api`, with no `opcache.file_cache` and no preload; otherwise one site could be served another's cached scripts, reset every site's cache or list other sites' paths ([bug 74182](https://bugs.php.net/bug.php?id=74182)). The pools of a master also share its private `/tmp`, where PHP keeps sessions and uploads by default, and php.net [warns](https://www.php.net/manual/en/session.configuration.php) that a shared session directory lets other users hijack sessions. Every pool therefore has its own session, upload and temporary directories. Native tests must prove these settings block cross-pool reads before any shared master is qualified.

A new build is applied with a restart, not `USR2`, until a native test proves that `USR2` re-execution refuses no connections. Adding or removing a pool uses a reload, which [recycles every pool of the master](https://github.com/php/php-src/blob/master/sapi/fpm/php-fpm.8.in). Pool changes therefore take Shared consent and list the other sites on that runtime, until a native test proves that in-flight requests survive the reload. Per-site limits come from pool settings (`pm.max_children`, `request_terminate_timeout`, `php_admin_value[memory_limit]`); systemd resource limits apply to the master as a whole. Pools keep `clear_env=yes`; passing a non-secret variable to PHP, such as for a WordPress plugin that reads `getenv()`, is an explicit per-site setting. Each pool writes its PHP error and slow logs into the site's log directory.

## Valkey

Sites that enable an object cache get their own Valkey instance from Ubuntu's `valkey-server` ([9.0 on Ubuntu 26.04](https://packages.ubuntu.com/search?keywords=valkey&searchon=names&suite=all&section=all)), from the packaged template unit with a drop-in that runs it as the site user. It listens only on a private Unix socket, keeps no persistence and no password, has its own `maxmemory` and eviction policy, and denies admin commands; the default instance is masked. A shared instance cannot isolate flushes on those versions: Laravel's cache flush [ignores the prefix](https://laravel.com/docs/13.x/cache), the WordPress Redis Object Cache plugin's [README](https://github.com/rhubarbgroup/redis-cache/blob/develop/README.md) documents a database flush path, and per-database ACL rules arrive only in Valkey 9.1. When the operator enables the cache for WordPress, Barectl may install that one pinned plugin. See [ADR 0030](adr/0030-give-each-site-its-own-valkey-instance.md).

## Settings and secrets

Operators edit ordinary variables and secrets in the dashboard. The authoritative copy lives on the server in private site-owned files (`.env`, a private file loaded by `wp-config.php`), never readable at rest in the controller database and never in the Nix store. FPM pools cannot read systemd credentials, whose directory is readable only by the unit's user, and `env[]` has the exposure systemd [warns about](https://www.freedesktop.org/software/systemd/man/255/systemd.exec.html) for `Environment=`. Worker and timer units that run as the site user may use `LoadCredential=`.

A value entered in the browser is held in the run's row encrypted with a key that exists only in the running worker's memory, so it cannot be read after a worker restart or after 10 minutes, and it is cleared once sent. The worker sends it as standard input to a fixed command that stages it in a root-only directory on tmpfs; the ordinary transient unit then consumes it and removes it on every exit path. Values never appear in argv, unit properties, the journal, events or responses, and a canary test in the fast layer checks every one of those places. `php artisan config:cache` copies secrets into `bootstrap/cache/config.php`, which gets the same protection. See [ADR 0032](adr/0032-keep-secrets-in-private-native-files.md).

## Automation

Scheduled tasks are systemd timers with oneshot services; always-on workers are services. Each is a persistent unit named `barectl-site-<id>-<role>` in its site's slice. The site identifiers `apply`, `site`, `repo` and `backup` are reserved so these names never collide. A scheduled tick runs as the site user and does not take the global mutation lock: a site change stops the site's slice first, and a server-wide change does not need to. See [ADR 0036](adr/0036-run-site-automation-in-per-site-slices-without-the-global-lock.md).

A [timer](https://www.freedesktop.org/software/systemd/man/255/systemd.timer.html) never starts a service that is still running; Ubuntu 26.04's systemd 259 offers `DeferReactivation=` so a run that outlasts its interval is not followed immediately by the next. Per-minute jobs set `AccuracySec=1s`, because the default is one minute; oneshot services need an explicit time limit, one hour for the Laravel scheduler. Laravel uses `schedule:run` every minute and `queue:work` workers whose `--timeout` stays below `retry_after` ([queues](https://laravel.com/docs/13.x/queues)). WordPress uses an optional timer running [`wp cron event run --due-now`](https://developer.wordpress.org/cli/commands/cron/event/run/), and only after that timer is verified does Barectl set `DISABLE_WP_CRON`.

## Backups

restic comes from the Nix catalog; nixos-26.05 packages 0.18.1, the same release as Ubuntu 26.04's [universe package](https://packages.ubuntu.com/search?keywords=restic&searchon=names&suite=all&section=all), and later versions arrive with catalog updates. Each site has its own onsite repository and optionally an S3-compatible offsite one (S3, R2). restic's [locks](https://restic.readthedocs.io/en/stable/100_references.html) are taken by restic processes, which other Barectl work does not see, so backup, copy, forget and prune run as native units with one maintenance actor per repository. [Exit codes](https://restic.readthedocs.io/en/stable/075_scripting.html) and JSON output are the parsing contract. `forget` acts only on snapshots carrying Barectl's tags. The kept copy of each scope is verified by reading back that snapshot, not by a plain `check`. Pruning credentials are separated from capture credentials only where the provider allows; R2 does not. R2 also does not implement the S3 Object Lock API and uses its own [bucket locks](https://developers.cloudflare.com/r2/buckets/bucket-locks/); immutability is configured per provider and never implied.

Scheduled captures are live: the database dump first, then the files, and the recovery point says so. Manual captures and the safety capture before a restore pause the site through a Caddy gate and an idle pool, without reloading the shared master. See [ADR 0037](adr/0037-capture-scheduled-backups-live.md).

A recovery point holds the application files, persistent uploads and storage, a database dump streamed over standard input, the site's private configuration where recovery needs it (encrypted by restic like everything else), and a small non-secret description of the application, runtime and database versions. The repository password and recovery instructions are kept apart from the backup, so they survive the server's loss. An export for local development never copies production secrets. Restore follows [ADR 0022](adr/0022-review-destructive-restore-and-coordinated-capture.md): files and database are not one transaction, a safety copy comes first, ownership is reset to the target site user, and a partial or unknown result leaves the site gated for reviewed recovery. A files-only restore is allowed only from a full recovery point, with a warning. See [ADR 0031](adr/0031-back-up-with-restic.md).

## Logs

journald holds host and service logs in persistent storage, set by a drop-in at foundation setup; retention uses `SystemMaxUse`, `SystemKeepFree` and `MaxRetentionSec`, which removes whole files and is approximate. Caddy writes per-site JSON access logs with size and age rotation. PHP error and slow logs and Laravel logs stay in the site's private log directory, rotated by Ubuntu's logrotate or the framework's own daily logs. One run's journal is selected with `journalctl --invocation`. Barectl reads logs through bounded SSH commands and never loads whole files into the controller.

## Tests and build time

A full local build targets 10 minutes and never exceeds 15, and so does required CI. Tests prove behavior an operator or site depends on; tests that only restate the implementation, and tests of removed code, are not kept. The fast layer replays recorded real command output at the `RemoteShell.run` seam of [ADR 0002](adr/0002-keep-the-remote-shell-seam.md), one transcript per server state keyed by the pin set; an unrecorded command fails and asks for a new recording, and the recorder refuses to record secret reads. Native validators (`caddy validate`, `php-fpm -t`) and payload failures before side effects run in one container from the post-bootstrap snapshot. Native lifecycle scenarios run on servers booted from that snapshot, built by Barectl's own foundation apply and keyed by a hash of the rendered payload and the catalog lock. Scenarios share one server per lane with their own names, and nothing in the build reaches the internet: Ubuntu packages, the Nix cache and WordPress archives come from local mirrors. A budget spike measures bootstrap time, snapshot cost, lane scaling and the fast layer before the rest of the harness is built. See [ADR 0033](adr/0033-prove-real-behavior-in-two-test-layers.md).

## Evidence

Measured on 2026-10-10; the host checks ran on Ubuntu 26.04 arm64:

- E1: Caddy's upstream APT repository answered `402 Payment Required` for its index to a real `apt update`. nixos-26.05 packages Caddy 2.11.7, the current upstream release.
- E2: multi-user Nix 2.35.2, installed with `--daemon --yes --no-channel-add`, installs and runs in the disposable-server container; the installer finished 3 seconds after download, and the daemon socket and service were active.
- E3: at the pinned nixos-26.05 commit, evaluation took 8 seconds. Realising php84, php85, Caddy 2.11.7, restic 0.18.1, Composer 2.10.3, WP-CLI 2.12.0 and Node.js 24.21.0 with `max-jobs = 0` took 22 seconds with no builds, and the store totalled 995 MiB. php84's default build includes OPcache, mysqli, pdo_mysql, pgsql, pdo_pgsql, curl, gd, intl, mbstring, zip, exif, xml and sodium, but not redis.
- E4: copying store paths to a local binary cache keeps the `cache.nixos.org-1` signatures, so the test mirror needs no trust change.

## Rollout

| Phase | Deliverable | Exit requirement |
|---|---|---|
| A. Foundation | Saved connections with fingerprint confirmation, fresh-host setup, Nix, Caddy, runtimes, shared PHP-FPM, plain PHP sites over HTTP, discovery, and the new native test harness | Two sites share one PHP runtime and a third uses another; deny rules and OPcache protections pass; a fresh controller reconstructs all three; the build meets the [budget](#tests-and-build-time), shown first by a spike ([#322](https://github.com/rajandangi/barectl/issues/322)) |
| B. PHP sites | WordPress and Laravel creation and deployment, databases, HTTPS, settings and secrets | Create, deploy, reload and repair without routine SSH |
| C. Automation | WordPress cron, Laravel scheduler and workers, Valkey, log viewing | Runs without the controller; failed and unknown outcomes shown honestly |
| D. Protection | restic onsite and S3/R2, recovery points, selective restore | Full, database-only and files-only restores across servers, including after controller loss |
| E. Operations | Three-level dashboard (servers, a server's stack, a site), Server Jobs, history, log retention, permissions, security baseline | Fresh-controller discovery and low-resource load tests |
| F. Later languages | Node.js and Python services, Go and Rust binaries | Same application contract, no new transport |

The Nginx, Certbot, APT-PHP, third-party PHP source and rclone code and their native tests are deleted when Phase A ships. Until Phase B lands, the main branch has no HTTPS, WordPress or database workflows. Each phase owns its own specification, tickets and qualification record, and must measure memory and disk on 1, 2 and 4 GiB hosts before claiming a minimum size.

## Open qualification items

- The same catalog realisation on amd64, measured so far on arm64 only.
- AppArmor behavior of the Nix daemon and installer on Ubuntu 26.04 hosts beyond the disposable server.
- `nix-env --set` with a store path creating a generation atomically.
- OPcache protections and per-pool directories blocking cross-pool reads.
- FPM restart window on a build change, whether `USR2` re-execution is safe, and whether in-flight requests survive a pool reload.
- FPM behavior when a reload meets an invalid configuration.
- Whether a Hydra-built extension such as phpredis loads into the matching default build, for Phase C.
- Ubuntu's `valkey-server` template unit for per-site instances.
- restic with R2 end to end, retention by tag, and read-back verification of the kept copy.
