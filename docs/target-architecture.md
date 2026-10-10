# Target architecture

Accepted direction for [#323](https://github.com/rajandangi/barectl/issues/323). Nothing in this document is implemented. It replaces the planned Nginx, Certbot, APT-PHP and rclone stack for new servers; the released v0.2 and v0.3 behavior described in the [README](../README.md#current-status) and [architecture](architecture.md) remains what the code does until each phase below lands and is qualified. Sources were read on 2026-10-10.

Barectl is a portable, local-first, agentless control plane for fresh Ubuntu 26.04 LTS servers. Ubuntu 24.04 is not supported on the target stack; a later LTS is added only by its own reviewed release policy and qualification. Mature native components own hosting mechanics. Barectl owns the operator experience, review, admission, reconciliation and recovery, through the existing pyinfra SSH connection and the detached native execution of [ADR 0006](adr/0006-use-native-bootstrap-execution.md). The [core philosophy](../README.md#core-philosophy) is unchanged: the server is the source of truth, and a new controller with authorized SSH access reconstructs supported state without the previous controller's database.

## Stack

| Area | Target | Supply | Decision |
|---|---|---|---|
| Operating system and native services | Ubuntu LTS, MariaDB and/or PostgreSQL, Valkey | Ubuntu archive through reviewed APT transactions ([ADR 0007](adr/0007-admit-exact-package-transactions-with-an-inline-apt-guard.md)) | [ADR 0026](adr/0026-manage-fresh-hosts-on-one-target-stack.md) |
| Web serving and HTTPS | Caddy | Caddy's official APT repository | [ADR 0027](adr/0027-serve-sites-and-https-with-caddy.md) |
| Language runtimes and tools | PHP CLI and FPM, Composer, WP-CLI, Node.js, Python, uv, restic | One multi-user Nix installation with a pinned nixpkgs | [ADR 0028](adr/0028-supply-runtimes-and-tools-from-pinned-nix.md) |
| PHP serving | One PHP-FPM master per runtime, one pool per site | Nix | [ADR 0029](adr/0029-share-one-php-fpm-master-per-runtime.md) |
| Object cache | One Valkey instance per site that enables it | Ubuntu archive | [ADR 0030](adr/0030-give-each-site-its-own-valkey-instance.md) |
| Backups | restic, onsite plus optional S3-compatible offsite | Nix | [ADR 0031](adr/0031-back-up-with-restic.md) |
| Settings and secrets | Private native files written through confidential SSH input | none | [ADR 0032](adr/0032-keep-secrets-in-private-native-files.md) |
| Build and tests | Two test layers, 10-minute target, 15-minute limit | none | [ADR 0033](adr/0033-prove-real-behavior-in-two-test-layers.md) |
| Background work | systemd services and timers | Ubuntu | [ADR 0020](adr/0020-run-laravel-background-work-with-native-systemd.md) and this document |
| Logs | journald, Caddy file logs, application logs | Ubuntu, Caddy | this document |

APT keeps owning the operating system and native services. Nix owns Barectl's language runtimes and the tools that need a newer or pinned version than the archive offers. No server mixes APT PHP and Nix PHP for managed sites.

## Fresh hosts only

V1 provisions and manages fresh, qualified Ubuntu 26.04 LTS hosts. Bootstrap verifies the release, architecture, privileges, host identity, disk and memory headroom, and the absence of another web stack or PHP installation before it changes anything. Servers set up by earlier Barectl builds, and other panels' servers, are reported as unsupported and are never rewritten. Each architecture (amd64, arm64) is supported only after its own qualification. See [ADR 0026](adr/0026-manage-fresh-hosts-on-one-target-stack.md).

Discovery reads Caddy, Nix, FPM, systemd, database, Valkey and restic evidence and adopts administrator changes that stay within the supported settings, instead of requiring byte-exact files. Configuration outside them is reported, and only the mutations that depend on it are blocked.

## Scope and non-goals

The trust model is one owner or a trusted team hosting their own applications. Sites are separated by Unix accounts, private directories, FPM pools, database principals and their own cache instances; they share the kernel, Caddy, PHP-FPM masters and SQL engines, which is not container or VM isolation. V1 offers no hostile multi-tenancy, container orchestration, billing, DNS hosting or email hosting, and no arbitrary Caddyfile or system editing. A site's SSH user is not a confined shell; SFTP-only chroot is offered where suitable. Metrics are on demand (CPU, memory, disk, services, FPM pool status, web checks); persistent charts need a later server-side sampler.

## Caddy

Install Caddy from its [official repository](https://caddyserver.com/docs/install) (`https://dl.cloudsmith.io/public/caddy/stable/deb/debian`, keyring `/usr/share/keyrings/caddy-stable-archive-keyring.gpg` from [the published key](https://dl.cloudsmith.io/public/caddy/stable/gpg.key)). Ubuntu 26.04 ships only [2.6.2](https://packages.ubuntu.com/search?keywords=caddy&searchon=names&suite=all&section=all) in universe, without the 2026 fixes in [2.11.3](https://github.com/caddyserver/caddy/releases/tag/v2.11.3) and later. The [packaged unit](https://raw.githubusercontent.com/caddyserver/dist/master/init/caddy.service) runs as `caddy`, reloads with `caddy reload --force` and keeps state in `/var/lib/caddy`. Before any implementation, a real `apt update` on Ubuntu 26.04 must confirm the repository's indexes and current package; a read on 2026-10-10 returned HTTP 402 for the indexes while the key was available.

Layout: `/etc/caddy/Caddyfile` imports `/etc/caddy/sites/*.caddy`, one file per site. A change renders the candidate, checks host conflicts, runs [`caddy validate`](https://caddyserver.com/docs/command-line), replaces the file, reloads and verifies routing. A failed reload [keeps the running configuration](https://caddyserver.com/docs/api), so the payload restores the previous file before it reports. The admin endpoint listens on a Unix socket in a `caddy`-owned directory that site users cannot reach, with reloads pointed at it through a unit override, because [the API docs](https://caddyserver.com/docs/api) advise against a TCP admin endpoint where untrusted code runs, and `admin off` would prevent reloads. Operators change sites through a small catalog of tested settings (primary domain, aliases, redirects, compression), not a free Caddyfile editor.

PHP sites use [`php_fastcgi`](https://caddyserver.com/docs/caddyfile/directives/php_fastcgi) to the site's FPM socket plus `file_server`. Caddy documents no default deny for dotfiles, `wp-config.php` or PHP under uploads, and [`hide` is not a security boundary](https://caddyserver.com/docs/caddyfile/directives/file_server), so the convention carries explicit deny rules that native tests prove.

[Automatic HTTPS](https://caddyserver.com/docs/automatic-https) issues and renews certificates. Caddy offers no certificate status command or endpoint, so discovery reports certificate state from the stored certificate files, a TLS probe and journald. Native tests point Caddy at Pebble through `acme_ca` and `acme_ca_root`. Per-site access logs use the [`log` directive](https://caddyserver.com/docs/caddyfile/directives/log) with `roll_size`, `roll_keep` and `roll_keep_for`; sensitive headers are redacted by default.

## Nix

Install multi-user Nix with the [official installer](https://nix.dev/manual/nix/latest/installation/installing-binary) for an exact release, verified before use. Ubuntu 26.04's [`nix-bin`](https://packages.ubuntu.com/search?keywords=nix-bin&searchon=names&suite=all&section=all) is 2.34.3, in universe without updates. The installer creates the `nixbld` group and [build users](https://nix.dev/manual/nix/latest/installation/multi-user) from UID 30001, which site accounts must avoid. [`allowed-users`](https://nix.dev/manual/nix/latest/command-ref/conf-file#conf-allowed-users) limits the daemon to root and an operator group; nobody is added to `trusted-users`, which the manual describes as equivalent to root. Site users run store binaries without daemon access. The only substituter is `https://cache.nixos.org` with its published key; nothing is built from untrusted caches.

Each server pins one nixpkgs commit through a [pinned tarball](https://nix.dev/reference/pinning-nixpkgs); flakes remain [experimental](https://nix.dev/manual/nix/latest/development/experimental-features). nixos-26.05 provides php83, php84 and php85, Composer, WP-CLI, nodejs_22 and nodejs_24, Python, uv and restic. [Hydra](https://hydra.nixos.org/jobset/nixos/release-26.05) built php84, php85 and the extensions WordPress and Laravel need, Composer, WP-CLI, Node.js, Python and uv for x86_64-linux and aarch64-linux; php83's extensions and restic still need the same check. A stable branch is maintained only until the next one, so the pin moves about every six months as a reviewed change.

Each runtime is a [profile](https://nix.dev/manual/nix/latest/command-ref/files/profiles) under `/nix/var/nix/profiles/barectl/`, set with [`nix-env --set`](https://nix.dev/manual/nix/latest/command-ref/nix-env/set). Generations are the rollback candidates and garbage-collection roots; collection never uses `-d` and keeps the active and previous generation. Discovery reads the profiles, their store paths and [closure sizes](https://nix.dev/manual/nix/latest/command-ref/new-cli/nix3-path-info). The store is world-readable, so no configuration, credential or user data passes through Nix.

Measured from cache metadata on x86_64, php85 is about 276 MiB on disk; php84, php85, Composer, WP-CLI, nodejs_24, python313 and uv together are about 799 MiB on disk and 255 MiB to download.

## PHP-FPM

A runtime is one exact PHP build and extension set. Each runtime has one FPM master as a native systemd unit, with one pool per site under the site's own user and socket. The [NixOS module](https://github.com/NixOS/nixpkgs/blob/nixos-26.05/nixos/modules/services/web-servers/phpfpm/default.nix) is the reference for the unit (`Type=notify`, `php-fpm -y`, reload by `USR2`); the unit must not set `PHP_INI_SCAN_DIR`, which the nixpkgs wrapper uses to load extensions.

[OPcache](https://www.php.net/manual/en/opcache.configuration.php) is one shared cache per master. Its protections are off by default, so every master sets `opcache.validate_permission=1`, `opcache.validate_root=1` and `opcache.restrict_api` to a path no site can write, or one site could be served another's cached scripts, reset every site's cache or list other sites' paths ([bug 74182](https://bugs.php.net/bug.php?id=74182)). Native tests must prove these settings block cross-pool reads before any shared master is qualified.

A pool change [reloads the whole master](https://github.com/php/php-src/blob/master/sapi/fpm/php-fpm.8.in), so every site on that runtime briefly recycles workers, and the review lists those sites. Per-site limits come from pool settings (`pm.max_children`, `request_terminate_timeout`, `php_admin_value[memory_limit]`); systemd resource limits apply to the master as a whole. Pools keep `clear_env=yes`; passing a non-secret variable to PHP, such as for a WordPress plugin that reads `getenv()`, is an explicit per-site setting.

## Valkey

Sites that enable an object cache get their own Valkey instance from Ubuntu's `valkey-server` ([9.0 on Ubuntu 26.04](https://packages.ubuntu.com/search?keywords=valkey&searchon=names&suite=all&section=all)), running as the site user on a private Unix socket with `maxmemory` and an eviction policy. A shared instance cannot isolate flushes on those versions: Laravel's cache flush [ignores the prefix](https://laravel.com/docs/13.x/cache), the WordPress Redis Object Cache plugin's [README](https://github.com/rhubarbgroup/redis-cache/blob/develop/README.md) documents a database flush path (its default flush behavior is not yet verified), and per-database ACL rules arrive only in Valkey 9.1. See [ADR 0030](adr/0030-give-each-site-its-own-valkey-instance.md).

## Settings and secrets

Operators edit ordinary variables and secrets in the dashboard. The authoritative copy lives on the server in private site-owned files (`.env`, a private file loaded by `wp-config.php`), never in the controller database or the Nix store. FPM pools cannot read systemd credentials, whose directory is readable only by the unit's user, and `env[]` has the exposure systemd [warns about](https://www.freedesktop.org/software/systemd/man/255/systemd.exec.html) for `Environment=`. Worker and timer units that run as the site user may use `LoadCredential=`. Secret values travel over SSH standard input into a short-lived root-only staging file and are atomically placed; they never appear in argv, unit properties, the journal, events or responses. `php artisan config:cache` copies secrets into `bootstrap/cache/config.php`, which gets the same protection. See [ADR 0032](adr/0032-keep-secrets-in-private-native-files.md).

## Automation

Scheduled tasks are systemd timers with oneshot services; always-on workers are services, as [ADR 0020](adr/0020-run-laravel-background-work-with-native-systemd.md) already decides for Laravel. A [timer](https://www.freedesktop.org/software/systemd/man/255/systemd.timer.html) never starts a service that is still running; Ubuntu 26.04's systemd 259 offers `DeferReactivation=` so a run that outlasts its interval is not followed immediately by the next. Per-minute jobs set `AccuracySec=1s`, because the default is one minute; oneshot services need an explicit time limit. Laravel uses `schedule:run` every minute and `queue:work` workers whose `--timeout` stays below `retry_after` ([queues](https://laravel.com/docs/13.x/queues)). WordPress uses an optional timer running [`wp cron event run --due-now`](https://developer.wordpress.org/cli/commands/cron/event/run/), and only after that timer is verified does Barectl set `DISABLE_WP_CRON`.

## Backups

restic comes from the Nix catalog at the pinned version (0.19.1 upstream on 2026-10-10); Ubuntu 26.04's universe package is [0.18.1](https://packages.ubuntu.com/search?keywords=restic&searchon=names&suite=all&section=all). A backup writes files and a database dump into an onsite repository and optionally copies snapshots to an S3-compatible repository (S3, R2). restic's [locks](https://restic.readthedocs.io/en/stable/100_references.html) are taken by restic processes, which other Barectl work does not see, so backup, copy, forget and prune run as native units under Barectl's shared lock, with one maintenance actor per repository. [Exit codes](https://restic.readthedocs.io/en/stable/075_scripting.html) and JSON output are the parsing contract. R2 does not implement the S3 Object Lock API and uses its own [bucket locks](https://developers.cloudflare.com/r2/buckets/bucket-locks/); immutability is configured per provider and never implied.

A recovery point holds the application files, persistent uploads and storage, a consistent database dump, the site's private configuration where recovery needs it (encrypted by restic like everything else), and a small non-secret description of the application, runtime and database versions. The repository password and recovery instructions are kept apart from the backup, so they survive the server's loss. An export for local development never copies production secrets. Restore follows [ADR 0022](adr/0022-review-destructive-restore-and-coordinated-capture.md): files and database are not one transaction, a safety copy comes first, and a partial or unknown result leaves the site gated for reviewed recovery. See [ADR 0031](adr/0031-back-up-with-restic.md).

## Logs

journald holds host and service logs; retention uses `SystemMaxUse`, `SystemKeepFree` and `MaxRetentionSec`, which removes whole files and is approximate. Caddy writes per-site JSON access logs with size and age rotation. Laravel and PHP error logs stay in the site's private log directory, rotated by Ubuntu's logrotate or the framework's own daily logs. One run's journal is selected with `journalctl --invocation`. Barectl reads logs through bounded SSH commands and never loads whole files into the controller.

## Tests and build time

A full local build targets 10 minutes and never exceeds 15, and so does required CI. Tests prove behavior an operator or site depends on; tests that only restate the implementation, and tests of removed code, are not kept. A fast layer checks Barectl's own logic against recorded real command output and native validators. About 15 to 25 native lifecycle scenarios run on servers booted from a cached post-bootstrap snapshot, sharing one server per lane with their own names, and nothing in the build reaches the internet. See [ADR 0033](adr/0033-prove-real-behavior-in-two-test-layers.md).

## Rollout

| Phase | Deliverable | Exit requirement |
|---|---|---|
| A. Foundation | Fresh-host bootstrap, Nix, Caddy, shared PHP-FPM, discovery, and the new native test harness | Two sites share one PHP runtime and a third uses another; OPcache protections pass; a fresh controller reconstructs all three; the build meets the [budget](#tests-and-build-time), shown first by a spike with one WordPress site ([#322](https://github.com/rajandangi/barectl/issues/322)) |
| B. PHP sites | WordPress and Laravel creation and deployment, databases, HTTPS, settings and secrets | Create, deploy, reload and repair without routine SSH |
| C. Automation | WordPress cron, Laravel scheduler and workers, Valkey, logs | Runs without the controller; failed and unknown outcomes shown honestly |
| D. Protection | restic onsite and S3/R2, recovery points, selective restore | Full, database-only and files-only restores across servers, including after controller loss |
| E. Operations | Three-level dashboard (servers, a server's stack, a site), history, log retention, permissions | Fresh-controller discovery and low-resource load tests |
| F. Later languages | Node.js and Python services, Go and Rust binaries | Same application contract, no new transport |

Each phase owns its own specification, tickets and qualification record, and must measure memory and disk on 1, 2 and 4 GiB hosts before claiming a minimum size.

## Open qualification items

- Caddy repository availability and package version on Ubuntu 26.04.
- Nix cold install time, store size and AppArmor behavior of the daemon's build sandbox on Ubuntu 26.04.
- Whether a custom PHP extension set stays a binary-cache hit.
- `opcache.validate_permission` blocking cross-pool reads.
- FPM behavior when a reload meets an invalid configuration.
- Ubuntu's `valkey-server` configuration and template unit for per-site instances.
- restic with R2 end to end, and prune under a bucket lock.
