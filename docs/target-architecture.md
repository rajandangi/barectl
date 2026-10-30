# Target architecture

The one stack Barectl manages, tracked in [#323](https://github.com/rajandangi/barectl/issues/323). Phase A implements the saved connections, host standing, host foundation, runtimes, server defaults, plain PHP sites over HTTP with per-site HAProxy and PHP-FPM, discovery and the change engine described below; Phase B adds WordPress, Laravel, HTTPS, databases and settings; Phase C adds background work, the per-site object cache and logs; Phase D adds restic backups, recovery points, retention, integrity, restore, export and disaster recovery ([backups](backups.md), [Phase D qualification record](phase-d-qualification.md)). The remaining sections record the accepted direction for later phases ([rollout](#rollout)). The Nginx, Certbot, APT-PHP and rclone stack this replaces was deleted at the Phase A exit. The PHP serving design was amended on 2026-10-15 by [ADR 0038](adr/0038-drain-site-php-through-private-haproxy.md). Source evidence below is dated.

Barectl is a portable, local-first, agentless control plane for fresh Ubuntu 26.04 LTS servers. Ubuntu 24.04 is not supported on the target stack; a later LTS is added only by its own reviewed release policy and qualification. Mature native components own hosting mechanics. Barectl owns the operator experience, review, admission, reconciliation and recovery, through the existing pyinfra SSH connection and the detached native execution of [ADR 0006](adr/0006-use-native-bootstrap-execution.md). The [core philosophy](../README.md#core-philosophy) is unchanged: the server is the source of truth, and a new controller with authorized SSH access reconstructs supported state without the previous controller's database.

## Stack

| Area | Target | Supply | Decision |
|---|---|---|---|
| Operating system and native services | Ubuntu LTS, MariaDB and/or PostgreSQL, Valkey | Ubuntu archive through reviewed APT transactions ([ADR 0007](adr/0007-admit-exact-package-transactions-with-an-inline-apt-guard.md)) | [ADR 0026](adr/0026-manage-fresh-hosts-on-one-target-stack.md) |
| Adding a server | Saved connection, host key confirmed against the provider's fingerprint | none | [ADR 0034](adr/0034-trust-a-fresh-host-by-confirming-its-fingerprint.md) |
| Changes | One change engine, consent derived from declared effects | none | [ADR 0035](adr/0035-one-change-engine-with-effect-derived-consent.md) |
| Public web serving and HTTPS | Caddy | Nix | [ADR 0027](adr/0027-serve-sites-and-https-with-caddy.md) |
| Language runtimes and tools | PHP CLI and FPM, Composer, WP-CLI, Node.js, Python, uv, restic, Caddy, HAProxy | One multi-user Nix installation, exact store paths from a catalog lock | [ADR 0028](adr/0028-supply-runtimes-and-tools-from-pinned-nix.md) |
| PHP serving | Private HAProxy per site, independent PHP-FPM masters per site and runtime | Nix | [ADR 0038](adr/0038-drain-site-php-through-private-haproxy.md) |
| Object cache | One Valkey instance per site that enables it | Ubuntu archive | [ADR 0030](adr/0030-give-each-site-its-own-valkey-instance.md) |
| Backups | restic, per-site repositories onsite plus optional S3-compatible offsite | Nix | [ADR 0031](adr/0031-back-up-with-restic.md), [ADR 0037](adr/0037-capture-scheduled-backups-live.md) |
| Settings and secrets | Private native files written through confidential SSH input | none | [ADR 0032](adr/0032-keep-secrets-in-private-native-files.md) |
| Build and tests | Two test layers, five-minute target, 15-minute limit | none | [ADR 0033](adr/0033-prove-real-behavior-in-two-test-layers.md) |
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

Discovery records and presents the host standing, named evidence and foundation-stage states on Overview. Its current provisional headroom thresholds are 4 GiB free disk and 900 MiB available memory; both remain explicitly unqualified until native qualification establishes supported limits. Opening Overview reads the stored snapshot and makes no SSH call.

On a target-stack host, discovery reads Caddy, Nix, FPM, systemd, database, Valkey and restic evidence and adopts administrator changes that stay within the supported settings, instead of requiring byte-exact files. A resource with a setting Barectl does not interpret is Outside supported settings: it is reported once, and only the changes that depend on it are blocked.

## Adding a server

A server is added through a saved connection: address, user (root by default), port and a key reference, either this computer's SSH agent or an approved key file ([saved server connections](saved-server-connections.md)). The connection never stores a private key. A fresh cloud host gets new host keys at first boot, so Barectl does not ask the operator to edit SSH files first. The operator pastes the fingerprint the provider shows for the new host; Barectl connects, accepts the presented key only on an exact match and records it in a Barectl-owned known_hosts file on the controller. A changed or revoked key is refused, and no key is trusted on first use. The check result shows the host's standing and, for a Fresh host, the next action, Set up server. See [ADR 0034](adr/0034-trust-a-fresh-host-by-confirming-its-fingerprint.md).

## Host foundation

Setting up a Fresh host is one reviewed plan, executed as one transient unit under the shared lock ([ADR 0006](adr/0006-use-native-bootstrap-execution.md)). Its stages run in order and each reports its own result:

1. Preflight: Ubuntu 26.04, a qualified architecture, root or the exact sudo authorization, disk and memory headroom, no other web stack, PHP or panel, and neither `apt-daily` nor `apt-daily-upgrade` running. A host that fails any check is refused cleanly, before anything changes.
2. Nix: install the pinned release and write `nix.conf` ([Nix](#nix)).
3. Catalog realisation: Caddy, Composer, WP-CLI and HAProxy from the catalog lock, each as a profile.
4. Caddy: the unit, the `caddy` user and the main configuration ([Caddy](#caddy)), and the per-site HAProxy and PHP-FPM unit templates.
5. journald: a drop-in for persistent storage.
6. Verify: each stage's result is checked against its supported shape.

Runtimes are not part of the foundation. An operator adds a runtime from the Stack page before a site selects it. A PHP runtime starts one diagnostic master, `php-fpm@<runtime>`, that serves no site; each site's serving master starts with the site. [Setting up a server](bootstrap.md) describes the review, the run and its verification.

## Changes and consent

One change engine owns every change: prepare, review, apply natively, verify and reconcile. Each kind of change supplies its inspection, a pure review, a native body and its verification; a run refers to the one stored review it applies. The review declares the change's effects, and its consent level follows from them: Read, Site, Shared or Destructive. A Shared change lists every affected site, and that list is rechecked under the lock before apply. See [ADR 0035](adr/0035-one-change-engine-with-effect-derived-consent.md).

## Scope and non-goals

The trust model is one owner or a trusted team hosting their own applications. Sites are separated by Unix accounts, private directories, FPM pools, database principals and their own cache instances; they share the kernel, Caddy and SQL engines, which is not container or VM isolation. V1 offers no hostile multi-tenancy, container orchestration, billing, DNS hosting or email hosting, and no arbitrary Caddyfile or system editing. A site's SSH user is not a confined shell; SFTP-only chroot is offered where suitable. Metrics are on demand (CPU, memory, disk, services, FPM pool status, web checks); persistent charts need a later server-side sampler.

Public exposure is limited to SSH, 80/tcp, 443/tcp and 443/udp; the firewall standard (Phase E) allows exactly these. In Phase A the only public listener Barectl adds is Caddy on 80/tcp: its admin endpoint is a Unix socket, each site's HAProxy and PHP-FPM listen only on Unix sockets, and foundation verification checks that nothing listens on Caddy's default admin port 2019. Reviewed package updates cover the Ubuntu archive only; Caddy and the runtimes are updated through catalog updates.

## Caddy

Caddy comes from the pinned Nix catalog: nixos-26.05 packages 2.11.7, the current upstream release, while Ubuntu 26.04 ships only [2.6.2](https://packages.ubuntu.com/search?keywords=caddy&searchon=names&suite=all&section=all) in universe, without the 2026 fixes in [2.11.3](https://github.com/caddyserver/caddy/releases/tag/v2.11.3) and later. Upstream's [documented APT repository](https://caddyserver.com/docs/install) answered `402 Payment Required` for its index to a real `apt update` on Ubuntu 26.04 on 2026-10-10. Barectl owns the systemd unit, modeled on [upstream's](https://raw.githubusercontent.com/caddyserver/dist/master/init/caddy.service) (`caddy` user, `Type=notify`, reload through `caddy reload`, state in `/var/lib/caddy`), and the `caddy` system user. No APT package is installed or masked.

Layout: `/etc/caddy/Caddyfile` imports `/etc/caddy/sites/*.caddy`, one file per site. The main file holds only the admin socket, `auto_https off`, `strict_sni_host`, the sites import and a final `:80` catch-all that answers 404 for unknown hosts. Phase B adds the ACME email when it enables HTTPS. The admin endpoint is a Unix socket with mode 0600 in the unit's `RuntimeDirectory`, which site users cannot reach. `caddy reload` reads the admin address from the configuration it loads, so the unit needs no reload override. [The API docs](https://caddyserver.com/docs/api) advise against a TCP admin endpoint where untrusted code runs, and `admin off` would prevent reloads.

A site change runs one step: validate a copy of the whole tree with the candidate swapped in, replace the live file only if it still has the reviewed bytes, reload, verify that the running configuration equals the configuration on disk, and restore the previous file if the reload fails. A failed reload [keeps the running configuration](https://caddyserver.com/docs/api). The previous file is kept only in the plan and run, not in a backup directory on the server. Discovery reads site files through `caddy adapt` on the server, which is upstream's own parser, so Barectl has no Caddyfile parser. Operators change sites through a small catalog of tested settings (primary domain, aliases, redirects, compression), not a free Caddyfile editor.

PHP sites send dynamic HTTP through a fixed private per-site Unix listener to HAProxy, which performs HTTP-to-FastCGI routing. Caddy still owns static serving, Host routing and explicit deny rules. Dotfiles except `/.well-known/`, `wp-config.php`, and PHP under uploads including path-info forms must remain denied. Caddy documents no default deny for these paths, and [`hide` is not a security boundary](https://caddyserver.com/docs/caddyfile/directives/file_server). The document root remains private to its site user and permitted serving identities. The new socket and file permissions require native qualification; a site user must not bypass HAProxy admission by connecting directly to FPM. Domain names have no Barectl length limit beyond DNS's own.

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

Servers never evaluate nixpkgs. Barectl's source holds a catalog lock, generated by a CI job from one pinned nixpkgs commit: for each entry and architecture, the exact `out` output store path and closure size. A server runs [`nix-store --realise`](https://nix.dev/manual/nix/latest/command-ref/nix-store/realise) on exactly those paths and refuses anything else, the Nix counterpart of the exact APT transactions in [ADR 0007](adr/0007-admit-exact-package-transactions-with-an-inline-apt-guard.md). Flakes remain [experimental](https://nix.dev/manual/nix/latest/development/experimental-features) and are not used. The catalog's entries are php84 and php85 (their default builds), nodejs_22, nodejs_24, Caddy, Composer, WP-CLI, HAProxy, restic and fcgi, the FastCGI client Barectl uses to read a master's loaded protections, plus the packaged `redis` extension for each PHP runtime (`php84_redis`, `php85_redis`) that is supply for a site's object cache and never a runtime an operator adds. The lock, its generation and its CI checks are described under [runtime catalog lock](quality.md#runtime-catalog-lock). cache.nixos.org serves the default PHP builds and the packaged extension set, but no `withExtensions` environment carrying extra extensions such as phpredis and imagick on either architecture, so no such build can be locked. The Hydra-built extension packages do substitute with `max-jobs = 0`, and a site loads phpredis from its locked store path through its own pool and command wrappers, not through a `withExtensions` build ([PHP extensions](runtimes.md#php-extensions), [#390](https://github.com/rajandangi/barectl/issues/390)). Builds are retired, never removed: a retired build is still recognized by its store path but never offered, so a newer controller identifies an older server's builds, while an older controller reports a newer catalog's builds as unknown and blocks the changes that depend on them.

Each runtime is a [profile](https://nix.dev/manual/nix/latest/command-ref/files/profiles) under `/nix/var/nix/profiles/barectl/`, set with [`nix-env --set`](https://nix.dev/manual/nix/latest/command-ref/nix-env/set). Generations are the rollback candidates and garbage-collection roots; collection never uses `-d` and keeps the active and previous generation. Discovery reads the profiles, matches their store paths to the catalog lock, and reads references and closure sizes with `nix-store -q`, not the experimental `nix path-info`. The store is world-readable, so no configuration, credential or user data passes through Nix.

## Runtimes

A runtime is a PHP branch and extension set with a name, such as `php84`. Its exact build changes over time: each catalog update becomes a new profile generation, and the previous generation stays for rollback. Sites select a runtime; identical builds are shared, never copied per site.

Security fixes for PHP, Caddy and the other catalog entries reach servers through a reviewed in-branch catalog update shipped with a Barectl release. Applying an update requires review of every affected site and its native services. A PHP serving update must use the qualified admission and drain protocol; restarting a shared profile is not a request-preservation strategy. This is a stated limitation: a fix published in nixpkgs reaches servers only when Barectl ships a catalog release containing it. The nixpkgs branch itself moves about every six months, when a stable branch ends, as a reviewed change.

The server's default PHP and Node.js commands are links in `/usr/local/bin`. Each site has a root-owned `/var/www/<id>/bin` with `php`, `node`, `composer` and `wp` bound to the site's runtime, which its workers and timers use. Changing the server default never changes existing sites.

## PHP-FPM

Each site has one ordinary foreground HAProxy process and a separate serving FPM master for its selected runtime. A PHP switch temporarily has source and target masters for that site. Sites share immutable runtime builds, but no serving master or OPcache. HAProxy explicitly sets `nbthread 1`, uses no daemon or master-worker mode and has no `ExecReload`; PHP switching does not reload HAProxy or Caddy. Site creation starts independent HAProxy/FPM services and publishes its new Caddy site file through the existing validated reload and rollback contract, without reloading other sites' HAProxy or FPM services. Shared Caddy effects retain effect-derived Shared consent. Native configuration and authenticated process/API evidence must establish one serving generation. See [ADR 0038](adr/0038-drain-site-php-through-private-haproxy.md).

Per-runtime diagnostic-only masters may remain for Add runtime build, extension and protection verification. They never host site pools. Each site master reuses the fixed unprivileged diagnostic and loaded-protection guard bound to its own identity, plus private independent application status for drain evidence.

HAProxy supplies HTTP-to-FastCGI admission from the pinned Nix catalog. Both supported PHP backend objects remain statically declared with explicit IDs, fixed sockets, finite limits and disabled defaults. They disable FastCGI keepalive; switching retains the inactive object in maintenance rather than deleting or dynamically re-adding it. Root-only API access and private frontend/backend sockets prevent application users from bypassing admission or changing it. Exact process identity, configuration and complete backend inventory are native evidence, not controller history.

A switch verifies and enables target FPM, enables target admission and places source in maintenance. It atomically publishes the unedited native `show servers state` output through HAProxy's `server-state-file`, while the base configuration stays immutable. Publication precedes source cleanup. A pre-publication crash preserves both FPM services and the previous persisted selection. Exact repeated-selection and restart behavior remain unqualified.

Source cleanup requires the supported `wait srv-removable` predicate in the authenticated proxy process, then complete native status and PID evidence showing every source application worker Idle. The wait callback has no full thread isolation; explicit `nbthread 1` prevents CLI callback interleaving with synchronous backend selection and reservation. No force persistence, health or agent checks, extra backend aliases or direct application clients may bypass this boundary. Process identity, full inventory and maintenance state must remain verified. This protects work after `fastcgi_finish_request()` through the subsequent FPM drain. A sampled zero counter or fixed grace period is insufficient. A bounded operation that cannot drain retains source and reports an incomplete transition for a freshly reviewed finish or revert. Rollback after target admission follows the full reverse drain protocol. All steps keep the existing native mutation and site deployment locks and sole SSH execution boundary.


[OPcache protections](https://www.php.net/manual/en/opcache.configuration.php) remain mandatory on every master: permission and root checks, root-only API restriction, no file cache and no preload. Each site keeps private session, upload and temporary directories. FPM preserves the pinned Nix wrapper's extension scan configuration. Per-site process, memory and filesystem separation needs native proof; this remains trusted-team hosting rather than hostile multi-tenancy. A switch takes Site consent when its effects are confined to that site. Genuine shared effects still derive Shared consent from the change engine.

## Object cache

Each site that enables an object cache gets its own Valkey instance over a private Unix
socket, with its own reviewed memory bound, no TCP, password or persistence, and an ACL
that keeps ordinary flushes but refuses administrative commands. The PHP client is phpredis
from the runtime catalog, loaded into that site's own master and CLI wrappers
([PHP extensions](runtimes.md#php-extensions)). WordPress is wired through the pinned Redis
Object Cache plugin and `WP_REDIS_*` constants; Laravel through its own `.env`, a cached
configuration rebuild and a graceful worker restart. [Object cache](object-cache.md) holds
the convention, the ordering, the refusals and the measured enable cost, and
[ADR 0030](adr/0030-give-each-site-its-own-valkey-instance.md) the decision.

## Valkey

One Ubuntu `valkey-server` package is installed per server from Server **Settings > Object
cache (Valkey)** by one reviewed exact APT transaction, and the distribution's shared
`valkey-server.service` is stopped and masked. Each site that enables an object cache gets
its own `valkey-server@<identifier>` instance. [Object cache](object-cache.md) owns the
install, the instance configuration, the ACL and the client supply
([ADR 0030](adr/0030-give-each-site-its-own-valkey-instance.md)); the
[Phase C qualification record](phase-c-qualification.md#memory) holds the measured memory.

## Settings and secrets

Operators edit ordinary variables and secrets in the dashboard. The authoritative copy lives on the server in private site-owned files (`.env`, a private file loaded by `wp-config.php`), never readable at rest in the controller database and never in the Nix store. FPM pools cannot read systemd credentials, whose directory is readable only by the unit's user, and `env[]` has the exposure systemd [warns about](https://www.freedesktop.org/software/systemd/man/259/systemd.exec.html) for `Environment=`. Worker and timer units that run as the site user may use `LoadCredential=`.

A value entered in the browser is sealed under the worker's key and stored only as ciphertext in the run's row. The worker mints that key when it starts and keeps it in memory; the controller's private key file carries it to the request handler so nothing is stored in plaintext, and a worker restart replaces it. So the value cannot be read after a worker restart or after 10 minutes, and it is cleared once sent. The worker sends it as standard input to a fixed command that stages it in a root-only directory on tmpfs; the ordinary transient unit then consumes it and removes it on every exit path. Values never appear in argv, unit properties, the journal, events or responses, and a canary test in the fast layer checks every one of those places. `php artisan config:cache` copies secrets into `bootstrap/cache/config.php`, which gets the same protection. See [ADR 0032](adr/0032-keep-secrets-in-private-native-files.md).

## Automation

WordPress server cron, the Laravel scheduler and Laravel database queue workers are
implemented, with the per-site slice, the status projection, the fence and restore step and
the per-site cache wiring. [Automation](automation.md) owns the units, the actions, the
refusals, the projection and the fence;
[ADR 0036](adr/0036-run-site-automation-in-per-site-slices-without-the-global-lock.md) the
decision, and the [Phase C qualification record](phase-c-qualification.md) the evidence.

## Backups

Restic 0.18.1 is supplied from the catalog lock. Each site has an encrypted onsite
repository with a random server key and the operator's recovery passphrase, and a server may
connect one Amazon S3 or Cloudflare R2 bucket as offsite storage. Every backup, copy, check,
cleanup, restore and export is a change on the one engine, or a fixed native unit for the
schedules; results stay four separate findings: saved here, copied offsite, verified, and
restored successfully. **Enable backups**, **Back up now** (Database only or Full site), the
one schedule, **Keep backups for**, **Check backups**, **Restore** (Database only, Files only
or Full site, also across servers and from a removed site), **Export**, **Copy offsite
again**, **Keep**, offsite storage setup and removal, passphrase replacement, **Reopen
site**, and **Delete removed-site backups** are implemented ([backups](backups.md)). What is not qualified is listed in the
[Phase D qualification record](phase-d-qualification.md). See ADRs
[0031](adr/0031-back-up-with-restic.md), [0037](adr/0037-capture-scheduled-backups-live.md),
[0022](adr/0022-review-destructive-restore-and-coordinated-capture.md) and
[0032](adr/0032-keep-secrets-in-private-native-files.md).

## Logs

The host foundation keeps journald logs in persistent storage, and Caddy writes per-site JSON
access logs. A site's **Logs** section lists its access log, PHP error and slow logs,
application log and the journals of its background-work units and its cache, reads bounded
and scrubbed pages on explicit request, and follows new lines while it is open. Every file
Barectl creates in a site's log directory rotates by size and age. [Logs](logs.md) owns the
catalogue, the bounds, the cursors, the scrubbing and the rotation convention.

## Tests and build time

A full local build targets five minutes and never exceeds 15, and so does each required CI shard ([test time budget](quality.md#test-time-budget)). Tests prove behavior an operator or site depends on; tests that only restate the implementation, and tests of removed code, are not kept. The fast layer replays recorded real command output at the `RemoteShell.run` seam of [ADR 0002](adr/0002-keep-the-remote-shell-seam.md), one transcript per server state keyed by the pin set; an unrecorded command fails and asks for a new recording, and the recorder refuses to record secret reads. Native validators (`caddy validate`, `php-fpm -t`) and payload failures before side effects run in one container from the post-bootstrap snapshot. Native lifecycle scenarios run on servers booted from that snapshot, built by Barectl's own foundation apply and keyed by a hash of the rendered payload and the catalog lock. Scenarios share one server per lane with their own names, and nothing in the build reaches the internet: Ubuntu packages, the Nix cache and WordPress archives come from local mirrors. A budget spike measures bootstrap time, snapshot cost, lane scaling and the fast layer before the rest of the harness is built. See [ADR 0033](adr/0033-prove-real-behavior-in-two-test-layers.md).

## Evidence

Measured on 2026-10-10; the host checks ran on Ubuntu 26.04 arm64:

- E1: Caddy's upstream APT repository answered `402 Payment Required` for its index to a real `apt update`. nixos-26.05 packages Caddy 2.11.7, the current upstream release.
- E2: multi-user Nix 2.35.2, installed with `--daemon --yes --no-channel-add`, installs and runs in the disposable-server container; the installer finished 3 seconds after download, and the daemon socket and service were active.
- E3: at the pinned nixos-26.05 commit, evaluation took 8 seconds. Realising php84, php85, Caddy 2.11.7, restic 0.18.1, Composer 2.10.3, WP-CLI 2.12.0 and Node.js 24.21.0 with `max-jobs = 0` took 22 seconds with no builds, and the store totalled 995 MiB. php84's default build includes OPcache, mysqli, pdo_mysql, pgsql, pdo_pgsql, curl, gd, intl, mbstring, zip, exif, xml and sodium, but not redis; the locked `php84_redis` extension adds phpredis for a site that enables the object cache.
- E4: copying store paths to a local binary cache keeps the `cache.nixos.org-1` signatures, so the test mirror needs no trust change.
- E5: on GitHub's x86_64 runner (2026-10-10), realising the eight catalog entries of that release with `nix-store --realise --option max-jobs 0 --option fallback false` took 2 seconds, 239 store paths, 931 MiB unpacked in the store and 599 MiB of entry-closure downloads (shared closures counted per entry), with no derivations built; the arm64 runner measured 2 seconds, 239 store paths, 925 MiB unpacked and 586 MiB. Runner networks sit beside the cache's CDN; a server's first realisation is slower, and the daily watch job re-measures it. Phase C adds the two extension entries, so the next hosted realisation covers twelve builds; on the local arm64 lane the four new extension paths in the lock realised with `max-jobs = 0` and `fallback = false` in 1 s with no derivations built (the two php84/php85 redis closures are 50,074,912 B unpacked and 11,275,675 / 11,275,666 B downloaded on aarch64).

## Apps

The Django apps follow the pillars. `operations` owns the change engine. `bootstrap` owns host standing and the host foundation. `runtimes` owns the catalog lock, profiles and PHP-FPM masters. `sites` owns site layout, per-site admission and serving selection, and Caddy site files. `servers` and `discovery` keep connections, trust and evidence. The [module map](architecture.md#module-map) lists the modules. Later phases add `databases`, `wordpress` and `laravel` (B), `settings`, `automation`, `cache` and `logs` (B and C), and `backups` (D).

## Rollout

| Phase | Deliverable | Exit requirement |
|---|---|---|
| A. Foundation | Saved connections with fingerprint confirmation, fresh-host setup, Nix, Caddy, runtimes, per-site HAProxy and PHP-FPM, plain PHP sites over HTTP, discovery, and the new native test harness | Two sites select one PHP runtime and a third another, with independent masters and admission; request-preserving switches, deny rules and OPcache protections pass; a fresh controller reconstructs all three; the build meets the [budget](#tests-and-build-time), shown first by a spike ([#326](https://github.com/rajandangi/barectl/issues/326)) |
| B. PHP sites | WordPress and Laravel creation and deployment, databases, HTTPS, settings and secrets | Create, deploy, reload and repair without routine SSH |
| C. Automation | WordPress cron, Laravel scheduler and workers, Valkey, log viewing | Runs without the controller; failed and unknown outcomes shown honestly |
| D. Protection | restic onsite and S3/R2, recovery points, selective restore | Full, database-only and files-only restores across servers, including after controller loss |
| E. Operations | Three-level dashboard (servers, a server's stack, a site), Server Jobs, history, log retention, permissions, security baseline | Fresh-controller discovery and low-resource load tests |

The Nginx, Certbot, APT-PHP, third-party PHP source and rclone code and their native tests were deleted at the Phase A exit. HTTPS by default ([#376](https://github.com/rajandangi/barectl/issues/376), [HTTPS](tls.md)), database engines and site databases ([#378](https://github.com/rajandangi/barectl/issues/378), [#379](https://github.com/rajandangi/barectl/issues/379), [databases](databases.md)) and Create WordPress site ([#380](https://github.com/rajandangi/barectl/issues/380), [WordPress](wordpress.md)) landed in Phase B. Each phase owns its own specification, tickets and qualification record, and must measure memory and disk on 1, 2 and 4 GiB hosts before claiming a minimum size.

## Qualification

Phase A's native scenarios exercise the items this design left open: independent site masters with their OPcache protections, private directories and admission sockets blocking cross-site access, the single-thread removability check and complete FPM drain in both switch directions, target failure, interrupted native state and fresh-controller finish or reverse, and the HAProxy service convention. Phase C's scenarios prove the per-site automation, cache and log conventions, the fence and restore step and the scheduled breadth job. The [Phase A qualification record](phase-a-qualification.md), the [Phase B qualification record](phase-b-qualification.md) and the [Phase C qualification record](phase-c-qualification.md) name the revisions, architectures, results, measured memory and disk, and what remains unqualified.

Still open, for later phases or beyond the disposable server:

- AppArmor behavior of the Nix daemon and installer on Ubuntu 26.04 hosts other than the disposable server.
- ~~Whether a Hydra-built extension such as phpredis loads into the matching default build from its locked store path, for Phase C.~~ Settled in Phase C (#390): it loads, but only from a site pool or command line after the packaged ini; see [PHP extensions](runtimes.md#php-extensions).
- ~~Ubuntu's `valkey-server` template unit for per-site instances.~~ Settled in Phase C (#392, #393): the packaged template runs one site's instance through a root-owned drop-in; see [object cache](object-cache.md#the-instance).
- restic with R2 end to end, retention by tag, and read-back verification of the kept copy.
