# Object cache

Valkey is Ubuntu 26.04's Redis-compatible cache server. Barectl installs it once per
server from Server **Settings > Object cache (Valkey)**, and gives every WordPress or
Laravel site that enables an object cache its own instance
([ADR 0030](adr/0030-give-each-site-its-own-valkey-instance.md)). A fresh controller
reconstructs both from the package database and systemd; Barectl keeps no marker on the
server.

## Install Valkey (implemented, #391)

Server **Settings > Object cache (Valkey)** shows whether the server has Valkey, its
version, and whether the distribution's shared unit is stopped and masked, or offers
**Install Valkey**. The primitive follows the Database install pattern of
[databases](databases.md#install-a-database-engine-implemented-378): one reviewed change,
Shared consent, one exact APT transaction.

- The **review** simulates `valkey-server` with APT's own resolver against the server's
  configured sources and names the package, its exact version and APT's reported download
  size. It refuses when the server is not a verified Target stack, when a package would be
  upgraded, removed or reinstalled, when a package is held, when APT reports a problem, or
  when an installed Valkey package is outside the supported profile or its shared unit is
  still running. An installed and masked Valkey proposes no changes.
- The **body** installs exactly the reviewed packages with one `apt-get install` under the
  inline `DPkg::Pre-Install-Pkgs` guard ([ADR 0007](adr/0007-admit-exact-package-transactions-with-an-inline-apt-guard.md)).
  It rechecks a precondition digest under the mutation lock, stops and masks
  `valkey-server.service`, and verifies that nothing listens on TCP 6379. It reports one
  `barectl-result` line and never rolls a package transaction back.
- **Shared consent**: installing affects the whole server, so a Site operator is refused in
  the page and on a direct prepare POST. Only an Administrator applies it. The review names
  the package, its version and the download size in its summary and details.
- **apt-daily admission and the lock**: every change runs the same engine admission, which
  refuses `apt_active` while `apt-daily` or `apt-daily-upgrade` has processes, and
  `lock_busy` while another Barectl change holds the mutation lock.

### The shared unit stays masked

Ubuntu's package starts one shared `valkey-server.service`. Barectl never uses it: the
body masks it and checks `LoadState=masked`, `UnitFileState=masked` and
`ActiveState=inactive`, and the review's verification requires the same shape plus an
empty `ss` answer for port 6379. A later per-site instance uses the packaged
`valkey-server@<identifier>.service` template instead.

### Restarting units after the package transaction (#428)

A package transaction runs `systemctl daemon-reload`, and masking the unit needs another.
That clears the loaded execution metadata of running units, so the foundation's diagnostic
PHP masters, each site's PHP master and each site's proxy read as unverifiable on the next
discovery even though they serve traffic. The reviewed change restarts exactly the running
units it affects — `php-fpm@php84.service`, `php-fpm@php85.service`, and each site's
`php-fpm-site-<runtime>@<id>.service` and `haproxy-site@<id>.service` — and prints each
restarted unit to the run's journal. A restarted proxy loads its persisted server state, so
discovery reads the runtime selection and the server's check-health counter from it rather
than requiring a fixed counter value. If a restart fails the run is partly applied with
`valkey_reload`, never a silent success.

## Fresh-controller reconstruction

Discovery reads Valkey as one typed component observation in
`discovery/observations/components.py`: the `valkey-server` and `valkey-tools` packages and
their versions from the same dpkg query as every other component, and
`valkey-server.service`'s load, active and unit-file states from `systemctl show`. The
Valkey version query runs only when the package inventory already lists a Valkey package,
so a server without Valkey issues exactly the fixed reads earlier recorded transcripts
hold. A masked, inactive unit and the package version are all a fresh controller needs; no
Barectl file or database participates.

## A site's own cache (implemented, #392 and #393)

A WordPress or Laravel site's **Settings > Object cache** turns on one cache that belongs
to that site. A plain PHP site is not offered it. Turning it on is one reviewed Site change:
no other site, serving process or cache changes. Turning it off is one reviewed Site change
too.

### The instance

The packaged `valkey-server@<identifier>.service` template runs the instance. Barectl adds a
root-owned drop-in at `/etc/systemd/system/valkey-server@<identifier>.service.d/barectl.conf`
that names the site's own configuration, runs the process as `s<identifier>`, and gives it
its own runtime directory:

```
[Service]
User=s<identifier>
Group=s<identifier>
ExecStart=
ExecStart=/usr/bin/valkey-server /etc/valkey/<identifier>.conf --supervised systemd --daemonize no
PIDFile=/run/valkey/<identifier>/valkey-server.pid
RuntimeDirectory=valkey/<identifier>
RuntimeDirectoryMode=0700
ReadWritePaths=/run/valkey/<identifier> /var/lib/valkey/<identifier>
```

The configuration `/etc/valkey/<identifier>.conf` is root-owned and readable by the site
account (`0640 root:s<identifier>`), and the site's data directory is
`/var/lib/valkey/<identifier>` (site-owned, `0700`). The instance listens only on
`/run/valkey/<identifier>/valkey.sock` with `unixsocketperm 600`: `port 0`, no password, no
TCP listener, `save ""` and `appendonly no`, `protected-mode yes`, `maxmemory` from
{32, 64, 128, 256} MiB (default 64) and `maxmemory-policy allkeys-lru`. The default ACL user
keeps ordinary data commands, including `FLUSHDB`/`FLUSHALL` that `cache:clear` and the
plugin use, and loses the administration commands one site must not run against its cache:
`+@all -@admin -debug -module`. `CONFIG`, `MODULE`, `DEBUG`, `ACL` and `SHUTDOWN` are
refused; `PING`, `INFO`, `GET`, `SET` and the flushes work.

Valkey stays outside the site's automation slice, so pausing a site's background work never
stops its cache or its serving.

On the disposable arm64 lane, enabling the client on a site took 3.59 s, served 210 requests
with 2 refused (502) over a 0.17 s window, left the runtime master's `MainPID` and invocation
untouched, and reported `redis` 6.3.0 with `Zend OPcache` through the site's diagnostic pool
(`disposable/test_native_qualification.py::SitePHPMasterRestart`).

### WordPress wiring and ordering

Turning on, in this order:

1. create and start the instance, and prove the site account can open its connection;
2. write the three Barectl-owned constants into `private/wp-config.php` through the same
   atomic site-owned writer the WordPress settings change uses:

   ```php
   define( 'WP_REDIS_SCHEME', 'unix' );
   define( 'WP_REDIS_PATH', '/run/valkey/<identifier>/valkey.sock' );
   define( 'WP_REDIS_PREFIX', 's<identifier>:' );
   ```

   `WP_REDIS_*` stays reserved: the WordPress settings screen can never edit these lines,
   and any other value is outside the supported grammar;
3. install the one pinned **Redis Object Cache** plugin (version `3.0.0`, archive size
   `730620` bytes and SHA-256 `7a03342d…8f54a` in `cache/plugin.py`) from the site's own
   private staging directory after checking both, activate it, and enable its drop-in with
   `wp redis enable`;
4. prove `wp redis status` reports `Status: Connected`, `Client: PhpRedis`, `Drop-in: Valid`
   and the pinned `Plugin Version`, and that the instance answers as the site account.

The client is phpredis from the runtime catalog ([PHP extensions](runtimes.md#php-extensions)).
The site's own PHP master and command wrappers must already load it; the review refuses
otherwise and the card offers **Load the cache client**, which prepares #390's Site change
first. The review names phpredis, the plugin version and the reviewed memory limit.

Turning off disconnects the application first: disable the plugin drop-in, clear the three
constants, deactivate the plugin, and only then stop, disable and remove the instance, its
configuration, its drop-in, its data and its runtime directory. Afterwards there is no
instance, no drop-in and no `WP_REDIS_*` line.

The card refuses with a reason when Valkey is not installed on the server (offering
**Install Valkey** first, through the same install review Server Settings uses), when the
site is not a verified WordPress installation, when a fresh observation of the site is
unavailable, or when the site does not load phpredis. Turning off stays available for a
site whose cache artifacts exist, so a broken cache can always be removed from the
dashboard.

The plugin archive comes from `downloads.wordpress.org` in production and from the local
byte-exact mirror in the native lanes; `disposable/mirror.py` pins the same version and the
daily **Native drift** job watches it, exactly as it does Phase B's WordPress archive.

### Laravel wiring and ordering

A Laravel site gets no plugin. Turning on, in this order:

1. create and start the same per-site instance, and prove the site account can open its
   private connection;
2. write the three cache keys into `private/laravel.env` through the same atomic site-owned
   writer the Edit settings change uses, keeping every other line byte-identical:

   ```
   CACHE_STORE=redis
   REDIS_HOST=/run/valkey/<identifier>/valkey.sock
   REDIS_PORT=0
   ```

   Laravel reads `REDIS_PORT=0` as "no TCP port" and the host as a Unix socket path;
3. rebuild Laravel's cached configuration when `bootstrap/cache/config.php` is in use;
4. gracefully restart the site's **running** queue workers (`systemctl restart`, so each
   finishes its current job within its own stop budget); a deliberate Stop survives an
   unrelated cache change.

While those keys name the site's own private connection they are **Barectl-managed**:
`CACHE_STORE`, `REDIS_HOST` and `REDIS_PORT` show as read-only in Environment, their values
are withheld by the native read, and an Environment review that names one is refused. A
supported hand edit of another key stays editable. If an operator changes the store by hand
to something else, the two `REDIS_*` keys remain managed and can still be removed.

Turning off **disconnects the application first**: restore `CACHE_STORE` to the store the
site used before Barectl changed it (or remove the key when it was absent), remove the two
managed connection keys, rebuild the cached configuration, restart the running workers, and
only then stop and remove the instance. The previous store is recorded in the applied
review's immutable document on the controller that turned the cache on. A controller with
no such record refuses instead of guessing, and a hand-chosen store that no longer points at
the managed connection is left untouched.

The review refuses turning on when the host is not Target stack, Valkey is not installed or
its shared unit is not stopped and masked, the site is not a verified Laravel installation,
the site is not fully managed or its last deploy left the current release incomplete (a
gate, a partly deployed release or an unknown outcome), the site does not load phpredis, the
existing instance is outside supported settings, or the previous store is unknown while the
current environment already names `redis`. Turning off stays available for a gated or partly
deployed site whose cache artifacts or managed keys exist.

### Reading the cache on demand

**Check the cache** queues one read through the worker and `RemoteShell` as the site's own
account, never on a page GET. It runs one fixed `valkey-cli INFO` under the shared read
lock and keeps only four numbers on the request row: `used_memory`, `maxmemory`,
`evicted_keys` and `connected_clients`, plus `running`, `stopped` or `unreadable`. The row
is replaced by the next reading and expires after a day; nothing is copied into a snapshot
or a second history. The Overview line shows the cache's state from the last observation,
the reading's memory against its limit and its evictions when one was asked for, and the
time it was checked. Caddy access logs are not used for this.

### Discovery, hand edits and reconstruction

A discovery read recognizes each site's instance from the configuration digest, the
drop-in, the unit's own properties, the socket's owner and mode, and the application's
constants, plugin version and drop-in. It reports one state per site:

- **On** — a reviewed configuration, the drop-in and unit as written, a running instance,
  the site-owned socket at `0600`, phpredis, and (WordPress) complete `WP_REDIS_*` wiring
  with the pinned plugin or (Laravel) the exact `.env` cache triple;
- **Off** — no instance artifacts and no wiring;
- **Partly on** — an instance or wiring that is incomplete (stopped, no socket, missing
  drop-in, partial constants or `.env` keys, another plugin version, no phpredis);
- **Outside supported settings** — a hand edit the convention does not interpret, such as a
  changed `User`, `ExecStart` or socket path, or a configuration other than a reviewed one.

A hand edit of the memory limit to another reviewed size is supported: discovery adopts it
as **On** with that limit, and a review prepared for it proposes nothing. Any other change
is reported once and blocks turning the cache on; turning it off remains available. A
fresh controller reconstructs all of it from `systemctl show`, the files and the constants,
without a Barectl marker or database.

### Removal

Removing a site stops, disables and removes its `valkey-server@<identifier>.service`, its
configuration, drop-in, data and runtime directories along with its other resources. The
removal inventory is closed: the reviewed path and service lists carry the cache artifacts.
