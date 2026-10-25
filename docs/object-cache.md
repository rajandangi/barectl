# Object cache

Valkey is Ubuntu 26.04's Redis-compatible cache server. Barectl installs it once per
server from Server **Settings > Object cache (Valkey)** and, in later work, gives every
site that enables an object cache its own instance
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
  refuses `apt_active` while `apt-daily`, `apt-daily-upgrade` or `unattended-upgrades` has
  processes, and `lock_busy` while another Barectl change holds the mutation lock.

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

## Per-site instances (planned, #392/#393)

`cache/convention.py` is the reviewed extension point for those tickets: the packaged
instance unit, the identifier-bound paths (`/etc/valkey/<id>.conf`, `/var/lib/valkey/<id>`,
`/run/valkey/<id>/valkey.sock`), the reviewed memory sizes, and the configuration renderer
for a socket-only, non-persistent, `allkeys-lru` instance whose default user loses
administration commands but keeps the flushes an application needs.
`cache.presentation.prerequisite` is the "install first, then continue" hook a site screen
uses until the server-wide install exists.
