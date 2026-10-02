# Native recovery after a partial change

Barectl's changes are ordinary native effects, and a controller can be stopped at any
boundary. This guide is the inspection-first path for the supported v0.3 actions: read the
native evidence, understand what exists, and repair it through ordinary Linux and
application administration. Barectl does not run destructive cleanup, does not resume a
partial change automatically, and does not replay a lost request. The per-action boundary
tables remain authoritative and are linked below.

## First moves

1. Open the server's page. The run keeps its audit for the life of the controller database,
   and **Check outcome** inspects the original run's unit without submitting anything new.
   A run can end succeeded, failed, partly applied, unknown, or refused before any change.
2. Read the unit's own record on the server:

   ```sh
   systemctl status 'barectl-apply-*'
   journalctl -u 'barectl-apply-<unit>' --no-pager
   ```

   The payload writes Certbot's bounded output and its own drift markers
   (`barectl-tls: drift: <check>`) to the journal, and each action's exit status names its
   boundary in the owning document.
3. Read the paths the action touches with `ls -ld`, `stat` and `cat` before changing
   anything. A later plan reviews the current state and proposes only what remains; it
   never adopts a foreign resource.
4. The shared mutation lock is `/run/lock/barectl/mutation.lock`. It is empty and holds no
   state; `/run` is cleared by a reboot, which releases it. A process left holding it is
   visible with `fuser -v /run/lock/barectl/mutation.lock`.

## Sites and files

- **Partial account, directories or files** ([recovering a partial site](sites.md#recovering-a-partial-site)):
  inspect `getent passwd s<identifier>` and `getent group s<identifier>`, the directories
  under `/var/www/<identifier>`, the pool, the Nginx source and its enablement link, and
  the socket with `ls -l /run/php/s<identifier>.sock`. The run's audit lists the exact
  reviewed bytes and modes. `nginx -t` and `php-fpm<version> -t` show whether the current
  configuration is accepted. A new site plan reports a fully satisfied supported site as a
  no-op and otherwise shows what exists; it never deletes content or rewrites an
  unrecognized file.
- **Staged replacements left beside a destination** appear as hidden
  `.<identifier>.conf.<unit-hex>` files under `/etc/nginx/sites-available` or
  `/etc/php/<version>/fpm/pool.d`. They are never read as current state; remove them once
  the reviewed destination is confirmed.
- **Recovery preimages** of replaced site files are root-only
  `/var/backups/nginx/<identifier>.conf.<unit-hex>`. To restore one, use ordinary
  administration (`cat` the preimage over the source, then `nginx -t -q` and
  `systemctl reload nginx.service`).

## Package initialization

- **Nginx, PHP, MariaDB, PostgreSQL and Certbot** are installed only through reviewed
  package plans. If a run stopped after `dpkg` changed packages, complete or repair the
  installation with `apt`, `dpkg --audit`, `dpkg --configure -a` and the engine's own
  initialization. The per-profile boundary tables and refusal texts are in
  [bootstrap](bootstrap.md); MariaDB's and PostgreSQL's readiness checks and recovery notes
  are in [bootstrapping a server](bootstrap.md#mariadb) and
  [PostgreSQL](bootstrap.md#postgresql).
- **Certbot renewal setup** keeps its runtime masks until a restart when it stops at the
  inhibition or override boundary; the three renewal files, the exact bytes and the
  recovery table are in [recovering a partial setup](tls.md#recovering-a-partial-setup).
- **An interrupted database engine** leaves its package and data directory in place.
  Barectl never erases a data directory, starts a stopped cluster during review, or
  migrates data. Inspect the engine's log and unit, then repair or initialize through its
  own tools.

## Site databases

- **Partial DDL** ([recovering a partial binding](databases.md#recovering-a-partial-binding)): connect through the
  engine's local administration socket and read what exists before changing anything —
  MariaDB: `mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock --user=root -e
  "SHOW CREATE USER 's<id>'@'localhost'; SHOW CREATE DATABASE \`s<id>\`; SHOW GRANTS FOR
  's<id>'@'localhost';"`; PostgreSQL: `runuser -u postgres -- psql -X -c "\du s<id>"
  -c "\l s<id>"`. A principal, database or grant created by a stopped run stays; a new
  review reports it as complete when it matches the convention or refuses each difference.
  Never drop a database or role that may hold application data; repair grants statement by
  statement and verify the effective rule, not just presence.
- **The access proof** uses a temporary probe in the site's document root. If a probe is
  left (`/var/www/<id>/dbprobe-<token>.php`, root:<site-group> 0640), remove it once its
  bytes are confirmed.

## Certificates and HTTPS

- **Issued but not activated** ([issuance](tls.md#issuance)): a successful order leaves
  Certbot's ordinary lineage `/etc/letsencrypt/live/<identifier>` and Nginx unchanged. Do
  not order again; prepare an **HTTPS activation** plan, which reads the existing lineage
  and refuses only genuine mismatches. Check the lineage with
  `openssl x509 -noout -subject -dates -ext subjectAltName -fingerprint -sha256 -in
  /etc/letsencrypt/live/<identifier>/cert.pem`, and the renewal configuration with
  `test -f /etc/letsencrypt/renewal/<identifier>.conf`.
- **A refused or failed redirect stage** ([activation](tls.md#activation)) leaves the
  verified HTTPS candidate in place. Inspect the site file
  (`/etc/nginx/sites-available/<identifier>.conf`), `nginx -t`, and the HTTP behavior
  (`/usr/bin/php<php> -n` status client or `curl -I`), then prepare the activation again;
  it proposes only the redirect. The preimage and the shared rejection server remain.
- **A partial HTTPS candidate** exits 58, 59, 60 or 90: read the site file against the
  reviewed bytes, restore the root-only preimage when needed, and run `nginx -t -q` before
  any reload. Never leave a configuration that `nginx -t` refuses in place unnoticed.
- **The certificate on disk differs from the one served**: compare fingerprints —

  ```sh
  openssl x509 -outform DER -in /etc/letsencrypt/live/<identifier>/cert.pem | sha256sum
  timeout 5 openssl s_client -connect 127.0.0.1:443 -servername <name> </dev/null \
      2>/dev/null | openssl x509 -outform DER | sha256sum
  ```

  If the served value is a previous certificate, the deploy hook's reload failed or has
  not run; read `journalctl -u certbot.service -u nginx.service`, then
  `nginx -t -q && systemctl reload nginx.service`. Certbot's own zero exit does not prove a
  deployment: the wrapper exits 80 when the renewed certificate is not the one served.
- **Unknown or absent SNI** must receive no certificate. The shared rejection server is
  `/etc/nginx/conf.d/tls-default-reject.conf`, root:root 0644 with both 443
  `default_server` listeners and `ssl_reject_handshake on`; competing defaults must be
  removed through ordinary administration.

## Unknown outcomes and reboots

- A run whose outcome is **unknown** (a lost answer, a restart, an unreadable unit) stays
  reconciling until **Check outcome** establishes it from the same unit. Barectl never
  resubmits it.
- After a **reboot**, the runtime lock is gone and any runtime Certbot masks are cleared;
  the earlier run's effects are exactly what the filesystem holds. Re-run discovery: it
  reconstructs sites, bindings and certificates from native evidence, naming inaccessible
  root-only evidence explicitly. A fresh controller with authorized SSH access and root or
  noninteractive sudo can reconstruct the same relationships from a read-only preparation;
  it cannot recover another controller's private audit history or lost application data.
- Finished `barectl-apply-*` units are retained until a reviewed cleanup plan clears them;
  their cgroups are empty, so they never block mutation.

## What is never promised

Barectl never removes a site, database, lineage, account or backup automatically; never
replays a lost request; never adopts another controller's or an operator's unrelated
resource; and never rebuilds lost application or database data. When native evidence is
gone, the outcome stays unknown and the repair is ordinary administration.
