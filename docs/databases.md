# Database engines and site databases

Barectl installs and removes one **database engine per server** — MariaDB or PostgreSQL,
never both — from the server's configured Ubuntu archive. Each WordPress and Laravel site
gets its own database and principal, both named `s<id>`, over the local socket
([site databases](#site-databases-implemented-379)).

## Install a database engine (implemented, #378)

Server **Settings > Database** shows whether the server has MariaDB, PostgreSQL or no
engine, with the engine's version and how it is running, and offers **Install** for the
engine it lacks. Installing is one reviewed change:

- The **review** simulates the installation with APT's own resolver against the server's
  configured sources and names every package at its exact version in the review document.
  It refuses when the server is not a verified Target stack, when it already runs the other
  engine, when an installed engine is a foreign package or another version, when a package
  would be upgraded, removed or reinstalled, or when a package is held. The review is
  Shared consent, because the engine is a whole-server resource.
- The **body** installs exactly the reviewed packages with one `apt-get install` under the
  inline `DPkg::Pre-Install-Pkgs` guard, which refuses unless APT's resolved actions are
  exactly the reviewed ones ([ADR 0007](adr/0007-admit-exact-package-transactions-with-an-inline-apt-guard.md)).
  It rechecks a precondition digest under the mutation lock, starts and enables the engine's
  service, applies the hardening below, and reports one `barectl-result` line. Barectl never
  rolls a package transaction back.
- **Git** can be named in the same reviewed transaction, so a later Laravel creation
  ([#382](https://github.com/rajandangi/barectl/issues/382)) installs it with the engine in
  one change.

### Hardening

- **MariaDB** listens on its local socket only: `/etc/mysql/mariadb.conf.d/60-barectl.cnf`
  sets `skip-networking`, and the body removes every anonymous account and drops the test
  database. There is no TCP listener on 3306.
- **PostgreSQL** keeps the distribution's local `peer` authentication and its
  loopback-only listener; Barectl changes no file and verifies the shape instead.

MariaDB and PostgreSQL both leave a single administrative principal (`root@localhost`
through the socket; the `postgres` role through peer authentication). No application
principal, database or password exists until a site has one.

## Remove a database engine (implemented, #378)

**Remove** is a reviewed change that removes the engine's packages and stops its service.
It is refused while the engine holds any database, so a site's data can never be stranded,
and it never drops a database or deletes data itself. Removing an engine so the other one
can be installed is ordinary administration; Barectl refuses to install the second engine
while the first is present.

## Fresh-controller reconstruction

Discovery already reads MariaDB and PostgreSQL as typed component observations
(`discovery/observations/components.py`): each engine's package and version from the dpkg
database and its service units from systemd. A fresh controller reconstructs the engine and
its version from the server alone, with no Barectl marker, manifest or database. Nothing in
passive discovery reads a database catalog or runs a database client; a site's binding is
reconstructed by a fresh review, which reads the engine's catalog through the authorized
change path.

## Site databases (implemented, #379)

Each site's database and principal are both named `s<id>` and authenticate as the site's
Linux user over the local socket — MariaDB `unix_socket` or PostgreSQL `peer` — so no
database password exists anywhere and no `AS` mapping is created
([ADR 0010](adr/0010-use-local-site-identities-for-database-access.md)). A plain PHP site
adds its own database from **Site Settings > Database**, which shows the connection details.
A Laravel site consumes the same convention from its own Create site change (#382). Removing
a site drops this database and principal as part of its reviewed removal
([removing a site](sites.md#removing-a-site)).

**Add site database** is one reviewed change. Its review reads the site's native state and
the engine's catalog, then refuses unless the site is complete, exactly one engine is
managed, and the catalog holds at most an exact prefix of the convention's statements. The
review names the statements that remain:

| Step | MariaDB | PostgreSQL |
| --- | --- | --- |
| principal | `CREATE USER \`s<id>\`@\`localhost\` IDENTIFIED VIA unix_socket` | `CREATE ROLE ... LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE ... PASSWORD NULL` |
| database | `CREATE DATABASE \`s<id>\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci` | `CREATE DATABASE ... OWNER s<id> TEMPLATE template0 ENCODING 'UTF8' LOCALE_PROVIDER libc` |
| privileges | `GRANT ALL PRIVILEGES ON \`s<id>\`.*` with no `GRANT OPTION` | `REVOKE CONNECT, TEMPORARY ON DATABASE ... FROM PUBLIC` |
| schema | — | `REVOKE ALL ON SCHEMA public FROM PUBLIC` (PostgreSQL only) |

The statements run one by one and report progress, so a partial run names how far it got
([ADR 0013](adr/0013-create-a-database-binding-statement-by-statement.md)). The body
revalidates the site identity and the catalog digest under the mutation lock, publishes a
probe in the root-owned site directory, and proves the binding through the site's own PHP
master: the probe is sent as a FastCGI request as root directly to the site's private
socket, and must report the site's identity, its own table created, used and dropped, only
its own database visible, and administration and a password-less TCP login refused. A
binding is ready only when that proof passes. A fresh review finishes only the remaining
statements and never rewrites or drops what exists.

The principal holds every privilege on its own database and none globally, so it can dump
and re-import that one database and read no other. Dumps run `mariadb-dump --single-transaction
--quick --no-tablespaces --routines --events --triggers` for MariaDB and `pg_dump --no-owner
--no-privileges` for PostgreSQL, both as the site's own principal; imports feed the dump back
through `mariadb` or `psql -X` as that same principal. No separate dump user exists: one would
need read access across every site's database, broader than the site principal already holds.

A fresh review reconstructs the binding from the server's catalog alone, so a second
controller proposes no changes. Passive discovery keeps reading only the engine's package
and units; the catalog read belongs to the change's preparation and verification.

