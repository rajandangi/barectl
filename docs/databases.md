# Database engines and site databases

Barectl installs and removes one **database engine per server** — MariaDB or PostgreSQL,
never both — from the server's configured Ubuntu archive. Site databases themselves (the
`s<id>` principal the site's applications sign in as) are [Phase B's next slice
(#379)](https://github.com/rajandangi/barectl/issues/379).

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
passive discovery reads a database catalog or runs a database client; those reads belong to
a change's preparation and verification.

## Site databases (planned, #379)

Site databases are planned in the [Phase B
specification](https://github.com/rajandangi/barectl/issues/356): each site's database and
principal are named `s<id>` and authenticate as the site's Linux user over the local socket
([ADR 0010](adr/0010-use-local-site-identities-for-database-access.md), [ADR
0013](adr/0013-create-a-database-binding-statement-by-statement.md)), so no database
password exists anywhere.
