# Create a database binding statement by statement, and prove it through the site's pool

A binding creates a principal, a database and its privileges in the engine's catalog. These statements cannot form one transaction: MariaDB commits each account and database statement on its own, and PostgreSQL's `CREATE DATABASE` cannot run inside a transaction block. The payload therefore runs each reviewed statement in its own client invocation, reports how far it got by its exit status, and never compensates: nothing it created is dropped. Implemented in `databases/native.py` (the payload) and `databases/apply.py` (outcomes and verification); qualified on the disposable Ubuntu 24.04 and 26.04 servers ([MariaDB](../v0.3-qualification.md#mariadb-site-database), [PostgreSQL](../v0.3-qualification.md#postgresql-site-database)).

## Order and exclusion

The payload runs under the mutation lock of [ADR 0006](0006-use-native-bootstrap-execution.md). After admission it revalidates what the review read: the site's digest ([site preparation](../ssh-connections.md#the-revalidation-digest)), the engine's package digest ([ADR 0007](0007-admit-exact-package-transactions-with-an-inline-apt-guard.md)), the driver package's installed version, and the SHA-256 of the catalog read, which lists every account, database, grant and setting under the principal's name and, when the other engine is installed, whether it holds anything under that name, so two plans reviewed on different engines cannot both apply. Every query of the read is ordered, so an unchanged catalog reads as the same bytes. It publishes the temporary probe, proves through the site's pool that PHP runs as the site user with the driver loaded, and reads the catalog's digest again immediately before the first statement. The statements then run in order: the principal, the database, then the privileges.

No statement is conditional. `IF NOT EXISTS` and `OR REPLACE` would silently accept a resource another administrator created between the last check and the statement; the engine's own uniqueness instead fails the statement, and the payload stops. The lock excludes Barectl runs from every controller; the engines' uniqueness excludes everyone else.

## Boundaries

Exit 15 means nothing changed because something reviewed differs. 32 means the pool did not run the probe as reviewed, 33 that the principal already existed, 34 that the first statement failed with the catalog unchanged; all three are refusals before changes. 56 to 64 are partial completion: 56 the first statement failed but a principal now exists, 57 the database already existed, 58 its statement failed, 59 the privileges, 60 PostgreSQL's public schema revoke, 61 a catalog that differs from the predicted after-state, 62 a binding the pool cannot use as reviewed, 63 a probe left, 64 a probe that could not be published. After a failing statement the payload prints the catalog read, bounded, to the unit's journal. The pages turn the exit status into what exists and the ordinary administration that completes or removes it ([recovering a partial binding](../databases.md#recovering-a-partial-binding)). A killed wrapper, a timeout or a reboot leaves the boundary unknown; a new review shows the current state. Binding actions keep their exit codes to themselves: bootstrap's `Exit` reserves only the shared admission and package codes.

## After-state

Preparation predicts the catalog read's text once every statement took effect: the read before, whose section for the engine is replaced by exactly the rows the convention's statements create. The payload compares the read after the last statement with that digest, so a grant another administrator added meanwhile, or a statement that took effect differently, is reported rather than accepted. That the MariaDB and PostgreSQL clients print exactly the predicted rows is qualified on both releases.

## Proof through the pool

A binding is reported ready only when PHP under the site's own pool connects with its actual driver. The probe is published in the root-owned site directory, root's and readable by the site's group, never in the document root, which the site user owns: staging a file in a directory another user can write and then changing its owner would race that user ([ADR 0012](0012-publish-site-files-without-replacing-them.md)). The payload sends it FastCGI requests as root directly to the pool's socket, with the PHP CLI's own client, so no web server route, HTTP request or log is involved. Its full report must be exactly the reviewed one: the site's identity, its own table created, used and dropped, only its own database visible, administration refused, and a password-less TCP login refused. The exact probe is removed while its bytes still match, on success and before any later failure exits; a changed probe is kept, and the run exits 63.

## Never dropped

Nothing is undone. A principal, database or grant the run created stays after any later failure, and so does anything an application wrote. No run is resumed, replayed or adopts an existing resource: a new review is refused as a partial binding or a collision until ordinary administration completes or removes what exists.

## Limit

The lock is cooperative, and the statements are not one transaction. Between two statements another administrator can change the catalog; the after-state comparison reports it, but cannot prevent it. A PostgreSQL database accepts connections from any role between its creation and the revoke of PUBLIC's `CONNECT`; it is empty then, and the binding is reported ready only after both revokes.
