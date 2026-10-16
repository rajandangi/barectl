# Site databases

Accepted Phase B design; not implemented. Barectl has no database workflow on `main`: it installs no database engine, creates no database and reads no database binding.

The accepted direction, from the [target architecture](target-architecture.md#stack):

- MariaDB and PostgreSQL come from the Ubuntu archive through reviewed, exact APT transactions ([ADR 0007](adr/0007-admit-exact-package-transactions-with-an-inline-apt-guard.md)).
- Each site's database principal authenticates as its Linux site user over the local socket, with no controller-held password ([ADR 0010](adr/0010-use-local-site-identities-for-database-access.md)).
- A binding's statements cannot form one transaction, so they run one at a time and report how far they got ([ADR 0013](adr/0013-create-a-database-binding-statement-by-statement.md)).
- Database dumps for recovery points stream over standard input into restic ([ADR 0031](adr/0031-back-up-with-restic.md)).

The Phase B specification and its tickets will define the workflow, permissions and recovery. The [v0.4](v0.4.md) and [v0.5](v0.5.md) specifications are requirement inputs.
