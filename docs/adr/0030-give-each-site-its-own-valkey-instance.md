# Give each site its own Valkey instance

Accepted on 2026-10-10 for [#323](https://github.com/rajandangi/barectl/issues/323); not implemented. A site that enables an object cache gets its own Valkey server from Ubuntu's `valkey-server` package, running as the site user on a private Unix socket with its own `maxmemory` and eviction policy.

One shared instance with per-site ACL users and key prefixes was the first plan, for lower memory. It cannot contain flushes: Laravel's cache flush ignores the configured prefix, the WordPress Redis Object Cache plugin documents a database flush path, and per-database ACL rules exist only from Valkey 9.1, while Ubuntu ships 7.2 on noble and 9.0 on resolute. Denying flush commands would break ordinary `cache:clear` and plugin flushes; allowing them would let one site wipe every site's cache. A small idle instance per site is the cheaper failure.

Revisit when the supported releases ship a Valkey with per-database ACLs and the applications flush only their own database. Details are in the [target architecture](../target-architecture.md#valkey).
