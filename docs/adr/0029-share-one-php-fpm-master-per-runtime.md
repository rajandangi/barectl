# Share one PHP-FPM master per runtime, with protected OPcache

Accepted on 2026-10-10 for [#323](https://github.com/rajandangi/barectl/issues/323); not implemented. A runtime is one exact PHP build and extension set. It runs one FPM master as a native systemd unit, with one pool per site under the site's user and socket. A master per site would multiply memory and OPcache on small servers; one master for every version is impossible.

Sharing a master shares its OPcache, whose protections are off by default. Every master therefore sets `opcache.validate_permission=1`, `opcache.validate_root=1` and a root-only `opcache.restrict_api`; without them one site could be served another site's cached scripts, reset every site's cache or list other sites' paths. A shared master is not qualified until native tests prove these settings block cross-pool reads.

A pool change reloads the whole master, so reviews list every site on that runtime, and master-level settings (extensions, OPcache) are reviewed as affecting all of them. Per-site limits come from pool settings; systemd limits apply to the master. The trust model is one owner or a trusted team, not mutually hostile tenants. Details are in the [target architecture](../target-architecture.md#php-fpm).
