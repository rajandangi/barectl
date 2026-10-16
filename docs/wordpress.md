# WordPress

Accepted Phase B design; not implemented. Barectl has no WordPress workflow on `main`. A site's `bin/wp` wrapper runs the catalog's WP-CLI with the site's PHP runtime, and its Caddy route already refuses `wp-config.php` and PHP under uploads ([site convention](site-conventions.md#serving)), but Barectl installs, inspects and maintains no WordPress application.

The accepted direction:

- WordPress is an application on a site, not a server or a site type ([ADR 0017](adr/0017-manage-wordpress-as-a-site-application.md)).
- Secrets are generated on the server and the first administrator password is set from a terminal, never through the controller ([ADR 0018](adr/0018-generate-wordpress-secrets-on-the-server.md)). Settings and secrets live in private native files ([ADR 0032](adr/0032-keep-secrets-in-private-native-files.md)).
- WordPress needs a site database and HTTPS, which Phase B also delivers ([databases](databases.md), [HTTPS](tls.md)).
- WordPress cron runs from a per-site systemd timer in Phase C ([ADR 0036](adr/0036-run-site-automation-in-per-site-slices-without-the-global-lock.md)).

The [v0.4 specification](v0.4.md) and the [WordPress native design](wordpress-native-design.md) are requirement inputs; the target architecture's ADRs supersede their Nginx and APT mechanics.
