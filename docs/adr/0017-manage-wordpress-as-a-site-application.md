# Manage WordPress as a site application

Accepted for the [v0.4 specification](../v0.4.md), with implementation and qualification pending. WordPress is an application on a convention site, not a new server profile or a resource inferred from a controller's installation history. Use the site's Linux identity, selected PHP CLI, MariaDB socket binding and existing native execution adapter. Extend the exact Nginx grammar for WordPress routing and its provisioning gate, preserving the application's routing through challenge, HTTPS and redirect changes. Generic PHP sites retain their existing forms.

## Discovery and execution

Passive discovery examines bounded native files and, when already authorized, fixed database queries. It never includes application PHP or invokes WordPress. Explicit WP-CLI inspection can load application code and change application state even when the command intends to list data. It therefore needs separate authorization, the native mutation lock and a finite transient systemd unit. Root may manage native configuration; WordPress, plugins, themes and WP-CLI run only as the site user. `--skip-plugins` does not skip must-use plugins, as the [WP-CLI global parameters](https://developer.wordpress.org/cli/commands/plugin/list/#global-parameters) explain.

This preserves [ADR 0006](0006-use-native-bootstrap-execution.md)'s SSH and execution boundary and [ADR 0015](0015-recognize-only-the-convention.md)'s convention rule. A native WordPress installation made by an administrator is equally recognizable when its operative resources match. A content change does not invalidate the underlying site's infrastructure. Missing or edited configuration blocks only dependent actions.

## Initial scope

v0.4 supplies single-site installation, explicit inventory and integrity checks, cache flush and soft rewrite flush. PostgreSQL adapters, multisite, imports, core/plugin/theme replacement, activation hooks and URL migration require separate designs. WordPress's [upgrade guidance](https://developer.wordpress.org/advanced-administration/upgrade/upgrading/) recommends backing up files and the database. Barectl's roadmap puts verified restore in v0.6; v0.4 must not call an untested export a rollback guarantee. Operators retain ordinary WordPress and terminal administration, including patching with their own backup/recovery process. The dashboard explains this maintenance responsibility.

Nginx cannot consume WordPress's `.htaccess`; [WordPress's Nginx guidance](https://developer.wordpress.org/advanced-administration/server/web-server/nginx/) establishes the need for a front-controller route. The fixed routing and upload restrictions are Barectl policy. They do not authorize a general configuration editor or adopt that guide's historical TLS examples.

The lock coordinates cooperating Barectl controllers and guarded Certbot renewal. It cannot stop web requests, application cron, administrator commands or WordPress's own updater. Existing installations keep their native update/cron policy; inspection reports it where available. v0.4 does not disable security updates to claim broader exclusion. Application actions promise their stated postconditions, not an atomic snapshot of a busy WordPress database.
