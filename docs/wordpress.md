# WordPress

Barectl creates a WordPress site through the one change engine ([ADR 0035](adr/0035-one-change-engine-with-effect-derived-consent.md)): Create WordPress site ([#380](https://github.com/rajandangi/barectl/issues/380)). The site's `bin/wp` wrapper runs the catalog's WP-CLI with the site's PHP runtime, and its Caddy route refuses `wp-config.php`, dotfiles and PHP under uploads ([site convention](site-conventions.md#serving)).

## Creating a site

Choosing **WordPress** on the **Create site** page opens the WordPress form, which asks for the domain, the site title, the administrator username and email, and the PHP runtime; the site's short name is derived from the domain and stays editable under More options. It is disabled with the reason on a server whose only database engine is PostgreSQL, because WordPress needs MariaDB. The administrator password is asked for on the confirm screen, not the create form, and reaches the server only through the confidential input channel ([ADR 0032](adr/0032-keep-secrets-in-private-native-files.md)); it is never stored, and the review offers a browser-generated value.

One reviewed change composes the site's Phase A layout with its MariaDB binding ([ADR 0010](adr/0010-use-local-site-identities-for-database-access.md)), downloads the pinned WordPress release whose size and SHA-256 are in `wordpress/convention.py`, verifies and extracts it as the site user, writes a fixed public loader and a private configuration with eight server-generated salts, runs `wp core install --prompt=admin_password --skip-email` as the site user with the password on standard input, stores pretty permalinks, opens the site and verifies the home, login and REST pages over its own HTTPS address. A failing verification restores the maintenance gate.

WordPress, WP-CLI and the site's plugins run only as the site user. Root writes native configuration only. The public loader is fixed; the private configuration is the only place the salts live, and neither the salts nor the password reach the controller or the browser after apply.

## Discovery and execution

Passive discovery reads bounded native files only: `current/public/wp-includes/version.php` for the core version literal and the fixed loader and private configuration's shape. It never runs PHP, and a fresh controller reconstructs the site and its core version from the server alone.

## Actions

A WordPress site's **WordPress** section offers two actions. Each is one Site review, runs WP-CLI as the site user in the transient unit, and reports one bounded, sanitized result line: WP-CLI's own output is never stored in the controller or written to the journal.

- **Reset administrator password** asks for the administrator username on the section and for the new password on the review's confirm screen. The named user must hold WordPress's administrator role. The password reaches the server only through the confidential input channel ([ADR 0032](adr/0032-keep-secrets-in-private-native-files.md)); `wp user update --prompt=user_pass --skip-email` reads it on standard input, and WordPress's own sign-in page must accept it before the run reports success. The value is never in an argument, an environment, a unit property or the journal, and nothing outside WordPress's own hash keeps it. If the update runs but its result cannot be confirmed, the run reports partly applied and says the password may have changed.
- **Verify core files** compares the installed core with WordPress.org's official checksums for the reviewed version through `wp core verify-checksums`. A match reports success. A mismatch and an unavailable checksum service (the site's network cannot reach WordPress.org, or WP-CLI cannot read the site) are separate refusals, and neither changes anything on the server.

Both actions refuse a site that is not WordPress, a partly applied installation, and a site whose native evidence changed since the review. Discovery reads nothing new for either action.

## Recovering an interrupted install

A run that stops before verification leaves the maintenance gate in place. A fresh review reads the site's native state, recognizes the gate, and finishes only what is missing: it never reinstalls into tables that already exist and never regenerates salts. Missing or edited private configuration blocks the change rather than being overwritten.

## Maintenance and later scope

Barectl does not manage plugins, themes or core updates; WordPress keeps updating itself as
the site user. Extra named constants are edited under **WordPress settings**, with
Barectl-owned names kept fixed ([settings](settings.md)).

## Scheduled events

A WordPress site's Settings gains **Scheduled tasks**, which moves WP-Cron to the server
([automation](automation.md)). Turning it on runs due events every minute as the site's own
account, waits for one successful run, and only then sets `DISABLE_WP_CRON` in the private
configuration so page loads stop running cron. Turning it off clears the constant first and
then stops the server task. A hand-made crontab entry, Supervisor program or other service
already running cron for the site blocks turning it on, and a `DISABLE_WP_CRON` set by hand
with no server task is shown as "No cron is running".

