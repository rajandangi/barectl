# WordPress

Barectl creates a WordPress site through the one change engine ([ADR 0035](adr/0035-one-change-engine-with-effect-derived-consent.md)): Create WordPress site ([#380](https://github.com/rajandangi/barectl/issues/380)). The site's `bin/wp` wrapper runs the catalog's WP-CLI with the site's PHP runtime, and its Caddy route refuses `wp-config.php`, dotfiles and PHP under uploads ([site convention](site-conventions.md#serving)).

## Creating a site

The Create WordPress site tile asks for the domain, the site title, the administrator username and email, and the PHP runtime; the site's short name is derived from the domain and stays editable under More options. It is disabled with the reason on a server whose only database engine is PostgreSQL, because WordPress needs MariaDB. The administrator password is asked for on the confirm screen, not the create form, and reaches the server only through the confidential input channel ([ADR 0032](adr/0032-keep-secrets-in-private-native-files.md)); it is never stored, and the review offers a browser-generated value.

One reviewed change composes the site's Phase A layout with its MariaDB binding ([ADR 0010](adr/0010-use-local-site-identities-for-database-access.md)), downloads the pinned WordPress release whose size and SHA-256 are in `wordpress/convention.py`, verifies and extracts it as the site user, writes a fixed public loader and a private configuration with eight server-generated salts, runs `wp core install --prompt=admin_password --skip-email` as the site user with the password on standard input, stores pretty permalinks, opens the site and verifies the home, login and REST pages over its own HTTPS address. A failing verification restores the maintenance gate.

WordPress, WP-CLI and the site's plugins run only as the site user. Root writes native configuration only. The public loader is fixed; the private configuration is the only place the salts live, and neither the salts nor the password reach the controller or the browser after apply.

## Discovery and execution

Passive discovery reads bounded native files only: `current/public/wp-includes/version.php` for the core version literal and the fixed loader and private configuration's shape. It never runs PHP, and a fresh controller reconstructs the site and its core version from the server alone.

## Recovering an interrupted install

A run that stops before verification leaves the maintenance gate in place. A fresh review reads the site's native state, recognizes the gate, and finishes only what is missing: it never reinstalls into tables that already exist and never regenerates salts. Missing or edited private configuration blocks the change rather than being overwritten.

## Maintenance and later scope

Barectl does not manage plugins, themes or core updates; WordPress keeps updating itself as the site user. Reset administrator password and Verify core files are [#381](https://github.com/rajandangi/barectl/issues/381), extra constants are [#383](https://github.com/rajandangi/barectl/issues/383), and WordPress cron is the [Phase C specification](https://github.com/rajandangi/barectl/issues/357).
