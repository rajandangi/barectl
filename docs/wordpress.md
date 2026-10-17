# WordPress

Barectl has no WordPress workflow on `main`. A site's `bin/wp` wrapper runs the catalog's WP-CLI with the site's PHP runtime, and its Caddy route already refuses `wp-config.php` and PHP under uploads ([site convention](site-conventions.md#serving)), but Barectl installs, inspects and maintains no WordPress application.

WordPress sites are planned in the [Phase B specification](https://github.com/rajandangi/barectl/issues/356), and WordPress cron in the [Phase C specification](https://github.com/rajandangi/barectl/issues/357).
