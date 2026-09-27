# Configuration observations depend on the component's package observation

Barectl reads Nginx site files and PHP-FPM pools only where the dpkg database shows the web-stack component installed, because the layout it reads (`/etc/nginx/sites-enabled` and `/etc/php/<version>/fpm/pool.d`) is a convention of the Debian packages. When the component's package observation is not observed, the site-file or pool observation takes that observation's outcome, source and warning and reads nothing, the same rule the service observation follows. PHP-FPM pool directories are read only for the PHP versions of installed `php<version>-fpm` packages. When the component is installed, Barectl reads its Debian directory only after confirming that the main configuration file (`/etc/nginx/nginx.conf`, or the version's `php-fpm.conf`) includes it as the stock file does. When that file or the directory is missing, or the include is not confirmed, the observation is unsupported: Barectl has made no finding about configuration kept elsewhere.

## Consequences

- Configuration left behind by a removed but not purged package (dpkg state `rc`) is not reported, since no installed component loads it.
- On a server without dpkg, Nginx site files and PHP-FPM pools are unsupported even when the Debian directories exist.
- An observed Nginx site file or PHP-FPM pool is in a directory the main configuration file includes. Barectl does not read other files that configuration includes, and it assumes the daemon uses the packaged main configuration file.
