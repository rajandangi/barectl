# Per-site PHP versions

Each site selects its own PHP runtime, and sites on one server can run different PHP versions. The runtimes come from Barectl's pinned [runtime catalog](target-architecture.md#nix) ([ADR 0028](adr/0028-supply-runtimes-and-tools-from-pinned-nix.md)), not from APT, and each site runs its own PHP-FPM master for its selection ([ADR 0038](adr/0038-drain-site-php-through-private-haproxy.md)).

| Task | Where | Document |
| --- | --- | --- |
| Install PHP 8.4 or 8.5 on a server | **Stack → Runtime catalog → Add runtime** | [Runtimes](runtimes.md) |
| Choose a new site's PHP | **Create HTTP site** | [Creating a PHP site](sites.md#creating-a-site) |
| Move a site to another PHP runtime without dropped requests | The site's **Runtime** page | [Site PHP selection](runtimes.md#site-php-selection) |
| Set what the server's plain `php`, `composer` and `wp` run | **Stack → Defaults** | [Server command defaults](runtime-defaults.md) |

The offered PHP runtimes are `php84` and `php85`, the default builds of PHP 8.4 and 8.5 at the catalog's pinned nixpkgs revision for the server's architecture. A runtime's exact build changes only through a reviewed catalog update shipped with a Barectl release. Builds dropped from a later catalog stay recognized as retired, so a newer controller still identifies them on older servers.

A switch is refused when the target runtime lacks a PHP module the site's current runtime loads, naming the module. Changing a site's PHP changes its PHP-FPM master and its `bin/php`, `bin/composer` and `bin/wp` wrappers; it does not touch the site's files, other sites or the server defaults.

Extensions beyond each build's packaged set, such as phpredis or imagick, are not offered. The [competitor and package-source analysis](php-versions-competitor-analysis.md) compares per-site PHP with hosted panels, native server panels and container platforms.
