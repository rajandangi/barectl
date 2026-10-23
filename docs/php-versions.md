# Per-site PHP versions

Each site selects its own PHP runtime, and sites on one server can run different PHP versions. The runtimes come from Barectl's pinned [runtime catalog](target-architecture.md#nix) ([ADR 0028](adr/0028-supply-runtimes-and-tools-from-pinned-nix.md)), not from APT, and each site runs its own PHP-FPM master for its selection ([ADR 0038](adr/0038-drain-site-php-through-private-haproxy.md)).

| Task | Where | Document |
| --- | --- | --- |
| Install PHP 8.4 or 8.5 on a server | **Stack → Runtime catalog → Add runtime** | [Runtimes](runtimes.md) |
| Choose a new site's PHP | **Create HTTP site** | [Creating a PHP site](sites.md#creating-a-site) |
| Move a site to another PHP runtime without dropped requests | The site's **Runtime** page | [Site PHP selection](runtimes.md#site-php-selection) |
| Set what the server's plain `php`, `composer` and `wp` run | **Stack → Defaults** | [Server command defaults](runtime-defaults.md) |
| Apply a newer catalog build without dropped requests | **Stack → PHP runtimes → Update available** | [Catalog updates](#catalog-updates) |
| Remove an unused PHP version | **Stack → PHP runtimes → Remove runtime** | [Removing a runtime](#removing-a-runtime) |

The offered PHP runtimes are `php84` and `php85`, the default builds of PHP 8.4 and 8.5 at the catalog's pinned nixpkgs revision for the server's architecture. A runtime's exact build changes only through a reviewed catalog update shipped with a Barectl release. Builds dropped from a later catalog stay recognized as retired, so a newer controller still identifies them on older servers.

A switch is refused when the target runtime lacks a PHP module the site's current runtime loads, naming the module. Changing a site's PHP changes its PHP-FPM master and its `bin/php`, `bin/composer` and `bin/wp` wrappers; it does not touch the site's files, other sites or the server defaults.

Extensions beyond each build's packaged set, such as phpredis or imagick, are not offered. The [competitor and package-source analysis](php-versions-competitor-analysis.md) compares per-site PHP with hosted panels, native server panels and container platforms.

## Removing a runtime

**Stack → PHP runtimes** offers **Remove runtime** for an installed PHP or Node runtime that no site and no server default selects. A runtime with users explains them instead: the sites by name, or the server default. A site whose PHP transition is incomplete also blocks PHP removal until it is finished or reversed on the site's Runtime page.

The review names the exact catalog build, the profile generation and the native files it deletes. Apply rechecks the profile, every site's PHP wrappers, the site pool configuration and the server defaults under the mutation lock, stops the diagnostic master, deletes only the convention's files, removes the profile's generations and collects the store paths that become unreachable. Other runtimes and their generations stay. A runtime used by a change prepared from another controller is refused when the body rechecks it, so two controllers cannot strand a site's selection.

## Catalog updates

When a Barectl release ships a newer catalog build for an installed entry, **Stack → PHP runtimes** shows **Update available** with the old and new versions and the sites that select the runtime. One review covers every installed entry with an older build.

A PHP update keeps requests served through [ADR 0038](adr/0038-drain-site-php-through-private-haproxy.md): each affected site moves to the other installed PHP runtime through the same private-admission drain as a site PHP change, the updated profile becomes the new generation, its diagnostic master restarts and verifies, and each site moves back. The update is refused when a PHP runtime with sites has no other installed PHP runtime to hold them. Caddy and HAProxy restart only when their own builds change, and the review lists that. A failure reports incomplete; every site keeps serving, the previous generation stays installed, and a fresh review finishes the remaining work. After the update verifies, older generations are collected while the active build and its predecessor stay as rollback candidates.
