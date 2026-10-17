# Server command defaults

The target stack has independent PHP and Node.js defaults on the server's Stack page. A current discovery lists installed, recognized runtime profiles. Preparing a default creates an immutable review. Applying it requires Shared consent and changes the server's plain commands under the native mutation lock.

The default does not change any existing site's command links, pool, socket, files or service. A new site's form preselects the observed PHP default only when that runtime is currently verified for site creation. An older or failed discovery cannot authorize a change or supply that initial selection.

## Native convention

Root owns the command links in `/usr/local/bin`:

| Commands | Link target |
| --- | --- |
| `php` | `/nix/var/nix/profiles/barectl/<php-entry>/bin/php` |
| `composer`, `wp` | `/usr/local/libexec/barectl/defaults/<php-entry>/<command>` |
| `node`, `npm`, `npx` | `/nix/var/nix/profiles/barectl/<node-entry>/bin/<command>` |

PHP entries are `php84` and `php85`; Node entries are `nodejs_22` and `nodejs_24`. A selected profile must resolve to an installed catalog build for the server's architecture. Known retired builds remain recognizable. This operation neither downloads nor installs a runtime.

The PHP wrappers and their directories are root-owned executable configuration with mode 0755. Composer executes the selected PHP against the package's interpreter-neutral `share/php/composer/bin/composer`. WP-CLI executes that PHP against `share/wp-cli/wp-cli.phar`. Direct links to the packages' `bin` wrappers would select the package's PHP instead.

Composer's wrapper sets PATH to the selected PHP profile, the helper directories in the installed Composer package's immediate Nix references, and the standard system directories. The read-only `nix-store --query --references` operation identifies those immutable dependencies. Git, curl, unzip, xz and 7zz must be available there. This preserves the pinned package's helper access without installing or evaluating anything during discovery or a default change. WP's wrapper uses the same deterministic PATH and the selected interpreter.

Discovery reconstructs defaults from the exact command targets, wrapper bytes, directory permissions and known profile identities. It uses no inventory or operation-history file. A command or wrapper outside this convention is reported as set by the administrator. Barectl refuses the affected default change and leaves it alone. Every command destination, wrapper preimage and parent directory is inspected before a mutation. The accepted unit rechecks that evidence under the shared native lock before writing anything.

If a filesystem operation fails after the first write, the run reports a partial outcome. Discovery reports the resulting native command state. It does not infer that a partially changed command family is complete or overwrite an unrecognized file to repair it.

## Upstream references

The [pinned Composer package](https://github.com/NixOS/nixpkgs/blob/7c8764b7c7b09b34f632464276218ef9090eaa11/pkgs/development/php-packages/composer/default.nix) defines its helper PATH. Its [installation hook](https://github.com/NixOS/nixpkgs/blob/7c8764b7c7b09b34f632464276218ef9090eaa11/pkgs/build-support/php/builders/v2/hooks/composer-install-hook.sh) defines the interpreter-neutral source layout. The [WP-CLI package](https://github.com/NixOS/nixpkgs/blob/7c8764b7c7b09b34f632464276218ef9090eaa11/pkgs/by-name/wp/wp-cli/package.nix) provides the PHAR. [Node profile composition](https://github.com/NixOS/nixpkgs/blob/7c8764b7c7b09b34f632464276218ef9090eaa11/pkgs/development/web/nodejs/symlink.nix) includes matching npm and npx. The [Nix 2.35 query documentation](https://nix.dev/manual/nix/2.35/command-ref/nix-store/query) defines immediate-reference queries.
