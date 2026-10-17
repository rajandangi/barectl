# Host your first PHP site

This walkthrough takes a fresh Ubuntu 26.04 server from **Add server** to a PHP site served over HTTP. Each step is its own reviewed action; the linked documents hold the details, refusals and recovery. HTTPS, databases and application installation are not available yet ([roadmap](../ROADMAP.md)).

## Before you start

- A fresh Ubuntu 26.04 LTS server on amd64 or arm64, with at least 4 GiB free disk and 900 MiB available memory, and nothing else installed: no web server, PHP, hosting panel or Nix ([prerequisites](bootstrap.md#prerequisites)).
- SSH access as root, or as a user with passwordless sudo, with the key in the controller's SSH agent or in a key file an administrator approved ([saved server connections](saved-server-connections.md)).
- The server's host key fingerprint from your provider's console.
- A Barectl account in the Administrator group, and the worker running ([run locally](../README.md#run-locally)).

## 1. Add the server

Choose **Add server**, enter a name, the address, the SSH user and the key choice, and press **Save and check**. On a new host the check stops at the unknown host key and shows its fingerprint. Paste the fingerprint from your provider's console into **Provider host key fingerprint** and choose **Confirm fingerprint and check** ([confirming a fresh host](ssh-connections.md#confirming-a-fresh-saved-address-host)). Overview then shows the host standing: a Fresh host is ready.

If the standing is Not manageable, Overview lists the reasons. Resolve them through ordinary administration and check again; Barectl never changes such a server.

## 2. Set up the server

Choose **Set up server** and prepare the review. Read what it installs and downloads, then apply it. The run takes a few minutes and reports its stages: preflight, Nix, catalog, Caddy, journald and verify ([setting up a server](bootstrap.md)). If the server is still running its first-boot package updates, the review is refused; wait and prepare again.

## 3. Add a PHP runtime

Open **Stack**, find **Runtime catalog** and choose **Add runtime** for `php84` or `php85`. Apply the review ([runtimes](runtimes.md)). Optionally set it as the server's default PHP under **Defaults** ([server defaults](runtime-defaults.md)); new sites then preselect it.

## 4. Create the site

Open **Sites** and use **Create HTTP site**: enter the domain names, keep or edit the identifier derived from the first name, and choose the runtime. Prepare and apply the review ([creating a PHP site](sites.md)). The run verifies the site by requesting it from the server itself, then links to the site's page once discovery observes it.

Point your domain's DNS at the server to reach the placeholder page from the internet; Barectl does not manage DNS. Copy your code into `/var/www/<identifier>/current/public` as the site user, for example with `sudo -u s<identifier>`, keeping PHP source at mode 0600 and static files at 0640 ([site convention](site-conventions.md#site-directory)). The site user's shell is `nologin`, so it has no SSH login of its own.

## Next steps

- Move the site to another PHP version from its **Runtime** page; requests in progress finish on the old version.
- Read [native recovery](recovery.md) to find the site's files, services and logs on the server.
