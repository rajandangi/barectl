# Host your first PHP site

This walkthrough takes a fresh Ubuntu 26.04 server from **Add server** to a PHP site served over HTTPS. Each step is its own reviewed action; the linked documents hold the details, refusals and recovery. A WordPress or Laravel site, a database engine and Laravel deployment follow the same journey ([sites](sites.md), [databases](databases.md)).

## Before you start

- A fresh Ubuntu 26.04 LTS server on amd64 or arm64, with at least 4 GiB free disk and 900 MiB available memory, and nothing else installed: no web server, PHP, hosting panel or Nix ([prerequisites](bootstrap.md#prerequisites)).
- SSH access as root, or as a user with passwordless sudo, with the key in the controller's SSH agent or in a key file an administrator approved ([saved server connections](saved-server-connections.md)).
- The server's host key fingerprint from your provider's console.
- The Barectl superuser created during [local setup](../README.md#run-locally), with the worker running. If you use a delegated account, check the [required permissions](operator-accounts.md).

## 1. Add the server

Choose **Add server**, enter a name, the address, the SSH user and the key choice, and press **Save and check**. On a new host the check stops at the unknown host key and shows its fingerprint. Paste the fingerprint from your provider's console into **Provider fingerprint** and choose **Confirm and check**. A fresh host shows **Needs setup** and offers **Set up server**. [Confirming a fresh host](ssh-connections.md#confirming-a-fresh-saved-address-host)

If the status is **Cannot be managed**, read the reasons on the server page. Resolve them through ordinary administration and choose **Refresh server** to check again.

## 2. Set up the server

Choose **Set up server** and prepare the review. Read what it installs and downloads, then apply it. The run takes a few minutes and reports its stages: preflight, Nix, catalog, Caddy, journald and verify ([setting up a server](bootstrap.md)). If the server is still running its first-boot package updates, the review is refused; wait and prepare again.

## 3. Add a PHP runtime

On the server page, open **Settings > PHP versions**. Under **Add PHP version**, choose PHP 8.4 or 8.5 and confirm the change. Optionally choose **Default PHP** on the same page to preselect that version for new sites. [Runtimes](runtimes.md) · [Server defaults](runtime-defaults.md)

## 4. Create the site

Open **Sites** on the server page and choose **Create site**. Select **PHP** and a PHP version, enter the domain names, then keep or edit the site identifier. Choose **Continue** and confirm the change. The run requests the site from the server to verify it and links to the site page after discovery finds it. [Creating a PHP site](sites.md)

Point your domain's DNS at the server to reach the placeholder page from the internet; Barectl does not manage DNS. Copy your code into `/var/www/<identifier>/current/public` as the site user, for example with `sudo -u s<identifier>`, keeping PHP source at mode 0600 and static files at 0640 ([site convention](site-conventions.md#site-directory)). The site user's shell is `nologin`, so it has no SSH login of its own.

## Next steps

- Move the site to another PHP version from its **Settings**; requests in progress finish on the old version.
- Read [native recovery](recovery.md) to find the site's files, services and logs on the server.
