# Host your first site

Create site prepares the software a site needs. WordPress installation is an explicit choice. [Site creation qualification](site-creation-qualification.md) records the supported combinations and delivery evidence.

## Before you start

Run Barectl and its controller worker. Configure an SSH alias with host-managed credentials and verified host trust, then use an operator account authorized for the selected hosting actions. The account created with `createsuperuser` has all permissions.

Use a supported Ubuntu server. For HTTPS, point your domain at that server and make ports 80 and 443 reachable. Barectl does not change DNS or firewalls. [SSH registration](ssh-aliases.md) covers connection setup.

## Create the site

Open **Servers**, choose **Add server**, select your SSH alias and wait for the connection check to finish. Open **Sites** and choose **Create site** or **Create WordPress site**.

Enter the domain. A PHP site can request HTTPS and an optional database. A WordPress site also needs a title, administrator username and email; it includes MariaDB and HTTPS. Accept the displayed certificate authority's agreement. Optional **Site settings** hold additional domains and a different PHP version.

Press **Create**. Follow the progress view while Barectl prepares missing software, creates the isolated site and selected database, enables HTTPS, and installs WordPress when explicitly requested. No separate source, package, driver or intermediate review click is required.

## Open WordPress

When creation completes, choose **Show administrator password** in the browser that submitted the request, copy it, and open **WordPress login**. The password is shown once and clears from the page after one minute. If browser first access is unavailable, use the explicit administrator password recovery on the site's WordPress page.

## Change a runtime version

Open the server's **Setup** section to change the default PHP or Node version. Existing sites retain their selections. Open a site's **Overview** to change that site's version. Barectl installs an eligible missing version and shows progress; other sites remain pinned.

A Node selection records the site's version pin and displays its exact executable. Use that executable for site commands and builds; ordinary `node`, `npm` and `npx` commands still use the server default. Application deployment and process services are separate.

## If creation stops

The progress view names the stopped stage and retains completed work. Correct the reported connection, permission, source, DNS or server conflict before proceeding. Unknown native outcomes must be checked before another mutation. Barectl does not delete partial content or databases or repeat uncertain installations.

**Advanced** contains individual diagnostic plans and detailed native evidence. Existing [site recovery](sites.md#recovering-a-partial-site), [TLS recovery](tls.md) and [WordPress Finish](wordpress.md#finishing-a-partial-installation) remain available after fresh inspection. They are recovery tools rather than prerequisites for ordinary creation.
