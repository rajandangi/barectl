# Host your first PHP site

This guide follows the current dashboard on `main`. For an older installation, select its release tag before following the documentation. It creates native PHP hosting with a placeholder page, an optional database and HTTPS. Application installation remains planned.

## Before you start

- Run Barectl and its `db_worker` process as described in [Run locally](../README.md#run-locally).
- Use an Ubuntu 26.04 server that meets the [bootstrap prerequisites](bootstrap.md#prerequisites). A fresh supported server is the simplest starting point.
- Configure an SSH alias, credentials and verified host trust on the controller. Provisioning requires root or the documented noninteractive sudo authority. [SSH registration](ssh-aliases.md) explains the setup.
- Use an operator account with the relevant discovery, bootstrap, site, database and TLS permissions. The account created with `createsuperuser` has all permissions. [Operator accounts](../README.md#operator-accounts) lists them.
- For public HTTPS, use a domain you control, configure its DNS and make ports 80 and 443 reachable. Barectl does not configure DNS or firewalls.

## 1. Connect your server

Open **Servers**, choose **Add server** and select your configured SSH alias. Registration queues a connection check and opens the server's **Overview**.

Wait for the check to finish. Confirm the recorded platform, hosting components and collection time. If it stays queued, check that the controller worker is running. Resolve host-key or authentication failures through the controller's SSH configuration before retrying.

## 2. Prepare web hosting

Open **Setup**. For each missing component, prepare, review and apply its profile, starting with Nginx and then PHP FPM and CLI. For this journey, use the distribution's default PHP profile. Additional branches from the approved PHP source remain subject to the [per-site PHP qualification gates](php-versions-qualification.md).

Read the proposed package changes and service effects before applying. Package metadata refresh is a separate reviewed action if needed. If evidence is unavailable or configuration is unsupported, follow the refusal's explanation before proceeding.

Wait for verification and refresh observations before creating the site. See [Bootstrapping a server](bootstrap.md) for exact requirements and recovery.

## 3. Create the PHP site

Open the server's **Sites** section and use **Site plans**. Choose a site identifier, such as `demo`, enter your domain names and select an installed PHP branch from the recorded observations. Refresh unavailable evidence before selecting. A fresh review checks whether that branch is qualified for this server. `demo.example.com` is a documentation example; replace it with a domain you control.

Use the [site naming rules](sites.md#names) for identifiers and explicit DNS names. Reserved identifiers, wildcards and IP addresses are refused.

Choose **Prepare site plan**. Review the dedicated Linux account, directories, generated files and shared-service reloads, then apply from the plan's page. An expired or changed review needs a new preparation.

After verification and discovery observe the site, follow the link to its **Overview**. Barectl verifies the placeholder page from the server itself. Check the domain in your own browser to confirm public reachability separately.

## 4. Add a database if needed

Open the site's **Database** section and choose MariaDB or PostgreSQL. If the engine or PHP database driver is missing, use the link to **Setup**. Prepare, review and apply those separate setup actions, then return to the site's Database section.

Prepare and review the site's database binding, then apply from its plan page. Adding a binding does not install the engine or driver.

Use the connection guidance shown for the observed binding. It applies to site code running as the site's Linux user through a local socket, without a database password. Remote TCP access is not part of this workflow. See [Site databases](databases.md).

## 5. Enable HTTPS

Open the site's **HTTPS** section. Check the exact domains listed and enter your certificate contact email. **Check readiness** is an optional read-only check of the DNS evidence.

Stop or upgrade older Barectl controllers before enabling renewal; mixed-version mutation is unsupported. See the [TLS requirements](tls.md).

Read the action's disclosure before choosing **Enable HTTPS**. One request authorizes the challenge route, guarded Certbot renewal, production certificate order and HTTPS activation, including Certbot's subscriber-agreement handling. A database is not required.

Follow the installation stages until their outcomes are established. Check public HTTPS in your browser and verify the HTTP redirect. A passing DNS review does not prove the certificate authority can reach the server. See [TLS](tls.md#create-and-install).

## 6. Check observations and history

Refresh observations to see the current native configuration. Use the site's **Activity** for creation, database and HTTPS records; server-wide setup and discovery records remain in the server's Activity.

Accepted native mutations continue under systemd if the controller disconnects. Discovery and plan preparation depend on the controller worker. Retained history does not establish current site health or guarantee a future certificate renewal.

## If an operation stops

Open its original run page. For an uncertain result, choose **Check outcome** to inspect the original operation. Do not assume nothing changed or submit another certificate order while its outcome is uncertain.

Partial changes remain on the server. A reviewed **Finish** plan can create missing HTTP site resources while existing resources still match the convention. TLS has its own recovery procedure. Follow [Native recovery](recovery.md).
