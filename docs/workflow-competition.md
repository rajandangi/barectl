# Workflow competition research

Researched: 2026-10-04. Status: research and proposed workflow, not an accepted specification or implemented redesign. Design-system selection is outside this research.

## Method and scope

This comparison reads current first-party documentation for CloudPanel v2, Laravel Forge and Coolify. The linked pages were opened and their substantive instructions checked; search snippets were not used as evidence. No authenticated competitor dashboard, usability session, installation or failure experiment was performed. Documentation establishes advertised flows, not their ease of use or every interface state. Missing documentation is not proof that a feature is absent.

The question is how Barectl can make its existing capabilities useful without asking operators to navigate its execution engine. CloudPanel supplies a close native PHP-site comparison; Forge supplies an application-delivery comparison; Coolify supplies a different resource and deployment model. This is a qualitative workflow study, not a market-share, pricing or security ranking.

Barectl's baseline comes from the [README](../README.md), [v0.3 specification](v0.3.md), [site workflow](sites.md), [database workflow](databases.md), [TLS workflow](tls.md) and [domain language](../CONTEXT.md). Hosting resources are implemented; application deployment remains planned. The [dashboard plan](dashboard-plan.md) describes the existing interface; v0.1-era decisions are historical scope, not limits on current v0.3 capabilities.

## Documented workflow comparison

| Operator task | CloudPanel v2 | Laravel Forge | Coolify | Implication for Barectl (analysis) |
| --- | --- | --- | --- | --- |
| Connect and prepare a server | Install the panel on an empty server through SSH with root access. [Installation][cp-install] | "New server" asks for name/provider, then server type, region and size; custom VPS adds IP and SSH port. [Servers][forge-server] | Add a manual server, choose SSH identity, then validate and install/verify Docker and start the proxy. Validation can change the server. [Add server][cool-server] | Separate read-only connection verification from reviewed setup; describe readiness for the next task. |
| Create the first useful entity | Add Site chooses a site type; PHP creation asks for application, domain and PHP version, then application files can be uploaded through the site user. WordPress has its own creation flow. [Add Site][cp-site] | Site creation covers web directory/PHP and source-control selection; a repository and branch can install the application. [Sites][forge-site] | A first-app guide creates a project and Docker Image resource, runs `nginx:alpine`, then opens a generated URL. [First app][cool-first] | Make the promised endpoint explicit: v0.3 produces a PHP hosting site, not a deployed application. |
| Associate a database | Add Database requests database name, user and password; database-user creation includes database and permission selection. [Databases][cp-db] | Server Storage > Database creates databases; additional users receive selected database access; application environment configuration connects an external database. [Databases][forge-db] | Database resources expose an Internal URL; applications on the same destination use it in their environment variables. [Databases][cool-db] | Put the site's optional database beside that site and provide accurate socket-based connection instructions. |
| Enable HTTPS and resolve DNS blockers | SSL/TLS > Actions > New Let's Encrypt Certificate asks for names and offers Create and Install; valid DNS records are required. [TLS][cp-tls] | Site Domains combines domains/certificates. HTTP-01 needs server-directed DNS and public port 80; current docs recommend DNS-01 using a Forge-managed CNAME target. [Domains][forge-domains] | Configure an `https://` domain and redeploy; the proxy requests/renews certificates. Public routing and ports 80/443 remain prerequisites. [Domains][cool-domains] | Offer one HTTPS goal, then explain each blocking hostname/address and the operator's correction. Do not import hosted DNS delegation. |
| Diagnose progress or failure | A log viewer exposes Nginx/PHP-FPM logs, also available under the site user's logs directory. The checked pages do not establish an interruption/reconciliation UX. [Logs][cp-logs] | Deployments documents optional post-deploy health checks and default email notification for failed deployments. [Deployments][forge-deploy] | Deployments and runtime Logs answer separate questions; diagnosis starts with status and the first failing deployment command. [Operations][cool-ops] | Preserve action context, show completed/current stages and first actionable failure, and keep detailed evidence accessible. |
| Recover after a change | No atomic provisioning or automatic recovery guarantee was established by the reviewed pages. | The reviewed deployment and site docs describe application operations, not proof of Barectl-equivalent mutation guarantees. | Rollback selects a retained older application image; it does not undo database migrations or restore persistent storage. [Rollbacks][cool-rollback] | Use precise outcomes and recovery actions; never label an infrastructure retry "rollback" or imply it reverses user data. |

## Findings and limits

### 1. Give a site or application a stable home

CloudPanel documents named tasks such as Add Site, Databases, SSL/TLS and Logs. Forge groups domains, repository configuration and deployment around a site. Coolify gives each application separate Configuration, Deployments and Logs views. These are documented navigation/task structures, not a claim that every screen is simple. [CloudPanel][cp-site], [Forge][forge-site], [Coolify][cool-ops]

**Analysis:** Barectl should let an operator choose a domain and remain in that site's context while adding its database or HTTPS. A site's native identity is still necessary, but its FPM socket and configuration fingerprint are supporting evidence. Existing services, permissions and immutable reviews can remain behind this interface. Navigation should not mirror bootstrap/site/database/TLS Python modules.

### 2. Reach a small, observable success before optional complexity

Coolify's first-app guide intentionally avoids Git and build configuration, ending at a visible Nginx page. Its generated `sslip.io` URL is for HTTP testing; current domain documentation warns against changing it to HTTPS. Forge instead supplies a preview `on-forge.com` domain with HTTPS. Those are different platform provisions, not universal prerequisites. [First app][cool-first], [Coolify domains][cool-domains], [Forge domains][forge-domains]

**Analysis:** Barectl can already verify an HTTP PHP site with explicit Host routing before public DNS exists. It should distinguish "HTTP and PHP verified on this server" from "public domain reachable" and "application deployed." A placeholder is a valid first success, provided it is named honestly. A hosted preview-DNS service would introduce another dependency and needs a separate architecture decision; it is not required for the workflow redesign.

### 3. Explain prerequisites at the blocked action

All three products retain operator work around DNS or server access. CloudPanel's concise certificate action still requires valid DNS; Forge separates HTTP-01 from hosted DNS-01; Coolify server validation can install Docker and restart it. Simplicity does not establish absence of prerequisites or mutation. [CloudPanel TLS][cp-tls], [Forge domains][forge-domains], [Coolify server][cool-server]

**Analysis:** For Barectl HTTPS, show a compact readiness result for each requested name: expected destination, observed A/AAAA answers, HTTP reachability and the applicable blocker. Say what to correct and where to recheck. Do not promise automatic DNS/firewall repair, CDN support or issuance retries. For database setup, identify a missing engine or PHP driver at the site's Add database action, while retaining the separate reviewed package action and its effects on other sites.

### 4. Separate task progress from ongoing site state

Coolify explicitly distinguishes deployment output from runtime application logs. Forge offers post-deploy reachability checks; neither is evidence that a cached inventory continuously proves health. [Coolify operations][cool-ops], [Forge deployments][forge-deploy]

**Analysis:** Barectl needs two visible dimensions: what the current operation has done, and what native evidence currently establishes. "Certificate obtained; HTTPS activation failed" is more useful than a single failed badge. An unreachable controller must not become "server offline." An old successful run must not override new configuration drift. The server/site view needs collection times; Activity is this controller's operation record, not another device's recoverable private history.

## Proposed workflow using current capabilities

This proposal changes presentation and orchestration only after acceptance. It does not loosen admission, privilege checks, native locking or review requirements.

Proposed page hierarchy:

- **Server:** Overview, Websites, Setup, Activity, Advanced. Overview summarizes evidence and next steps; Websites opens a domain; Setup holds reviewed stack actions; Advanced exposes native diagnostics.
- **Website:** Overview, Database, HTTPS, Activity, Advanced. Deployment belongs in a later accepted application-delivery slice and has no active control today.

The interaction is Servers → chosen server → Websites → chosen domain → Database or HTTPS → action progress → updated website overview. Create PHP site starts from Websites and returns there after review/apply. Each page keeps the server and website context; Activity links back to the affected entity and original operation.

1. **Connect server.** Choose the existing controller SSH alias, verify connection and inspect the server. Show unsupported/inaccessible evidence and host-trust remediation without a browser trust bypass.
2. **Prepare web hosting.** Show installed Nginx/PHP evidence and the available reviewed setup actions. Do not equate an installed package with a verified ready service or silently bundle metadata refresh/package changes.
3. **Create PHP site.** Enter explicit domains and the required identifier, with its purpose explained. Prepare the existing plan, show a short effect summary and access to the complete exact review, then apply. End with verified HTTP/PHP outcome and the site page.
4. **Add database, optionally.** Start from that site. Show its current binding, available supported engines and missing prerequisites. Reuse engine/driver setup and database actions; disclose restarts. One database per site and socket authentication remain the v0.3 boundary.
5. **Enable HTTPS, independently.** Start from that site's domains and contact email. Reuse Create and Install with one authorization and stage progress. DNS problems show corrections; database absence never blocks HTTPS.
6. **Continue from the site.** Overview shows domain/PHP/database/HTTPS evidence and last inspection. Activity links the relevant operation and safe outcome inspection. Advanced details contain native resources and admission evidence. Do not advertise unimplemented deploy/edit/delete controls.

The journey is a suggested order, not a mandatory wizard. Existing native sites must enter through discovery; operators may add HTTPS before a database. Unsupported or partial layouts need honest explanations and the existing manual recovery route. Lost acknowledgement offers Check outcome for the original operation; partial changes require inspection and fresh review, not automatic replay.

## Later application delivery is a separate product slice

Barectl v0.3 has no Git/Composer/WP-CLI deployment, framework rewrite templates, environment editor, queue setup or release rollback. Forge's repository-to-application flow demonstrates the larger outcome users may expect; CloudPanel also distinguishes generic PHP-site creation from subsequent file upload. [Forge sites][forge-site], [CloudPanel sites][cp-site]

Before adding "Deploy application," choose a bounded outcome, such as one qualified Laravel or WordPress path, and specify source access, native layout, database configuration, verification and recovery. Research the framework and established deployment tools before custom execution. Keep the existing SSH boundary and reconstructable native state; do not borrow Coolify's container model, Forge-managed DNS delegation or CloudPanel's installed-panel assumption merely to copy their buttons.

## Validation before implementation claims

Test the proposed journey locally with representative operators: a fresh supported server, an already prepared server, a site discovered by a fresh controller, wrong DNS/AAAA, missing database driver, native lock conflict, partial apply and lost acknowledgement. Ask them to create a PHP site, associate its optional database and enable HTTPS without being taught plan terminology. Record task completion, wrong turns, understanding of blockers and recovery, and whether they distinguish hosting readiness from application deployment. Engineering tests remain required, but cannot replace this usability evidence.

[cp-install]: https://www.cloudpanel.io/docs/v2/getting-started/other/
[cp-site]: https://www.cloudpanel.io/docs/v2/frontend-area/add-site/
[cp-db]: https://www.cloudpanel.io/docs/v2/frontend-area/databases/
[cp-tls]: https://www.cloudpanel.io/docs/v2/frontend-area/tls/
[cp-logs]: https://www.cloudpanel.io/docs/v2/frontend-area/logs/
[forge-server]: https://laravel.com/forge/docs/servers/the-basics
[forge-site]: https://laravel.com/forge/docs/sites/the-basics
[forge-domains]: https://laravel.com/forge/docs/sites/domains
[forge-db]: https://laravel.com/forge/docs/resources/databases
[forge-deploy]: https://laravel.com/forge/docs/sites/deployments
[cool-server]: https://coolify.io/docs/core/infrastructure/servers/add-server
[cool-first]: https://coolify.io/docs/deploy-your-first-app
[cool-domains]: https://coolify.io/docs/core/networking/domains
[cool-db]: https://coolify.io/docs/databases/
[cool-ops]: https://coolify.io/docs/applications/operations/overview
[cool-rollback]: https://coolify.io/docs/applications/deployments/rollbacks
