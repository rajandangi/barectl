# TLS

HTTPS installation offers only managed sites with observed evidence from the current discovery snapshot. Inaccessible or unsupported evidence keeps the site unavailable; give the SSH identity the documented read access and refresh discovery before preparing HTTPS. Changed and partly applied sites remain unavailable until ordinary restoration or a reviewed site Finish plan makes them managed. This follows [ADR 0015](adr/0015-recognize-only-the-convention.md); [convention qualification](convention-qualification.md) records the integration evidence.

Barectl prepares HTTPS for sites that follow the [native site convention](site-conventions.md) in reviewed steps. Every change refuses while Certbot's scheduled renewal has processes ([renewal exclusion](#renewal-exclusion)); **renewal setup** installs the distribution's Certbot and guards its packaged renewal; an existing site gains its HTTP-01 **challenge route**; a **production order** issues its certificate; and **activation** serves HTTPS and redirects HTTP without touching the certificate. The design is [v0.3](v0.3.md#tls-preparation-issuance-and-renewal) and the [TLS convention](site-conventions.md#tls-convention); the qualified revisions are in [v0.3 qualification](v0.3-qualification.md#tls-readiness-and-staging).

## Create and Install

Open a discovered site's **HTTPS** section, check the listed domains, enter the contact email and press **Enable HTTPS**. **TLS plans** in the server's **Advanced** section offers the same action as **Create and Install**, with a choice of site. Barectl prepares the HTTP-01 challenge route, installs and guards Certbot renewal, checks fresh DNS readiness, orders the production certificate and activates HTTPS with the HTTP redirect automatically. No separate agreement checkbox, staging action or activation confirmation is required. The installation request authorizes Certbot's noninteractive subscriber-agreement handling ([ADR 0014](adr/0014-install-site-certificates-with-one-operator-action.md)).

The site's page shows that site's latest installation: each of the four stages (route preparation, renewal setup, certificate order, HTTPS activation) as completed, current, not started or failed, with its preparation and run times and links to those original records. The domains come from the current observation and the request carries the observation revision the page showed, so a stale page or changed domains are refused before anything is recorded; a repeated submission or reload returns the same installation. A site database is not required. The request needs `servers.view_server` and `discovery.view_siteobservation` for the site, and the installation permissions below; database permissions play no part.

Each native mutation still uses the existing worker, immutable plan, native lock and verification. Changed domains, a changed connection or identity, unsupported configuration, failed DNS, missing permissions and failed verification stop the sequence. An uncertain run pauses it; open the current step and use **Check outcome**, which inspects the original unit without resubmitting. A verified success continues the sequence; a failed or unknown outcome never automatically retries an order. A stage whose run could not be verified, or whose outcome is unknown or still being reconciled, is shown as **Outcome not established**, never as failed, with **Check outcome** on that original run, also after the installation stopped; when it is the order, the page says a certificate may have been issued and asks for that check before any new order. When the order verified and activation is established not to have changed the server (refused before any change), the page says the certificate was issued and is kept natively and that HTTPS was not activated; an activation that failed after changing the server, including one whose verification failed, says so; see [recovery](recovery.md#certificates-and-https). An installation recorded for other domains than the site now observed is labelled as an earlier installation for that identifier, and a verified installation is shown as historical, never as the current certificate state. No stage is rolled back, and correcting a blocker, for example DNS that the readiness review on the same page records, does not start a new order: a new installation needs a new submission. A passing readiness review does not prove that a public authority can reach the server. The site's observed certificate and its collection time remain separate from this controller's installation history.

The current native step keeps running without a controller. Starting later steps needs the controller's worker. Completed installation records stay local; another device reconstructs the site's native certificate and renewal state, not this installation's private progress. An active installation prevents server registration removal between steps. Starting again after a verified installation prepares satisfied steps without issuing another certificate or changing the site.

The default authority is Let's Encrypt. The selected names and authority stay fixed for the installation. Port 80 and, for serving HTTPS, port 443 must be publicly reachable. DNS must satisfy the existing readiness policy, including each published address family. The implementation does not configure DNS or firewalls.

The following individual actions are under **Advanced TLS plans and diagnostics**. They remain available for staging qualification, inspection and recovery; Create and Install performs the production installation without these intermediate operator actions.

## Permissions

TLS plans have their own permissions, separate from site and bootstrap permissions:

| Stage | Permissions |
| --- | --- |
| View TLS plans and their preparations | `servers.view_server` and `tls.view_tlsplan` |
| Prepare a TLS plan | the above and `tls.prepare_tlsplan` |
| Apply a TLS plan, and close a run whose outcome is unknown | the above and `tls.apply_tlsplan` |
| Order a production certificate | the above, `tls.prepare_tlsplan` to prepare, and `tls.issue_certificate` to apply |

A production order's apply needs `tls.issue_certificate` instead of `tls.apply_tlsplan`; asking the worker to submit one without it is refused before anything is queued. Site and bootstrap permissions grant none of these, and an account that may view only site or bootstrap plans never sees a TLS plan, its run or its line in Activity.

## Certbot renewal setup

Open the server and press **Prepare renewal setup plan** in **TLS plans**. The worker reads the server as root or through noninteractive sudo and changes nothing. The plan is the Certbot package profile, reviewed exactly as bootstrap reviews a package installation ([ADR 0007](adr/0007-admit-exact-package-transactions-with-an-inline-apt-guard.md)): Certbot 2.9.0 on Ubuntu 24.04 and 4.0.0 on 26.04, from the release's `main` and `universe` components, with the transaction's exact closure, the APT hooks, sources and indexes, and every bootstrap refusal. Beside the package effects it reviews its own: the runtime inhibition, the three renewal files with their complete bytes ([guarded renewal](site-conventions.md#guarded-renewal)), the override systemd must load before the timer is enabled, and the compatible-controller requirement. Its review also shows renewal's state as read: whether `certbot.timer` is enabled and active, when it last and next runs, and the last renewal's outcome ([renewal outcomes](#renewal-outcomes)). That is a protected, read-only renewal inspection: only accounts with `tls.prepare_tlsplan` can request it, and it reads nothing secret.

Setup is admitted only when nothing can renew outside the guard:

- Certbot is not installed, or it is installed at the qualified version with only its unmodified `cli.ini` and empty `renewal-hooks` directories under `/etc/letsencrypt`: no account, lineage, renewal configuration or hook. `/var/lib/letsencrypt` may hold site webroots only, and `/root/.config/letsencrypt` must not exist.
- No other unit named like `certbot`, `acme`, `letsencrypt`, `lego` or `dehydrated`, no Certbot snap, no scheduled task naming a certificate tool other than Certbot's unmodified `/etc/cron.d/certbot`, which does nothing under systemd, and no Certbot plugin or other ACME client package.
- No override of Certbot's units besides Barectl's drop-in, no runtime unit under `/run/systemd/system`, and the renewal files absent or exactly the reviewed ones, below root-controlled directories.

A refusal names what to do through ordinary administration, such as `systemctl disable --now <unit>`, `snap remove certbot` or `systemctl unmask --runtime certbot.timer certbot.service`; Barectl never disables or removes anything itself. After an interrupted setup, a new plan proposes only what remains, such as publishing the missing files and enabling the timer.

A fully installed guard with the timer enabled and active can be recognized through a separate read-only review even after issuance. That review checks the qualified installed Certbot, the packaged CLI configuration, exact guard files and effective service override, the existing automation and the stability of the evidence. Accounts and ordinary `archive`, `live` and `renewal` state may remain. Renewal configurations are parsed with Certbot's existing ConfigObj dependency and must use the convention's webroot, lineage paths and ECDSA P-256 policy; unknown renewal parameters, custom hooks, authorities outside the configured allowlist and unrelated configuration refuse recognition. The renewal directory must be a real root-owned directory only root can write. This review proposes no changes and never constructs a mutation payload. Installing or repairing a guard still requires the pristine state above; existing certificates and accounts are never adopted for a setup mutation.

Issuance reads existing account and lineage evidence as root or through authorized noninteractive sudo, just as activation does. Denied evidence refuses the review and cannot be treated as an absent certificate that should be ordered again.

### Applying renewal setup

A setup run is an apply run like any other, with `tls.apply_tlsplan` ([ADR 0013](adr/0013-inhibit-certbot-renewal-until-the-guard-is-verified.md)). One native unit, under the mutation lock:

1. rechecks the APT digest, the package digest and the renewal digest, a fixed root read of Certbot's configuration and state directories, the renewal files, Certbot's units and drop-ins, scheduled tasks and other certificate automation;
2. masks `certbot.timer` and `certbot.service` at runtime and rechecks that renewal has no processes;
3. installs the reviewed transaction with the pre-install guard, when the plan installs packages; the maintainer scripts cannot enable or start the masked timer;
4. publishes the missing renewal files, each staged beside its destination and linked into place only while the destination is absent;
5. reloads systemd, unmasks the service and requires it to load exactly the reviewed override, with both scripts valid shell;
6. unmasks the timer and enables and starts it;
7. requires `certbot --version` to report the reviewed version.

Verification then reads, as root, each file's bytes, owner and mode, the service's effective override, the timer's enablement, state, schedule and drop-ins, that no runtime unit remains, and Certbot's version, and checks that each installed package is at its reviewed version with nothing for `dpkg --audit` to report.

### Recovering a partial setup

| Exit | Execution | What exists; ordinary administration |
| --- | --- | --- |
| 15, 16, 21, 23, 25 | Refused before changes | Nothing changed; the runtime masks were removed. Prepare again. |
| 27 | Refused before changes | systemd refused the runtime mask; any mask added was removed. |
| 20 | Failed after dpkg changed packages | Certbot may be partly installed; complete it with apt and dpkg. The units stay masked until `systemctl unmask --runtime certbot.timer certbot.service` or a restart, and the timer stays disabled. |
| 28 | Partly applied | Certbot is installed; some renewal files may be missing. The units stay masked; a new plan publishes what is missing. |
| 29 | Partly applied | The files exist, but systemd did not load the reviewed override or a script is not valid shell: inspect `systemctl cat certbot.service`. The timer stays masked and disabled. |
| 30 | Partly applied | The override is verified, but the timer could not be enabled: `systemctl status certbot.timer`. |
| 24 | Validation failed | `certbot --version` reported another version. |

A terminated run, one stopped at its runtime limit or one whose outcome is unknown after a restart leaves the timer masked for the rest of that boot, and disabled after it.

## Renewal outcomes

`certbot.service` records each renewal's outcome itself; Barectl keeps no record on the server.

| Exit | Result | Meaning |
| --- | --- | --- |
| 0 | success | Nothing was due, or each due certificate renewed and Nginx serves it. |
| 75 | success | Skipped: another change held the mutation lock. |
| 76 | success | Skipped: a Barectl run still had processes. |
| 71 | failure | The lock directory or file was not safe; nothing ran. |
| 80 | failure | A certificate renewed on disk, but Nginx does not serve it: the deploy hook's `nginx -t` or reload failed, as the journal records. Run `nginx -t`, repair the configuration and `systemctl reload nginx.service`. |
| other | failure | Certbot failed; its log is `/var/log/letsencrypt/letsencrypt.log`. |
| | timeout | The run reached its 30 minute start limit and systemd stopped it. |

Read them with `systemctl show certbot.service -p Result -p ExecMainStatus` and `journalctl -u certbot.service`.

## Preparing a challenge route

Open the server and use **TLS plans**. Enter the identifier of an existing site. The worker reads the server as root or through noninteractive sudo exactly as [site preparation](ssh-connections.md#site-preparation) does, and changes nothing.

A challenge route is proposed only for a site that site admission finds complete, with every resource the convention names. A site file that already serves challenges from a conforming webroot is a plan without changes. Preparation refuses:

- a site that is not one complete convention site; site admission's single **not following the convention** refusal names the resource, and the site's plan is applied first;
- `/var/lib` or `/var/backups` that is not a root-owned directory only root can write, and `/var/lib/letsencrypt` or `/var/backups/nginx` that exists with another owner or mode than the convention's;
- an existing `/var/lib/letsencrypt/<id>` beside a site file without the route, which Barectl does not adopt;
- everything site admission refuses, such as unknown configuration, another site that declares one of the names, or evidence that changed while it was read.

## What a challenge route plan reviews

- The site file's current bytes, kept as the recovery preimage, and its complete replacement: the same file with one location, `^~ /.well-known/acme-challenge/`, served as files from `/var/lib/letsencrypt/<id>` ([challenge route](site-conventions.md#challenge-route)). Every other request is served as before.
- The webroot `/var/lib/letsencrypt/<id>` (root:www-data 0750), and `/var/lib/letsencrypt` (root:root 0755) and `/var/backups/nginx` (root:root 0700) when they are absent.
- The backup `/var/backups/nginx/<id>.conf.<unit>`, root:root 0600, named after the run's unit, which no Nginx include loads.
- `nginx -t` before the reload of `nginx.service`, the temporary probe, and that nothing is rolled back.

## Applying

A challenge route run is an apply run like any other ([applying reviewed plans](ssh-connections.md#applying-reviewed-plans)), with `tls.apply_tlsplan` at request, at dispatch and for acknowledging an unknown outcome. One native unit, under the mutation lock:

1. recomputes the [site revalidation digest](ssh-connections.md#the-revalidation-digest), which also covers the webroot and the backups, and requires the site file to be a root-owned 0644 regular file with one link and the preimage's bytes, the webroot, backup and stage paths to be absent, and every directory above them to be root's; otherwise exit 15, with nothing changed;
2. records the site's front-page status, creates the directories and copies the site file to the backup, whose bytes must equal the preimage's;
3. stages the replacement beside the site file, checks its bytes, and renames it over the site file only while that file still has the preimage's bytes ([ADR 0012](adr/0012-publish-site-files-without-replacing-them.md#replacement));
4. runs `nginx -t`; if it refuses, renames a copy of the backup back over the site file, runs `nginx -t` again, and reloads nothing;
5. reloads `nginx.service`;
6. writes `/var/lib/letsencrypt/<id>/.well-known/acme-challenge/barectl-<token>` and requires, for each name over each reviewed address family, the probe's exact bytes, 404 for its `.php` name and for the challenge directory, and the front page's earlier status;
7. removes the probe and the directories it wrote, if its bytes still match.

Verification then reads as root the site file's bytes, owner, mode and link count, the link's target, the webroot, the backup's bytes, owner and mode, that the probe and `.well-known` are gone, and that `nginx -t` accepts the configuration while `nginx.service` runs. A new discovery reports the webroot as the site's **HTTP-01 webroot** resource.

## Recovering a partial challenge route

Each exit status after the admission exits of [ADR 0006](adr/0006-use-native-bootstrap-execution.md#payload) names the boundary the run reached. Barectl never removes the webroot or the backup automatically and never resumes a run; a new plan shows what exists.

| Exit | Boundary | What exists; ordinary administration |
| --- | --- | --- |
| 15 | Evidence changed | Nothing changed. Prepare again. |
| 56 | Directories or backup | Some of the webroot, `/var/backups/nginx` and the backup; the site file is unchanged. Inspect with `ls -ld`. |
| 57 | Replacement | Webroot and backup; the site file was not replaced, or had changed and was kept. |
| 58 | Candidate refused, restored | `nginx -t` refused the candidate; the preimage was restored and `nginx -t` accepts it. Nothing was reloaded. |
| 59 | Candidate refused, not restored | Restore with `cp /var/backups/nginx/<id>.conf.<unit> /etc/nginx/sites-available/<id>.conf`, then `nginx -t`. Nothing was reloaded. |
| 90 | Reload | The route is on disk and valid; `systemctl status nginx.service`. |
| 91 | Not serving | The route was reloaded, but the probe or the 404 answers or the front page differed; the probe was removed. Inspect with `nginx -T`; restore the preimage and reload if the site no longer serves as before. |
| 92 | Probe left | The probe could not be removed or had changed: remove `/var/lib/letsencrypt/<id>/.well-known`. |

A terminated run or one stopped at its runtime limit may stop at any boundary; its page says so, and the site file is either the preimage or the reviewed replacement.

## Renewal exclusion

Certbot's packaged renewal takes the mutation lock only through the guarded wrapper a later setup installs, and its children do not keep the lock. Every apply run's admission therefore refuses with exit 25, before any change, while `certbot.service`'s control group has processes, including a process that outlived the service's main process; a closure of an unknown outcome stays reconciling for the same reason ([ADR 0006](adr/0006-use-native-bootstrap-execution.md#payload)). The check holds only between compatible controllers: upgrade or stop controllers from before it, such as v0.2, before a server is managed with renewal. No remote registry records which controllers exist, and an administrator's own commands outside the lock are not excluded.

## Readiness

Open the server and press **Prepare TLS readiness review** in **TLS plans**, with the identifier of a site whose file serves its challenge route. The worker reads the server without changing it: the site, as a site plan's preparation reads it, then the server's own resolver's answer for each of the site's names (A, AAAA, CNAME and CAA through `resolvectl`), the server's own global addresses (`ip`), its NTP synchronization (`timedatectl`) and the authority directory's answer over each family the names publish (an HTTP/1.0 GET over the system trust store). DNS, the addresses, the clock and the directory need no privilege; only the site's reads need root or noninteractive sudo. The review records each read and judges it:

- a name that does not resolve, the resolver's failure and a dangling CNAME are refused as incomplete evidence;
- resolved addresses must be the server's own: anything else, such as a proxy or content delivery network's, refuses the destination, since an order would prove their path, not this server's. The names must also all resolve to the same addresses; several routing targets refuse;
- a published AAAA record requires the server to hold a global IPv6 address and the directory to answer over IPv6: IPv4 success cannot stand in for it;
- a CAA record that does not name the authority refuses: the authority would refuse the order;
- the clock must be NTP synchronized and the directory must answer an ACME document over every read family.

The site must be one complete convention site, judged by the same site admission question a challenge route uses, or site admission's **not following the convention** refusal, naming the resource, is recorded: a readiness review writes nothing and prepares nothing. The authority is the allowlist's default; the staging order's preparation repeats the same reads fresh for the reviewed staging authority.

The site's **HTTPS** section queues the same review for that site and shows it in the site's context; the review keeps the server's own global IPv4 and IPv6 addresses read at preparation, with the collection time and whether address evidence was available, for refused reviews once the addresses were read as well as eligible ones. Each domain shows its observed A/AAAA answers beside the expected destinations. Expected addresses are never inferred from the controller's DNS, an SSH alias or a fingerprint; a review recorded before this evidence existed says **Expected destination not recorded** and offers a fresh review. A passing review, a server-side route probe and an outbound directory read do not prove that a public certificate authority can reach the server over HTTP; rechecking is a read-only action and never an automatic certificate retry.

## Staging

A separately reviewed **staging order** demonstrates the public path for one site without touching production state. Open the server and press **Prepare staging order plan**, with the site identifier, the staging account's contact address, the allowlisted authority and noninteractive registration under the authority's terms. Requesting the order authorizes its subscriber-agreement handling; no separate checkbox is required. The preparation repeats the [readiness](#readiness) reads fresh.

A staging plan reviews, beside the readiness evidence, the guarded Certbot at its qualified version, the exact names, the authority, its directory and which CAA value it records under, the contact address, the isolated staging directories and the staged certificate's state. The staging account registers with the operator's address and no other secret; the private key never leaves the server and no plan, output or audit prints one. Certificates are ECDSA P-256 (`secp256r1`), the only key policy qualified on both Certbot versions. When a staging certificate for exactly the reviewed names already exists, the review is a plan without changes with its validity dates; a lineage for other names is never adopted.

A run is an apply run like any other, with `tls.apply_tlsplan`, under the mutation lock: it rechecks the reviewed site digest, requires Certbot, creates the root-only isolated directories, runs one `certonly` order against the staging authority through the site's challenge webroot and validates the staged certificate's subject alternative names immediately afterwards. A lost answer is reconciled from the unit alone, like any other run; Barectl never orders twice and never retries automatically.

Creating the first staging directory changes its parent's directory link count. After that authorized setup, the run records the site digest again under the same lock and requires it to remain unchanged throughout the order. The original reviewed digest is still checked before any staging directory is created.

The order's bounded output goes to the unit's journal. Its exit names the failure for the run's page, which keeps no remote output:

| Exit | Boundary | What exists; ordinary administration |
| --- | --- | --- |
| 15 | Evidence changed | Drift before or during the order. A staged certificate may exist; inspect the isolated staging state and HTTP before preparing again. |
| 95 | Challenge not validated | DNS or routing: the names' addresses, the route's serving or port 80's reachability differ from the review. Nothing was created but the staging directories. |
| 96 | CAA refused the order | The authority refused under the names' CAA records. Change them or choose an authority they name. |
| 97 | Authority rate-limited | The authority asked for a retry later; Barectl never retries automatically. Nothing was created but the staging directories. |
| 98 | Account refused | The staging account's registration was refused; check the contact address and the authority's terms. |
| 99 | Order failed otherwise | The journal holds Certbot's bounded output for inspection. Working HTTP is unchanged. |

A successful run's verification reads the staged certificate's subject, validity dates and names as root, proves no lineage was created in the production configuration and queues no discovery; the run's audit carries the certificate's validity span as the time-stamped evidence. Staging success is diagnostic evidence only: it never installs the untrusted certificate in Nginx and never certifies that a later production order will succeed.

## Issuance

A separately reviewed **production order** issues the site's one certificate from the allowlisted production authority. Open the server and press **Prepare production order plan**, with the site identifier, the account's contact address and noninteractive registration under the authority's terms. The production authority is the allowlist entry `BARECTL_ACME_PRODUCTION` names (Let's Encrypt production by default); requesting the order authorizes its subscriber-agreement handling, and the preparation repeats the [readiness](#readiness) reads fresh.

The plan reviews the site and its challenge route exactly as [staging](#staging) does, the guarded Certbot at its qualified version, the production authority, its directory and CAA value, the contact address and Certbot's ordinary lineage `/etc/letsencrypt/live/<identifier>`. It reads the existing production lineage and account state as root: a matching lineage is a plan without changes that names its validity dates and points at a fresh [activation](#activation) review; a lineage for other names or an account whose contact differs is refused, never adopted and never silently reused. Certificates are ECDSA P-256 (`secp256r1`); no plan, output or audit prints a private key or account credential.

A run is an apply run with `tls.issue_certificate`, under the mutation lock. Before Certbot runs it rechecks, inside the unit, the site digest, the guarded renewal setup's digest, the readiness digest (the same fresh DNS, address, clock and directory reads as one hash) and the lineage/account state digest; any change stops it with exit 15 (or 95 for the readiness reads) and Certbot never runs. It then runs one `certonly` order through the site's challenge webroot into Certbot's ordinary configuration, work and log directories. The order's output is classified into the same boundaries as staging, and its own lineage legitimately changes the certificate paths afterwards, so no site digest is rechecked after the order.

| Exit | Boundary | What exists; ordinary administration |
| --- | --- | --- |
| 15 | Evidence changed | Nothing changed, Certbot never ran. Prepare again. |
| 95 | Challenge not validated | DNS or routing differs from the fresh recheck or the order. Working HTTP is unchanged and no lineage was created. Readiness again names what differs. |
| 96 | CAA refused the order | The authority refused under the names' CAA records. Change them or choose an authority they name. |
| 97 | Authority rate-limited | The authority asked for a retry later; Barectl never retries production orders automatically. |
| 98 | Account refused | The production account's registration was refused; check the contact address and the authority's terms. |
| 99 | Order failed otherwise | The journal holds Certbot's bounded output. An issued certificate, if one exists, is left in place; a fresh activation review can reference it. |

A lost answer is reconciled from the unit alone through **Check outcome**; Barectl never orders twice. A successful run's verification reads the lineage as root and records, timestamped, the certificate's subject, names, validity dates, serial, SHA-256 DER fingerprint, key curve, that the private key's public half matches the certificate, and that Certbot's renewal configuration exists. The audit carries the validity span. Issuance never touches Nginx; serving the certificate is the activation's separate review.

## Activation

A separately reviewed **HTTPS activation** serves the issued lineage. Open the server and press **Prepare HTTPS activation plan**, with the site identifier. The review needs root or noninteractive sudo, because the lineage and the effective Nginx configuration are root-only. It reads the issued lineage's public identity (names, key identity, renewal configuration, fingerprint, expiry) and refuses a missing, mismatched, expired or otherwise unqualified lineage; it reads the shared default TLS rejection server `/etc/nginx/conf.d/tls-default-reject.conf` and every effective `default_server` on 443, refusing a competing custom default and a shared file with other bytes.

The plan reviews the site file's two exact candidate states from [the convention](site-conventions.md#tls-convention): first HTTPS with HTTP and the challenge route unchanged, then the HTTP redirect to the literal canonical name with the challenge route preserved; a site already serving the redirect is a plan without changes, and a site already serving HTTPS proposes only the redirect. The previous bytes are kept as the run's root-only recovery preimage, and no HSTS is set.

A run is an apply run with `tls.apply_tlsplan`, under the mutation lock, and publishes in order:

1. the shared default TLS rejection server, when it is absent: root:root 0644 with IPv4 and IPv6 443 `default_server` listeners and `ssl_reject_handshake on`, so an unknown name receives no certificate;
2. the HTTPS candidate, after keeping the preimage and requiring `nginx -t` to accept it before any reload, then verifies with `openssl s_client` that every reviewed name is served the reviewed certificate's exact DER bytes and that an unknown name is rejected;
3. the redirect candidate, again requiring `nginx -t` first, then verifies the challenge route still answers, HTTP answers 301 to the canonical name, the served certificate is unchanged, and a Host different from a valid SNI is not served the site.

A refused HTTPS candidate is restored from the preimage. A refused or failed redirect candidate restores (or keeps) the verified HTTPS candidate: that is partial completion, and HTTPS keeps serving.

| Exit | Boundary | What exists; ordinary administration |
| --- | --- | --- |
| 15 | Evidence changed | Nothing was published. Prepare again. |
| 56 | Preimage directory failed | The backup directory could not be created; nothing was replaced. |
| 57 | Rejection server refused | The shared default file could not be published exactly; the site file was not changed. |
| 58 | HTTPS candidate not published | The staged candidate failed or the site file changed; nothing was reloaded. |
| 59 | Candidate restored | `nginx -t` refused HTTPS; the preimage was restored and `nginx -t` accepts again. Nothing was reloaded. |
| 60 | Preimage not restored | `nginx -t` refused and the site file could not be restored. Restore the preimage through ordinary administration, then run `nginx -t`. |
| 90 | Reload failed | HTTPS is on disk and accepted, but `nginx.service` did not reload; inspect `systemctl status nginx.service`. |
| 91 | Not served | A reviewed name is not served the reviewed certificate, or an unknown name still received one. Inspect with `openssl s_client` and `nginx -T`. |
| 92 | Redirect failed | HTTPS keeps serving; the redirect candidate could not be published, accepted or reloaded. Prepare the activation again. |
| 93 | Not redirecting | The redirect is on disk and reloaded, but HTTP does not redirect, the challenge route no longer answers, the served certificate changed or a mismatched Host was served. Inspect through ordinary administration. |
| 94 | Restore failed | The redirect was refused and the HTTPS candidate could not be restored; restore it through ordinary administration, then run `nginx -t`. |

Verification re-reads, as root, the site file, the recovery preimage and the shared rejection server's bytes and modes, `nginx -t`, the actually served certificate per name, that an unknown name is rejected, that a mismatched Host is not served, and the HTTP redirect and challenge statuses; it records them timestamped with the run. Discovery then reconstructs the activated site from the server: the Nginx file's stage and certificate references, the public certificate's names, issuer, validity and fingerprint where readable, and per-name served fingerprints, naming inaccessible root-only evidence instead of absence (see [reconstruction](v0.3-qualification.md)).
