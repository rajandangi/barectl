# TLS

Barectl prepares HTTPS for sites that follow the [native site convention](site-conventions.md) in reviewed steps. Implemented today: every change refuses while Certbot's scheduled renewal has processes ([renewal exclusion](#renewal-exclusion)), and an existing site can gain its HTTP-01 **challenge route**. Barectl does not install Certbot, contact a certificate authority or order certificates yet; the accepted design is [v0.3](v0.3.md#tls-preparation-issuance-and-renewal) and the [TLS convention](site-conventions.md#tls-convention).

## Permissions

TLS plans have their own permissions, separate from site and bootstrap permissions:

| Stage | Permissions |
| --- | --- |
| View TLS plans and their preparations | `servers.view_server` and `tls.view_tlsplan` |
| Prepare a TLS plan | the above and `tls.prepare_tlsplan` |
| Apply a TLS plan, and close a run whose outcome is unknown | the above and `tls.apply_tlsplan` |

`tls.issue_certificate` is reserved for ordering production certificates, which no plan offers yet. Site and bootstrap permissions grant none of these, and an account that may view only site or bootstrap plans never sees a TLS plan, its run or its line in Activity.

## Preparing a challenge route

Open the server and use **TLS plans**. Enter the identifier of an existing site. The worker reads the server as root or through noninteractive sudo exactly as [site preparation](ssh-connections.md#site-preparation) does, and changes nothing.

A challenge route is proposed only for a site that site admission finds complete, with every resource the convention names. A site file that already serves challenges from a conforming webroot is a plan without changes. Preparation refuses:

- a site that does not exist or is incomplete; apply its site plan first;
- `/var/lib` or `/var/backups` that is not a root-owned directory only root can write, and `/var/lib/letsencrypt` or `/var/backups/nginx` that exists with another owner or mode than the convention's;
- an existing `/var/lib/letsencrypt/<id>` beside a site file without the route, which Barectl does not adopt;
- everything site admission refuses, such as unknown configuration, another site with the same names, or evidence that changed while it was read.

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
