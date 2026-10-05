# Dashboard workflows

The accepted [dashboard specification](https://github.com/rajandangi/barectl/issues/179) organizes work around managed servers and sites. This document records the server navigation and connection journey implemented by [#180](https://github.com/rajandangi/barectl/issues/180). Later tickets retain their own acceptance and qualification requirements. This page does not certify their delivery.

## Server navigation

Servers and Activity remain the global navigation. Registration selects an existing controller SSH alias, queues the existing connection check and opens the managed server Overview. Credentials and host trust stay on the controller host. Barectl offers no browser key upload or host-trust bypass.

| Section | Stable URL | Scope in the first navigation slice |
| --- | --- | --- |
| Overview | `/servers/<pk>/` | Recorded connection outcome, observation time, observed platform and hosting components, connection remediation and a relevant next action with its reason. |
| Sites | `/servers/<pk>/sites/` | Permitted cached site observations, domain-led, each linking to its scoped site page; the existing reviewed site-plan workflow. The redesigned creation journey belongs to #183. |
| Setup | `/servers/<pk>/setup/` | Observed hosting summary, the reviewed Nginx/PHP/MariaDB/PostgreSQL profiles, package metadata refresh and finished-run cleanup, and the server-wide PHP database-driver card. Each action keeps its own permission. A `?from=<identifier>` context offers a return link to that site's entry under Sites only when the identifier is a name Barectl addresses and appears in the current complete observation; the identifier is carried through the preparation and polling responses. |
| Activity | `/servers/<pk>/activity/` | This registration's local discovery attempts and permitted preparation/apply history. Later work adds the complete resource-scoped recovery journey. |
| Advanced | `/servers/<pk>/advanced/` | Technical native evidence and the existing reviewed site, database and HTTPS workflows, kept reachable for a permitted operator. Bootstrap plans remain here as an alias for earlier deep links; Setup is their focused home. Refusals, material effects and recovery instructions remain available at their action. |

Each page keeps the managed server's name and a return to Servers. Sections use ordinary links, identify the current section and support direct loading, reload and browser back/forward navigation. Section visibility follows existing viewing permissions. A hidden control does not replace authorization on the destination request.

Navigation GETs read permitted cached observations and local operation records. They queue no remote inspection or mutation and make no SSH connection. Existing discovery recovery can mark an abandoned local attempt failed while preserving the last successful snapshot. Explicit connection checks still submit a CSRF-protected POST to the existing service and worker.

## Connection states and next actions

The next-action guidance describes what the recorded evidence suggests. It is not an eligibility check for a mutation. Preparation, immutable review, admission, native locking and fresh revalidation retain their existing authority.

| Recorded state or evidence | Operator guidance | Authority and limits |
| --- | --- | --- |
| Empty server inventory | Explain controller SSH aliases and offer registration to an authorized operator. | Registration requires `servers.view_server` and `servers.add_server`. |
| Not verified, no successful snapshot | Verify the connection before relying on server observations. | Explicit check requires `discovery.add_discoveryattempt` as well as server viewing permission. |
| Check queued | Show the queued time; explain how to start the controller worker if it remains queued. | No duplicate check while the server's active slot is occupied. |
| Check running | Show its start time and explain that host trust and observations are being checked. | Poll the existing local status endpoint; polling does not start remote work. |
| Another remote operation active | Explain why a new connection check must wait and retain ordinary navigation. | The existing operation slot blocks conflicting work. Restricted operation details stay hidden. |
| SSH alias unavailable | Restore the alias on the controller or edit the registration with permission. | An active connection attempt retains its queued/running status. No browser credential or host-trust bypass. |
| Failed or interrupted check | Display the sanitized failure and offer Retry connection check when permitted and available. | Preserve the previous successful snapshot with its collection time and an explicit stale notice. Retry is read-only discovery. |
| Verified connection and collected snapshot | Show the observed platform, package and service facts and collection time. Offer Refresh observations or the permitted hosting task suggested by those facts. | Verified describes the recorded SSH check. It does not establish that the server is healthy, online or publicly reachable. |
| Component absent | Link to its existing reviewed setup where available. | Absence must come from an observation that establishes absence. A suggested setup still needs fresh preparation and review. |
| Evidence inaccessible or unsupported | Explain what could not be read or interpreted and retain the evidence under Advanced. | Do not convert unknown evidence into absence or recommend installation on that basis. |
| Prepared hosting components observed | Link to Sites when the operator may view it. | Package/service observations alone do not prove site eligibility, public DNS, HTTPS or deployed applications. |

Collection time describes when observations were read. A successful historical action and current native state answer different questions. Failed refreshes never replace native evidence with local history as authority. The successful snapshot remains available for inspection; it cannot authorize a mutation without the existing fresh checks.

## Permissions and existing task links

All server sections require authentication and `servers.view_server`. Site observations also require `discovery.view_siteobservation`. Reviewing, preparing and applying bootstrap, site, database or TLS work retains each action's own permissions. See [operator permissions](../README.md#operator-accounts), [database permissions](databases.md#permissions) and [TLS permissions](tls.md#permissions). Inventory access grants no preparation or apply authority.

Existing plan, preparation, apply and certificate-installation detail URLs remain authorized by their existing action. Existing section endpoints retain partial HTMX responses for polling and return full task pages or fixed server-section redirects for ordinary navigation. Legacy section anchors have permission-appropriate task links so an operator can return to the server without guessing a provisioning module. Redirect destinations come from known routes, not arbitrary request input. Unknown managed server registrations still return not found.

## Site pages

A discovered site opens at `/servers/<pk>/sites/<identifier>/overview/` with Overview, Database, HTTPS, Activity and Advanced sections, each at `/servers/<pk>/sites/<identifier>/<section>/`. The identifier is resolved within that registration's current complete observation; an identifier or old action record is not current site identity, and the same identifier on another server never shares context. The Sites inventory leads with observed domain names, keeps the identifier, and shows PHP version, database evidence and certificate evidence without splitting aliases into separate sites.

Overview keeps convention conformity and the site's facts, with the collection time; Database and HTTPS show their own evidence with the collection time, and the inventory summarizes each beside the domains. A conforming layout is not called healthy, a binding is not called verified application access, and a renewal file is not proof of future renewal. Database, HTTPS and Activity link to the existing authorized workflows until #184, #185, #186 and #187 move them into the site; Advanced holds native resources, read commands and fingerprints. No site editing, deletion, domain change, application deployment or PHP-version switching is offered.

When the latest complete collection confirms absence, the page says **Site not found in the latest observation**, offers a return to Sites and permitted historical activity, and offers no change controls. No current complete observation, whether stale, interrupted, failed or unreadable sites, is unknown rather than a confirmed removal. Site pages require `servers.view_server` and `discovery.view_siteobservation`; plan and apply permissions remain independent, and navigation reads cached observations only. A new registration never inherits detached audit because its name or SSH alias matches an old one.

## Accessibility and verification

Section links use a named navigation region and current-location indication. Routine polls preserve keyboard focus and entered values. State changes update the existing persistent status announcement; unchanged polls do not repeatedly announce the same outcome. An operator's explicit check may move focus to the connection heading when the submitted button disappears. Narrow layouts keep navigation, remediation and action text readable without horizontal page scrolling.

Use the existing browser journey and request/service tests for registration, check, refresh, failed refresh, interrupted-attempt recovery, section navigation and authorization. Request tests verify full pages for history restores, partial-response behavior, CSRF and the absence of remote work in navigation. Qualification must distinguish automated checks, an implementer walkthrough and actual user testing. [Quality requirements](quality.md) define the local gates and exact-commit native qualification.

## Upstream guidance and project choices

The following official sources informed the first navigation slice. The section map, guidance matrix and authorization boundaries are Barectl decisions from the accepted specification.

- [USWDS side navigation](https://designsystem.digital.gov/components/side-navigation/) recommends current-page indication and testing the navigation in the application. Barectl retains its existing theme and uses ordinary section links.
- [Django 6.1 authentication and permissions](https://docs.djangoproject.com/en/6.1/topics/auth/default/#the-permission-required-decorator) documents request-level permission checks. Barectl retains its action-specific permissions when relocating controls.
- [Official HTMX 4.0.0 guidance](https://raw.githubusercontent.com/bigskysoftware/htmx/v4.0.0/dist/skills/htmx-guidance.md) defines explicit inheritance, partial/full request headers and polling. Barectl preserves the existing fragment and full-page contract documented in [frontend assets](frontend-assets.md#htmx-4).

The [workflow competition study](workflow-competition.md) remains first-party documentation research, not usability evidence. Its proposed workflow is now governed by the accepted dashboard specification; delivery is recorded per implementation ticket.
