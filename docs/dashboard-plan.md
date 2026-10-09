# Custom dashboard design

Status: design confirmed by the operator, including the Barectl theme requirements. Confirmed choices below define intended behavior; **Current implementation** states what exists. This note supplements `docs/v0.1.md`.

## Confirmed decisions

- The first usable milestone is an end-to-end workflow: sign in, register a managed server by its controller SSH alias, verify its host key against the controller's known_hosts, run read-only discovery, and review the results.
- Target one trusted operator per installation initially. The application may run locally or on a private management host. Shared team access and tenant isolation are outside this milestone.
- The custom dashboard owns all operator workflows. Django admin is not installed and must not be used as a fallback.
- Use Django authentication behind the custom sign-in interface.
- Keep the Barectl login separate from server users and permissions. Each device has a local application database by default; SSH determines server access. Planned optional remote database support can share application records without requiring a hosted Barectl service.
- Reviewed web-stack setup, PHP site creation, site databases and HTTPS installation are implemented through v0.3. Application deployment remains planned.
- Create the initial operator account and recover passwords using terminal commands on the controller host. Public registration and email-based recovery are outside v0.1.
- In v0.1, use the controller host's SSH agent or key files for authentication. Do not upload private keys through the browser or store SSH secrets in the application database in this milestone. A hosted installation uses credentials available on that host, not on the browser user's laptop. Saved SSH connection details are planned for a later release.
- Run discovery after the first verified connection, then on explicit Refresh requests. Display the collection time. Scheduled discovery is outside this milestone.
- Use [USWDS](https://github.com/uswds/uswds) as the design system and Django templates with HTMX 4 interactions.
- In v0.1, register servers by selecting an existing SSH alias configured on the controller host. Connection details and credential references are managed on that host, not entered through the dashboard.
- Establish verified SSH host trust on the controller host before connecting. Reject unknown or changed host keys; do not offer a browser bypass.
- Run discovery with the SSH user's existing permissions and no automatic `sudo` in v0.1. Return partial results with explicit warnings when observations are inaccessible. Inaccessible software must not be reported as absent.
- Server Overview shows the observed platform, hosting components and service states, and discovery warnings. Capacity and native configuration evidence remain available under Advanced. Display the collection time prominently: results are snapshots, not live monitoring.
- If discovery fails or is interrupted, preserve the last successful snapshot, show the latest attempt's outcome, and offer manual retry. Allow only one discovery job per managed server at a time within the installation's database.
- Removing a server requires confirmation, is blocked during discovery, and deletes only Barectl's local records, never the remote server or the controller's SSH files. See `docs/ssh-connections.md#server-removal`.
- Use Servers and Activity as the global navigation. Each managed server has Overview, Sites, Setup, Activity and Advanced sections with stable direct links. The [dashboard workflow contract](dashboard-workflows.md) records their current scope, connection states and permission boundaries. Use responsive USWDS components with Barectl branding, and do not display controls for unimplemented features.
- Discovery history and Activity show records from the Barectl application database. Native server history is a separate planned view; it cannot reconstruct another device's private Barectl records. Cached observations remain visibly stale when current native evidence is unavailable.
- Future management from independent devices must follow [the architecture requirements](architecture.md#management-from-multiple-devices). Show available native evidence of conflicting operations, block the requested change, and require fresh discovery and review when the conflict ends. Do not silently queue a stale plan or imply that a shared database is required.
- Apply the palette in `docs/design-palette.md` through Barectl's USWDS theme. Retain USWDS as the component and design-token framework.
- Use Inter for the English interface, with the weights, fallback stack and self-hosted asset requirements in `docs/frontend-assets.md`.
- Use Vite for the frontend asset build, including USWDS Sass, JavaScript, and fonts. Integrate its production manifest with Django templates and static file deployment.
- Use Django 6.1.1, pinned in the project dependency and lockfile. See `docs/documentation-sources.md` for version-matched official guidance.
- Require strict typing and static analysis across first-party code, including Vite and Sass sources. CI checks mypy/Django-stubs, Ruff, templates, TypeScript, type-aware Oxlint, CSS, and dependency audits. See `docs/quality.md` for scope and runtime-validation limits.
- Before selecting dependencies or recommending implementation approaches, check official framework and maintainer guidance, verify compatibility, and distinguish upstream recommendations from project choices.

The exact palette and semantic role mappings are recorded in `docs/design-palette.md`. Blue is the primary action color, crimson is the brand accent, and warm paper colors define the surfaces. Error and destructive states use their own color family.

## Reviewed bootstrap

[v0.2 reviewed bootstrap](v0.2.md) defines plan preparation, explicit metadata refresh, apply confirmation, native outcome reconciliation, and retained audit. Keep each control absent until its qualifying implementation passes. Preparing and reviewing plans, applying metadata refresh, cleanup, Nginx and PHP 8.3 plans, Check outcome and outcome-unknown acknowledgement are offered ([bootstrapping a server](bootstrap.md)). The Servers and Activity navigation remains the operator entry point; no separate admin interface is introduced.

## Planned server Jobs view

The [server Jobs specification](server-jobs.md), tracked in [#284](https://github.com/rajandangi/barectl/issues/284), owns the accepted journey, implementation decisions and tests for work planned after 0.6. Implementation and qualification remain pending.

Jobs shows Needs attention, Running, Automatic work and Recent results for one server, with explicit Refresh, optional filters and viewer-local times. Main-screen wording must make sense to a business owner without Linux knowledge; technical evidence is optional.

Native server history remains distinct from Activity's private records. Existing feature permissions, safe-result rules and recovery workflows apply. Missing or unreadable evidence is explicit, and Jobs never automatically repeats uncertain work. See the specification for the full scope and delivery criteria.

## Credential boundary

### Planned saved server connections

The [accepted specification](saved-server-connections.md) adds a plain-language connection-details form alongside existing SSH aliases. It stores non-secret settings locally, uses host-managed keys or the controller's SSH agent, refuses unknown or changed server identities, and checks connections through the existing discovery worker. The operator's add, save, check, correct and edit journey is the primary test boundary, with independent-controller proof. Implementation and qualification remain pending.

Host-managed credentials avoid adding a web-based key store. They do not prevent a compromised Barectl process from using the permissions of its SSH agent or readable key files. Keep the controller account's access limited to the managed servers and permissions it needs. Host identity verification remains required independently of the authentication key source.

## USWDS integration findings

USWDS provides component markup, CSS, JavaScript, design tokens, and layout utilities. Use its npm package `@uswds/uswds` with the committed lockfile. Serve the compiled assets from Barectl and retain the required upstream notices.

Use documented HTML components in Django templates. USWDS documents component initialization and cleanup methods, and HTMX 4 fragment replacements need lifecycle handling. Barectl binds page-shell components once and fragment components to each swapped fragment root; browser tests cover repeated updates. See `docs/frontend-assets.md#components-and-htmx-lifecycle`.

Sources: [USWDS installation and JavaScript guidance](https://github.com/uswds/uswds), [USWDS utilities](https://designsystem.digital.gov/utilities/).

## Current implementation

The foundation runs Django 6.1.1. Sign-in, Servers and Activity use Barectl's USWDS theme, self-hosted Inter, HTMX 4 and Vite-built assets. Servers lists and searches the inventory. Operators register and edit servers by choosing a controller SSH alias, and remove local registrations after confirmation. Registration queues the existing connection check and opens the managed server Overview. Operator accounts and password recovery use terminal commands on the controller host. Django admin is not installed.

Managed servers have bookmarkable Overview, Sites, Setup, Activity and Advanced sections. Overview shows the recorded connection outcome, observed platform and hosting components, collection time and a relevant next action. Advanced exposes capacity, native configuration details and supporting evidence. Verified connection is a recorded SSH outcome, not a live health claim. Explicit refresh and retry use the existing durable worker; failed or interrupted attempts preserve the last successful snapshot with a stale notice. Navigation itself queues no remote work. See the [dashboard workflow contract](dashboard-workflows.md).

Setup retains the existing reviewed bootstrap plans. Sites retains permitted cached site observations and reviewed site creation. Permission-appropriate links retain the existing database and one-action HTTPS workflows and their advanced diagnostics. These create native PHP hosting resources and an initial placeholder page; application deployment remains planned. The later dashboard tickets redesign these task journeys and add scoped site detail pages. See [bootstrap](bootstrap.md), [sites](sites.md), [databases](databases.md) and [TLS](tls.md).

Server Activity shows this registration's local discovery attempts and authorized preparation/apply history. Global Activity includes all permitted local records. Historical success never establishes current native state. Only the current successful discovery snapshot is kept, so earlier successes no longer have their collection time or observation warnings. See [SSH connections and discovery](ssh-connections.md).

## Implementation verification

Frontend versions, USWDS/HTMX 4 lifecycle integration, SSH alias resolution, host-key enforcement and durable worker behavior are engineering facts to establish with tests and upstream documentation, not product choices to ask the operator to research.

## Workflow research

[The competition study](workflow-competition.md) compares documented workflows in CloudPanel, Laravel Forge and Coolify, and proposes a site-centered journey using Barectl's current capabilities. The [accepted dashboard specification](https://github.com/rajandangi/barectl/issues/179) now governs the redesign. The [dashboard workflow contract](dashboard-workflows.md) distinguishes the first navigation slice from later task journeys. The research is not user-testing evidence. Application delivery needs a separate specification; changing the design system is outside this study.
