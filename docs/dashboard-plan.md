# Custom dashboard design

Status: design confirmed by the operator, including the Barectl theme requirements. Confirmed choices below define intended behavior; **Current implementation** states what exists. Navigation, screens and the operator journey are specified in one place, the [dashboard journey specification](https://github.com/rajandangi/barectl/issues/179); this document holds the platform, design-system and credential choices that journey builds on.

## Confirmed decisions

- Target one trusted operator per installation initially. The application may run locally or on a private management host. Shared team access and tenant isolation are outside this milestone.
- The custom dashboard owns all operator workflows. Django admin is not installed and must not be used as a fallback.
- Use Django authentication behind the custom sign-in interface.
- Keep the Barectl login separate from server users and permissions. Each device has a local application database by default; SSH determines server access. Planned optional remote database support can share application records without requiring a hosted Barectl service.
- Reviewed server setup, runtimes and PHP site creation over HTTP are implemented. HTTPS, databases and application deployment are later phases.
- Create the initial operator account and recover passwords using terminal commands on the controller host. Public registration and email-based recovery are not offered.
- Use the controller host's SSH agent or approved key files for authentication. Do not upload private keys through the browser or store SSH secrets in the application database. A hosted installation uses credentials available on that host, not on the browser user's laptop.
- Run discovery after the first verified connection, then on explicit Refresh requests. Display the collection time. Scheduled discovery is outside this milestone.
- Use [USWDS](https://github.com/uswds/uswds) as the design system and Django templates with HTMX 4 interactions.
- Register servers with a saved connection (address, SSH user, port and key reference) or, as an advanced option, an existing SSH alias configured on the controller host.
- Trust an unknown host key only when it matches the fingerprint the operator pastes from the provider. Reject changed or revoked host keys; do not offer a browser bypass.
- Run ordinary discovery with the SSH user's existing permissions, and target-stack reads with root or verified noninteractive sudo of exact fixed commands. Return partial results with explicit warnings when observations are inaccessible. Inaccessible software must not be reported as absent.
- If discovery fails or is interrupted, preserve the last successful snapshot, show the latest attempt's outcome, and offer manual retry. Allow only one discovery job per managed server at a time within the installation's database.
- Removing a server requires confirmation, is blocked during discovery, and deletes only Barectl's local records, never the remote server or the controller's SSH files. See `docs/ssh-connections.md#server-removal`.
- Discovery history and Activity show records from the Barectl application database. Native server history is a separate planned view; it cannot reconstruct another device's private Barectl records. Cached observations remain visibly stale when current native evidence is unavailable.
- Management from independent devices follows [the architecture requirements](architecture.md#management-from-multiple-devices). Show available native evidence of conflicting operations, block the requested change, and require fresh discovery and review when the conflict ends. Do not silently queue a stale plan or imply that a shared database is required.
- Use responsive USWDS components with Barectl branding. Never present an unimplemented feature as a working control; a planned option may appear only when it is plainly marked as not yet available.
- Apply the palette in `docs/design-palette.md` through Barectl's USWDS theme. Retain USWDS as the component and design-token framework.
- Use Inter for the English interface, with the weights, fallback stack and self-hosted asset requirements in `docs/frontend-assets.md`.
- Use Vite for the frontend asset build, including USWDS Sass, JavaScript, and fonts. Integrate its production manifest with Django templates and static file deployment.
- Use Django 6.1.1, pinned in the project dependency and lockfile. See `docs/documentation-sources.md` for version-matched official guidance.
- Require strict typing and static analysis across first-party code, including Vite and Sass sources. CI checks mypy/Django-stubs, Ruff, templates, TypeScript, type-aware Oxlint, CSS, and dependency audits. See `docs/quality.md` for scope and runtime-validation limits.
- Before selecting dependencies or recommending implementation approaches, check official framework and maintainer guidance, verify compatibility, and distinguish upstream recommendations from project choices.

The exact palette and semantic role mappings are recorded in `docs/design-palette.md`. Blue is the primary action color, crimson is the brand accent, and warm paper colors define the surfaces. Error and destructive states use their own color family.

## Planned server Jobs view

The [server Jobs specification](server-jobs.md), tracked in [#284](https://github.com/rajandangi/barectl/issues/284), owns the planned Jobs view. Implementation and qualification remain pending.

## Credential boundary

### Saved server connections

[Saved server connections](saved-server-connections.md) store non-secret settings locally, use the controller's SSH agent or an approved key file, and refuse unknown or changed server identities until the operator confirms the provider's fingerprint.

Host-managed credentials avoid adding a web-based key store. They do not prevent a compromised Barectl process from using the permissions of its SSH agent or readable key files. Keep the controller account's access limited to the managed servers and permissions it needs. Host identity verification remains required independently of the authentication key source.

## USWDS integration findings

USWDS provides component markup, CSS, JavaScript, design tokens, and layout utilities. Use its npm package `@uswds/uswds` with the committed lockfile. Serve the compiled assets from Barectl and retain the required upstream notices.

Use documented HTML components in Django templates. USWDS documents component initialization and cleanup methods, and HTMX 4 fragment replacements need lifecycle handling. Barectl binds page-shell components once and fragment components to each swapped fragment root; browser tests cover repeated updates. See `docs/frontend-assets.md#components-and-htmx-lifecycle`.

Sources: [USWDS installation and JavaScript guidance](https://github.com/uswds/uswds), [USWDS utilities](https://designsystem.digital.gov/utilities/).

## Current implementation

Django 6.1.1 with Barectl's USWDS theme, self-hosted Inter, HTMX 4 and Vite-built assets. Operator accounts and password recovery use terminal commands on the controller host. Django admin is not installed. The [dashboard workflow contract](dashboard-workflows.md) records the screens and workflows as they behave today, until the journey specification replaces them.

## Implementation verification

Frontend versions, USWDS/HTMX 4 lifecycle integration, SSH alias resolution, host-key enforcement and durable worker behavior are engineering facts to establish with tests and upstream documentation, not product choices to ask the operator to research.

## Workflow research

The [dashboard journey specification](https://github.com/rajandangi/barectl/issues/179) owns the dashboard's navigation and journey. The [competition study](workflow-competition.md) is its documentation evidence, not usability evidence.
