# Custom dashboard design

Status: design confirmed by the operator, including the Barectl theme requirements. Confirmed choices below define intended behavior; **Current implementation** states what exists. This note supplements `docs/v0.1.md`.

## Confirmed decisions

- The first usable milestone is an end-to-end workflow: sign in, register a managed server by its controller SSH alias, verify its host key against the controller's known_hosts, run read-only discovery, and review the results.
- Target one trusted operator per installation initially. The application may run locally or on a private management host. Shared team access and tenant isolation are outside this milestone.
- Remove Django admin entirely, including its `/admin/` interface. Build custom forms for normal inventory workflows; do not retain admin as an internal fallback.
- Keep Django authentication behind the custom sign-in interface. Removing the admin interface does not mean replacing Django's authentication system.
- Provisioning and site creation remain later milestones.
- Create the initial operator account and recover passwords using terminal commands on the controller host. Public registration and email-based recovery are outside v0.1.
- Use the controller host's SSH agent or key files for authentication. Do not upload private keys through the browser or store SSH secrets in the application database. A hosted installation uses credentials available on that host, not on the browser user's laptop.
- Run discovery after the first verified connection, then on explicit Refresh requests. Display the collection time. Scheduled discovery is outside this milestone.
- Use [USWDS](https://github.com/uswds/uswds) as the design system, replacing the earlier Tailwind direction. Keep Django templates with HTMX 4 interactions.
- Register servers by selecting an existing SSH alias configured on the controller host. Connection details and credential references are managed on that host, not entered through the dashboard.
- Establish verified SSH host trust on the controller host before connecting. Reject unknown or changed host keys; do not offer a browser bypass.
- Run discovery with the SSH user's existing permissions and no automatic `sudo` in v0.1. Return partial results with explicit warnings when observations are inaccessible. Inaccessible software must not be reported as absent.
- The server overview shows OS, CPU, memory, disk, web-stack components and service states, detected Nginx site files, and discovery warnings. Display the collection time prominently: results are snapshots, not live monitoring.
- If discovery fails or is interrupted, preserve the last successful snapshot, show the latest attempt's outcome, and offer manual retry. Allow only one discovery job per managed server at a time.
- Removing a server requires confirmation, is blocked during discovery, and deletes only Barectl's local records, never the remote server or the controller's SSH files. See `docs/ssh-connections.md#server-removal`.
- Use two main navigation sections: Servers and Activity. Each server page contains its overview, web-stack components, detected Nginx site files, and discovery history. Use responsive USWDS components with Barectl branding, and do not display controls for unimplemented features.
- Apply the palette in `docs/design-palette.md` through Barectl's USWDS theme. Retain USWDS as the component and design-token framework.
- Use Inter for the English interface, with the weights, fallback stack and self-hosted asset requirements in `docs/frontend-assets.md`.
- Use Vite for the frontend asset build, including USWDS Sass, JavaScript, and fonts. Integrate its production manifest with Django templates and static file deployment.
- Use Django 6.1.1, verified against the official download page and PyPI. The foundation dependency and lockfile have been upgraded to this version.
- Require strict typing and static analysis across first-party code. The foundation now has strict mypy/Django-stubs, expanded Ruff rules, template linting, strict TypeScript, type-aware ESLint, CSS linting, and dependency audits configured in CI. Extend these checks when implementing Vite and Sass. See `docs/quality.md` for scope and runtime-validation limits.
- Before selecting dependencies or recommending implementation approaches, check official framework and maintainer guidance, verify compatibility, and distinguish upstream recommendations from project choices.

The exact palette and semantic role mappings are recorded in `docs/design-palette.md`. Blue is the primary action color, crimson is the brand accent, and warm paper colors define the surfaces. Error and destructive states use their own color family.

## Credential boundary

Host-managed credentials avoid adding a web-based key store. They do not prevent a compromised Barectl process from using the permissions of its SSH agent or readable key files. Keep the controller account's access limited to the managed servers and permissions it needs. Host identity verification remains required independently of the authentication key source.

## USWDS integration findings

USWDS provides component markup, CSS, JavaScript, design tokens, and layout utilities. Use its npm package `@uswds/uswds` and a lockfile when implementing the frontend. Tailwind is not needed for this direction. Serve the compiled assets from Barectl and retain the required upstream notices.

Use documented HTML components in Django templates. USWDS documents component initialization and cleanup methods, and HTMX 4 fragment replacements need lifecycle handling. Barectl binds page-shell components once and fragment components to each swapped fragment root; browser tests cover repeated updates. See `docs/frontend-assets.md#components-and-htmx-lifecycle`.

Sources: [USWDS installation and JavaScript guidance](https://github.com/uswds/uswds), [USWDS utilities](https://designsystem.digital.gov/utilities/).

## Current implementation

The foundation runs Django 6.1.1. The sign-in page, the Servers page and the Activity page use Barectl's USWDS theme, self-hosted Inter, HTMX 4 and Vite-built assets. The Servers page lists and searches the inventory; the navigation contains Servers, Activity and Sign out. Operators register and edit servers by choosing an SSH alias from the controller's configuration (`docs/ssh-aliases.md`), and remove them after confirmation. Each server has a page showing its connection state, a snapshot of its operating system, capacity, web-stack components, Nginx site files and PHP-FPM pools, and refresh and retry controls; the same page lists its discovery history, and the Activity page lists every recorded attempt across servers with each attempt's outcome, worded as on the server page, recorded and finished times, sanitized failure reasons, the collection time of the snapshot it published and, for each server's current snapshot, its inaccessible or unsupported observation warnings. Only the current snapshot is kept, so earlier successes show no collection time or warnings. A durable worker verifies the SSH connection after registration, refresh or retry and collects the snapshot, with recovery of interrupted attempts that preserves the previous snapshot (`docs/ssh-connections.md`). Django admin is not installed; the dashboard is the only operator interface. Operator accounts are created and their passwords reset with terminal commands on the controller host. Provisioning and other changes to servers are not implemented.

## Implementation verification

Frontend versions, USWDS/HTMX 4 lifecycle integration, SSH alias resolution, host-key enforcement and durable worker behavior are engineering facts to establish with tests and upstream documentation, not product choices to ask the operator to research.
