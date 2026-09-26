# Barectl color palette

Use these colors for Barectl's USWDS theme. USWDS provides the components and design tokens. The English typography requirements are in `docs/frontend-assets.md`.

## Semantic colors

| Role | Value |
| --- | --- |
| Primary action, links, and focus | `#003893` |
| Primary hover and strong blue | `#00245f` |
| Information | `#315fa3` |
| Brand accent | `#dc143c` |
| Strong brand accent | `#8f0c27` |
| Page background | `#f8f6f0` |
| Raised surface and cards | `#fffdfa` |
| Sunken surface | `#e6e0d5` |
| Main text | `#242832` |
| Muted text | `#5c6470` |
| Control boundary | `#8c877f` |
| Subtle boundary | `#e6e0d5` |
| Text on filled controls | `#ffffff` |
| Success | `#1d6f4a` |
| Warning | `#8a5800` |
| Destructive action and error | `#a51c30` |

## Color families

| Family | Soft background | Border | Light or information | Main | Strong |
| --- | --- | --- | --- | --- | --- |
| Primary blue | `#e8eef8` | `#8ca7d1` | `#315fa3` | `#003893` | `#00245f` |
| Crimson accent | `#fce9ed` | `#eb899d` | `#e4526e` | `#dc143c` | `#8f0c27` |
| Success | `#e8f4ee` | `#7db99e` | N/A | `#1d6f4a` | `#12442f` |
| Warning | `#fff3d9` | `#d4a953` | N/A | `#8a5800` | `#5f3b00` |
| Destructive and error | `#f9e8ea` | `#d38a95` | N/A | `#a51c30` | `#6f1220` |

## Theme implementation rules

- Use primary blue for primary actions and focus, crimson for brand accents, and the distinct destructive family for errors and destructive actions.
- Map colors through USWDS theme settings and Barectl semantic tokens rather than scattering literal values across templates.
- Use soft family colors for tinted status backgrounds, with their corresponding foreground and boundary roles. Never use color as the only indication of status.
- Preserve accessible contrast for the actual foreground/background combinations used. Palette reuse does not establish that every possible pairing is accessible.
- This palette defines a light theme. Strong shades provide interaction and emphasis colors. Dark mode remains outside this requirement.

## USWDS token mapping

`frontend/styles/_palette.scss` holds the values above. `frontend/styles/_theme.scss` passes them to USWDS theme settings:

| USWDS token | Barectl role |
| --- | --- |
| `primary-lighter`, `primary-light`, `primary`, `primary-vivid`, `primary-dark` | Primary blue family; `primary-vivid` is information blue |
| `secondary-lighter`, `secondary-light`, `secondary`, `secondary-vivid`, `secondary-dark` | Crimson accent family |
| `base-lightest` | Raised surface and cards |
| `base-lighter` | Sunken surface and subtle boundary |
| `base-light` | Control boundary |
| `base`, `base-dark` | Muted text |
| `base-darker`, `base-darkest`, `ink` | Main text |
| `info-*`, `success-*`, `warning-*`, `error-*` | Status families; `error-*` is also the destructive family |
| `white` | Text on filled controls |

USWDS needs a token for the body background so it can check text contrast. Barectl uses `base-lightest` there and applies the page background, `#f8f6f0`, in its own stylesheet. The two colors have nearly the same luminance.

The sign-in page, Servers page and header use this theme: crimson for the header rule and eyebrow labels, primary blue for actions, links and focus, and the warm paper surfaces.
