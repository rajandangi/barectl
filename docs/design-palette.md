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

The palette is an approved design requirement. The running Barectl UI has not yet been restyled.
