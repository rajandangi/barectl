# Security baseline and package maintenance competitor analysis

Official sources inspected on 2026-10-09. This review compares the workflows needed for [v0.9](v0.9.md), not pricing or every feature. "Not established" means the inspected sources do not prove the capability; it does not mean the product lacks it. GridPane and Cleavr were not compared because no official documentation for these topics was found.

## Documented workflows

| Product | Documented behavior | Limits and unresolved evidence |
| --- | --- | --- |
| Laravel Forge | UFW blocks everything except 22, 80 and 443; the Network tab adds allow or deny rules for ports, ranges and source addresses. Password SSH is disabled at provisioning. Ubuntu's automatic security updates stay on. [Security](https://laravel.com/forge/docs/servers/security), [network](https://laravel.com/forge/docs/resources/network), [SSH keys](https://laravel.com/forge/docs/ssh). | Rules added with `ufw` outside Forge do not appear. Deleting the SSH rule is only warned about; recovery is the provider console. Pending updates, restart required and a reboot action are not established. |
| Ploi | UFW with 22, 80 and 443; named rules with port or range, protocol, allow or deny and source networks. The SSH rule keeps Ploi's management addresses allowed. fail2ban is installed but disabled. Pending updates are counted and can run on a schedule. [Firewall](https://ploi.io/documentation/server/how-do-i-manage-firewall-rules), [fail2ban](https://ploi.io/documentation/server/how-do-i-enable-fail2ban-on-my-server), [updates](https://ploi.io/documentation/server/how-do-i-updateupgrade-packages-on-my-server). | The update guide dates from 2018; current behavior is not established. Lockout protection depends on Ploi's own addresses. |
| RunCloud | firewalld with 22, 80 and 443; deploying rules replaces rules added by hand. fail2ban with an unban list. A Restart Recommended badge and optional scheduled restarts. [Security](https://runcloud.io/docs/server/security/), [maintenance](https://runcloud.io/docs/smart-scheduled-maintenance). | Uses an installed agent. SSH policy and automatic updates are not established. |
| SpinupWP | UFW allowing SSH, HTTP and HTTPS; fail2ban for SSH; unattended-upgrades for security updates with automatic reboot off and discouraged; a restart-required notice, email and reboot button. [Security](https://spinupwp.com/doc/server-site-security/), [installed software](https://spinupwp.com/doc/software-installed-spinupwp-server/). | Its pages disagree on whether an Install updates action exists or is planned. |
| CloudPanel | UFW with preset rules the operator can add, edit and delete; recommends restricting SSH and the panel port to known addresses or using the provider firewall. [Security](https://www.cloudpanel.io/docs/v2/admin-area/security/). | SSH policy, automatic updates and brute-force protection are not established. |
| Coolify | Does not configure a firewall; lists required ports and recommends the provider firewall or ufw-docker. [Firewall](https://coolify.io/docs/core/infrastructure/servers/firewall). | Warns that a wrong SSH rule can lock the operator out; no protection is documented. |
| ServerAvatar | UFW rules in the dashboard; toggles for root login, password authentication and SSH port; scheduled security updates; fail2ban settings; scheduled reboots. [Security settings](https://serveravatar.com/docs/server/security-settings), [firewall](https://serveravatar.com/docs/server/firewall/), [fail2ban](https://serveravatar.com/docs/server/fail2ban), [auto-reboot](https://serveravatar.com/docs/server/auto-reboot/). | No lockout safeguard is documented for SSH changes. Whether its updates are security-only is not established. |

No inspected product documents a security score or audit view; Forge links a third-party integration.

## Decisions for Barectl

These are design conclusions, not claims about competitors' implementations.

- Firewall, key-only SSH, automatic security updates and a restart action are table stakes. Barectl offers each through review instead of applying them silently at provisioning.
- Use UFW, the tool Ubuntu ships and most compared products use. Read rules from the server so rules added outside Barectl are visible, and block changes to configuration that does not follow the standard instead of overwriting it as RunCloud does.
- Lockout is the main documented risk and only Ploi guards against it, by allowing its own addresses. Barectl uses a native confirm-or-revert window instead, which needs no fixed management addresses.
- Keep Ubuntu's unattended-upgrades as the only automatic update mechanism, with automatic reboot off, as SpinupWP does. Report restart required and offer a reviewed restart; do not schedule reboots or update runs.
- Install updates is the gap most products leave unclear. Barectl reviews an exact transaction and its service restarts before installing.
- Leave fail2ban out. Key-only sign-in removes password guessing, and OpenSSH 10.2 on Ubuntu 26.04 enables `PerSourcePenalties` by default. Ubuntu 24.04's OpenSSH 9.6 does not have it; the review says so.
- Do not offer an SSH port change. Socket-activated SSH on Ubuntu 24.04 needs socket regeneration, and a port change adds lockout risk for little benefit.
- Show no security score. Report findings and their limits, including cloud firewalls Barectl cannot see and Docker's bypass of UFW.
