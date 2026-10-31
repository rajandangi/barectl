# Security checks

A server's **Security** section, beside Sites, Activity, Settings and Advanced, reports what
Barectl could read about its exposure. It is read-only in this slice: every check action is
disabled with "Not available yet" (the Web runtimes check links to the existing catalog
update in Advanced), and nothing on the server changes.

## What it reads

Discovery reads the checks through the fixed root path (`discovery/root_read.py`): root, or
the exact passwordless sudo authorization. Without either, every check says "Could not
check" with that reason. It never prompts and never falls back to an unprivileged guess.

| Check | Evidence |
| --- | --- |
| Firewall | UFW package and service state, `ufw status verbose`, `ufw show added`, `ufw.conf`, the IPv6 setting and digests of `before.rules` and `after.rules`; firewalld, Docker, nftables and iptables for another manager. |
| Firewall listeners | `ss -Hlnptu` listeners, compared with the effective SSH ports, 80/tcp, 443/tcp and 443/udp, as part of the Firewall check. |
| SSH sign-in | `sshd -T` effective settings, `ssh.socket` listen values, accounts with a login shell and no readable `authorized_keys`, and OpenSSH's per-source penalties. |
| Automatic security updates | `apt-config dump`, the two `apt-daily` timers, the `50unattended-upgrades` conffile digest and the newest unattended-upgrades log. |
| Ubuntu updates | `apt-get -s upgrade --with-new-pkgs`, `apt-cache policy`, `apt-mark showhold` and the newest package-list index time, without refreshing the lists. |
| Restart needed | `/run/reboot-required` and `/run/reboot-required.pkgs`. |
| Web runtimes | The existing runtime and foundation observations, compared with the catalog lock this release ships; each in-use runtime shows its profile build and age. |

Rules and settings in the supported shape are adopted whoever made them (ADR 0026).
Anything else is reported once as outside supported settings and would block only the
action that depends on it. A cloud provider's firewall is outside what Barectl can see,
and the section says so.

## Storage and presentation

The snapshot keeps one typed row per check with its own outcome, plus child rows for
firewall rules, listeners and waiting updates (ADR 0003). Opening the section reads only
the stored snapshot; it makes no SSH connection and queues no operation. The page says
when each check was read and whether a later connection check failed, using the same
freshness notice as the rest of the server page. It shows no score.

Engine detail, such as service state and configuration files, stays in
[Advanced](dashboard-workflows.md). The Caddy administration socket, its port 2019,
Nix users and OPcache protections come from the existing foundation and runtime
verdicts there; this section does not read them again.

## Limits

- The checks are a snapshot, not live status. A later failed or running connection check
  marks them stale without discarding the last readable evidence.
- Security changes, their consent, and the confirm-or-revert window are later Phase E
  slices ([#301](https://github.com/rajandangi/barectl/issues/301)); none is offered here.
- Web runtime fixes arrive through reviewed Barectl releases, not Ubuntu updates. The
  check links to the existing catalog update action rather than adding another path.
