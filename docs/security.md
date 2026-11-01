# Security checks

A server's **Security** section, beside Sites, Activity, Settings and Advanced, reports what
Barectl could read about its exposure. Automatic security updates can be turned on or off,
and Ubuntu updates can be checked for and installed from the section. Every other check
action is disabled with "Not available yet" (the Web runtimes check links to the existing
catalog update in Advanced), and those changes arrive in later Phase E slices.

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

## Automatic security updates

Ubuntu's standard is its own package, enabled by default:
`unattended-upgrades` installed, `APT::Periodic::Update-Package-Lists "1"` and
`APT::Periodic::Unattended-Upgrade "1"`, the package's allowed origins, no package
blacklist, `Unattended-Upgrade::Automatic-Reboot` false, and both `apt-daily.timer` and
`apt-daily-upgrade.timer` enabled. Barectl reads these through `apt-config dump`, the two
timers, the package's conffile digest and the newest log under
`/var/log/unattended-upgrades/`. The newest log result is labeled as Ubuntu's own history,
not as a Barectl record.

**Turn on** and **Turn off** are kinds of the one change engine ([ADR
0035](adr/0035-one-change-engine-with-effect-derived-consent.md)). Both set
`unattended-upgrades/enable_auto_updates` through `debconf-set-selections` and run
`dpkg-reconfigure -f noninteractive unattended-upgrades`; Barectl never writes a second
scheduler or edits `/etc/apt/apt.conf.d` by hand. The package's own config script reads the
current `20auto-upgrades` file before asking its question, so the body first installs the
package's own shipped enabled or disabled file through `ucf`; without that, a
noninteractive reconfigure cannot change the answer. A missing package is installed first
through the exact APT transaction of [ADR
0007](adr/0007-admit-exact-package-transactions-with-an-inline-apt-guard.md), with every
package and version named in the review. The body reads the effective values back and the
run verifies them again from a fresh read.

The change declares a server effect naming the sites read from current evidence, so it needs
Shared consent and its site list is rechecked under the mutation lock. Customized allowed
origins, a package blacklist, automatic reboot or a disabled timer are reported and left
unchanged; Turn on refuses them. Turn off is still offered because it only stops Ubuntu's
own automatic work. Automatic updates can restart the database engine and Valkey, so sites
may pause briefly; they do not restart Caddy, HAProxy or PHP from the Nix catalog.

## Ubuntu updates

The check lists Ubuntu's waiting package updates, security updates first, with the age of
the package lists. Security means the candidate is published by the release's `-security`
suite, even when Ubuntu also copies it into `-updates`. Phased candidates are shown as
waiting for Ubuntu's rollout, held packages as held by an administrator, and an update that
would remove a package as blocked. The section never installs those.

**Check for updates** is its own change kind. It runs Ubuntu's `apt-get update` under the
shared mutation lock, changes no installed package, and then refreshes discovery so the list
age and waiting updates are read back from the server. A permitted operator sees it beside
the waiting updates and whenever the lists are more than a day old.

**Install updates** offers security updates only, or all installable updates. Its review
extends Phase B's exact APT transaction ([ADR
0024](adr/0024-admit-exact-reviewed-upgrade-transactions.md)): it names every selected
package at its candidate version with `--only-upgrade` and every new dependency, with the
download and installed sizes. Removals and downgrades refuse, as do an unfinished package
state and a package whose configuration file differs from dpkg's or ucf's recorded digest,
each with a reason. Held, phased and blocked updates stay listed as kept waiting and are
never installed. Only the authenticated Ubuntu 26.04 archive suites are accepted; Barectl
adds no source.

The confirm screen discloses the services Ubuntu may restart and the sites they serve. The
database engine and Valkey can restart, so their sites may pause briefly; SSH can restart
without affecting site traffic. Web serving and PHP come from Nix and are not restarted by
Ubuntu updates. The body rechecks the reviewed package state under the mutation lock and the
inline guard admits only the reviewed upgrade and new-package lines, so a list refresh, a
hold, a modified configuration file or a newly resolved dependency between review and apply
stops the run instead of installing more than was confirmed. A lost response is reconciled
from the unit's native evidence and never resubmitted.

Verification reads every installed version, `dpkg --audit`, the foundation's profile units
and each site's [readiness](sites.md#readiness). Discovery then reads the versions, the
waiting updates and any restart Ubuntu asks for from the server alone.

## Limits

- The checks are a snapshot, not live status. A later failed or running connection check
  marks them stale without discarding the last readable evidence.
- Automatic security updates and Ubuntu package updates can be changed here. The firewall,
  SSH sign-in and restart actions, and their confirm-or-revert window, are later Phase E
  slices ([#301](https://github.com/rajandangi/barectl/issues/301)).
- Installing updates is not reversible. Downgrades are refused, so recovery is ordinary
  administration or a backup. A restart Ubuntu asks for is shown, not performed here.
- The newest log is Ubuntu's own retained output. A host without it shows that the history
  could not be read; Barectl does not reconstruct a result from another file.
- Web runtime fixes arrive through reviewed Barectl releases, not Ubuntu updates. The
  check links to the existing catalog update action rather than adding another path.
