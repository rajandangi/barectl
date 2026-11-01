# Security checks

A server's **Security** section, beside Sites, Activity, Settings and Advanced, reports what
Barectl could read about its exposure. The standard firewall can be turned on and extra
ports allowed or removed, key sign-in required, automatic security updates turned on or
off, and Ubuntu updates checked for and installed from the section. Restart remains a
later Phase E slice. The Web runtimes check links to the existing catalog update in
Advanced.

## What it reads

Discovery reads the checks through the fixed root path (`discovery/root_read.py`): root, or
the exact passwordless sudo authorization. Without either, every check says "Could not
check" with that reason. It never prompts and never falls back to an unprivileged guess.

| Check | Evidence |
| --- | --- |
| Firewall | UFW package and service state, `ufw status verbose`, `ufw show added`, `ufw.conf`, the IPv6 setting and digests of `before.rules` and `after.rules`; firewalld, Docker, nftables and iptables for another manager. |
| Firewall listeners | `ss -Hlnptu` listeners, compared with the effective SSH ports, 80/tcp, 443/tcp and 443/udp, as part of the Firewall check. |
| SSH sign-in | `sshd -T` effective settings and `sshd -T -C` for each login account on this connection, `ssh.socket` listen values, accounts with a login shell and no `authorized_keys` readable to that account, and OpenSSH's per-source penalties. |
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

## Firewall

UFW 0.36.2 from the Ubuntu archive is the only supported firewall. The standard is UFW
active and enabled at boot, `IPV6=yes`, deny incoming, allow outgoing, deny routed, logging
low, and an allow rule for every effective SSH port on TCP, 80/tcp, 443/tcp and 443/udp, on
IPv4 and IPv6. 80/tcp serves certificate challenges and redirects visitors to HTTPS;
443/udp serves HTTP/3. A missing UFW is installed first through the exact APT transaction of
[ADR 0007](adr/0007-admit-exact-package-transactions-with-an-inline-apt-guard.md), naming
every package and version.

**Turn on firewall** is a kind of the one change engine ([ADR
0035](adr/0035-one-change-engine-with-effect-derived-consent.md)) and declares a server
effect, so it needs Shared consent and its site list is rechecked under the mutation lock.
It adopts rules in the supported grammar whoever added them; a rule outside it, an edited
`before.rules` or `after.rules`, firewalld, Docker installed, or another nftables or
iptables filter ruleset refuses firewall actions only. UFW's own chains and Docker's
internal DNS rules are not another manager.

The effective SSH ports are the `sshd -T` port lines, `ssh.socket`'s `ListenStream` values
and the ports sshd actually listens on. They must agree and include the port the server's
SSH daemon sees the verified connection on; otherwise every firewall action refuses.

**Allow a port** and **Remove a port** take one port or range, TCP or UDP, from anywhere or
from one IPv4 or IPv6 network. They are offered only while the standard holds. Standard
rules cannot be removed; removing an absent rule or adding a duplicate is "No changes
needed". Changes go only through `ufw` commands and the rule files are never edited.
Preparation runs each rule change with `ufw --dry-run`. It does not dry-run `ufw enable`:
ufw 0.36.2 writes `ENABLED=yes` to `/etc/ufw/ufw.conf` even under `--dry-run`, so the body
enables and validates the result under the lock instead.

### Confirm-or-revert

Every firewall change runs inside the five-minute window of [ADR
0023](adr/0023-change-server-access-with-native-confirm-or-revert.md). Its body saves a
root-only preimage of the UFW files under `/run/barectl/revert-<run>`, records whether UFW
was enabled, arms `barectl-revert-<run>.timer` with `systemd-run --on-active=300`, then
applies and validates. A failed body starts the revert service at once. The revert service
waits up to 120 seconds for the mutation lock, restarts on failure up to three times,
restores the preimage, and then runs `ufw reload`, or `ufw --force disable` when UFW was
disabled before.

After a successful run the worker opens a **new** verified connection, not the one that
watched the run, and runs one fixed confirmation under the mutation lock. It stops the
timer and removes the preimage only when the revert service has no invocation and an empty
control group. The run page shows the window outcome as **Kept**, **Put back** or **Not
known**, read from the timer, service, journal and preimage. A successful run whose window
is not confirmed is recorded as failed: the server puts the old firewall back on its own.
Every change payload refuses while a revert timer is active, its service is running or
failed, or a preimage remains. A restart inside the window keeps the new firewall and loses
only the automatic put-back.

## SSH sign-in

**Require key sign-in** writes `/etc/ssh/sshd_config.d/00-barectl-sign-in.conf` as
root:root 0644. It sets `PasswordAuthentication no`,
`KbdInteractiveAuthentication no` and `PermitRootLogin prohibit-password`. When the
verified Barectl connection signs in as a non-root user with the required sudo access,
it sets `PermitRootLogin no` instead. It does not change ports, listen addresses, users
or keys. OpenSSH's `PerSourcePenalties` remains at its default.

Preparation reads the effective `sshd -T` settings and checks `sshd -T -C` for each
account with a login shell using the current connection's client and server addresses
and port. It accepts the packaged `sshd_config.d/*.conf` include and `Match` conditions
limited to User, Group or all. Other includes or address, host and port dependent
conditions leave the SSH check unknown and refuse the change, because one controller
address cannot establish the policy for every connection. The confirm screen lists
login accounts whose `authorized_keys` is unreadable to that account. Site accounts
with `nologin` do not appear. Barectl refuses when it cannot read the accounts or check
their effective sign-in settings. An earlier drop-in that wins, or a supported `Match`
block that still allows passwords, makes verification fail.

This is a Shared server change in the same five-minute [confirm-or-revert](#confirm-or-revert)
window as the firewall. The body saves the prior drop-in or its absence, arms the timer,
writes the fixed file, runs `sshd -t`, and reloads an active `ssh.service`. If the body
or a new key connection cannot confirm the policy, the revert service restores the
prior file, runs `sshd -t` and reloads SSH. Both `ssh.socket` and `ssh.service` may be
enabled on Ubuntu 26.04; no socket restart is needed for this policy.

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
- The firewall, SSH sign-in, automatic security updates and Ubuntu package updates can be
  changed here. Restart is a later Phase E slice
  ([#301](https://github.com/rajandangi/barectl/issues/301)).
- A firewall whose revert service fails is left for ordinary administration: every later
  change refuses while the failed service or its preimage remains, and Barectl never retries
  the revert.
- Installing updates is not reversible. Downgrades are refused, so recovery is ordinary
  administration or a backup. A restart Ubuntu asks for is shown, not performed here.
- The newest log is Ubuntu's own retained output. A host without it shows that the history
  could not be read; Barectl does not reconstruct a result from another file.
- Web runtime fixes arrive through reviewed Barectl releases, not Ubuntu updates. The
  check links to the existing catalog update action rather than adding another path.
