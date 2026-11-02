# Phase E qualification record

This record lists the evidence for the Phase E exit of specification
[#301](https://github.com/rajandangi/barectl/issues/301), gathered for
[#415](https://github.com/rajandangi/barectl/issues/415). It names the revision tested, the
environments, the measured times against the budget of
[ADR 0033](adr/0033-prove-real-behavior-in-two-test-layers.md), the native scenarios that
walk the Security section, and what is not qualified. Anything this record does not list as
passing is not qualified.

## Revisions

<!-- FILL: tested revisions and the integration branch tip. -->

## Environments

<!-- FILL: local arm64 host, hosted amd64 GitHub runner, server image digests and versions. -->

## Build budget

<!-- FILL: measured fast gate, joint fast stage, browser, native stage, longest item and wall
time against the table in quality.md#test-time-budget. -->

## Security lifecycle

The section's lifecycle is proven by the existing target-stack scenarios, each on a set-up
server with sites. They run in the required Native workflow on amd64 and in Native weekly on
arm64.

| Scenario | Class | What it proves |
| --- | --- | --- |
| Security checks | `SecurityChecks` | Every check is read from ordinary discovery, the default view shows tasks without native terms, and a fresh controller reconstructs the checks after equivalent and conflicting ordinary changes. |
| Firewall | `FirewallLifecycle` | Turn on the standard, add and remove operator ports, keep and put back the window, a second controller refusing, a held lock, and a rule that blocks the new connection. |
| SSH sign-in | `SignInLifecycle` | Require key-only sign-in, the confirm-or-revert window, account disclosure and recovery. |
| Ubuntu updates | `SecurityUpdates` | Check for updates, install an exact reviewed security update from the dated snapshot, and refuse a stale review, unreviewed dependency, hold and modified conffile. |
| Restart | `VmRestart` | A real kernel reboot changes the boot ID, SSH returns, services and sites answer, and a stopped guest closes as outcome unknown. |

## What the section proves

- **Checks.** Every check is ordinary discovery through the fixed root read; opening the
  section reads only the stored snapshot and makes no SSH connection. Each row says what was
  seen, why it matters, when it was read and at most one next action. Unreadable evidence is
  "Could not check" with its reason, and there is no score. A rule, setting or manager outside
  the supported shape is reported once and blocks only the action that depends on it.
- **Firewall.** The standard is UFW active at boot, IPv6, deny incoming, allow outgoing, deny
  routed and logging low, with each effective SSH port, 80/tcp, 443/tcp and 443/udp. Operator
  ports are added and removed in the supported grammar. Docker, firewalld, a foreign nftables
  or iptables ruleset, an edited rule file or an unsupported UFW rule refuses firewall actions
  only. The review says a provider firewall is outside what Barectl can see.
- **SSH sign-in.** The fixed `00-barectl-sign-in.conf` drop-in disables passwords and
  keyboard-interactive sign-in and limits root to keys, or refuses root when the verified
  connection is not root. The review lists login accounts without readable keys. A later
  setting or `Match` block that overrides the policy is detected, and `sshd -t` runs before a
  reload.
- **Confirm-or-revert.** Firewall and SSH changes save a root-only preimage, arm a 300-second
  timer, apply and validate, then confirm over a **new** verified connection. The result is
  Kept, Put back or Not known from native evidence. Every other change refuses while a window
  is open or a put-back failed. A restart inside the window keeps the new configuration.
- **Automatic security updates.** The check reads Ubuntu's own effective settings, timers,
  conffile digest and newest log. Turn on and Turn off use the package's debconf setting and
  `dpkg-reconfigure`; they never add a second scheduler, never enable automatic reboot, and
  leave customized origins, blacklists and disabled timers alone.
- **Ubuntu updates.** Waiting updates are listed from current lists with their age, security
  first, and phased, held and blocked updates marked. Check for updates refreshes the lists.
  Install updates names every package, version and new dependency and admits only that exact
  transaction; removals, downgrades, holds, pending dpkg states and modified conffiles refuse.
  The review names the services and sites a restart may pause. Verification reads installed
  versions, `dpkg --audit`, profile units, Caddy routing and site readiness.
- **Restart.** The review names `/run/reboot-required.pkgs`, sites, services, downtime and the
  scheduled-task disclosure. The body refuses while managed work runs, writes its result and
  reboots. Success is a new boot ID on a fresh connection with services and sites answering.
  No connection in ten minutes is outcome unknown with provider-console guidance, never a
  retry.
- **Permissions, audit and accessibility.** Viewing uses the existing view permissions and
  preparing uses the existing prepare permissions plus Shared consent; there is no
  security-specific permission. A viewer or site operator sees no control and a forged POST
  is refused. Security records live only in the Barectl database. The Security default view
  passes the #179 banned-terms check, and the restart and updates controls work by keyboard at
  320 px.

## Acceptance criteria

<!-- FILL: one row or bullet per acceptance criterion with the evidence. -->

## Not qualified

<!-- FILL: real gaps only, including any architecture or lane not run. -->

## Handoff

<!-- FILL: final head, PR, and checks. -->
