# ADR-0016: Server settings, host name, updates and reboot

- Status: accepted
- Date: 2026-11-04
- Amends: 03-admin-features (ADM-SRV-01, 02, 05, 06, 08)

## Context

Admins need to set the server up and change its basics from the panel:
the first-run settings, the host name, a few global defaults with search,
update preferences and a safe reboot. Some settings must reach other parts
(PHP pools of every account, the panel's session limits, the OS).

## Decision

- **Global settings are a catalogue in code** (key, group, type, default,
  range): default PHP version, upload limit, the panel's session idle time
  and lifetime, update channel and window, automatic OS updates. Values are
  stored under `settings.<key>`; unknown keys and out-of-range values are
  refused. A change is audited and applied: PHP settings re-apply every
  account (the PHP pool gets `upload_max_filesize` and `post_max_size`), session
  limits apply at once (`auth.Service.SetSessionLimits`, also at start),
  automatic OS updates write apt's `20auto-upgrades` through the agent.
- **Setup** (first run, editable any time) sets the host name, time zone
  (`timedatectl`, names checked against the tz database), the admin's
  contact address and the DNS settings (name servers and server IPs, through
  the zones service). The dashboard points to it until it is done.
- **Changing the host name** sets the system name and the 127.0.0.1.1 line of
  `/etc/hosts` (`hostnamectl`), the name AutoSSL gets a certificate for, and
  the mail server's name (and queues its apply). A name that is an account's
  domain is refused. The panel's certificate for the new name comes from
  AutoSSL; the DNS record for it is the admin's.
- **Updates:** the panel checks GitHub's releases (stable: latest;
  beta: newest including pre-releases), at most hourly, and says whether a
  newer one exists. It does not install updates yet; the window and channel
  are kept for when it does.
- **Reboot:** graceful or forced, after typing the admin's password again,
  audited before it happens, started by the agent a few seconds later so the
  call answers.
- **Rebuild** (`POST /server/rebuild`, `xcpctl rebuild --yes`) queues an apply
  of every account, every DNS zone and the mail settings from the panel's
  database, as jobs.

## Consequences

- Changing the PHP settings re-applies every account: on a big server that is
  a burst of jobs.
- The system time zone changes at once, but xcp-agent (cron schedules) uses
  the zone it started with until it restarts.
- A host name change leaves the panel on its old certificate until AutoSSL
  issues one for the new name.
