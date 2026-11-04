# ADR-0017: Firewall, brute-force protection and IP access control

- Status: accepted
- Date: 2026-11-04
- Amends: 03-admin-features (ADM-SEC-01, 02, 03)

## Context

A hosting server is scanned and guessed at all day: SSH, mail, FTP and the
panel's own sign-in. Admins need a firewall they can manage from the panel,
automatic bans of addresses that keep failing to sign in, and a way to limit
the panel, SSH and FTP to known networks — without being able to lock
themselves out by accident.

## Decision

- **Our own nftables table.** XCP owns table `inet xcp` and never touches
  other tables or the rules of other tools. Sets: `allow4/6`, `deny4/6`
  (intervals) and `ban4/6` (with per-element timeouts). Chain `input`
  (hook input, priority -10, policy accept) in this order: loopback; allow
  lists (accept); deny lists and bans (drop); established and related
  (accept); per-service restrictions (panel port, SSH port, FTP; IPv4 and
  IPv6 as separate rules); rate-limit meters; under the *closed* policy,
  ICMP, the open ports, then drop. The *open* policy lets in whatever is not
  refused.
- **The configuration is one JSON setting (`firewall`)**, normalised on
  save (`internal/fwcfg`): addresses and networks parsed, ports checked, the
  panel's and SSH ports always open under the closed policy. Bans live in
  the table `fw_bans` (migration 0017): address, reason, source (ssh, mail,
  ftp, panel, manual), time, expiry (empty: permanent), who lifted it.
- **Applying is an agent operation** (`FirewallApply`, typed rules, no
  free-form text): the agent renders the script, checks it with
  `nft -c -f -`, loads it atomically with `nft -f -` (a table delete and
  re-create in one transaction, so no gap), and writes
  `/etc/xcp/firewall.nft`. `xcp-firewall.service` (oneshot, only if that file
  exists) loads the file at boot, before the network. Disabled: the table is
  deleted. The panel queues job `firewall.apply` (unique, lock key
  `firewall`) after every change; a five-minute job `firewall.expire` marks
  ended bans and re-applies.
- **Lockout guard.** Saving a configuration that would stop the admin's own
  address from reaching the panel (deny entry, restriction without it,
  closed policy without the panel port) puts that address on the allow list
  and says so. Bans never apply to allow-listed, the admin's own or loopback
  addresses.
- **Brute-force detection in `xcp-logd`** (it already follows the logs and
  the journal; it has no network and no privileges, and only writes the
  panel database and queues the job). It reads the journal units `ssh`,
  `dovecot`, `pure-ftpd` and Postfix after a cursor, matches failed logins
  (sshd "Failed password", "Invalid user", too many attempts; Postfix SASL
  failures; Dovecot auth failures with `rip=`; pure-ftpd "Authentication
  failed" with the client address) and the panel's refused sign-ins from the
  audit log (after the last event read). A sliding window per address counts
  them; at the threshold (default 5 in 10 minutes) the address is banned for
  a time (default 60 minutes), and for good after N earlier bans (default
  3). The configuration decides which sources count. Allow-listed and
  loopback addresses are never banned.
- **IP access control** (ADM-SEC-03): `restrict` lists networks per service
  (`panel`, `ssh`, `ftp`); only they reach it. Empty: everyone.
- **UI**: a Firewall page for admins (rules, restrictions, rate limit,
  brute-force settings, bans with lift and manual ban). All of it is
  admin-only and audited (`firewall.save`, `firewall.ban`, `firewall.unban`).

## Consequences

- A failed `nft -c` leaves the running rules untouched and fails the job
  with nft's message.
- Detection works from log lines; a service that changes its wording stops
  being counted until the pattern is updated. The parsers have unit tests
  with real lines.
- Fail2ban-style ban of *ranges*, country blocks and port knocking are not
  done. Ports of accounts' own services are not managed per account.
