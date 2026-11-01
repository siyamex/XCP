# ADR-0008: Autoresponders with Sieve, Roundcube sign-on with temporary IMAP passwords, pipes as the account user

- Status: accepted
- Date: 2026-11-01
- Amends: ADR-0007; 06-service-drivers.md §4 (Mail)

## Context

Mail part 2 needs autoresponders with dates and an interval (USR-MAIL-05),
webmail with single sign-on (USR-MAIL-11, ADM-MAIL-11) and forwarders that
hand mail to a script (USR-MAIL-03, left over from part 1). The panel
keeps only password hashes, so it cannot sign anyone in to IMAP with their
password; and nothing of a user's must run as root.

## Decision

- **Autoresponders** are Sieve vacation scripts (Dovecot Pigeonhole). The
  agent writes one per mailbox with an autoresponder to
  `/etc/dovecot/xcp/sieve/<domain>/<local>.sieve`, readable by the account's
  group only, compiles it with `sievec`, and Dovecot runs it before
  delivery (`sieve_before`). The dates are checked in the script
  (`currentdate`), so a reply starts and stops without the panel; the
  interval is Sieve's `:days`. The user's own Sieve filters (P2) come after it.
- **Webmail** is Roundcube, pinned by version and SHA-256 like phpMyAdmin,
  in `/usr/share/xcp/roundcube`, run by its own PHP-FPM pool as `xcp-rc`,
  with a SQLite database, served only on the server's own name at
  `/webmail/` (its `public_html` alone is reachable). Its login form works
  as usual.
- **Sign-on:** the agent makes a random temporary password for the mailbox,
  valid 8 hours, adds its hash to a second Dovecot passdb (tried after the
  real one) and writes a one-time ticket (address, temporary password,
  2 minutes) that only `xcp-rc` can read. The browser goes to
  `/webmail/?_xcp_ticket=<id>`; a small Roundcube plugin deletes the ticket
  and logs in with it, so IMAP and submission accept it for the session.
  Expired temporary passwords are dropped by a job every 30 minutes and on
  every change; a mailbox whose login is off (or a suspended account) gets
  none and loses those it had.
- **Pipes** run as the account's Linux user: for each pipe forwarder the
  agent adds a Postfix `pipe` transport with `user=<account>` and the
  script's absolute path (inside the account's home) to `master.cf`, and a
  transport map entry for the address. Postfix's own time limit applies.
  The account's resource slice does not (Postfix starts the process), so
  scripts get only Postfix's limits; running them in the slice waits for
  the jail work (P3).

## Consequences

- No master password: Roundcube can sign in only where a ticket says.
- Temporary passwords stay valid for the session's length even if the user
  changes the real password; turning login off ends them at once.
- `master.cf` becomes agent-rendered (static services plus pipe transports).
