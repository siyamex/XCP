# ADR-0028: Mail sending limits

- Status: accepted
- Date: 2026-11-05

## Decision

- The package's `mail_per_hour` (it existed in the limits but nothing used
  it) limits how many **recipients** an account may send to per hour. It
  counts recipients, not messages, because a message to 500 addresses is the
  abuse this is meant to stop.
- `xcp-mailpolicy` is a Postfix **policy service**. Only the submission (587)
  and smtps (465) services ask it, with
  `smtpd_end_of_data_restrictions = $mua_data_restrictions`
  (`check_policy_service unix:/run/xcp-mailpolicy/policy.sock`), so mail
  that arrives from outside is never limited and nothing slows the normal
  smtp port. At the end of each message Postfix sends the signed-in login and
  `recipient_count`.
- It maps the login to its mailbox, account and package in the panel
  database (cached for a minute), keeps a sliding hour in one-minute steps
  per account in memory, and answers `dunno` or `450 4.7.1 The hourly sending
  limit of N recipients of this account is reached`. A message that would cross
  the limit is refused whole and not counted, so a smaller one can still pass
  and the sender's mail program retries later. A limit of nothing means none.
- **Fail open**: if the daemon is down or slow (`smtpd_policy_service_default_action
  = DUNNO`, 10 s timeout) or the database lookup fails, mail goes through.
  A limit must not become an outage.
- The daemon runs as the panel's user with no network and no privileges
  (like `xcp-logd`); its socket is `0660` for the `postfix` group in a
  `0750` runtime folder. The installer starts it with the rest of the mail
  stack, before Postfix.
- The counts are in memory: a restart gives every account a fresh hour.

## Consequences

- Mail from a mailbox to its own account's other mailboxes through submission
  counts too: it is sending.
- Per-mailbox limits, a per-domain limit and a server-wide default are not
  done.
