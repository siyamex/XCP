# ADR-0030: Server-wide spam settings

- Status: accepted
- Date: 2026-11-05
- Amends: 03-admin-features (ADM-MAIL-05, in part)

## Decision

- Three settings join the mail settings (ADR-0007): the score from which
  Rspamd **refuses** a message (8 to 100, Rspamd's own 15 by default and for
  settings saved before this), a **block list** of addresses and domains, and
  an **allow list** of domains. They are applied with the other mail settings
  by the same job and need no migration (the settings are one JSON document).
- Rspamd's files: `local.d/actions.conf` (`reject = N`), `local.d/multimap.conf`
  (the block list as a `from` map scoring 20, above the default refusal score
  so blocked mail is refused; with a higher refusal score it is delivered,
  carries a high `X-Spam-Level` and lands in the mailboxes' Junk by their own
  filters, ADR-0029) and `local.d/whitelist.conf` (allowed domains score -6 **only
  when the message is signed with DKIM or passes SPF**, so a forged sender
  gets nothing). The maps are `/etc/rspamd/xcp/*.map`.
- Entries are validated twice (panel and agent): lower-case domains and
  addresses of a narrow alphabet, at most 1000 per list; the allow list takes
  domains only, because an allowed address cannot be proved by SPF or DKIM.
- Rspamd's configuration changes by restart/reload of `rspamd.service`
  only when a file changed.

## Not done

Bayes learning from the Junk folder (needs Dovecot's IMAP Sieve hooks), the
Rspamd web UI behind the panel, per-symbol scores, and the auto-hold of
suspected spammers by defer and bounce rates (ADM-MAIL-04).
