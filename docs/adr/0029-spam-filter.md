# ADR-0029: Spam filter per mailbox

- Status: accepted
- Date: 2026-11-05
- Amends: 05-user-features (USR-MAIL-08), 03-admin-features (ADM-MAIL-05, in part)

## Decision

- **Rspamd scores, the mailbox decides.** Rspamd's milter adds
  `X-Spam-Level` (a star per point of score) and `X-Spam-Status` to every
  message. `local.d/milter_headers.conf` first removes any `X-Spam*` header
  the sender made up (the `remove-headers` routine runs whatever the score),
  and applies to local and signed-in senders too, so a header in a mailbox is
  always Rspamd's. The server's global actions (greylist, reject at the
  server's score) are Rspamd's defaults; a message that Rspamd rejects never
  reaches a mailbox.
- **A Sieve script per mailbox** (the one `sieve_before` already runs, which
  holds the autoresponder) tests `X-Spam-Level` for the owner's threshold
  (1 to 50, default 6 which is Rspamd's own limit) and files the message under
  Junk (`fileinto :create`, needs the `mailbox` extension) or deletes it
  (`discard`) and stops, so a spam message gets no autoresponse. The allow
  list is tested first (those senders are never spam), then the block list
  (always spam), then the score. Entries are addresses or patterns like
  `*@example.com`, lower case, `[A-Za-z0-9._%+@*-]` only, at most 200 per list;
  nothing else reaches the script (`agent.CheckSpamFilter`), and strings are
  Sieve-quoted.
- A filter switched off renders no tests at all.
- **Storage and API**: table `mailbox_spam` (no row: the default), part of
  the account's backup. `GET/PUT /mailboxes/{id}/spam`; users need the
  `spam_filter` feature (it existed in the catalogue without effect), admins
  need nothing. The apply job sends every mailbox's filter, so the script of
  mailboxes that never changed it is the default one. The accounts' render
  version went to 3 so existing mailboxes get it after the upgrade.
- The user's own Sieve rules (managesieve) come after this script; they do not
  see spam that was filed or deleted.

## Consequences

- A delete action is final and silent; the page says so.
- The score is Rspamd's: the threshold means "this many points", not a
  percentage. Stars are capped by Rspamd.

## Not done

Server-wide Rspamd settings (reject score, Bayes learning from the Junk
folder, global lists, the Rspamd web UI), auto-hold of suspected spammers.
