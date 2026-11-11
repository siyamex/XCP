# ADR-0036: Track delivery

Status: accepted (2026-11-11)

## Context

USR-MAIL-10 and ADM-MAIL-03: customers and admins want to know what happened
to a message. The answer is in Postfix's log, which only root and the
journal groups can read, and which `xcp-logd` already follows once a minute
for bandwidth (ADR-0012).

## Decision

- `xcp-logd` keeps doing the reading. The parser that follows each queue ID
  now also emits one **delivery** for every `to=... status=...` line and for
  every refusal on arrival (`reject:` and `milter-reject:` lines), with the
  time, queue ID, envelope sender, recipient, original recipient, status,
  relay, size and the other side's answer (cut at 300 bytes).
- They go into `mail_deliveries` (migration 0027) in the same transaction as
  the log position, so a line is stored once. Rows older than 14 days are
  deleted on every tick.
- Rows carry the lower-cased domains of the three addresses, not an account.
  An account sees the rows where one of them is one of its domains; the
  admin sees all. A message between two accounts is visible to both.
- `GET /accounts/{id}/mail/deliveries` and `GET /server/mail/deliveries`
  with `search` (part of an address, or an exact queue ID) and `status`;
  the newest 200. No agent call and no log access for the API.
- Message subjects and bodies are not recorded: Postfix does not log them
  and the panel should not hold them.

## Consequences

- Up to two minutes pass before a message shows up.
- History starts when this version is installed; older log lines are not
  read back.
- A sender that is deferred for days makes one row per attempt.
- Mail the customer's scripts send through `sendmail` appears under the
  envelope sender's domain, which may be the host name: then only the admin
  sees it, unless the recipient is local.

## Not done

- Statistics per account (ADM-MAIL-04's defer/fail share and auto-hold).
- Export, and more than 200 results.
