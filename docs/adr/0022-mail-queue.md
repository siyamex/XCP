# ADR-0022: Mail queue

- Status: accepted
- Date: 2026-11-04

## Decision

- Admins see what Postfix has not delivered (`postqueue -j`: id, queue,
  arrival, size, sender, recipients with the reason delivery waits) and can
  try it again (`postqueue -f` for everything deferred, `postqueue -i ID` for
  chosen messages) or delete it (`postsuper -d ID`, or `-d ALL deferred`).
- Typed agent ops, no free-form commands. Message ids come from the
  browser and go to a command line, so they must match
  `^[0-9A-Za-z]{6,20}$`, at most 500 at a time, and each is its own argument.
- The listing is the newest 500; the panel says when there may be more.
- Admin-only, every action audited (`mail.queue.<action>`).
- Users do not see the queue: it holds other accounts' mail.

## Not done

Hold and release, viewing a message's headers or body, per-domain views
for resellers, and delivery tracking by recipient (`USR-MAIL` tracking).
