# ADR-0027: Messages to customers

- Status: accepted
- Date: 2026-11-04
- Amends: 04-reseller-features (RSL-ACC-09, RSL-UI-03)

## Decision

- The panel sends mail through the server's own Postfix on 127.0.0.1:25
  (it accepts mail from this machine). No new credentials. Sender: the admin
  contact address from the server setup, else `noreply@<host name>`.
- **Welcome message**: queued by `accounts` when a new account becomes active
  the first time, if it has an email address (the retry of a failed set-up
  does not send it again). The text is the owner's own (reseller), else the
  admin's, else a built-in one. Passwords are never in it.
- **Message to all customers**: admins reach every account, resellers their
  own. Accounts without an address are skipped, an address that several
  accounts share gets one message. One per ten minutes per sender, at most
  2000 recipients. Runs as a job, 10 per second at most, and reports how many
  were sent and failed. It is audited with its subject and recipient count.
- **Text rules**: a subject of one line (200 characters), a body of 8000;
  only `{{username}}`, `{{domain}}`, `{{panel_url}}`, `{{owner}}`. Rendering
  is a single pass of replacement, not a template language, so a value cannot
  carry syntax and nothing can run. The mail library encodes the subject and
  the body, so a line break in a value cannot add a header.
- Resellers need no extra privilege to message their own customers.

## Not done

Dashboard notices, templates per event (suspension, quota), a send history,
HTML mail, opt-out, per-reseller sending addresses.
