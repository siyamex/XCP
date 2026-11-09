# ADR-0033: Notices to customers

- Status: accepted
- Date: 2026-11-09

## Decision

- Six automatic emails to a customer's address (accounts without one get
  none): **suspended**, **reactivated**, **disk almost used up**, **disk
  full**, **traffic almost used up**, **traffic used up**.
- **Texts** are editable like the welcome message (ADR-0027): the sender's own,
  else the admin's, else the built-in one (`notice_templates`, owner `''` for
  the admin). An empty subject and body go back to the default. Variables are
  those of the welcome message plus `reason`, `used`, `limit`, `percent`.
  `GET /messages/notices`, `PUT /messages/notices/{kind}` for admins and
  resellers.
- **Suspension and reactivation**: `accounts.Service` calls an `OnStatus` hook
  after the change succeeded; the messages service queues a `messages.notice`
  job (three attempts), so a slow mail server never delays the suspension.
- **Usage**: an hourly job (`messages.usage`, minute 20) compares each active
  account's disk (from the agent's status, by account name) and traffic of the
  current month (`usage_bandwidth`) with its package. From the warning share
  (setting `notices.percent`, 80 by default, 50 to 99) a warning goes out;
  at the limit, a "full" notice. Packages without that limit are skipped.
- **Once each**: `notices_sent (account, kind, period)`. Traffic notices are
  once per month (the period is the month); disk notices once, and again only
  after the use has fallen below the warning share. After "full", the warning
  is not repeated.
- The master switch is the server setting `notices.enabled` (on by default).
- Mail goes through the same local SMTP client as the other messages.

## Not done

- Notices to the admin about customers' usage, and per-package warning shares.
