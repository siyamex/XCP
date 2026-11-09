-- Notices to customers (ADR-0033): the texts the admin and the resellers
-- changed, and which notices went out, so each is sent once.

CREATE TABLE notice_templates (
    owner_id   TEXT NOT NULL,           -- '' the admins, else a reseller
    kind       TEXT NOT NULL,
    subject    TEXT NOT NULL,
    body       TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (owner_id, kind)
) STRICT;

CREATE TABLE notices_sent (
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    kind       TEXT NOT NULL,
    period     TEXT NOT NULL DEFAULT '', -- the month for traffic, '' for disk
    sent_at    TEXT NOT NULL,
    PRIMARY KEY (account_id, kind, period)
) STRICT;
