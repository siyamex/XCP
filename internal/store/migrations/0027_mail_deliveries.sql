-- What Postfix did with each message, for "track delivery" (USR-MAIL-10,
-- ADM-MAIL-03). xcp-logd writes the rows from Postfix's log and removes
-- them after two weeks. Rows are found by the domains of the addresses, so
-- they need no account: a domain's history goes on when it changes hands.

CREATE TABLE mail_deliveries (
    id            INTEGER PRIMARY KEY,
    at            TEXT NOT NULL,
    queue_id      TEXT NOT NULL,           -- '' for mail refused before it was queued
    sender        TEXT NOT NULL,
    recipient     TEXT NOT NULL,
    orig_to       TEXT NOT NULL,           -- the address written to, if forwarded
    sender_domain TEXT NOT NULL,
    rcpt_domain   TEXT NOT NULL,
    orig_domain   TEXT NOT NULL,
    status        TEXT NOT NULL,           -- sent, deferred, bounced, expired, rejected
    relay         TEXT NOT NULL,
    detail        TEXT NOT NULL,           -- the other server's answer, shortened
    size          INTEGER NOT NULL
) STRICT;

CREATE INDEX mail_deliveries_at ON mail_deliveries (at);
CREATE INDEX mail_deliveries_sender ON mail_deliveries (sender_domain, id);
CREATE INDEX mail_deliveries_rcpt ON mail_deliveries (rcpt_domain, id);
CREATE INDEX mail_deliveries_orig ON mail_deliveries (orig_domain, id) WHERE orig_domain <> '';
