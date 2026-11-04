-- The welcome message of new accounts (RSL-ACC-09, ADR-0027): the admin's
-- (owner_id '') and each reseller's own.

CREATE TABLE message_templates (
    owner_id   TEXT PRIMARY KEY,
    subject    TEXT NOT NULL,
    body       TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;
