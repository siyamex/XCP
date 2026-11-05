-- Spam filter of a mailbox (USR-MAIL-08, ADR-0029). No row: the defaults.

CREATE TABLE mailbox_spam (
    mailbox_id TEXT PRIMARY KEY REFERENCES mailboxes (id) ON DELETE CASCADE,
    enabled    INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    threshold  INTEGER NOT NULL DEFAULT 6 CHECK (threshold BETWEEN 1 AND 50),
    action     TEXT NOT NULL DEFAULT 'junk' CHECK (action IN ('junk', 'delete')),
    allow_list TEXT NOT NULL DEFAULT '[]',
    block_list TEXT NOT NULL DEFAULT '[]',
    updated_at TEXT NOT NULL
) STRICT;
