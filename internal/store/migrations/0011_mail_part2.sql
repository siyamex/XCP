-- Mail part 2 (USR-MAIL-05, USR-MAIL-03 pipes; ADR-0008).

CREATE TABLE mail_autoresponders (
    mailbox_id TEXT PRIMARY KEY REFERENCES mailboxes (id) ON DELETE CASCADE,
    subject    TEXT NOT NULL,
    body       TEXT NOT NULL,
    start_date TEXT NOT NULL DEFAULT '',  -- YYYY-MM-DD; '' = from now
    end_date   TEXT NOT NULL DEFAULT '',  -- YYYY-MM-DD, inclusive; '' = until removed
    days       INTEGER NOT NULL DEFAULT 1 CHECK (days BETWEEN 1 AND 30),
    updated_at TEXT NOT NULL
) STRICT;

-- A pipe forwarder hands mail to a script in the account's home, run as its user.
ALTER TABLE mail_forwarders ADD COLUMN pipe TEXT NOT NULL DEFAULT '';
