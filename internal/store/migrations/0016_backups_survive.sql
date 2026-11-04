-- Backups outlive their account (ADR-0015): an account's removal keeps its
-- archives, so an admin can restore it. The record keeps the account's
-- name and loses its id.

CREATE TABLE backups_new (
    id          TEXT PRIMARY KEY,
    account_id  TEXT REFERENCES accounts (id) ON DELETE SET NULL,
    username    TEXT NOT NULL DEFAULT '',
    kind        TEXT NOT NULL CHECK (kind IN ('manual', 'scheduled')),
    status      TEXT NOT NULL CHECK (status IN ('running', 'ok', 'failed')),
    file        TEXT NOT NULL DEFAULT '',
    size        INTEGER NOT NULL DEFAULT 0,
    sha256      TEXT NOT NULL DEFAULT '',
    detail      TEXT NOT NULL DEFAULT '',
    job_id      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    finished_at TEXT
) STRICT;

INSERT INTO backups_new (id, account_id, username, kind, status, file, size, sha256, detail, job_id, created_at, finished_at)
    SELECT b.id, b.account_id, COALESCE((SELECT a.username FROM accounts a WHERE a.id = b.account_id), ''), b.kind, b.status, b.file,
           b.size, b.sha256, b.detail, b.job_id, b.created_at, b.finished_at
    FROM backups b;

DROP TABLE backups;
ALTER TABLE backups_new RENAME TO backups;
CREATE INDEX backups_account ON backups (account_id, created_at);
CREATE INDEX backups_orphans ON backups (username) WHERE account_id IS NULL;
