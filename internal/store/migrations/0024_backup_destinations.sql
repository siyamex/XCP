-- Remote destinations for copies of the account backups (ADR-0031).
-- config is JSON without secrets; secrets_enc is the sealed JSON of the
-- passwords, keys and secret keys.

CREATE TABLE backup_destinations (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    kind        TEXT NOT NULL CHECK (kind IN ('folder', 'sftp', 's3')),
    config      TEXT NOT NULL,
    secrets_enc BLOB,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
) STRICT;

-- What is known of a backup's copy at a destination.
CREATE TABLE backup_remote (
    backup_id      TEXT NOT NULL REFERENCES backups (id) ON DELETE CASCADE,
    destination_id TEXT NOT NULL REFERENCES backup_destinations (id) ON DELETE CASCADE,
    status         TEXT NOT NULL CHECK (status IN ('running', 'ok', 'failed')),
    detail         TEXT NOT NULL DEFAULT '',
    size           INTEGER NOT NULL DEFAULT 0,
    at             TEXT NOT NULL,
    PRIMARY KEY (backup_id, destination_id)
) STRICT;
