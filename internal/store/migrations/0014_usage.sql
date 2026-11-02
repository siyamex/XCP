-- Bandwidth per domain and UTC day (USR-STAT-01, ADR-0012), written by
-- xcp-logd. The domain is kept by name, so a month's usage survives
-- removing the domain; it goes with the account.

CREATE TABLE usage_bandwidth (
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    domain     TEXT NOT NULL,
    day        TEXT NOT NULL,  -- 2006-01-02, UTC
    bytes_web  INTEGER NOT NULL DEFAULT 0,
    bytes_mail INTEGER NOT NULL DEFAULT 0,
    bytes_ftp  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (account_id, domain, day)
) STRICT;

-- Where xcp-logd is in each log: a file's inode and offset, or the
-- journal's cursor. Written in the same transaction as the bytes.
CREATE TABLE log_offsets (
    source   TEXT PRIMARY KEY,
    inode    INTEGER NOT NULL DEFAULT 0,
    offset   INTEGER NOT NULL DEFAULT 0,
    cursor   TEXT NOT NULL DEFAULT ''
) STRICT;
