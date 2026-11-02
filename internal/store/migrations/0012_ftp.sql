-- FTP logins of accounts (USR-FTP-01, ADR-0010). The panel database is the
-- source of truth; xcp-agent writes the logins for xcp-ftpauth from it.
-- A login is <name>@<domain>, with a domain of the account.

CREATE TABLE ftp_accounts (
    id            TEXT PRIMARY KEY,
    domain_id     TEXT NOT NULL REFERENCES domains (id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    password_hash TEXT NOT NULL,  -- {ARGON2ID}..., what xcp-ftpauth checks
    home_rel      TEXT NOT NULL DEFAULT '.',  -- folder relative to the account's home
    quota_mb      INTEGER NOT NULL DEFAULT 0 CHECK (quota_mb >= 0),  -- 0 = no quota of its own
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    UNIQUE (domain_id, name)
) STRICT;
