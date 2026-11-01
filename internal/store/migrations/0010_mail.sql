-- Mail of accounts' domains (USR-MAIL-01, 03, 06, 09; ADR-0007). The panel
-- database is the source of truth; xcp-agent builds the mail maps from it.

CREATE TABLE mail_domains (
    domain_id    TEXT PRIMARY KEY REFERENCES domains (id) ON DELETE CASCADE,
    dkim_key_enc BLOB,                        -- RSA signing key (PKCS #8 PEM), encrypted
    catch_all    TEXT NOT NULL DEFAULT '[]',  -- JSON array of addresses for unknown ones; [] rejects them
    updated_at   TEXT NOT NULL
) STRICT;

CREATE TABLE mailboxes (
    id            TEXT PRIMARY KEY,
    domain_id     TEXT NOT NULL REFERENCES domains (id) ON DELETE CASCADE,
    local_part    TEXT NOT NULL,
    password_hash TEXT NOT NULL,  -- {ARGON2ID}..., what Dovecot checks
    quota_mb      INTEGER NOT NULL DEFAULT 0 CHECK (quota_mb >= 0),  -- 0 = no limit of its own
    can_login     INTEGER NOT NULL DEFAULT 1 CHECK (can_login IN (0, 1)),
    can_receive   INTEGER NOT NULL DEFAULT 1 CHECK (can_receive IN (0, 1)),
    can_send      INTEGER NOT NULL DEFAULT 1 CHECK (can_send IN (0, 1)),
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    UNIQUE (domain_id, local_part)
) STRICT;

CREATE TABLE mail_forwarders (
    id           TEXT PRIMARY KEY,
    domain_id    TEXT NOT NULL REFERENCES domains (id) ON DELETE CASCADE,
    local_part   TEXT NOT NULL,
    destinations TEXT NOT NULL DEFAULT '[]',  -- JSON array of addresses
    fail_message TEXT NOT NULL DEFAULT '',    -- set: reject with this message instead
    created_at   TEXT NOT NULL,
    UNIQUE (domain_id, local_part)
) STRICT;
