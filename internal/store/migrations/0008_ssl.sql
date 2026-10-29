-- SSL certificates (ADM-SSL-01, 02, 05; USR-SSL-01, 03, 06; ADR-0005).
-- Private keys are encrypted with the master key and never returned by the API.

CREATE TABLE certificates (
    id         TEXT PRIMARY KEY,
    domain_id  TEXT UNIQUE REFERENCES domains (id) ON DELETE CASCADE,  -- NULL = the server's own (host name)
    source     TEXT NOT NULL CHECK (source IN ('acme', 'upload')),
    names      TEXT NOT NULL,  -- JSON array of the names it covers
    issuer     TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after  TEXT NOT NULL,
    cert_pem   TEXT NOT NULL,  -- the certificate, then its chain
    key_enc    BLOB NOT NULL,  -- PKCS #8 private key, encrypted
    created_at TEXT NOT NULL
) STRICT;

CREATE INDEX certificates_expiry ON certificates (not_after);
CREATE UNIQUE INDEX certificates_one_server ON certificates ((domain_id IS NULL)) WHERE domain_id IS NULL;

ALTER TABLE domains ADD COLUMN autossl INTEGER NOT NULL DEFAULT 1 CHECK (autossl IN (0, 1));  -- 0 = left out of AutoSSL
ALTER TABLE domains ADD COLUMN force_https INTEGER NOT NULL DEFAULT 0 CHECK (force_https IN (0, 1));
-- AutoSSL's last result for the domain and why: '' (not yet), ok, failed, skipped.
ALTER TABLE domains ADD COLUMN ssl_status TEXT NOT NULL DEFAULT '' CHECK (ssl_status IN ('', 'ok', 'failed', 'skipped'));
ALTER TABLE domains ADD COLUMN ssl_detail TEXT NOT NULL DEFAULT '';
ALTER TABLE domains ADD COLUMN ssl_checked_at TEXT;
