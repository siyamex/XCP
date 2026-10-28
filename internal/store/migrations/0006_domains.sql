-- Domains of an account (USR-DOM-01..07). Every domain gets its own virtual
-- host. Names are unique across the server, so one account can never serve
-- another account's domain.

CREATE TABLE domains (
    id         TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    name       TEXT NOT NULL UNIQUE,  -- lower-case ASCII; "*.example.com" for a wildcard subdomain
    kind       TEXT NOT NULL CHECK (kind IN ('primary', 'addon', 'sub', 'alias')),
    parent_id  TEXT REFERENCES domains (id),  -- sub: the domain it is under; alias: the domain whose site it shows
    docroot    TEXT NOT NULL DEFAULT '',      -- relative to the home folder; '' for an alias
    canonical  TEXT NOT NULL DEFAULT '' CHECK (canonical IN ('', 'www', 'bare')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;

CREATE INDEX domains_account ON domains (account_id);
CREATE INDEX domains_parent ON domains (parent_id);
CREATE UNIQUE INDEX domains_one_primary ON domains (account_id) WHERE kind = 'primary';

-- Existing accounts: their primary domain, served from public_html as before.
INSERT INTO domains (id, account_id, name, kind, docroot, created_at, updated_at)
SELECT 'd' || id, id, primary_domain, 'primary', 'public_html', created_at, updated_at FROM accounts;

-- Redirects of one domain (USR-DOM-06).
CREATE TABLE redirects (
    id         TEXT PRIMARY KEY,
    domain_id  TEXT NOT NULL REFERENCES domains (id) ON DELETE CASCADE,
    path       TEXT NOT NULL,                 -- "/" = the whole site
    target     TEXT NOT NULL,                 -- absolute http(s) URL
    code       INTEGER NOT NULL CHECK (code IN (301, 302, 307, 308)),
    keep_path  INTEGER NOT NULL CHECK (keep_path IN (0, 1)),  -- append the rest of the path to the target
    created_at TEXT NOT NULL,
    UNIQUE (domain_id, path)
) STRICT;
