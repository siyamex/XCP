-- Web settings of a domain (USR-WEB-04, 05, 08, 09; ADR-0020): error pages,
-- hotlink protection, IP blocker, compression and browser caching, as JSON.

CREATE TABLE domain_web (
    domain_id  TEXT PRIMARY KEY REFERENCES domains (id) ON DELETE CASCADE,
    options    TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;
