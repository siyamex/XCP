-- Packages and feature lists (ADM-PKG-01/02, RSL-PKG-01/02).
-- owner_id NULL means the package belongs to the admins (global);
-- a reseller's login ID makes it theirs (P2).

CREATE TABLE feature_lists (
    id         TEXT PRIMARY KEY,
    owner_id   TEXT REFERENCES logins (id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    features   TEXT NOT NULL DEFAULT '[]',           -- JSON array of enabled feature keys
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;

CREATE UNIQUE INDEX feature_lists_owner_name ON feature_lists (COALESCE(owner_id, ''), name);

CREATE TABLE packages (
    id              TEXT PRIMARY KEY,
    owner_id        TEXT REFERENCES logins (id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    feature_list_id TEXT NOT NULL REFERENCES feature_lists (id),
    limits          TEXT NOT NULL DEFAULT '{}',       -- JSON object, see internal/plans.Limits
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
) STRICT;

CREATE UNIQUE INDEX packages_owner_name ON packages (COALESCE(owner_id, ''), name);
CREATE INDEX packages_feature_list ON packages (feature_list_id);
