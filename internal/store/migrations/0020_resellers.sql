-- Reseller limits (ADM-RSL-02, ADR-0023). NULL = unlimited. A reseller may
-- allocate more disk or bandwidth than its cap only when overselling is on.

CREATE TABLE reseller_limits (
    login_id           TEXT PRIMARY KEY REFERENCES logins (id) ON DELETE CASCADE,
    max_accounts       INTEGER,
    disk_mb            INTEGER,
    bandwidth_mb       INTEGER,
    oversell_disk      INTEGER NOT NULL DEFAULT 0,
    oversell_bandwidth INTEGER NOT NULL DEFAULT 0,
    updated_at         TEXT NOT NULL
) STRICT;
