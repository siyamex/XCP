-- Firewall bans (ADM-SEC-01, ADR-0017): addresses banned by xcp-logd after
-- failed logins, or by an admin. The firewall's other settings are one JSON
-- setting ("firewall"). A ban is active until released_at is set (lifted,
-- or expired: expires_at passed); expires_at NULL is permanent.

CREATE TABLE fw_bans (
    id          TEXT PRIMARY KEY,
    ip          TEXT NOT NULL,
    reason      TEXT NOT NULL,
    source      TEXT NOT NULL CHECK (source IN ('ssh', 'mail', 'ftp', 'panel', 'manual')),
    created_at  TEXT NOT NULL,
    expires_at  TEXT,
    released_at TEXT,
    released_by TEXT NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX fw_bans_active ON fw_bans (released_at, expires_at);
CREATE INDEX fw_bans_ip ON fw_bans (ip, created_at);
