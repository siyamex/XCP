-- DNS zones served by this server (ADM-DNS-01..03, USR-DNS-01..03). The
-- panel database is the source of truth; xcp-agent pushes zones to PowerDNS.

CREATE TABLE dns_zones (
    id           TEXT PRIMARY KEY,
    account_id   TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    domain_id    TEXT UNIQUE REFERENCES domains (id) ON DELETE CASCADE,  -- the domain it was made for
    name         TEXT NOT NULL UNIQUE,
    -- Who handles mail for the domain (USR-DNS-03); "auto" decides from the MX records.
    mail_routing TEXT NOT NULL DEFAULT 'auto' CHECK (mail_routing IN ('auto', 'local', 'remote', 'backup')),
    -- The DNS server has the zone (its last apply succeeded). Zones it does
    -- not have yet are applied again by the dns.sync job.
    serving      INTEGER NOT NULL DEFAULT 0 CHECK (serving IN (0, 1)),
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
) STRICT;

CREATE INDEX dns_zones_account ON dns_zones (account_id);

-- SOA and the zone's own NS records are not stored: the agent makes them
-- from the server's DNS settings.
CREATE TABLE dns_records (
    id         TEXT PRIMARY KEY,
    zone_id    TEXT NOT NULL REFERENCES dns_zones (id) ON DELETE CASCADE,
    domain_id  TEXT REFERENCES domains (id) ON DELETE CASCADE,  -- made for this domain; removed with it
    name       TEXT NOT NULL,     -- fully qualified, without the final dot
    type       TEXT NOT NULL,
    ttl        INTEGER NOT NULL,
    content    TEXT NOT NULL,     -- stored form (internal/dnsrr)
    created_at TEXT NOT NULL,
    UNIQUE (zone_id, name, type, content)
) STRICT;

CREATE INDEX dns_records_zone ON dns_records (zone_id);
CREATE INDEX dns_records_domain ON dns_records (domain_id);
