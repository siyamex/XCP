-- What a reseller may do with its customers' accounts (ADM-RSL-03, ADR-0023).
-- A JSON array of privilege names; existing resellers keep every privilege.

ALTER TABLE reseller_limits ADD COLUMN privileges TEXT NOT NULL
    DEFAULT '["create","modify","suspend","password","terminate","impersonate"]';
