# ADR-0020: Per-domain web settings

- Status: accepted
- Date: 2026-11-04
- Amends: 05-user-features (USR-WEB-04, 05, 08, 09)

## Decision

- Users set, per domain: custom error pages, hotlink protection, an IP
  blocker, compression and browser caching. One JSON document per domain in
  `domain_web` (migration 0018), part of the account's backup export.
  Aliases use their parent's settings (they show its site). Allowed by the
  `domains` feature of the package.
- The agent renders them into the domain's virtual host. `WebOptions.Clean`
  is the only gate: error pages must be clean URL paths of 7 known status
  codes, addresses and networks are parsed (and never `0.0.0.0/0`), hotlink
  hosts are validated domain names, file types are `[a-z0-9]{1,10}`, caching is
  1 to 365 days. The panel cleans before saving; the agent cleans again
  before rendering. Nothing a user types is written to Apache as typed.
- IP blocker: `<RequireAll> Require all granted / Require not ip …`. Hotlink:
  `RewriteCond %{HTTP_REFERER}` against the site's own name and the allowed
  sites, `RewriteRule \.(jpg|png)$ - [F,NC]`; requests without a referrer
  pass when the user allows it. Compression and caching are in `IfModule`
  blocks (`mod_deflate`, `mod_expires`, which the installer enables), so a
  server that lacks a module still starts.
- The vhost output of a domain with no settings is byte-for-byte what it was.

## Not done

Country blocking (needs a GeoIP database), PHP ini editor (pool-level,
separate), leech protection, directory indexes per folder.
