# ADR-0034: Zone file import and export

- Status: accepted
- Date: 2026-11-09

## Decision

- `GET /dns/zones/{id}/export` downloads the zone as an RFC 1035 zone file
  (`$ORIGIN`, one line per record, names absolute, TXT as stored). The SOA is
  left out: the DNS server keeps it.
- `POST /dns/zones/{id}/import {text}` **adds** the records of a zone file
  (at most 1 MB, parsed with `miekg/dns`' zone parser, `$TTL`, `$ORIGIN`,
  relative names and comments work). Nothing is replaced or removed.
  - Each record goes through the same checks as one added by hand
    (`dnsrr`): names in the zone, valid data, TTL range.
  - Records the zone has already are counted and skipped; the SOA is skipped;
    types the panel does not manage (DNSSEC records, say) are listed.
  - **All or nothing**: an invalid record, a record outside the zone or a zone
    that would be invalid (CNAME conflicts, more than 2000 records) refuses
    the whole file (409 `bad_zone_file`, `record_conflict`, `too_many_records`),
    naming the first problems.
  - One zone job and one audit event (`dns.zone.import`) per import.
- Same access as the record editor (admins for their own accounts' zones,
  users with the DNS editor feature).

## Addendum: bulk TTL

- `POST /server/dns/bulk-ttl {ttl}` (admins) sets the TTL of every record of
  every zone (60 to 604800), queues the zones that changed and writes one audit
  event. The zone template and the default TTL for new records are not
  touched. DKIM/SPF/DMARC and the email routing have their own bulk actions (below).

## Addendum: orphan zones

- New agent RPC `DNSZoneList` (names PowerDNS serves). `GET /server/dns/orphans`
  lists the served zones that no account owns and whose names do not hold the
  name servers; `DELETE /server/dns/orphans/{name}` removes one after checking
  again that it is still an orphan (409 `zone_in_use` otherwise). Admins only,
  audited as `dns.orphan.delete`.

## Addendum: repair email DNS for all domains

- `POST /server/mail/repair-all` (admins) runs the existing per-domain repair
  (ADR on deliverability: DKIM key always, SPF and DMARC only where the zone
  has none) for every domain with email of the active accounts the admin owns.
  The result counts the domains looked at and changed and lists those whose DNS
  is elsewhere (`no_zone`) or that were refused.

## Addendum: email routing for all zones

- `POST /server/dns/bulk-mail-routing {mail_routing}` (admins) sets the email
  routing (`auto`, `local`, `remote`, `backup`) of every zone that does not
  have it already, in one transaction, calls the mail hook once for each
  account whose zones changed, and writes one audit event
  (`dns.bulk.mail_routing`). The MX records are not touched: `auto` keeps
  following them, the other values override them as for one zone.

## Not done

- "Reset to template" (USR-DNS-04), because it removes records.
- Replacing import (a zone file that becomes the zone).
