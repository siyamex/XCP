# ADR-0005: ACME with x/crypto/acme; certificates travel with the site

- Status: accepted
- Date: 2026-10-29
- Amends: 06-service-drivers.md §8 (SSL/ACME)

## Context

P1 needs free certificates for every hosted domain (AutoSSL), certificates
the user uploads, and a real certificate for the panel's host name. The plan
named the `lego` client running in the worker, with challenge files written
by the agent. Choices to make: which ACME client, where challenge files and
private keys live, and how certificates reach Apache.

## Decision

- **Client:** `golang.org/x/crypto/acme` (RFC 8555, including External
  Account Binding for ZeroSSL and similar CAs). x/crypto is a dependency
  already; lego would bring in its many DNS provider libraries, and P1
  needs only HTTP-01. DNS-01 (wildcards, P2) can use our own PowerDNS
  zones, so no provider library is needed for it either.
- **Providers:** Let's Encrypt (production and staging) and any other ACME
  directory URL, with an optional CA bundle (for an internal CA or Pebble
  in tests) and EAB key. One ACME account per directory, its key encrypted
  with the master key in the database.
- **HTTP-01 challenges** are files that xcp-api writes to
  `/var/www/xcp-acme/`; Apache serves `/.well-known/acme-challenge/` from it
  for every host name, the server's own included. This needs no root:
  the folder holds nothing but tokens. The agent renders sites so that no
  redirect (www/bare choice, force HTTPS, user redirects of "/") catches
  that path.
- **Private keys** of certificates are stored encrypted with the master key
  in the database, like other secrets, and are never returned by the API.
- **Deployment:** a site's certificate and key are part of the `SiteApply`
  request, like its other desired state. The agent checks that the key
  matches the certificate and that the certificate covers the name, writes
  them root-only under `/etc/xcp/ssl/sites/<user>/`, renders the `:443`
  virtual host and the force-HTTPS redirect, and rolls back with the rest
  if `apachectl -t` fails.
- **The server's host name** gets its own certificate, installed by a
  separate agent operation as `/etc/xcp/ssl/hostname.crt` and `.key`, next
  to the panel's self-signed pair, which stays: local tools reach the panel
  by IP (installer health check, `xcpctl doctor`) and pin it. xcp-api picks
  the certificate by the name the client asks for (SNI) and reloads both
  without a restart. Mail and FTP will use the host name certificate.

## Consequences

- No new heavy dependency; we own retries, order polling and rate-limit
  handling (one attempt per domain per run, failures recorded with the
  reason for the user).
- A compromised xcp-api could answer HTTP-01 challenges for names that point
  here. It could already get such names served (and so validated) through
  the agent, so this adds no new power.
- Private keys pass over the agent socket on every site apply. The socket
  accepts only xcp-api and root, and the agent does not log request bodies.
- Tests: the ACME flow runs end to end against Pebble in the installer test
  (CI), with our PowerDNS answering Pebble's lookups and Apache serving the
  challenges.
