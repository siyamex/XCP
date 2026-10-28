# ADR-0004: The agent renders service configs from typed requests

- Status: accepted
- Date: 2026-10-28
- Amends: 01-architecture.md §4 (reconciler)

## Context

The plan had xcp-api render config files (vhosts, PHP pools, mail maps)
and hand them to xcp-agent through `FileWriteManaged`. For Apache that is
a privilege escalation path: Apache config can run programs as root (for
example a piped `CustomLog "|/bin/sh ..."`), so whoever controls the text
controls root. A compromised xcp-api, the most exposed process, would win.

## Decision

- Service configs are rendered **inside xcp-agent** from embedded templates
  and typed, validated fields. The first operation is `SiteApply`
  (username, UID, domains, PHP version, suspended, PHP workers).
- Every field that reaches a template passes a strict validator (LDH
  domains, `[a-z][a-z0-9]*` usernames, `N.N` PHP versions), so no field can
  add a directive or a line.
- The agent tests the complete configuration with the service's own check
  (`apachectl -t`, `php-fpm -t`), restores the previous files if it fails,
  and reloads gracefully otherwise.
- `FileWriteManaged` stays for files that cannot run code (and is limited to
  allow-listed directories); it is not used for web, mail or DNS configs.

## Consequences

- The API decides *what* a site should be; only the agent decides *how*
  that is written. A compromised API can create or change sites through
  the same validated fields, but cannot inject configuration.
- Template changes ship with the agent binary. Golden tests in
  `internal/agent/web_test.go` pin the exact output.
- Admin customisation (P2, ADM-WEB-03) will be typed options or reviewed
  include files, not free text from the API.
