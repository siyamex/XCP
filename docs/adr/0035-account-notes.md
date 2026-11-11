# ADR-0035: Account notes and tags

Status: accepted (2026-11-11)

## Context

ADM-ACC-18 asks for internal notes and tags on accounts, for admins only.
Such notes are often about a person (payment behaviour, abuse history).

## Decision

- Table `account_notes` (migration 0026): one row per account with the note,
  the tags as a JSON array, who wrote it last and when. It goes with the
  account (`ON DELETE CASCADE`).
- `GET` / `PUT /accounts/{id}/note` for admins only. A note has at most 5000
  characters; an account at most 10 tags of lower-case letters, digits and
  hyphens (30 characters), stored sorted and without duplicates.
- Admins get `tags` with each account; `GET /accounts?tag=` filters. For
  resellers and customers the field is absent, also for a reseller's own
  customers.
- The audit event `account.note` records the tags and the note's length,
  not its text.
- The table is **not** part of the account export (`store.AccountTables`):
  customers can download their backups, and a backup may be restored on
  another server. A restored account therefore has no note.

## Not done

- Notes by resellers about their own customers.
- A history of a note's changes.
