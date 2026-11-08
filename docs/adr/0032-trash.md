# ADR-0032: Trash with restore

- Status: accepted
- Date: 2026-11-08

## Decision

- Deleting in the file manager already moved things to `~/.trash/<time>-<random>/`
  (ADR on the file manager). Each such folder is now a **batch**: it also holds
  `.origin.json`, which remembers where every item came from.
- **Listing** (`GET /accounts/{id}/files/trash`): the batches, newest first,
  with each item's name, original place, type and size.
- **Put back** (`trash-restore {id, names?}`): items return to their original
  place, making missing folders again. **Nothing is ever replaced**: if
  something is in the way, the item stays in the trash and is reported as a
  conflict. Batches from before this (no memory of the origin) go to the
  home folder. A batch that is empty after a restore disappears.
- **Empty** (`trash-empty {ids?}`): deletes batches for good, all without ids.
  Folders the person made unreadable are opened first, since they are the
  person's own. A budget of entries and a depth limit bound the work.
- Everything happens inside the account's own helper (`xcp-userd`, as the
  account's user, beneath its home folder through `fsx`): batch ids must match
  `YYYYMMDD-HHMMSS-<12 hex>` and item names cannot contain `/`, so no path can
  lead out of `~/.trash`.
- The trash counts against the disk quota, as it always did.

## Not done

Emptying the trash automatically after some days, a size limit for the
trash, and restoring to a different place.
