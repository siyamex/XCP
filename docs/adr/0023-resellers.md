# ADR-0023: Resellers (core)

- Status: accepted
- Date: 2026-11-04
- Amends: 03-admin-features (ADM-RSL-01, 02), 04-reseller-features

## Decision

- A reseller is a login with role `reseller`, made by an admin
  (`/resellers`). Its limits live in `reseller_limits` (migration 0020):
  most accounts, disk and bandwidth it may promise in all, and whether
  overselling each resource is allowed. Empty means unlimited.
- Ownership uses what the schema already had: `accounts.owner_id` and
  `packages.owner_id` (empty: the admins). The services call one function,
  `scope(p)`: admins `""`, resellers their own id. A reseller reads or
  changes only what it owns; anything else looks like "not found".
  Admins see every account (`visible(p)` is `*`) and the account view shows
  its owner.
- Packages: a reseller has its own, built from the **admin's feature lists**,
  which it can read but not change (own feature lists are P3, RSL-PKG-02).
  It cannot use the admin's packages.
- Quota: when a reseller makes an account or changes its package, the
  panel adds up what its packages promise (the account count, disk,
  bandwidth). Over the count it is refused; over a disk or bandwidth cap it is
  refused unless overselling is on for that resource. A package with no
  disk (or bandwidth) limit counts as all of it, so under a cap it is
  refused. Lowering limits below what is given out is allowed and only stops
  new accounts. Quota is checked when accounts are made or change package,
  not when a package is edited.
- Account jobs read the package's limits by id (`plans.Entitlements`), not
  as the admin, since the package may belong to a reseller.
- A reseller's customers are normal user logins whose `owner_id` is the
  reseller. Everything a customer does is unchanged. Suspending a reseller's
  login ends its sessions and stops it signing in; it does not touch its
  customers.
- The reseller routes: `GET/POST /resellers`, `PUT /resellers/{id}/limits`,
  `POST /resellers/{id}/(un)suspend` (admins); `GET /reseller/overview`
  (the reseller). `/accounts*` (lifecycle), `/packages*` and the read of
  `/feature-lists*` are open to resellers.

## Privileges (ADM-RSL-03)

Each reseller has a list of privileges (`reseller_limits.privileges`, migration
0021): `create`, `modify` (package and contact), `suspend` (and reactivate),
`password`, `terminate` and `impersonate` (ADR-0024). The accounts service
checks them before each action; reading is always allowed; admins are never
limited. A request that names none grants all, and existing resellers keep
all.

## Not done

Resellers editing
DNS/domains/mail of their customers (they use impersonation in the plan),
bulk actions, welcome messages, branding, IP delegation, token scopes.
