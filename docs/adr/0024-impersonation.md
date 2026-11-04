# ADR-0024: Signing in as a customer

- Status: accepted
- Date: 2026-11-04
- Amends: 04-reseller-features (RSL-ACC-05)

## Decision

- Admins, and resellers for their own customers, can sign in as the user of
  an active account (`POST /accounts/{id}/impersonate`). It needs a password
  confirmation in the last five minutes (`/me/reauth`; signing in counts).
- The new session is the user's, marked with `impersonator_id`, lasts at
  most an hour (and never past the normal limit), skips 2FA because the
  actor passed it, and cannot be used to start another impersonation.
  The caller's own session ends: afterwards the person signs in again.
- Every audit event made through the session records both the user and the
  impersonator; `auth.impersonate` records the start with the account.
- While impersonating, every state-changing request under `/me/*` is refused
  (`impersonating`): password, 2FA, tokens and sessions of the customer are
  out of reach. The panel shows a banner with a button that ends it.
- Targets must be users of active accounts: not admins or resellers, not
  suspended or removed accounts. Other roles cannot impersonate.

## Not done

Admins entering a reseller, a "return to my session" button (the actor signs
in again), per-reseller privilege to disable it.
