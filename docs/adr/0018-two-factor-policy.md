# ADR-0018: Two-factor sign-in policy

- Status: accepted
- Date: 2026-11-04
- Amends: 03-admin-features (ADM-SEC-08)

## Context

TOTP exists per login (ADR on auth). Admins need to require it for whole
roles, without a flag day that locks people out.

## Decision

- Global setting `auth.require_2fa`: `none` (default), `admins`, `resellers`
  (admins and resellers) or `all`. It is in the settings catalogue
  (ADR-0016), audited like any setting, and applies at once
  (`auth.Service.SetMFAPolicy`, also at start).
- A login that the policy covers and that has no 2FA can sign in, but every
  route except `/me`, `/me/password`, `/me/2fa/setup` and `/me/2fa/confirm`
  answers 403 `mfa_required`. `/me` reports `mfa_enrollment_required`; the
  web app sends the person to the security page with an explanation, where
  the QR code and recovery codes are shown as always.
- Nothing is revoked when the policy is turned on or off; disabling 2FA is
  still possible when the policy is off, and when it is on the person is sent
  back to set it up again.

## Consequences

- An admin who turns the policy on for admins is asked to set up 2FA at the
  next request: do that first. Recovery by the CLI (`xcpctl`) is unchanged.
- Passkeys (P2) will satisfy the policy when they exist.
