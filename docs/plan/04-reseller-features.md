# 04 — Reseller Features

A reseller is a hosting account that can also create and manage its own
customer accounts, within limits set by the admin. Every reseller action
is limited to accounts they own, and by the privilege list (`ADM-RSL-03`).
A reseller also has a normal user account for their own sites (all `USR-*`
features apply).

## RSL-ACC — Customer accounts
- **RSL-ACC-01** Create account (from the reseller's own packages, inside their quota of accounts/disk/bandwidth) `(P2)`
- **RSL-ACC-02** List and search own accounts with usage (disk, bandwidth, domains, mail, DBs) `(P2)`
- **RSL-ACC-03** Modify account: package, contact, password, primary domain `(P2)`
- **RSL-ACC-04** Suspend and unsuspend with reason; terminate (if privilege allows) `(P2)`
- **RSL-ACC-05** Login as one of their users (impersonation, audited) `(P2)`
- **RSL-ACC-06** Force password change; reset 2FA for a user `(P2)`
- **RSL-ACC-07** Bulk actions: change package, suspend, unsuspend, message `(P3)`
- **RSL-ACC-08** Over-quota / over-bandwidth lists for their accounts `(P2)`
- **RSL-ACC-09** Welcome message template for new accounts (with variables) `(P2)`

## RSL-PKG — Packages
- **RSL-PKG-01** Create, edit, clone, and delete own packages, within the reseller's own limits and the features allowed by the admin `(P2)`
- **RSL-PKG-02** Own feature lists (only a subset of the admin-allowed features) `(P3)`

## RSL-USE — Usage and limits
- **RSL-USE-01** Reseller dashboard: allocated vs used accounts, disk, bandwidth, domains (overselling shown clearly) `(P2)`
- **RSL-USE-02** Bandwidth and disk history per customer `(P3)`

## RSL-DNS — DNS and nameservers
- **RSL-DNS-01** Edit DNS zones of their customers' domains (if privilege allows) `(P2)`
- **RSL-DNS-02** Private (branded) nameservers `ns1.resellerbrand.com` `(P3)`
- **RSL-DNS-03** Own zone template override (default records for their new accounts) `(P3)`

## RSL-IP — IPs
- **RSL-IP-01** See IPs delegated to them; assign a delegated dedicated IP to a customer `(P2)`
- **RSL-IP-02** Choose their main shared IP from the delegated pool `(P3)`

## RSL-UI — Branding
- **RSL-UI-01** Own branding for their customers: logo, colours, product name, panel URL (custom hostname with auto SSL), login page, support links `(P3)`
- **RSL-UI-02** Own email templates for notices to their customers `(P3)`
- **RSL-UI-03** Message all their customers (email + dashboard notice) `(P2)`
- **RSL-UI-04** Own skeleton directory (default files for new accounts) `(P3)`

## RSL-BAK — Backups
- **RSL-BAK-01** Schedule backups of their customers' accounts to the reseller's own remote destination `(P3)`
- **RSL-BAK-02** Restore customer accounts from those backups `(P3)`

## RSL-DEV — Integration
- **RSL-DEV-01** API tokens (limited to the reseller's scope) for billing systems `(P2)`
- **RSL-DEV-02** Webhooks for events in their accounts (created, suspended, quota reached) `(P4)`

## RSL-SUP — Support
- **RSL-SUP-01** Ticket / message inbox from their customers; escalate to admin `(P4)`

## Rules the code must enforce
1. A reseller can never see or touch accounts, IPs, packages, or zones of
   another reseller or of the admin.
2. If overselling is **off**, the sum of package limits of all their accounts
   must stay ≤ the reseller limits. If it is **on**, only actual usage is checked.
3. A reseller package cannot give a feature the reseller does not have.
4. Suspending a reseller (by the admin) suspends all their accounts. Unsuspend
   restores only the accounts that were not suspended separately before.
5. Deleting a reseller requires choosing: delete all their accounts, or move
   them to another owner.
