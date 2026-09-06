# Data Model: Local-Only Mode (Remove Accounts & Backend API)

This feature removes application-level concepts and their read/write
code paths; it does not add or drop any database schema (see
[research.md](research.md) Decision 1). "Data model" here means what
each entity is *after* the change.

## Entities removed (no schema drop — see Migration Notes)

- **Account** — was an email + bearer-token identity persisted in
  `cloud_token.json` under the app-data directory, used to sign in and
  link a vault to the backend. After this change it does not exist;
  the file, if left over from a prior version, is simply never read
  again.
- **Profile Share / Invite** — was the mechanism for granting another
  account owner/editor/viewer access to a shared profile, represented
  as rows in `sync_meta` keyed by `share_id` / `share_role` /
  `share_name` / `dek` / `cloud_profile`. After this change no new rows
  of this shape are ever written or read; the concept no longer exists
  in the product.
- **Cloud Sync Session** — was the push/pull exchange between a device
  and the backend, ordered by HLC-stamped `updated_at` values. After
  this change it does not exist; there is no code path that contacts a
  backend to exchange records.

## Entities unchanged

- **Local Vault Profile** — the single, on-device, password-protected
  container for a user's data (magic `OMNV`, versioned header,
  `.sshclientx`/legacy `.submarine`). No schema or crypto change. It is
  now the *only* storage tier the product has.
- **Server, Credential, SSH Key, Folder, Command, Note, Monitor
  Config** — all fields unchanged. Each still carries its sync-only
  columns (`uuid`, `updated_at`, `deleted`, `edited_by`), which remain
  in the schema but are no longer read for any network purpose:
  - `uuid`, `updated_at`, `deleted` continue to be written by the
    existing DB triggers (harmless local bookkeeping; removing the
    triggers would be a riskier change than leaving them, per
    research.md Decision 1).
  - `edited_by` becomes permanently unset going forward — its only
    writer, `set_editor_label`, is removed (research.md Decision 3),
    since attributing an edit to a cloud account no longer means
    anything.
- **Known Hosts, Command History, Monitor Settings, Schema Meta** —
  already device-local, never synced; fully unaffected.

## Schema version

Current `SCHEMA_VERSION = 6`. This feature does not bump it: no column
is added or dropped, only application code stops reading/writing
certain existing columns/tables for a network purpose. If
implementation chooses to also delete orphaned `sync_meta` rows
(leftover `share_*`/`dek`/`cloud_profile` keys) as a one-time cleanup
on vault open, that is a row-level `DELETE`, not a schema change, and
needs no version bump — tasks.md decides whether that cleanup is worth
doing versus leaving the rows as further inert data.

## State transition: existing vault, opened after the update

1. Vault opens exactly as before (same header/crypto path; both
   `.sshclientx` and legacy `.submarine` extensions still read).
2. No `cloud_status` check occurs (command removed) → no cloud UI ever
   renders, silently (per FR-012).
3. Any `sync_meta` rows left over from prior sharing/cloud-linking
   remain on disk, unread and unused — a harmless leftover consistent
   with FR-010/FR-011 ("sharing simply ends" / cloud-only data loss is
   accepted; nothing is actively migrated).

## Migration notes

- No `ALTER TABLE` is required by this feature.
- No data migration/export tool is built (per FR-010/FR-011 and the
  Assumptions in spec.md).
- The only optional cleanup is the orphaned-`sync_meta`-row deletion
  mentioned above, which is additive-safe and reversible-by-absence
  (deleting rows that are already unused cannot corrupt anything readable).
