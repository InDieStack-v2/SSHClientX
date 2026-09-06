# Research: Local-Only Mode (Remove Accounts & Backend API)

Each decision resolves one "how do we do this without breaking the
constitution or existing data" question raised by the Technical
Context. No NEEDS CLARIFICATION markers remain.

## Decision 1: Sync-only DB columns/tables become dormant, not dropped

- **Decision**: Do not `DROP` the sync-only columns (`uuid`, `updated_at`,
  `deleted`, `edited_by`) on `servers`/`credentials`/`folders`/`ssh_keys`/
  `commands`/`notes`/`monitor_configs`, and do not drop the
  `sync_tombstones`/`sync_flags`/`sync_meta` tables. Stop writing
  cloud-only keys into `sync_meta` (`share_id`, `share_role`, `share_name`,
  `dek`, `cloud_profile`) and stop invoking any command that pushes/pulls
  to a backend. Leave the existing DB triggers that populate `uuid`/
  `updated_at`/`deleted` in place.
- **Rationale**: `schema_meta.schema_version` (currently `6`) has only
  ever moved forward via additive `ALTER TABLE … ADD COLUMN` — there is
  no DROP-COLUMN precedent anywhere in the migration code, and the
  constitution requires readers to keep older versions readable when a
  writer bumps the format. A destructive schema change here is the
  highest-risk way to satisfy FR-007 (no data loss); making the fields
  inert is lower-risk and sufficient.
- **Alternatives considered**: Write a migration to drop the columns/
  tables — rejected as unprecedented and riskier with no functional
  upside (the dormant columns cost nothing at rest).

## Decision 2: `hlc.rs` stays unchanged

- **Decision**: Keep `src-tauri/src/hlc.rs` as-is.
- **Rationale**: It generates the monotonic `updated_at` stamps written
  by the (retained, per Decision 1) DB triggers. It has no network or
  account dependency — it is pure local ordering logic, not part of the
  account/backend surface this feature removes.
- **Alternatives considered**: Replace HLC stamps with a plain system
  timestamp — rejected as unnecessary churn; HLC is not coupled to the
  removed cloud/identity code and touching it would be pure scope creep.

## Decision 3: `cloud.rs` and `identity.rs` are deleted; sync-orchestration commands in `lib.rs` are deleted

- **Decision**: Delete `src-tauri/src/cloud.rs` and
  `src-tauri/src/identity.rs` in full, and delete the 32
  `#[tauri::command]`s enumerated in `contracts/tauri-command-contract.md`
  under "Removed commands."
- **Rationale**: This is the entire account/backend-API surface named
  by FR-001–FR-005. The inventory found no local-only logic embedded in
  any of these commands that needs to survive, except the *local vault
  creation* boilerplate inside `import_shared_profile` and
  `restore_personal_profile` — and that boilerplate (`setup_master_db_inner`)
  is a shared helper already called by the plain `create_profile` path,
  so nothing is lost by deleting these two commands wholesale.
- **Alternatives considered**: Feature-flag/`cfg`-gate the cloud code
  instead of deleting it — rejected. The constitution's YAGNI guidance
  ("complexity requires a concrete current use") and User Story 3's
  requirement that the surface be *removed*, not hidden, both rule out
  a flag.
- **Follow-up for implementation**: Before deleting
  `get_or_create_dek`, `collect_local_records`, `apply_remote_records`,
  `build_pw_escrow_record`, `open_pw_escrow`, confirm none of them is
  called from a non-sync code path; if any is, keep it (or inline the
  part still needed) instead of deleting.

## Decision 4: `x25519-dalek` and `hkdf` removed from `Cargo.toml`; `reqwest` stays

- **Decision**: Remove the `x25519-dalek` and `hkdf` crate dependencies
  (used only by `identity.rs`). Keep `reqwest` — `about.rs::check_for_updates`
  (an unrelated, pre-existing GitHub release check) still depends on it.
- **Rationale**: Removes dependencies whose only reason to exist
  disappears with `identity.rs`, without touching a dependency still
  serving an unrelated, in-scope feature.

## Decision 5: CSP `connect-src` drops the backend origin

- **Decision**: Remove `https://api.sinaxhpm.com` from `tauri.conf.json`'s
  CSP `connect-src`.
- **Rationale**: FR-003/FR-004 require zero calls to any account/sync
  backend; leaving an allow-listed origin for a backend the app no
  longer calls would read as a leftover during a security audit and
  contradicts User Story 3 / SC-005. This also resolves a pre-existing
  inconsistency: the CSP origin (`api.sinaxhpm.com`) never actually
  matched the Rust-side hardcoded `CLOUD_API_BASE`
  (`https://submarine.sinaxhpm.com`) — both disappear together.
- **Alternatives considered**: Leave CSP unchanged since the webview
  never calls the backend directly anyway (the HTTP calls are made from
  Rust, and no `http:*`/fetch capability is even declared) — rejected
  for the audit-cleanliness reason above.

## Decision 6: Frontend — delete 4 components, surgically rewrite 1

- **Decision**: Delete `src/components/CloudPanel.tsx`,
  `ProfilePanel.tsx`, `InvitesSection.tsx`, `shareRoles.tsx` in full.
  Rewrite `ProfileSelectPage.tsx` to remove every cloud-branch
  state/prop/UI element (`cloudStatus`, `cloudProfiles`, `Row.cloud`,
  `CloudBar`, the cloud branch of `StatusChip`, `bringDown`,
  `deleteFromCloud`, the cloud half of `removeLocal`'s messaging) while
  preserving its local create/import/export/delete/unlock flow exactly
  as-is. In `DesktopApp.tsx`, remove the `ProfilePanel` mount/tab, all
  15 `bumpSync()` call sites, `handleCloudSync`/`quietSync`/`bumpSync`/
  the auto-sync interval effect, the `cloudSyncing`/`lastSyncLabel`/
  `autoSync`/`syncIntervalMin` state and their 2 `localStorage` keys,
  the `Sidebar` `syncing` prop, and the `cloud_status` lookup inside
  `handleProfileUnlocked`. Keep `handleLogout` (local profile-lock)
  unchanged — it is unrelated to cloud sign-out.
- **Rationale**: Matches the exact dependency graph found in the
  frontend inventory; no other file references these symbols.

## Decision 7: `check_for_updates` (GitHub release check) is out of scope

- **Decision**: Leave `about.rs::check_for_updates` and its
  `ProfileSelectPage`-mount-time call untouched.
- **Rationale**: It calls `api.github.com`, not the account/sync
  backend, and predates this feature. FR-003/FR-004/SC-003 are
  explicitly scoped to "account or sync backend" traffic, which this
  satisfies as written.
- **Note**: User Story 1's Independent Test phrase "zero network
  activity other than the SSH connection itself" reads more broadly
  than the FRs/SCs and would, read literally, fail against this
  pre-existing call. This is a spec-wording nuance, not a functional
  gap, and is recorded here rather than silently reconciled; no code
  change follows from it, and no other requirement depends on the
  broader reading.

## Decision 8: Transition UX is silent (already decided in Clarifications)

- **Decision**: No migration/notice screen is added anywhere.
  `cloud_token.json`, if left over from a prior version, is simply
  never read again once the cloud commands are deleted; implementation
  MAY delete the file opportunistically as harmless cleanup but does
  not need to.
- **Rationale**: Matches FR-008/FR-012 and the user's resolved
  clarification (silent transition, no in-app notice).

## Decision 9: Constitution amendment is a required follow-up, tracked outside this plan

- **Decision**: This plan does not edit
  `.specify/memory/constitution.md`. A separate `/speckit-constitution`
  pass is recommended to redefine Principle I (drop the cloud-sync- and
  account-auth-specific clauses that no longer describe anything real)
  and update the Technology & Architecture Constraints section
  (`CLOUD_API_BASE`, the CSP origin, the sync table list) to stop
  describing cloud sync as a current feature.
- **Rationale**: The constitution's own Governance section treats
  "adding a network origin" as a constitution-level change requiring
  Governance, not a silent code edit; removing one, and redefining a
  NON-NEGOTIABLE principle's text, is the same kind of change and
  should go through the same process (and, per the constitution's own
  versioning rule, redefining a principle is a MAJOR bump).
- **Alternatives considered**: Leave the constitution as-is — rejected,
  it would then describe cloud-sync rules for a feature that no longer
  exists, misleading future readers/agents.
