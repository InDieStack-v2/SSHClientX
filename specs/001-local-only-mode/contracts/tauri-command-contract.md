# Contract: Tauri IPC Command Surface Changes

This app's only "external interface" is the Tauri IPC boundary between
the Rust backend and the React frontend (`invoke('command_name', …)`).
This document is the contract for what changes on that boundary.

## Removed commands (32 total)

None of these may remain reachable from the frontend after this
feature ships. Deleting the frontend's call sites (see "Frontend
contract changes" below) without deleting the Rust command, or vice
versa, is an incomplete implementation.

**`cloud.rs` (module deleted, 10 commands):**
`cloud_status`, `cloud_signup`, `cloud_consume_verify_link`,
`cloud_set_password`, `cloud_login`, `cloud_logout`,
`cloud_request_password_reset`, `cloud_reset_password`,
`cloud_request_login_link`, `cloud_login_with_link`

**`lib.rs` — identity / sharing (16 commands):**
`identity_status`, `setup_identity`, `reset_identity`,
`share_current_profile`, `invite_to_share`, `list_shares`,
`share_member_list`, `accept_share`, `share_set_role`, `share_revoke`,
`share_leave`, `share_delete`, `profile_share_status`, `stop_sharing`,
`cloud_list_sync_profiles`, `cloud_delete_profile`

**`lib.rs` — sync orchestration / mixed local+cloud (6 commands):**
`import_shared_profile`, `restore_personal_profile`,
`force_push_profile`, `sync_now`, `profile_sync_stats`,
`set_editor_label`

> `import_shared_profile` and `restore_personal_profile` each contain a
> local-vault-creation step (`setup_master_db_inner`) alongside their
> cloud logic. That helper is shared with the plain `create_profile`
> path and MUST be kept; only these two commands themselves are
> removed, not the helper.

## Preserved commands (interface unchanged)

Every other command is untouched: `list_profiles`, `select_profile`,
`close_profile`, `delete_profile`, `export_profile`,
`import_profile_pick`, `import_profile_save`, `check_db_exists`,
`setup_master_db`/`setup_master_db_inner`, `create_profile`, and the
full set of server/credential/key/folder/command/note/tunnel/SFTP/
terminal/monitor commands (~100 commands, unaffected).

`about.rs::check_for_updates` is also unaffected (out of scope — see
research.md Decision 7).

## Implementation-time verification required

Before deleting these Rust-side helper functions, confirm no
non-sync caller remains: `get_or_create_dek`, `collect_local_records`,
`apply_remote_records`, `build_pw_escrow_record`, `open_pw_escrow`. If
any is still called from a preserved command, keep it (or keep only
the still-used portion).

## Frontend contract changes

- **Files deleted**: `src/components/CloudPanel.tsx`,
  `src/components/ProfilePanel.tsx`,
  `src/components/InvitesSection.tsx`, `src/components/shareRoles.tsx`.
- **File rewritten (not deleted)**: `src/components/ProfileSelectPage.tsx`
  — remove `cloudStatus`, `cloudProfiles`, `Row.cloud`, `CloudBar`, the
  cloud branch of `StatusChip`, `bringDown`, `deleteFromCloud`, and the
  cloud half of `removeLocal`'s messaging. Preserve the local
  create/import/export/delete/unlock flow unchanged.
- **`src/DesktopApp.tsx` changes**: remove the `ProfilePanel`
  mount/tab; remove all 15 `bumpSync()` call sites; remove
  `handleCloudSync`, `quietSync`, `bumpSync`, and the auto-sync
  interval effect; remove `cloudSyncing`, `lastSyncLabel`, `autoSync`,
  `syncIntervalMin` state and their 2 `localStorage` keys; remove the
  `Sidebar` `syncing` prop; remove the `cloud_status` lookup inside
  `handleProfileUnlocked`. Keep `handleLogout` (local profile-lock)
  unchanged.
- **Props removed with their owning components**: `ProfilePanel`'s
  `onSync`/`syncing`/`lastSyncLabel`/`autoSync`/`syncIntervalMin`/
  `onSetInterval`/`onToggleAutoSync` (moot — component deleted).

## Config/asset contract changes

- **`src-tauri/tauri.conf.json`**: remove `https://api.sinaxhpm.com`
  from CSP `connect-src`.
- **`src-tauri/Cargo.toml`**: remove `x25519-dalek`, `hkdf`. Keep
  `reqwest` (still used by `about.rs::check_for_updates`).
- **`README.md`**: remove/rewrite every cloud-sync/account-dashboard
  claim (TL;DR bullet, the "Zero-knowledge cloud sync" bullet + link,
  the full "End-to-End Encrypted Profile Sync" section and its FAQ
  entries, the Android section's cloud-sync claim, the SEO keyword
  line).
- **`docs/seo/faq.jsonld`** and **`docs/seo/software-application.jsonld`**:
  remove the cloud-sync Q&A entries and the "end-to-end encrypted
  profile sync" / "zero-knowledge cloud" mentions in `featureList` and
  `description`.
