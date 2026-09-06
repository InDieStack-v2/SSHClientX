---

description: "Task list template for feature implementation"
---

# Tasks: Local-Only Mode (Remove Accounts & Backend API)

**Input**: Design documents from `/specs/001-local-only-mode/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/tauri-command-contract.md, quickstart.md (all present)

**Tests**: Not explicitly requested in the spec. Each user story instead closes with its quickstart.md scenario as the independent-test task.

**Organization**: Tasks are grouped by user story to enable independent review and testing of each story's acceptance criteria.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (US1, US2, US3)
- Every task includes exact file path(s)

## ⚠️ Shippability note (read before executing)

Phases below are split by user story for **review clarity**, not for
**incremental deployment**. Phase 2 (Foundational) deletes every Rust
command that *all three* stories' frontends call, because
`src-tauri/src/cloud.rs` internally shares its network-exchange
functions (`sync_exchange`/`shared_sync_exchange`) between the
sign-in commands (US1) and the sync/share commands (US3) — they cannot
be safely split apart without a deeper call-graph audit than this plan
performed. **Do not ship Foundational + a subset of story phases as a
partial release**: after Phase 2, `ProfilePanel.tsx`/`InvitesSection.tsx`
(not touched until Phase 5) would still be present in the UI but would
error at runtime (IPC "command not found") since their commands are
already gone. Implement and ship Phases 1–6 together as one release.
The phase split still gives you a clean order to *write and review* the
diff in, and each story's quickstart scenario is still a valid
independent acceptance check to run once its phase lands.

## Path Conventions

Single project (Tauri 2 desktop/mobile app): Rust backend in
`src-tauri/src/`, React frontend in `src/`, docs at repo root and
`docs/seo/`.

---

## Phase 1: Setup

**Purpose**: Establish a clean baseline before any removal work starts.

- [X] T001 Verify the current baseline builds and tests pass: run `cargo build && cargo test` in `src-tauri/`, and `npm run typecheck && npm run build` at the repo root. Do not proceed until both are clean.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Remove the entire account/backend-API Rust surface. This
is one atomic unit of work — see the shippability note above for why
it isn't split further.

**⚠️ CRITICAL**: No user story frontend work can begin until this phase is complete.

- [X] T002 Grep `src-tauri/src/` for every call site of `get_or_create_dek`, `collect_local_records`, `apply_remote_records`, `build_pw_escrow_record`, `open_pw_escrow`, `cloud::sync_exchange`, and `cloud::shared_sync_exchange` to confirm the complete caller list before deleting anything (per `contracts/tauri-command-contract.md` § "Implementation-time verification required") — found `get_or_create_dek` also has a live caller in `setup_master_db_inner` (kept); the other four have zero callers outside the deleted commands/tests
- [X] T003 Delete `src-tauri/src/cloud.rs` in full
- [X] T004 Delete `src-tauri/src/identity.rs` in full
- [X] T005 Remove these 22 commands from `src-tauri/src/lib.rs`: `identity_status`, `setup_identity`, `reset_identity`, `share_current_profile`, `invite_to_share`, `list_shares`, `share_member_list`, `accept_share`, `share_set_role`, `share_revoke`, `share_leave`, `share_delete`, `profile_share_status`, `stop_sharing`, `cloud_list_sync_profiles`, `cloud_delete_profile`, `import_shared_profile`, `restore_personal_profile`, `force_push_profile`, `sync_now`, `profile_sync_stats`, `set_editor_label` — delete any helper confirmed exclusive to these by T002 (e.g. `rotate_share_dek`). Also deleted, discovered exclusive during this task: the `sync_engine_tests` test module, and helpers `collect_local_records`/`apply_remote_records`/`apply_remote_inner`/`apply_entity`/`apply_tombstone`/`build_pw_escrow_record`/`open_pw_escrow`/`encrypt_entity`/`decrypt_entity`/`json_to_sql`, structs `SyncRecord`/`Fk`/`EntitySpec`/`FkFixup`/`SyncReport`, const `ENTITIES`, and the now-orphaned `remove_profile_files` helper
- [X] T006 Remove the `mod cloud;` and `mod identity;` declarations and their command-registration entries (the `tauri::generate_handler!` list or equivalent) in `src-tauri/src/lib.rs` — also removed the `.setup(|app| { cloud::CloudState::new... })` block that managed cloud state at startup
- [X] T007 [P] Remove the `x25519-dalek` and `hkdf` dependencies from `src-tauri/Cargo.toml`
- [X] T008 [P] Remove `https://api.sinaxhpm.com` from the CSP `connect-src` in `src-tauri/tauri.conf.json`
- [X] T009 Run `cargo build && cargo test` in `src-tauri/` to confirm a clean compile with zero cloud/identity references, and that `sync_trigger_tests` still pass (the DB triggers themselves are kept — see `research.md` Decision 1 and 2). Result: clean build, 18/18 retained tests pass (24 tests removed: 7 from deleted `identity` module, 17 from deleted `sync_engine_tests`, which tested the now-removed sync-exchange logic)

**Checkpoint**: Rust backend no longer exposes any account/sync/share command. Frontend work can now begin — but see the shippability note; do not release yet.

---

## Phase 3: User Story 1 - Use the app with no account, ever (Priority: P1) 🎯

**Goal**: No sign-up, sign-in, magic-link, password-reset, or "connect to cloud" step exists anywhere in the app.

**Independent Test**: Disconnect the device from the network, launch the app, create a vault, add a server, and connect over SSH — everything succeeds with zero network activity to any account/sync host (spec.md User Story 1).

- [X] T010 [US1] Delete `src/components/CloudPanel.tsx`
- [X] T011 [US1] Rewrite `src/components/ProfileSelectPage.tsx`: remove the `CloudPanel` mount, `cloudStatus`, `cloudProfiles`, `Row.cloud`, `CloudBar`, the cloud branch of `StatusChip`, `bringDown`, `deleteFromCloud`, and the cloud half of `removeLocal`'s messaging — preserve the local create/import/export/delete/unlock flow exactly as-is
- [X] T012 [US1] In `src/DesktopApp.tsx`, remove the `cloud_status` lookup and the (now-deleted) `set_editor_label` call inside `handleProfileUnlocked`
- [X] T013 [US1] Run `npm run typecheck && npm run build` to confirm the frontend compiles clean with no references to deleted cloud commands/components
- [ ] T014 [US1] Execute `quickstart.md` Scenario 1 (fresh install works fully offline, including the tunnel and folder-mirror steps) and Scenario 2 (no hidden network calls); confirm both pass. **Partially verified only**: `npm run tauri dev` was smoke-tested — clean build, binary launched and ran stably with no errors/panics (confirmed via `ps`), then was shut down. This environment has no display server or Tauri WebDriver, so the actual window could not be screenshotted or clicked through — the visual "no sign-in step" check and the network-disconnected/packet-capture parts of Scenarios 1–2 still need a human to run on a real device. Static verification (no matching `invoke()` calls anywhere in `src/`, backend commands deleted, CSP origin removed) strongly supports that these will pass, but that is not the same as having run them.

**Checkpoint**: No sign-up/sign-in surface exists anywhere; the app is fully usable offline from first launch. (Sharing/sync UI from Phase 5 still visible until that phase lands — see shippability note.)

---

## Phase 4: User Story 2 - Existing local vaults keep working (Priority: P2)

**Goal**: Local vault files created by prior versions — including ones previously cloud-linked or shared — open with zero data loss and no migration notice.

**Independent Test**: Open a vault file created by the pre-removal version in the updated app and confirm every entity (servers, credentials, folders, keys, commands, notes) is present and usable, with no cloud-linked status or migration banner shown (spec.md User Story 2).

- [X] T015 [US2] [P] Add a one-time cleanup on vault open in `src-tauri/src/lib.rs`: delete orphaned `sync_meta` rows keyed `share_id`/`share_role`/`share_name`/`dek`/`cloud_profile` (per `data-model.md` "Migration notes" — additive-safe row cleanup, no schema change). **Expanded during implementation**: discovered `create_profile` was still stamping fresh `profile_id`/`cloud_profile` rows on every new profile, and `setup_master_db_inner` was eagerly minting a `dek` row on every vault open — both pure cloud-sync/sharing partitioning logic with no other purpose, so they'd have kept writing dead rows going forward even after this cleanup. Removed both write paths, added `profile_id` to the cleanup's key list, and deleted the now-fully-unused `get_or_create_dek` helper. Verified: `cargo build && cargo test` clean, 18/18 tests pass.
- [ ] T016 [US2] Execute `quickstart.md` Scenario 3: copy a pre-removal, previously cloud-linked/shared vault file into the updated app, open it, and confirm full data retention, no cloud-linked UI (already true from T011), no migration notice anywhere (FR-012), and — with a leftover `cloud_token.json` planted and a packet capture running — that first launch makes no network call and simply ignores the file (FR-008). **Not run**: this needs an actual pre-removal-version vault file (this session did not have one available) and hands-on UI verification, neither of which is possible from this terminal-only environment. Code-level support is in place: `setup_master_db_inner` now runs a `DELETE FROM sync_meta WHERE key IN (...)` cleanup on every open (verified via `cargo test`, no schema change), and no code path reads `cloud_token.json` anymore since `cloud.rs` is deleted — but the actual scenario needs a human to run it against a real legacy vault file.

**Checkpoint**: Legacy vaults — including previously shared/cloud-linked ones — open silently and completely intact.

---

## Phase 5: User Story 3 - No leftover account/sharing surface (Priority: P3)

**Goal**: Zero remaining UI, settings, or documentation reference to accounts, cloud sign-in, multi-device sync, or profile sharing.

**Independent Test**: Walk every screen of the app and read the README; confirm nothing mentions signing in, cloud accounts, multi-device sync, or sharing/inviting (spec.md User Story 3).

- [X] T017 [US3] [P] Delete `src/components/ProfilePanel.tsx`
- [X] T018 [US3] [P] Delete `src/components/InvitesSection.tsx`
- [X] T019 [US3] [P] Delete `src/components/shareRoles.tsx`
- [X] T020 [US3] In `src/DesktopApp.tsx`: remove the `ProfilePanel` mount/tab, all 15 `bumpSync()` call sites, `handleCloudSync`, `quietSync`, `bumpSync`, the auto-sync interval effect, the `cloudSyncing`/`lastSyncLabel`/`autoSync`/`syncIntervalMin` state and their 2 `localStorage` keys, and the `Sidebar` `syncing` prop. **Expanded during implementation**: also removed the dead `profileRail`/"Profile" nav button from `src/components/Sidebar.tsx` (it only ever navigated to the now-deleted `ProfilePanel`) and the "Cloud Sync" auto-sync toggle section from `src/components/SettingsPanel.tsx` (not caught by earlier planning research — both are part of the same leftover surface US3 targets)
- [X] T021 [US3] [P] Rewrite `README.md`: remove/replace the TL;DR "encrypted profile sync" line, the "Zero-knowledge cloud sync" bullet and account-dashboard link, the full "End-to-End Encrypted Profile Sync" section and its FAQ entries, the Android section's cloud-sync claim, and the SEO keyword line (exact locations in `contracts/tauri-command-contract.md`)
- [X] T022 [US3] [P] Rewrite `docs/seo/faq.jsonld` and `docs/seo/software-application.jsonld` to remove the cloud-sync Q&A entries and the "zero-knowledge cloud"/"end-to-end encrypted profile sync" mentions in `featureList`/`description`
- [X] T023 [US3] Run `npm run typecheck && npm run build` to confirm a clean compile after all deletions (verified together with T013 — both passed clean, bundle shrank ~951.9kB → ~901.3kB)
- [ ] T024 [US3] Execute `quickstart.md` Scenario 4: walk every screen plus the README and confirm zero remaining references. **Partially verified only**: the repo-wide grep sweep (T026) is a strong proxy for "no remaining references" and found/fixed 6 additional leftovers beyond the plan, and the README was read in full and re-verified clean. The literal "walk every screen" visual check still needs a human, since this environment can't drive or screenshot the native window (see T014's note).

**Checkpoint**: All three user stories are complete — the app has no account/cloud/sharing surface left anywhere, in code or docs.

---

## Phase 6: Polish & Cross-Cutting Concerns

- [X] T025 [P] Run the full `cargo test` suite in `src-tauri/` once more after all phases land, confirming zero regressions — 18/18 pass, `npm run typecheck && npm run build` also clean
- [X] T026 [P] Grep the whole repo (`src/`, `src-tauri/src/`, `README.md`, `docs/`) for residual case-insensitive matches of "cloud", "account", "sign in", "sign up", "share" outside legitimate matches (folder-mirror "sync", tunnel/port-forward code, unrelated identifiers) to catch anything missed. **Found and fixed 6 additional leftovers** beyond the planned file list: `src/components/SettingsPanel.tsx` ("don't sync with your cloud profile" copy), `docs/screenshots/README.md` (a `sync.png` cloud-sync screenshot requirement), `src-tauri/src/lib.rs` (3 stale comments referencing the removed `restore_personal_profile`/cloud token/cloud record store — one of which exposed genuinely dead code: `enforce_strength` was always `true` once its only other caller was gone, so the parameter and its dead branch were removed too), and `AGENTS.md` (agent-guidance doc had 9 stale references treating `CLOUD_API_BASE`, the CSP cloud origin, `CloudState`, and the deleted `sync_engine_tests`/`identity::tests` modules as permanent facts — rewritten to match current state)
- [X] T027 Run `/speckit-constitution` to redefine Principle I (drop the cloud-sync/account-auth clauses) and update the Technology & Architecture Constraints section (`CLOUD_API_BASE`, the CSP origin, the "Sync:" bullet and its synced-table/DEK-sealing rules) per `research.md` Decision 9. Done — constitution bumped 1.0.2 → 2.0.0 (MAJOR, redefines NON-NEGOTIABLE Principle I). Also fixed 2 more stale mentions the amendment surfaced: Principle III's "same vault format, SSH stack, and sync protocol" (dropped "and sync protocol") and Principle V's module list (dropped `cloud`, `identity`). Added an explicit new NON-NEGOTIABLE clause to Principle I barring reintroduction of any backend/account/sync dependency without a future amendment.

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — start immediately.
- **Foundational (Phase 2)**: Depends on Setup. **Blocks all user stories.**
- **User Story 1 (Phase 3)**: Depends on Foundational only.
- **User Story 2 (Phase 4)**: Depends on Foundational only; T016's quickstart scenario is more convincing once T011 (US1) has already removed the cloud-linked UI, so run Phase 4 after Phase 3 even though there's no hard code dependency.
- **User Story 3 (Phase 5)**: Depends on Foundational only; independent of Phase 3/4 content-wise.
- **Polish (Phase 6)**: Depends on Phases 3, 4, and 5 all being complete.

### Parallel Opportunities

- T007 and T008 (Phase 2) touch different files and can run in parallel.
- T017, T018, T019 (Phase 5, different files) can run in parallel; T021 and T022 (docs) can run in parallel with each other and with T017–T019.
- T025 and T026 (Phase 6) can run in parallel.
- Phases 3 and 5 touch different files for most of their tasks (only `DesktopApp.tsx` is edited in both, sequentially: T012 then T020) — a second implementer could start Phase 5's component deletions (T017–T019, T021, T022) while Phase 3 is still in review, as long as `DesktopApp.tsx` edits (T012, T020) stay sequential.

---

## Parallel Example: Phase 2 (Foundational)

```bash
Task: "Remove x25519-dalek and hkdf from src-tauri/Cargo.toml"
Task: "Remove https://api.sinaxhpm.com from CSP connect-src in src-tauri/tauri.conf.json"
```

## Parallel Example: Phase 5 (User Story 3)

```bash
Task: "Delete src/components/ProfilePanel.tsx"
Task: "Delete src/components/InvitesSection.tsx"
Task: "Delete src/components/shareRoles.tsx"
Task: "Rewrite README.md cloud-sync sections"
Task: "Rewrite docs/seo/faq.jsonld and docs/seo/software-application.jsonld"
```

---

## Implementation Strategy

Given the shippability note above, there is no safe partial-release
MVP for this feature — it is one atomic removal. The phase order below
is the recommended order to **write and review** the change in, not a
sequence of separately deployable increments:

1. Complete Phase 1 (Setup) and Phase 2 (Foundational) — this is the
   highest-risk part of the diff (deleting two Rust modules and 22
   commands) and should be reviewed on its own first.
2. Complete Phase 3 (US1) — validate with its quickstart scenarios.
3. Complete Phase 4 (US2) — validate with its quickstart scenario.
4. Complete Phase 5 (US3) — validate with its quickstart scenario.
5. Complete Phase 6 (Polish), **including T027's constitution
   amendment**, then release Phases 1–6 together as a single
   build/version. Do not tag the release before T027 lands.

---

## Notes

- [P] tasks touch different files with no ordering dependency on each other.
- [Story] labels map each task to the spec.md user story it satisfies.
- Commit after each task or logical group.
- Re-run the relevant quickstart.md scenario at the end of each story's phase, not just once at the very end.
- Do not release after Phase 2 or Phase 3 alone — see the shippability note at the top of this file.
