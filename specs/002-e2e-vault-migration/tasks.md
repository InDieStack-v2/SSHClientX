---

description: "Task list for End-to-End Encrypted Vault Migration"
---

# Tasks: End-to-End Encrypted Vault Migration

**Input**: Design documents from `/specs/002-e2e-vault-migration/`

**Prerequisites**: [plan.md](plan.md), [spec.md](spec.md), [research.md](research.md),
[data-model.md](data-model.md), [contracts/](contracts/)

**Tests**: Included, and **not optional here**. Constitution v3.1.0's Development Workflow
requires that "Rust changes that touch vault, sync, path guards, or host-key handling MUST
include or update module tests in the same crate." This is the largest vault change the
project has had. Tests follow the repo's existing convention — in-file `#[cfg(test)]` modules
(see `hlc.rs:118`, `lib.rs:638`), not a separate `tests/` tree.

**Organization**: Grouped by user story. Note the caveat in Implementation Strategy — User
Story 1 absorbed every clarification round, so it is not a small MVP.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependency on incomplete work)
- **[Story]**: US1–US4 from spec.md; Setup, Foundational, and Polish carry no story label
- **T120–T122** were added by `/speckit-analyze` remediation and sit in execution position, not ID order. Existing IDs were left stable so the Dependencies section and any external references stay valid.

## Path Conventions

Tauri 2 single repository. Rust core in `src-tauri/src/`, React renderer in `src/`. Paths
below are repository-relative and exact.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Dependencies and module scaffolding. Nothing here changes behaviour.

- [X] T001 Bump `rust-version` from `1.85` to `1.89` in `src-tauri/Cargo.toml` and replace the comment attributing the floor to russh 0.63 — the floor is now the secure-store binding (1.88) and `std::fs::File::try_lock` (1.89), per research.md Decision 13
- [X] T002 Add `keyring = "4.2"`, `chacha20poly1305 = "0.10"`, `bip39 = "2.2"`, `robius-authentication = "0.3.1"` to `[dependencies]` in `src-tauri/Cargo.toml`, each with a comment naming its constitution v3.1.0 table row
- [X] T003 Add `secret-service = { version = "5", default-features = false }` and `x11rb = { version = "0.14", features = ["screensaver"] }` under a Linux-only target block in `src-tauri/Cargo.toml` — `default-features = false` on secret-service is mandatory, see research.md Decision 8
- [X] T004 Create empty `src-tauri/src/vault.rs`, `keystore.rs`, `platform_auth.rs`, `lock.rs`, `recovery.rs` and declare all five `mod`s in `src-tauri/src/lib.rs`
- [X] T005 [P] Add `opt-level = 3` dev-profile entries for `chacha20poly1305`, `keyring` and `bip39` in `src-tauri/Cargo.toml`, matching the existing argon2/aes-gcm blocks so `tauri dev` unlock stays usable
- [X] T006 Verify no OpenSSL entered the tree: `cargo tree --manifest-path src-tauri/Cargo.toml -i openssl-sys` must find nothing, and confirm `cargo build` still needs no Perl

**Checkpoint**: Builds clean, no behaviour change, no new native dependency.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: The sealed container, the secure store, and the one verification pipeline.

**⚠️ CRITICAL**: No user story can begin until this phase is complete. Every story reads or
writes the container, and every story that touches a key goes through the keystore.

### Sealed container

- [X] T007 [P] Define the outcome-code enum (`BOX_*`, `VAULT_*`, `KIT_*`) with user-facing messages in `src-tauri/src/vault.rs`, exactly as listed in `contracts/sealed-container.md` §5 — each variant distinct, none collapsed (FR-036)
- [X] T008 Move `derive_key`, `encrypt_with_key`, `decrypt_with_key`, `vault_compress`, `vault_decompress` from `src-tauri/src/lib.rs:163-260` into `src-tauri/src/vault.rs` unchanged, updating call sites
- [X] T009 Make `encrypt_with_key`/`decrypt_with_key` in `src-tauri/src/vault.rs` generic over the `aead` 0.5 `Aead` trait so both `Aes256Gcm` and `XChaCha20Poly1305` work, and take associated data via `aead::Payload`
- [X] T010 Implement `kid` derivation (16 bytes from the DEK) in `src-tauri/src/vault.rs` per data-model.md §2.2
- [X] T120 [P] Generate and persist a random per-device `sender_id` (16 bytes) in `src-tauri/src/vault.rs`, stored device-locally like the existing sync node id in `lib.rs:366` — it MUST NOT derive from a hardware serial or anything surviving a reinstall (FR-011)
- [X] T011 Implement the `SSHCLTX1` writer in `src-tauri/src/vault.rs` per `contracts/sealed-container.md` §1, including the AAD of §1.1 and the trailing SHA-256 over all preceding bytes
- [X] T012 Implement the `SSHCLTX1` reader in `src-tauri/src/vault.rs` with declared-length self-consistency checks (no trailing slack, `sender_name_len` ≤ 255, valid UTF-8) returning `BOX_CORRUPT` on violation
- [X] T013 Implement format discrimination in `src-tauri/src/vault.rs` per `contracts/sealed-container.md` §2 — 8-byte `SSHCLTX1`, then 4-byte `OMNV`, else `BOX_BAD_MAGIC`
- [X] T014 Replace the fixed `NONCE_LEN` constant in `src-tauri/src/lib.rs:42` with a nonce length derived from the container's `alg` byte (24 for XChaCha20-Poly1305, 12 for AES-256-GCM) — research.md Decision 9 flags this as the real migration hazard, not the cipher swap
- [X] T015 [P] Add `#[cfg(test)]` tests in `src-tauri/src/vault.rs`: container round-trip; single-byte flip anywhere yields `BOX_CORRUPT`; truncation yields `BOX_CORRUPT`; altering `kid` or `generation` breaks the AEAD via AAD binding
- [X] T016 [P] Add `#[cfg(test)]` tests in `src-tauri/src/vault.rs` proving `OMNV` and `SSHCLTX1` bytes are discriminated correctly and that a legacy blob still decrypts through the old path

### Secure store

- [X] T017 [P] Implement the keystore wrapper in `src-tauri/src/keystore.rs` over `keyring::Entry`, with every call routed through `tokio::task::spawn_blocking` — Secret Service unlock prompts block the calling thread (research.md risk table)
- [X] T018 Implement error mapping in `src-tauri/src/keystore.rs` separating `VAULT_NO_KEYSTORE` from `VAULT_KEYSTORE_DENIED`, using the `secret_service::Error` downcast on Linux — needs both the `Unavailable` arm and the `MethodError(ServiceUnknown | NameHasNoOwner)` arm, per research.md Decision 5. Include a catch-all: `keyring_core::Error` is `#[non_exhaustive]`
- [X] T019 Handle `keyring_core::Error::Ambiguous` explicitly in `src-tauri/src/keystore.rs` rather than as a generic failure — multiple Secret Service items matching one attribute set is reachable if an earlier build wrote a different schema
- [X] T020 [P] Add `#[cfg(test)]` tests in `src-tauri/src/keystore.rs` covering the error-classification function against constructed error values for each arm, including the unknown/catch-all case

### Verification pipeline

- [X] T021 Implement `verify_and_import(bytes) -> Result` in `src-tauri/src/vault.rs` running the eight checks of `contracts/sealed-container.md` §3 **in order**, returning on first failure
- [X] T022 Implement disposition resolution in `src-tauri/src/vault.rs` — match `kid` against every key the device holds, then return `CreateProfile` (unclaimed key), `RestoreOver(profile)` (owned key), or `NoOp` (FR-031, FR-032, FR-032a)
- [X] T023 [P] Add `#[cfg(test)]` tests in `src-tauri/src/vault.rs` proving check ordering: a file with a foreign `kid` is **never** decrypted, and a truncated file reports `BOX_CORRUPT` rather than an auth failure

**Checkpoint**: Container reads and writes, keystore classifies its two failure kinds, one
verification pipeline exists. User story work can begin.

---

## Phase 3: User Story 1 — Vault stops being a portable password-locked file (Priority: P1) 🎯 MVP

**Goal**: The sealing key becomes device-bound. Existing vaults migrate, a copied file opens
nowhere, and the lock lifecycle, writer claim, and rollback detection that protect it all work.

**Independent Test**: Migrate a pre-feature profile with real content; confirm everything is
intact; copy the file to a second machine and confirm it is refused by name, not by a generic
wrong-password error. Full procedure: [quickstart.md](quickstart.md) §2–§3.

### 3a — Key model and sealing

- [X] T024 [US1] Implement DEK generation (32 CSPRNG bytes) and storage via `src-tauri/src/keystore.rs`, marked this-device-only, in `src-tauri/src/vault.rs` (FR-001, FR-002)
- [X] T025 [US1] Implement the two-of-two wrap in `src-tauri/src/vault.rs`: `K_combined = SHA-256(K_device ‖ Argon2id(password, salt))`, then `dek.wrap = AEAD(K_combined, DEK)` stored in app private storage — research.md Decision 3
- [X] T026 [US1] Wire `save_vault_blocking` in `src-tauri/src/vault.rs` to seal with XChaCha20-Poly1305 (`alg = 1`), advance `generation` by exactly one, and keep the existing tmp → fsync → rename atomicity (FR-005)
- [X] T027 [US1] Implement the five-deep revision history in `src-tauri/src/vault.rs`, rotating on each successful save (FR-006)
- [X] T028 [US1] Update the three `save_vault_async` call sites in `src-tauri/src/lib.rs` for the new signature and key source
- [X] T029 [US1] Fail closed on `VAULT_NO_KEYSTORE` in create, migrate, and save paths in `src-tauri/src/vault.rs`; never write an unprotected key (FR-003)
- [X] T030 [US1] Make a denied or unavailable keystore request retryable in `src-tauri/src/vault.rs`, leaving pending changes intact in the session (FR-003a, FR-003b)
- [X] T031 [P] [US1] Add `#[cfg(test)]` tests in `src-tauri/src/vault.rs` proving neither factor alone unwraps the DEK — keystore value without password fails, password without keystore value fails (SC-011)
- [X] T032 [P] [US1] Add `#[cfg(test)]` tests in `src-tauri/src/vault.rs` proving `generation` advances by exactly one per save and that five revisions are retained

### 3b — Migration

- [X] T033 [US1] Implement legacy-to-sealed migration in `src-tauri/src/vault.rs`: re-seal under a new DEK, preserving all content, only after the password has decrypted the legacy vault (FR-013, FR-014)
- [X] T034 [US1] Verify the re-sealed vault opens before treating migration as complete, and retain the pre-migration file until acknowledged, in `src-tauri/src/vault.rs` (FR-015)
- [X] T035 [US1] Make migration crash-safe in `src-tauri/src/vault.rs` — at every interruption point either the legacy file or the sealed file is intact and openable, never neither
- [X] T036 [US1] Migrate `.submarine` legacy files by the same path and leave the result under `.sshclientx` in `src-tauri/src/vault.rs` (FR-016)
- [X] T037 [US1] Trigger migration from `setup_master_db_inner` in `src-tauri/src/lib.rs:1070` and return the `UnlockOutcome` of `contracts/tauri-command-contract.md` §1
- [X] T038 [US1] Implement `migration_notice_ack(name)` in `src-tauri/src/lib.rs` which **deletes** the pre-migration file (FR-015a) — a retained legacy file opens with the password alone on any machine and nullifies the feature
- [X] T039 [US1] Emit the `vault-migration-notice` event from `src-tauri/src/lib.rs` per `contracts/tauri-command-contract.md` §6 (FR-017)
- [X] T040 [P] [US1] Add `#[cfg(test)]` tests in `src-tauri/src/vault.rs`: wrong password attempts no migration and leaves the legacy file untouched; a migrated vault's content matches the legacy vault's exactly

### 3c — Rollback detection

- [X] T041 [US1] Store and read the revision high-water mark in the OS secure store beside the DEK via `src-tauri/src/keystore.rs` — never in the vault file or anywhere a file restore would revert it (FR-062, FR-063)
- [X] T042 [US1] Compare file revision against the high-water mark on open in `src-tauri/src/vault.rs` and return `VAULT_ROLLBACK` when lower (FR-064)
- [X] T043 [US1] Implement `rollback_resolve(name, choice)` in `src-tauri/src/lib.rs` — `AcceptOlder` resets the high-water mark so the warning stops, `RestoreNewer` restores from local history (FR-065)
- [X] T044 [P] [US1] Add `#[cfg(test)]` tests in `src-tauri/src/vault.rs` proving `VAULT_ROLLBACK` is distinct from `BOX_OLDER` and from `VAULT_CORRUPT`, and that acceptance stops the warning recurring

### 3d — Single writer

- [X] T045 [US1] Implement the writer claim in `src-tauri/src/vault.rs` using `std::fs::File::try_lock` on a `<name>.sshclientx.lock` sidecar — never the vault file itself, since atomic-rename-on-save replaces the inode and would orphan the lock (research.md Decision 11)
- [X] T046 [US1] Acquire the claim in `select_profile` and release it in `close_profile` in `src-tauri/src/lib.rs:781,798`; a lock must **not** release it (FR-059)
- [X] T047 [US1] Return `VAULT_BUSY` naming the profile when the claim is held, in `src-tauri/src/lib.rs` (FR-058)
- [X] T048 [US1] Refuse any revision advance or vault write without the claim, in `src-tauri/src/vault.rs` (FR-061)
- [X] T049 [P] [US1] Add `#[cfg(test)]` tests in `src-tauri/src/vault.rs` proving a second acquisition fails while the first guard lives and succeeds after it drops. Hold exactly one guard — std documents re-locking an already-held handle as possibly deadlocking

### 3e — Lock lifecycle

- [X] T050 [US1] Implement the three-state lock machine (`unlocked`, `locked_soft`, `locked_hard`) in `src-tauri/src/lock.rs` per data-model.md §2.10
- [X] T051 [US1] Drop the DEK from process memory on every lock in `src-tauri/src/lock.rs`, and delete the platform-auth-gated keystore entry on hard locks only (FR-043, FR-043a, FR-043b)
- [X] T052 [US1] Register `on_window_event` in `src-tauri/src/lib.rs` and map `WindowEvent::Focused(false)` to a soft lock — this is net-new; the Rust side has no window-event handling today
- [X] T053 [P] [US1] Implement macOS idle via `CGEventSource::seconds_since_last_event_type` and screen-lock/sleep via `NSDistributedNotificationCenter` (`com.apple.screenIsLocked`/`Unlocked`) plus `NSWorkspaceWillSleep`/`DidWake` in `src-tauri/src/lock.rs`, registered with `run_on_main_thread`. Use `CGEventSource`, not IOKit — it needs no Accessibility permission
- [X] T054 [P] [US1] Implement Windows idle via `GetLastInputInfo` + `GetTickCount` (clamping the 49.7-day wrap and negative deltas) and session/power events via a `HWND_MESSAGE` window with `WTSRegisterSessionNotification` in `src-tauri/src/lock.rs`. Define `WTS_SESSION_LOCK`/`UNLOCK` locally — windows-sys does not export them — and handle `WM_WTSSESSION_CHANGE`/`WM_POWERBROADCAST` **inside the WndProc**, since both are `SendMessage`-delivered and never reach the message queue
- [X] T055 [P] [US1] Implement Linux idle via `x11rb` `screensaver_query_info` on X11 and `ext-idle-notify-v1` on Wayland (edge-triggered — synthesise elapsed time), plus logind `PrepareForSleep`/`Session.Lock` over `zbus`, in `src-tauri/src/lock.rs`. Do not use `org.freedesktop.ScreenSaver.GetActiveTime`; it reports screensaver runtime, not idle time
- [X] T056 [US1] Implement the idle timeout in `src-tauri/src/lock.rs`, user-configurable 1–60 minutes, default 15, not disableable, rejecting out-of-range values rather than clamping (FR-045)
- [X] T057 [US1] Seal pending changes before dropping the key, or defer the lock until that save completes, in `src-tauri/src/lock.rs` — never a partial write (FR-047)
- [X] T058 [US1] Keep SSH sessions, tunnels, transfers, mirrors and monitors running across every lock in `src-tauri/src/lock.rs`; no teardown, no reconnect (FR-049, FR-050)
- [X] T059 [US1] Emit `vault-lock-state` and `vault-background-activity` events from `src-tauri/src/lock.rs` per `contracts/tauri-command-contract.md` §6, the latter carrying no hostname, path, or content (FR-051)
- [X] T060 [US1] Make operations that run while locked and need unheld vault content fail or wait, never prompting for unlock and never reading the key back into memory, in `src-tauri/src/lock.rs` (FR-052)
- [X] T061 [P] [US1] Add `#[cfg(test)]` tests in `src-tauri/src/lock.rs` for the state-transition table of data-model.md §2.10, including that a soft lock followed by an idle timeout reaches `locked_hard`

### 3f — Unlock and identity confirmation

- [X] T062 [US1] Implement platform authentication in `src-tauri/src/platform_auth.rs` via `robius-authentication`, bridging its callback API to async with a `tokio::sync::oneshot`
- [X] T063 [US1] `#[cfg]` the platform-auth path out entirely on Linux in `src-tauri/src/platform_auth.rs` and always fall back to the password there (FR-056) — polkit needs a root-installed policy file and a running agent, and answers the wrong question
- [X] T064 [US1] Treat macOS `LAError -1004` (not interactive/foreground) and the first-call-after-login timeout as **retryable**, not as auth failure, in `src-tauri/src/platform_auth.rs`
- [X] T065 [US1] Fall back to the password after repeated platform-auth failure, with no attempt limit that can make a vault permanently unopenable, in `src-tauri/src/platform_auth.rs` (FR-057)
- [X] T066 [US1] Implement `vault_unlock_quick` (platform auth, valid only from `locked_soft`) and `vault_unlock_full` (password + secure store, valid from either state) in `src-tauri/src/lib.rs` (FR-053, FR-054)
- [X] T067 [US1] Implement `vault_lock`, `vault_lock_state`, `idle_timeout_get`, `idle_timeout_set` commands in `src-tauri/src/lib.rs` per `contracts/tauri-command-contract.md` §4
- [X] T068 [US1] Implement the shared identity-confirmation helper in `src-tauri/src/platform_auth.rs` satisfiable by platform auth or password only — never an in-app dialog (FR-055)
- [X] T069 [P] [US1] Add `#[cfg(test)]` tests in `src-tauri/src/lock.rs` proving a quick re-unlock is refused from `locked_hard` and accepted from `locked_soft`

### 3g — Renderer

- [X] T070 [P] [US1] Create `src/components/LockScreen.tsx` — quick vs full unlock paths, background-activity indicator, no vault content rendered
- [X] T071 [US1] Subscribe to `vault-lock-state` in `src/DesktopApp.tsx` and conceal all vault content on `locked_*`, **including retained terminal scrollback** — concealment is a UI obligation, not merely a stale-render (FR-046, FR-050)
- [X] T122 [US1] Capture the active view (session tab, tool panel, scroll position) before concealment and restore it on unlock, in `src/DesktopApp.tsx` (FR-048) — with focus-loss locking firing dozens of times a day, losing the user's place each time would make the app unusable
- [X] T072 [US1] Add the one-time migration notice and its acknowledgement to `src/components/ProfileSelectPage.tsx`, stating plainly that the file will no longer open on other machines (FR-017)
- [X] T073 [US1] Add the rollback-resolution dialog to `src/components/ProfileSelectPage.tsx`, naming both revisions and offering accept-older or restore-newer (FR-064)
- [X] T074 [US1] Surface `VAULT_BUSY`, `VAULT_NO_KEYSTORE` and `VAULT_KEYSTORE_DENIED` as distinct messages in `src/components/ProfileSelectPage.tsx`, the last with a retry affordance
- [X] T121 [US1] Change `list_profiles` in `src-tauri/src/lib.rs:750` to return `Vec<ProfileSummary>` (name, format, revision, busy) instead of `Vec<String>`, reading the revision straight from the container header — no key needed, so the picker stays cheap and lock-free (contracts §1). **T075 depends on this**
- [X] T075 [US1] Update `list_profiles` handling in `src/components/ProfileSelectPage.tsx` for the `ProfileSummary` shape (name, format, revision, busy) per `contracts/tauri-command-contract.md` §1

**Checkpoint**: The key model is device-bound, existing vaults migrate safely, and the lock,
claim, and rollback protections are live. Quickstart §2, §3, §6, §7, §8, §9 should pass.

---

## Phase 4: User Story 2 — Moving a vault to a second computer (Priority: P2)

**Goal**: An opt-in recovery kit, in either form, re-establishes the vault key on another
device the user controls.

**Independent Test**: Create a kit on machine A, migrate, then use it plus its **recovery
passphrase** on a clean machine B to open a file exported from A — and confirm the attempt
fails without that passphrase, and that A's vault password is never entered on B. Full
procedure: [quickstart.md](quickstart.md) §4.

**⚠️ Ships with US1.** US1 removes cross-device portability; releasing it without this strands
every multi-machine user (spec Assumptions).

- [X] T076 [US2] Implement kit sealing in `src-tauri/src/recovery.rs` — wrap the DEK under a **recovery passphrase** chosen for the kit, never a device vault password (FR-019a, FR-019a1)
- [X] T077 [US2] Implement the phrase form in `src-tauri/src/recovery.rs` using `bip39`: 32 bytes, KDF over the recovery passphrase with salt `SHA-256(kid)[0..16]`, authentication by recomputing `kid` from the unwrapped DEK and comparing to the vault file's (research.md Decision 10)
- [X] T078 [US2] Implement the file form in `src-tauri/src/recovery.rs` as a self-contained kit carrying salt, wrapped key, and `kid`
- [X] T079 [US2] Implement `recovery_kit_create(form, recovery_passphrase)` in `src-tauri/src/lib.rs`, requiring identity confirmation first, with the file form's save dialog defaulting to neither a cloud-synced nor a backed-up folder (FR-019f, FR-020)
- [X] T080 [US2] Implement `recovery_kit_consume(source, recovery_passphrase, vault_file?, new_vault_password)` in `src-tauri/src/lib.rs`, accepting either form, prompting for a vault password for **this** device, and routing through `verify_and_import` (FR-019d, FR-021, FR-021a, FR-041)
- [X] T081 [US2] Require the vault file for phrase-form consumption on every platform in `src-tauri/src/recovery.rs` (FR-019g)
- [X] T082 [US2] Validate the phrase checksum before any passphrase attempt in `src-tauri/src/recovery.rs`, returning `KIT_MALFORMED` distinctly from `KIT_WRONG_PASSPHRASE` (FR-019e)
- [X] T083 [US2] Report a passphrase mismatch as `KIT_WRONG_PASSPHRASE` in `src-tauri/src/recovery.rs`; a kit stays valid under its recovery passphrase regardless of any later vault-password change on any device (FR-019b)
- [X] T084 [US2] Place a consumed kit's key into this device's secure store as an **unclaimed** key via `src-tauri/src/keystore.rs`, wrapped under that device's own new vault password, so access does not depend on the kit remaining on disk (FR-021, FR-021a, FR-031a)
- [X] T085 [US2] Implement `unclaimed_keys_list` and `unclaimed_key_discard` in `src-tauri/src/lib.rs` so a consumed kit whose vault file never arrives is visible and disposable
- [X] T086 [P] [US2] Add `#[cfg(test)]` tests in `src-tauri/src/recovery.rs`: kit plus vault file without the recovery passphrase yields nothing and establishes no key (SC-013); a mistyped phrase word yields `KIT_MALFORMED` before any passphrase use; both forms of one kit are interchangeable (SC-014); no vault password appears in either kit form (SC-013a)
- [X] T087 [P] [US2] Create `src/components/RecoveryKitPanel.tsx` — form choice, recovery-passphrase entry at creation, phrase display for transcription, consume flow accepting typed words or a picked file plus a new vault password for this device
- [X] T088 [US2] State at creation time that the phrase form will also need the vault file, in `src/components/RecoveryKitPanel.tsx` (FR-019h) — discovering this at recovery time is itself a requirement failure
- [X] T089 [US2] Warn at creation that the kit, the vault file, and the recovery passphrase together grant full access, and that the recovery passphrase is separate from the vault password, in `src/components/RecoveryKitPanel.tsx` (FR-020)
- [X] T090 [US2] Offer the recovery kit at the moment migration completes, from `src/components/ProfileSelectPage.tsx` (FR-017)

**Checkpoint**: US1 + US2 together are releasable. Quickstart §4 passes.

---

## Phase 5: User Story 3 — Exporting an identifiable backup (Priority: P3)

**Goal**: Export the already-sealed vault under a name that says which point in time it is.

**Independent Test**: Export the same profile twice with a change between; the filenames are
distinguishable and ordered, and neither file reveals key material as text.
[quickstart.md](quickstart.md) §2 step 6.

- [X] T091 [US3] Require identity confirmation before export in `src-tauri/src/lib.rs:911` (FR-023)
- [X] T092 [US3] Export the stored sealed blob without unlocking the vault in `src-tauri/src/lib.rs:911` (FR-024)
- [X] T093 [US3] Suggest the filename `SSHClientX-{YYYYMMDD}-{HHmm}-g{generation}.sshclientx` in `src-tauri/src/lib.rs:911` per `contracts/sealed-container.md` §6 (FR-025)
- [X] T094 [US3] Remove any temporary or cached copy the app created during export, on both success and failure paths, in `src-tauri/src/lib.rs:911` (FR-027)
- [X] T095 [US3] Ensure an export taken while a save is in flight captures one complete revision, never a half-written one, in `src-tauri/src/vault.rs`
- [X] T096 [US3] Update the export flow in `src/components/ProfileSelectPage.tsx:142` for the identity-confirmation step and the new suggested filename

**Checkpoint**: Quickstart §2 export checks pass.

---

## Phase 6: User Story 4 — Import that says why a file was rejected (Priority: P4)

**Goal**: Every incoming file goes through one verification path, and each failure has its own
message. Import creates a new profile or restores over one, never silently discarding newer
content.

**Independent Test**: Feed the importer a genuine file, a byte-flipped file, a foreign-key
file, an older file, and a same-revision-different-content file; confirm five distinct outcomes
with the local vault unchanged in the four failures. [quickstart.md](quickstart.md) §5.

- [X] T097 [US4] Implement `import_vault_pick` in `src-tauri/src/lib.rs` — copy into the sandbox, then verify the copy that will actually be used, never re-reading the source (FR-030)
- [X] T098 [US4] Return the `StagedImport` shape with disposition and revisions from `src-tauri/src/lib.rs` per `contracts/tauri-command-contract.md` §2
- [X] T099 [US4] Implement `import_vault_commit` in `src-tauri/src/lib.rs` with atomic replacement preserving the replaced revision (FR-034)
- [X] T100 [US4] Require `confirm_older` for `BOX_OLDER` and `resolve_conflict` for `BOX_CONFLICT` in `src-tauri/src/lib.rs`; a commit without the matching confirmation returns the same code rather than proceeding (FR-033)
- [X] T101 [US4] Implement `import_vault_discard` and remove staged copies on commit, discard, and app exit, in `src-tauri/src/lib.rs` (FR-035)
- [X] T102 [US4] Offer `CreateProfile` only for an unclaimed key, and for an owned key offer restore-over while naming the owning profile, in `src-tauri/src/vault.rs` (FR-032, FR-032a)
- [X] T103 [US4] Delete the now-obsolete `import_profile_pick` and `import_profile_save` from `src-tauri/src/lib.rs:960,1014` and remove their command registrations
- [X] T104 [P] [US4] Add `#[cfg(test)]` tests in `src-tauri/src/vault.rs` covering all seven import failure outcomes and asserting the local vault is byte-identical after each (SC-004, SC-005)
- [X] T105 [P] [US4] Add a `#[cfg(test)]` test in `src-tauri/src/vault.rs` proving a file matching a key owned by an existing profile never produces a second profile sharing that key (SC-026)
- [X] T106 [US4] Rewrite the import flow in `src/components/ProfileSelectPage.tsx:156-188` as stage-then-commit, with a distinct message per outcome code and a recovery-kit pointer on `BOX_UNKNOWN_KEY`

**Checkpoint**: All four user stories functional. Quickstart §5 passes.

---

## Phase 7: Polish & Cross-Cutting Concerns

- [X] T107 [P] Implement diagnostic entries in `src-tauri/src/vault.rs` recording outcome code, timestamp, revisions, `kid` prefix and hash prefix for every failed migration, recovery, import and unlock (FR-067)
- [X] T108 Enforce the diagnostic exclusion list in `src-tauri/src/vault.rs` — no hostnames, paths, user-chosen filenames, usernames, credentials, phrase words, or vault content (FR-068, FR-069)
- [X] T109 [P] Add a `#[cfg(test)]` test in `src-tauri/src/vault.rs` scanning generated diagnostic output for forbidden substrings (SC-025)
- [X] T110 [P] Register the `.sshclientx` file association and `application/x-sshclientx` MIME in `packaging/arch/sshclientx.desktop` and the equivalent macOS/Windows bundle configuration in `src-tauri/tauri.conf.json` (FR-037)
- [X] T111 [P] Suppress OS content previews for vault files in `src-tauri/tauri.conf.json` and the packaging metadata (FR-037)
- [X] T112 Refuse export, import, and legacy-vault migration on Android with messages naming the platform and pointing at desktop; permit fresh profile creation through the shared vault path, in `src-tauri/src/lib.rs` (FR-039, FR-040)
- [X] T113 Enable Android to open, use and save a sealed vault whose key arrived via a kit, in `src-tauri/src/keystore.rs` and `src-tauri/src/vault.rs` (FR-038, FR-041, FR-042)
- [X] T114 [P] Add a UI warning when a profiles directory appears to sit inside a cloud-synced folder, in `src/components/ProfileSelectPage.tsx` — `flock` gives no cross-machine exclusion there (research.md Decision 11)
- [X] T115 [P] Update `README.md` and `ARCHITECTURE.md` for the device-bound vault, the recovery kit, and the loss of password-only portability
- [X] T116 Run `npm run typecheck` and `cargo test --manifest-path src-tauri/Cargo.toml`; both must pass
- [ ] T117 Walk every scenario in [quickstart.md](quickstart.md) on macOS, Windows and Linux, plus the Android section — several need a second machine and cannot be automated
- [ ] T118 Measure the Windows build cost of the third `windows` crate major; if it hurts, vendor the two `robius-authentication` platform files against the `windows` 0.62.2 already in the tree and pass the real Tauri HWND instead of `GetDesktopWindow()` (research.md Decision 6)
- [X] T119 Verify empirically that macOS `evaluatePolicy` works from an unsigned `cargo run` binary — research.md flags this as unconfirmed, and finding out during release prep would be expensive

---

## Dependencies

**Phase order**: Setup → Foundational → US1 → US2 → US3 → US4 → Polish.

**Hard blocks**:

- Phase 2 blocks every user story. Nothing in Phase 3+ can start before T023.
- T024–T032 (key model) block everything else in US1.
- T041 (high-water storage) requires T017–T018 (keystore wrapper).
- T077 (phrase form) requires T010 (`kid` derivation) and T021 (`verify_and_import`).
- T102 (disposition) requires T022.
- T075 (picker UI) requires T121 (the `ProfileSummary` return shape it renders).
- T113 (Android) requires US2 complete — Android's only path in is a recovery kit.

**Story independence**: US3 and US4 are genuinely independent of each other and of US2, given
Phase 2. **US2 is not independent of US1 for release purposes** — it may be built separately but
must ship with it.

---

## Parallel Execution Opportunities

- **Phase 1**: T005 and T006 alongside T001–T004.
- **Phase 2**: the container work (T007–T016) and the keystore work (T017–T020) are different
  files with no shared state — two people, or two sessions, in parallel.
- **Phase 3e**: T053, T054, T055 are three platform backends behind one interface. Ideal
  parallel split, and each needs its own machine to test anyway.
- **Phase 3**: all `[P]` test tasks (T031, T032, T040, T044, T049, T061, T069) run against
  finished implementation and are parallel with one another.
- **Phase 7**: T107, T109, T110, T111, T114, T115 touch disjoint files.

---

## Implementation Strategy

### The MVP caveat

Standard advice is "User Story 1 is the MVP." **That does not hold here.** US1 absorbed every
clarification round — migration, lock lifecycle, unlock, single-writer, and rollback detection
are all US1 acceptance scenarios — so Phase 3 alone is 54 tasks across five subsystems.

Two honest options:

1. **Ship US1 + US2 together as one release.** Correct, and large. This is what the spec's
   Assumptions require, since US1 without US2 strands multi-machine users.
2. **Split US1 along the sub-phase seams**, which were drawn to be separable:
   - **3a + 3b + 3g(partial)** — the key model and migration. This is the actual security
     change and is independently valuable and testable.
   - **3e + 3f** — lock lifecycle and unlock. Depends on 3a for a key to lock, but nothing
     else, and could follow in a second release.
   - **3c + 3d** — rollback detection and single writer. Both are integrity protections,
     independent of the lock work.

   Option 2 still cannot ship 3a without US2.

### Recommended increment order

1. Phases 1–2 (foundational, 24 tasks) — no user-visible change, everything depends on it.
2. Phase 3a/3b + Phase 4 — the key model, migration, and recovery kit. **First releasable
   increment.**
3. Phase 3c/3d — integrity protections.
4. Phase 3e/3f/3g — lock lifecycle and its UI.
5. Phases 5–6 — export and import upgrades.
6. Phase 7 — polish, platform registration, Android.

### Notes

- Every task touching the vault carries a constitutional test obligation. The `[P]` test tasks
  are not optional polish.
- T119 and T118 are investigations, not implementations; schedule them early enough that a bad
  answer can still change the plan.
