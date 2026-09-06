# Implementation Plan: Local-Only Mode (Remove Accounts & Backend API)

**Branch**: `001-local-only-mode` | **Date**: 2026-09-06 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/001-local-only-mode/spec.md`

## Summary

Remove SSHClientX's entire account/backend-API surface (sign-up/sign-in,
magic-link, password reset, multi-device cloud sync, and cross-account
profile sharing/invites) so the application works fully standalone with
zero dependency on any backend, for security reasons. Existing local
vault files must keep working exactly as before, and the transition is
silent — no migration notice or explanatory UI. Technical approach:
delete `src-tauri/src/cloud.rs` and `identity.rs` and their 32 exposed
Tauri commands; delete 4 frontend components and surgically rewrite a
5th (`ProfileSelectPage.tsx`) plus trim `DesktopApp.tsx`; drop the
backend CSP origin and the two now-unused crypto crates; leave the
existing sync-only DB columns/tables in place but dormant (no schema
migration, per research.md); rewrite README/SEO copy that markets cloud
sync. A separate constitution amendment is recommended as a follow-up
(see research.md Decision 9) but is out of scope for this plan.

## Technical Context

**Language/Version**: Rust 2021 (MSRV 1.70) for `src-tauri/`; TypeScript
+ React 18 for `src/`. Tauri 2 as the app framework.

**Primary Dependencies**: Removed — `x25519-dalek`, `hkdf` (only used by
`identity.rs`). Kept as-is — `russh`, `rusqlite` (bundled), `aes-gcm`,
`argon2`, `zstd`, `zeroize`, `reqwest` (still used by the unrelated
`about.rs::check_for_updates`), Tauri 2, React 18, Tailwind, xterm.js.

**Storage**: SQLite, bundled inside the AES-256-GCM/zstd-sealed vault
file (magic `OMNV`). Local-only after this change — no server-side
storage. Schema version stays at 6 (research.md Decision 1); sync-only
columns/tables are kept but become dormant rather than dropped.

**Testing**: `cargo test` for Rust (existing `sync_trigger_tests` stay
unchanged — the DB triggers they cover are retained per Decision 1);
`npm run typecheck` / `npm run build` for the frontend.

**Target Platform**: Desktop (Windows/macOS/Linux) and Android, via
Tauri 2, one shared core per the constitution's "One Core, Every
Platform" principle. The frontend inventory confirmed the cloud UI is
identical on both platforms today, so this removal needs no
platform-specific carve-out.

**Project Type**: Desktop application (Tauri 2 + Rust backend + React
frontend), single repository, no separate backend/frontend split for
this project's own code.

**Performance Goals**: No new performance targets; the removal must
not regress existing SSH/SFTP/tunnel/mirror/terminal performance.

**Constraints**: Zero outbound network calls to any account/sync
backend host, at any time (startup, background, or user action) —
FR-003/FR-004. Existing local vault files, including ones previously
cloud-linked or shared, must open with zero data loss — FR-007. CSP
`connect-src` must not allow-list the removed backend origin. The
pre-existing GitHub update check (`api.github.com`) is explicitly out
of scope (research.md Decision 7) and must not be touched by this
feature.

**Scale/Scope**: 32 Tauri commands removed across 2 Rust modules
(`cloud.rs` deleted whole, `identity.rs` deleted whole) plus 6 commands
in `lib.rs`; ~110 other commands in `lib.rs` untouched. 4 frontend
components deleted, 1 rewritten, 1 trimmed (`DesktopApp.tsx`, 15
`bumpSync()` call sites plus related state). 2 Cargo dependencies
removed. README + 2 SEO JSON-LD files rewritten.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-checked after Phase 1 design.*

- **Principle I (Device-Bound Secrets, NON-NEGOTIABLE)** — PASS. This
  feature does not touch Argon2 parameters, vault key derivation, or
  the AES-256-GCM sealing path. It removes the *only* other outbound
  network destination (the account/sync backend), which strictly
  narrows the attack surface the principle is protecting. No vault
  recovery/escrow mechanism is added. **Note**: several clauses of
  Principle I are *written in terms of* cloud sync/account auth
  existing ("Cloud sync MUST upload only ciphertext…", "Account auth…
  MUST NOT be used to derive or recover [the vault key]"). Nothing in
  this plan violates those clauses (they become vacuously satisfied),
  but they will describe a feature that no longer exists — flagged as
  a required constitution amendment, tracked outside this plan
  (research.md Decision 9), not a gate failure.
- **Principle II (Rust Owns Privilege)** — PASS. No new capability is
  granted; the CSP change only *removes* an allow-listed origin. No
  cryptography moves into the webview.
- **Principle III (One Core, Every Platform)** — PASS. The removal is
  applied identically to desktop and Android (no separate cloud-UI
  carve-out exists to preserve or diverge).
- **Principle IV (Explicit Trust Boundaries)** — PASS. Not touched;
  TOFU host-key pinning, path guards, and terminal-output handling are
  unaffected by this feature.
- **Principle V (Native and Lean)** — PASS, and directly advanced:
  this removes two dependencies (`x25519-dalek`, `hkdf`) and a large
  amount of code, which is the kind of "no unused plugin surface"
  outcome the principle asks for. New sync/cloud behavior is
  explicitly *not* being added, so the "extend existing modules"
  clause doesn't apply in the growth direction.

**Overall**: PASS. No violations requiring justification in Complexity
Tracking. One follow-up action (constitution amendment) is required but
does not block this plan or its implementation.

## Project Structure

### Documentation (this feature)

```text
specs/001-local-only-mode/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md         # Phase 1 output
├── quickstart.md         # Phase 1 output
├── contracts/
│   └── tauri-command-contract.md  # Phase 1 output
└── tasks.md              # Phase 2 output (/speckit-tasks — not created here)
```

### Source Code (repository root)

```text
src-tauri/
├── Cargo.toml            # remove x25519-dalek, hkdf
├── tauri.conf.json       # remove https://api.sinaxhpm.com from CSP connect-src
└── src/
    ├── cloud.rs           # DELETE (whole file)
    ├── identity.rs        # DELETE (whole file)
    ├── hlc.rs              # UNCHANGED (kept — local-only ordering logic)
    ├── about.rs            # UNCHANGED (check_for_updates is out of scope)
    └── lib.rs              # remove 22 commands (identity/sharing/sync-orchestration);
                              # ~110 other commands untouched; sync-only DB
                              # columns/tables left in place but dormant

src/
├── DesktopApp.tsx                    # trim: remove ProfilePanel mount/tab,
│                                        bumpSync() call sites, cloud-sync state
└── components/
    ├── CloudPanel.tsx                 # DELETE
    ├── ProfilePanel.tsx               # DELETE
    ├── InvitesSection.tsx             # DELETE
    ├── shareRoles.tsx                 # DELETE
    └── ProfileSelectPage.tsx          # REWRITE (remove cloud branch, keep local flow)

README.md                # rewrite cloud-sync marketing sections
docs/seo/
├── faq.jsonld                        # rewrite cloud-sync Q&A entries
└── software-application.jsonld       # rewrite cloud-sync featureList/description
```

**Structure Decision**: Single project, no new directories. This is a
subtractive change within the existing Tauri 2 + Rust + React layout;
no Option 2/3 (web app / mobile+API split) applies since the "backend"
being removed was an external cloud service, not a local sub-project.

## Complexity Tracking

*No entries — Constitution Check reported no violations.*
