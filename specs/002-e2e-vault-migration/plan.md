# Implementation Plan: End-to-End Encrypted Vault Migration

**Branch**: `002-e2e-vault-migration` | **Date**: 2026-09-06 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/002-e2e-vault-migration/spec.md`

## Summary

Replace the password-derived vault key with a device-bound one. Today
`Argon2id(password, salt)` *is* the AES key, so a copied `.sshclientx` opens on any machine
that has the password. After this feature the sealing key is a CSPRNG DEK held in the OS
secure store, wrapped under a key combined from that store **and** the password, so neither
alone opens a vault and a copied file opens nowhere.

Technical approach: extract the vault crypto from `lib.rs` into a new `vault.rs` and write the
`SSHCLTX1` container (key identifier, monotonic revision, AAD binding, SHA-256 trailer) while
keeping `OMNV` readable and migrating it on first successful unlock; add `keyring` for the
secure store with a `secret-service` downcast to separate "no store at all" from "this request
was denied"; add `chacha20poly1305` on the `aead` family already in the tree; build the single
`verify_and_import` pipeline every present and future transport routes through; add the lock
lifecycle, platform-authentication unlock, per-profile writer claim via `File::try_lock`, and
rollback detection against a high-water mark held beside the key.

**Gates are clear.** The constitution stands at v3.1.0: v3.0.0 made a device-bound vault legal,
v3.1.0 authorised the six dependencies this design needs. See Constitution Check.

## Technical Context

**Language/Version**: Rust 2021 for `src-tauri/`, **MSRV moving 1.85 → 1.89**
(research.md Decision 13: `keyring` 4.2 needs 1.88, `File::try_lock` needs 1.89). TypeScript +
React 18 for `src/`. Tauri 2.

**Primary Dependencies**: Added — `keyring` 4.2 (secure store), `secret-service` 5
`default-features = false` (Linux error downcast only), `chacha20poly1305` 0.10 (XChaCha20-Poly1305),
`robius-authentication` 0.3.1 (macOS/Windows platform auth), `bip39` 2.2 (recovery phrase),
`x11rb` 0.14 `screensaver` (Linux idle, Linux-only). Kept — `argon2`, `aes-gcm`, `sha2`,
`zstd`, `zeroize`, `rusqlite`, `russh`, Tauri 2. **No new Tauri plugin**, deliberately.
`File::try_lock` and the platform lock/idle hooks are std or already-present crates.

**Storage**: SQLite serialised, zstd-compressed, sealed. Payload unchanged
(research.md Decision 1); the container around it is replaced. Two formats live at once:
`SSHCLTX1` written, `OMNV` still read and migrated. DEK and revision high-water mark live in
the OS secure store, never on disk.

**Testing**: `cargo test` in-crate — constitution requires module tests for any change
touching vault, path guards, or host-key handling, and this is the largest vault change the
project has had. `npm run typecheck` / `npm run build` for the frontend.
[quickstart.md](quickstart.md) carries nine manual scenarios covering all 26 success criteria,
several of which need a second machine and cannot be automated.

**Target Platform**: Desktop (macOS, Windows, Linux) creates and migrates. Android opens,
uses, and saves a sealed vault whose key arrived via a recovery kit, but cannot create or
migrate one, and keeps refusing the general export/import flows. Both platforms read both
formats.

**Project Type**: Desktop + mobile application, Tauri 2 + Rust core + React renderer, single
repository.

**Performance Goals**: A full unlock is no slower than today's (SC-007) — Argon2id still runs
once, now producing a KEK rather than the key itself. A quick re-unlock completes in **under 2
seconds including the platform prompt** (SC-007, SC-018), which matters because focus-loss
locking makes it a many-times-a-day operation.

**Constraints**: DEK never in a file, a log, or the renderer (FR-002, Principle I). Keystore
calls block on GUI prompts, so all of them go through `spawn_blocking`, never the async
runtime. `secret-service` must carry `default-features = false` — cargo features are additive
and naming a crypto feature there would unify OpenSSL into keyring's copy. Locking never
disconnects a live SSH session (FR-049), and locking conceals retained terminal scrollback
rather than merely not refreshing it (FR-046, FR-050).

**Scale/Scope**: 89 functional requirements, 4 user stories, 5 cross-cutting blocks. Rust:
vault crypto extracted from `lib.rs:77-338` into a new `vault.rs`; 3 `save_vault_async` call
sites; `setup_master_db_inner` (`lib.rs:1070`) becomes the migration trigger; `export_profile`
(`lib.rs:911`) reworked; `import_profile_pick`/`import_profile_save` (`lib.rs:960`, `1014`)
replaced by a stage-then-commit pair; ~15 new commands; window-event handling is net-new (the
Rust side has none today). Frontend: `ProfileSelectPage.tsx` export/import flows, a new lock
screen and concealment layer, recovery-kit create/consume UI, migration notice, rollback
resolution.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-checked after Phase 1 design.*

Evaluated against **constitution v3.1.0**.

- **Principle I (Device-Bound Secrets, NON-NEGOTIABLE)** — **PASS.** The constitution requires
  precisely what this feature builds: CSPRNG DEK in the OS secure store, this-device-only,
  fail-closed with no unprotected fallback, password wrapped through Argon2id into a KEK that
  protects rather than derives the DEK, two-of-two unlock, XChaCha20-Poly1305 preferred, opt-in
  offline recovery kit. The design satisfies each clause.
- **Principle II (Rust Owns Privilege)** — **PASS, with one named exception.** All crypto,
  keystore, platform-auth, and file work is in Rust; the renderer receives outcome codes and
  decisions. **The exception**: recovery phrase words cross the IPC boundary once, outbound, at
  creation, so they can be displayed. This is unavoidable — a phrase the user cannot see is not
  a recovery kit — and is bounded by contract: display only, never persisted, never in
  `localStorage`. No new Tauri plugin is introduced, so no additional Governance step is
  triggered (research.md Decisions 6 and 11 both chose crates over plugins partly for this
  reason).
- **Principle III (One Core, Every Platform)** — **PASS.** v3.0.0 explicitly permits the
  desktop-creates / Android-consumes asymmetry and requires both platforms to read both
  formats, which this design does. Desktop-only paths (`rfd`, platform auth, idle/lock hooks)
  are `cfg`-gated as the principle requires. The asymmetry carries the amendment's stated lapse
  condition; it is not open-ended.
- **Principle IV (Explicit Trust Boundaries)** — **PASS, and extended.** New untrusted inputs
  arrive with this feature and are guarded: `sender_name` in a sealed container is
  display-only, capped at 255 bytes, never used to build a path and never interpreted as
  markup; imported bytes are copied into the sandbox and verified before use, with the key
  check ordered *before* the AEAD open so a foreign file is never decrypted; recovery-kit files
  are untrusted input on the same footing.
- **Principle V (Native and Lean)** — **PASS.** v3.1.0 carries an exhaustive six-row
  dependency table with the required reason per entry, and this design uses exactly those six
  and no more. No Tauri plugin is added, so the plugin surface does not widen and no further
  Governance step under Principle II is triggered. The MSRV floor is now stated in the
  constitution with its two causes, rather than sitting stale at 1.70.

  This gate **failed against v3.0.0** and the failure was real: that amendment authorised two
  dependencies, but clarification rounds afterwards added platform authentication (Q6) and the
  recovery-phrase form (Q2), which need four more. The amendment was stale relative to its own
  spec. v3.1.0 fixed it by naming all six with reasons; the alternative — dropping
  dependencies — was rejected for each, since `x11rb` is what makes the not-disableable idle
  timeout (FR-045) implementable on Linux at all.

**Overall**: **PASS.** No blocking follow-ups. Complexity Tracking below records the
dependency and module choices with the alternatives that were rejected.

### Post-design re-check

Phase 1 surfaced one requirement conflict, now resolved: bip39 cannot encode a self-contained
kit, so phrase-form recovery consumes the vault file to derive its Argon2 salt from the key
identifier. Written into the spec as FR-019g and FR-019h; analysis and the rejected bech32m
alternative are in research.md Decision 10. No constitutional consequence.

## Project Structure

### Documentation (this feature)

```text
specs/002-e2e-vault-migration/
├── plan.md                          # This file
├── research.md                      # Phase 0 — 13 decisions
├── data-model.md                    # Phase 1 — 11 entities, lifecycle and state tables
├── quickstart.md                    # Phase 1 — 9 validation scenarios → 26 success criteria
├── contracts/
│   ├── sealed-container.md          # Phase 1 — byte layout, verification order, outcomes
│   └── tauri-command-contract.md    # Phase 1 — IPC surface and events
├── checklists/
│   └── requirements.md              # Spec quality checklist (16/16)
└── tasks.md                         # Phase 2 (/speckit-tasks — not created here)
```

### Source Code (repository root)

```text
src-tauri/
├── Cargo.toml               # rust-version 1.85 → 1.89; add keyring, secret-service
│                            #   (default-features=false), chacha20poly1305,
│                            #   robius-authentication, bip39; x11rb under a Linux target
└── src/
    ├── vault.rs             # NEW — container read/write, verify_and_import, migration,
    │                        #   revision + high-water, writer claim. Moved out of lib.rs
    ├── keystore.rs          # NEW — keyring wrapper; the NO_KEYSTORE vs DENIED downcast;
    │                        #   all calls via spawn_blocking
    ├── platform_auth.rs     # NEW — robius on macOS/Windows; cfg'd out on Linux
    ├── lock.rs              # NEW — lock state machine; focus from Tauri, idle and
    │                        #   screen-lock per platform
    ├── recovery.rs          # NEW — kit create/consume, both forms
    └── lib.rs               # crypto at 77-338 REMOVED (moves to vault.rs);
                             #   setup_master_db_inner gains migration + rollback;
                             #   export_profile reworked; import_profile_* replaced;
                             #   ~15 commands added; on_window_event registered (net-new)

src/
├── DesktopApp.tsx           # lock-state subscription; conceal on locked_*, incl. scrollback
└── components/
    ├── ProfileSelectPage.tsx    # export/import rework, migration notice, rollback dialog
    ├── LockScreen.tsx           # NEW — quick vs full unlock, background-activity indicator
    └── RecoveryKitPanel.tsx     # NEW — create (phrase/file) and consume

packaging/                   # .sshclientx file association + application/x-sshclientx MIME
```

**Structure Decision**: Single project, five new Rust modules. `lib.rs` is already 8552 lines
and holds the vault crypto inline; this feature roughly triples that surface. Principle V says
new crypto behaviour must extend existing modules rather than grow ad-hoc — there is no
existing crypto module to extend, and the alternative is growing `lib.rs` further, so
extracting `vault.rs` and its siblings is consolidation rather than proliferation. The split
follows the precedent already set by `hlc.rs`, `mirror.rs`, and `tunnel.rs`.

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| 6 dependencies, authorised by constitution v3.1.0 (Principle V) | `robius-authentication` and `bip39` implement Q6 platform auth and Q2 phrase kits, both clarified after v3.0.0 was drafted | Hand-rolling platform auth means ~300 lines of unsafe FFI reproducing known traps (WinRT activation factory, mandatory availability pre-check, fresh `LAContext` per call); hand-rolling a checksummed word encoding is inventing format code on a recovery path |
| `x11rb` (Linux idle) | FR-045 makes the idle timeout not disableable, so idle must be measurable on Linux too. No cross-platform idle crate is safe to ship — `user-idle` and all its forks carry a macOS double-release that crashes with `EXC_GUARD` | Dropping it was considered and rejected: it would leave FR-045 unimplementable on Linux, which is a requirement violation rather than a reduced feature |
| `secret-service` as a direct dependency | Only way to distinguish `VAULT_NO_KEYSTORE` from `VAULT_KEYSTORE_DENIED`, which the spec insisted on — `keyring_core::Error` collapses them | Already in the tree via keyring, so it adds no compilation. Could be dropped only by abandoning the distinction, which would tell a user who dismissed a prompt that their machine is broken |
| 5 new Rust modules | The feature adds container, keystore, auth, lock, and recovery concerns at once | Inlining into `lib.rs` — rejected, it is 8552 lines already and this would add well over a thousand |
| Two vault formats live simultaneously | Unmigrated files must keep opening (FR-018, FR-042) | A forced flag-day migration — rejected, it would strand any vault not opened during the transition, including every Android vault |

## Resolved before `/speckit-tasks`

1. **Constitution review** — v3.0.0 completed Governance step 5; v3.1.0 followed to widen the
   dependency allowance. Both are in `.specify/memory/constitution.md`.
2. **Dependency addendum** — v3.1.0's Technology & Architecture Constraints now carry an
   exhaustive six-row table with a reason per dependency, plus the rule that a seventh needs
   Governance.
3. **research.md Decision 10** — resolved in favour of the 24-word phrase. Written into the
   spec as FR-019g (the vault file is required for phrase recovery) and FR-019h (say so at
   creation, not at recovery). The bech32m alternative stays documented in research.md as the
   rejected option.

Nothing blocks `/speckit-tasks`. Carry forward into implementation: the risk table at the end
of research.md, particularly that keystore calls must run on `spawn_blocking` because unlock
prompts block, that the nonce length is versioned through the container's `alg` byte rather
than by a constant, and that the two Windows message types must be handled inside the WndProc
because they never reach the message queue.
