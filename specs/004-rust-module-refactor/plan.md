# Implementation Plan: Rust Module Refactor

**Branch**: `004-rust-module-refactor` | **Date**: 2026-09-10 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from [spec.md](spec.md)

## Summary

The refactor hardens two existing correctness boundaries before moving code: profile lifecycle and vault persistence. A profile runtime will own every profile-derived task and resource through an epoch-guarded shutdown coordinator. A canonical per-profile save coordinator will serialize mutation ordering, vault snapshot/seal/history/atomic replacement, and generation commit. After those gates pass, the existing Tauri command adapters will delegate to typed lifecycle, repository, SSH/SFTP, monitor, and transfer services without changing command names, events, error codes, vault formats, platform gates, or security boundaries.

Delivery is staged within this feature:

1. strict profile lifecycle and shutdown;
2. serialized vault persistence;
3. contract-preserving structural extraction.

## Technical Context

**Language/Version**: Rust 2021, MSRV 1.89, Tauri 2; React 18/TypeScript remains the renderer contract surface.

**Primary Dependencies**: Existing Tokio runtime, Tauri state/commands, rusqlite bundled SQLite, zstd, AES/XChaCha vault primitives, keyring/secure-store integrations, russh/russh-sftp, notify mirror support, and current platform bridges. No new dependency is required for this refactor.

**Storage**: Existing SQLite profile database serialized into the current sealed vault format with existing keywrap sidecar, keystore device factor, bounded revision history, rollback high-water mark, and legacy readable vault support. No new tables or on-disk format.

**Testing**: `cargo test --manifest-path src-tauri/Cargo.toml`, `cargo check --manifest-path src-tauri/Cargo.toml`, `npm run typecheck`, focused Rust regression tests for lifecycle/save ordering, and manual validation in [quickstart.md](quickstart.md). The complete Rust and TypeScript baseline commands run at each lifecycle, persistence, and extraction gate, not only at final polish.

**Target Platform**: Shared desktop and Android Tauri application. Existing `cfg` gates remain authoritative for desktop-only dependencies and capabilities.

**Project Type**: Local-only desktop and mobile application with a Rust privileged core and React renderer.

**Performance Goals**: Expensive SQLite serialization, compression, sealing, filesystem sync, and keyring work must stay off the Tokio worker path. Profile close must not report success before all owned tasks complete or acknowledge cancellation; existing operation timeouts remain the upper bound for shutdown attempts.

**Constraints**: Preserve device-bound secrets, two-factor vault unlock, vault magic/extensions/formats, Argon2 parameters, history and rollback semantics, writer claims, path guards, TOFU/nonce flows, Docker allow-lists, command/event/error contracts, minimal capabilities/CSP, local-only operation, and Android/desktop gates. No new backend, account, telemetry, cloud sync, or cross-device path.

**Scale/Scope**: One existing Rust crate containing `lib.rs` at roughly 11k lines, approximately 100+ registered commands, multiple root-managed async registries, and supporting modules for vault, SSH, SFTP, tunnels, monitors, mirrors, Docker, QR transfer, recovery, lock, and keystore behavior. Phase 1 adds only lifecycle/save ownership boundaries; later phases extract existing implementations behind them.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **Principle I — Device-Bound Secrets: PASS.** The plan preserves the existing device-generated DEK, secure-store requirement, vault password wrapping, keywrap sidecar, no-plaintext persistence, and recovery/pairing boundaries. The save coordinator reuses existing sealing and keystore primitives; it does not change cryptographic constants or formats.
- **Principle II — Rust Owns Privilege: PASS.** Lifecycle, persistence, crypto, database, SSH/SFTP, filesystem, tunnel, mirror, Docker, and transfer operations remain in Rust. The renderer contract is frozen and no capability, shell, filesystem, webview, or CSP permission is added.
- **Principle III — One Core, Every Platform: PASS.** The shared `run()` composition root and module-owned behavior remain shared by desktop and Android. Existing `cfg` gates, Android bridge initialization, and explicit desktop-only refusals remain unchanged.
- **Principle IV — Explicit Trust Boundaries: PASS.** Runtime epochs prevent stale profile operations; existing path guards, host-key verification, nonce checks, Docker allow-lists, and vault verification remain the single trust boundaries. New lifecycle and save owners do not accept unvalidated renderer data directly.
- **Principle V — Native and Lean: PASS.** No new dependency, backend, plugin, protocol, or storage format is needed. The design reuses Tokio, existing cancellation/join patterns, `vault::seal_and_save`, current repositories/queries during transition, and existing command adapters.

**Gate result before research: PASS.** No governance exception or complexity violation is required.

## Project Structure

### Documentation (this feature)

```text
specs/004-rust-module-refactor/
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   └── tauri-command-contract.md
├── checklists/
│   └── requirements.md
└── tasks.md                         # phased implementation tasks
```

### Source Code (repository root)

```text
src-tauri/
├── Cargo.toml                       # unchanged dependency/features contract
└── src/
    ├── lib.rs                       # composition root, thin command adapters, registry during transition
    ├── profile_runtime.rs           # lifecycle types and runtime ownership; US1 implementation
    ├── vault_store.rs               # save-coordinator types and commit seam; US2 implementation
    ├── ssh_manager.rs               # existing SSH/TOFU ownership; extracted callers preserve its contracts
    ├── vault.rs                     # existing format, keywrap/history/rollback primitives; no format redesign
    ├── keystore.rs                  # existing secure-store classifications and blocking calls
    ├── recovery.rs                  # existing recovery/key establishment boundary
    ├── tunnel.rs                    # existing tunnel implementation, joined through runtime ownership
    ├── mirror.rs                    # existing mirror implementation, joined through runtime ownership
    ├── monitor.rs                   # existing monitor implementation, made awaitable through runtime ownership
    ├── docker.rs                    # existing Docker allow-listed commands and stream registry
    ├── qr_transfer.rs               # existing QR session state, owned by profile runtime during close
    ├── lock.rs                      # existing lock state and platform observers
    ├── database/                    # later typed schema/migration and profile repositories
    └── commands/                    # later thin Tauri command adapters grouped by domain
        ├── ssh.rs                   # SSH/session adapters
        ├── sftp.rs                  # SFTP/local-transfer adapters
        ├── profile.rs               # profile/vault/recovery/QR/import adapters
        ├── transfer.rs              # transfer/import staging adapters
        └── operations.rs            # Docker/monitor/tunnel/mirror/local/about adapters
```

**Structure Decision**: Start with two explicit ownership boundaries instead of splitting `lib.rs` by line ranges. `profile_runtime.rs` owns lifecycle admission and shutdown. `vault_store.rs` owns ordinary save ordering while delegating file-format work to `vault.rs`. Once those gates are verified, extract repositories and services by domain while keeping `lib.rs::run()` and the command registry as the stable composition boundary.

## Phase 0 Research

Completed in [research.md](research.md). All technical-context unknowns are resolved. The central decisions are the epoch-guarded runtime, canonical save coordinator, frozen command/event contract, staged extraction, and focused regression/manual validation gates.

## Phase 1 Design Artifacts

Completed:

- [data-model.md](data-model.md) — lifecycle, runtime resources, persistence operations, vault revisions, and compatibility entities.
- [contracts/tauri-command-contract.md](contracts/tauri-command-contract.md) — command, event, error, and platform compatibility contract.
- [quickstart.md](quickstart.md) — runnable baseline, manual scenarios, and phase gates.

## Constitution Check — Post-Design

- **Principles I–III:** PASS. Data model and contracts preserve device-bound keys, Rust privilege ownership, shared desktop/Android behavior, and target gates.
- **Principle IV:** PASS. The runtime epoch and strict shutdown add an explicit stale-operation boundary; all existing path, TOFU, nonce, Docker, and vault verification boundaries remain unchanged.
- **Principle V:** PASS. Phase 1 adds no dependency, plugin, capability, protocol, schema, or format. It reuses existing native primitives and keeps the composition root shared.
- **Compatibility:** PASS. The contract artifact freezes the registry, events, errors, sentinels, terminal base64 payload, secondary session IDs, and platform refusals before extraction.
- **Verification:** PASS. Focused lifecycle/save tests and the quickstart scenarios directly cover the clarified strict-shutdown and deterministic-conflict decisions.

**Overall post-design result: PASS.** Ready for `/speckit-tasks`.

## Complexity Tracking

No constitution violations or new dependency/storage/network complexity require justification.
