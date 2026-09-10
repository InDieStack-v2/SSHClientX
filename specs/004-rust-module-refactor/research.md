# Phase 0 Research: Rust Module Refactor

**Feature**: `004-rust-module-refactor` | **Date**: 2026-09-10 | **Spec**: [spec.md](spec.md)

This research resolves the design questions surfaced by the source review. It preserves the existing local-only product, vault formats, native privilege boundary, and user-visible command/event contracts.

## Decision 1 — Deliver the refactor in gated stages

**Decision**: Deliver the work in one feature through ordered stages:

1. profile lifecycle and strict shutdown;
2. canonical vault-save coordination;
3. repository/service extraction and contract-preserving module moves.

Each stage must pass its focused regression scenarios before the next stage begins.

**Rationale**: The first two stages address data-loss and cross-profile contamination risks. Structural extraction before those invariants are explicit would move the same ambiguity across more files and increase rollback cost. The clarified specification explicitly makes lifecycle and persistence safety precede structural extraction.

**Alternatives considered**:

- Full decomposition in one release — rejected because it combines lifecycle changes, persistence changes, and broad code movement before the safety boundaries are proven.
- Safety-only fixes — rejected because the stated feature includes maintainability improvements and the current `lib.rs` boundary remains a long-term coupling hotspot.

## Decision 2 — Use a per-profile runtime epoch and owned task registry

**Decision**: Introduce a profile runtime owner that carries the active profile identity and an epoch/generation gate. Every profile-owned task registers against that runtime and is cancellable through it. Profile close invalidates the epoch before teardown, then cancels and awaits owned tasks in a defined order.

The shutdown order is:

1. invalidate the runtime epoch to prevent late registration;
2. stop and await monitors, QR hosts/guests, Docker streams, transfers, mirrors, and tunnels;
3. stop interactive SSH sessions and terminal channels;
4. drain fingerprint and keyboard-interactive waiters;
5. release database/key material and the writer claim last.

A timeout or unacknowledged cancellation returns a close error and does not expose the profile as closed.

**Rationale**: `close_profile` currently clears several maps but does not own all task types or await all pollers. `SshState` also has generation/replay state that can admit a late handshake after close. LifecycleResearch found missing cleanup for `transfer_cancels`, `session_generation`, `session_tunnel_specs`, `DockerStreams`, and `QrTransferState`; monitor pollers have stop signals but no join handles. Mirror and tunnel already provide joinable patterns that can inform the owner.

**Evidence**: `src-tauri/src/lib.rs:913-1008,5945-5950,6123+`; `src-tauri/src/ssh_manager.rs:83-93`; `src-tauri/src/monitor.rs:230-281,461-563`; `src-tauri/src/mirror.rs:136-138,701-785,860-990`; `src-tauri/src/tunnel.rs:376-524`; `src-tauri/src/docker.rs:20-28,560-648`; `src-tauri/src/qr_transfer.rs:458-589,861-900`.

**Alternatives considered**:

- Clear maps and rely on dropped `Arc`s — rejected because pollers, spawned handlers, and transfer commands can remain alive after map removal.
- Best-effort cancellation followed by profile switch — rejected by clarification because old work must not outlive the profile boundary.
- One generic task abstraction immediately — deferred; first establish the lifecycle contract using existing subsystem-specific cancellation and join behavior.

## Decision 3 — Make one canonical vault-save coordinator

**Decision**: Route every ordinary profile save through one per-profile coordinator covering:

```text
mutation ordering → state snapshot → SQLite serialization → compression/seal → history rotation → temporary-file sync → atomic rename → generation commit
```

The coordinator must serialize the generation reservation and durable commit. It must not calculate `generation + 1` before entering the serialized boundary. A failed save must not advance the cached generation.

Mutation ordering must be deterministic. Distinct accepted mutations are retained; if accepted mutations target the same field, the later accepted mutation wins. The mutation and save ordering mechanism must not rely on caller scheduling alone.

**Rationale**: `save_vault_internal` currently keeps the connection mutex across the synchronous save (`src-tauri/src/lib.rs:281-310`), while `save_vault_async` snapshots generation and other metadata before `spawn_blocking` (`src-tauri/src/lib.rs:738-770`). Concurrent async calls can therefore select the same next generation and race during replacement/history rotation. The existing vault sealing code already provides the required atomic file and cryptographic invariants and should remain the implementation used inside the coordinator.

**Evidence**: `src-tauri/src/lib.rs:281-348,738-770,3544-4754,6640-6651,10120-10427`; `src-tauri/src/vault.rs:542-574,1792-1922`; `src-tauri/src/recovery.rs:194-219`.

**Alternatives considered**:

- Add only a save mutex around the current async wrapper — rejected because same-field mutation order would still depend on mutations occurring before the save lock is acquired.
- Keep synchronous and asynchronous save paths separate — rejected because separate paths recreate the current ordering bug and blocking behavior inconsistency.
- Change vault format or cryptographic constants — rejected; existing sealed format, legacy reads, key wrapping, history, and error classification are compatibility contracts.

## Decision 4 — Extract repositories and services behind unchanged adapters

**Decision**: Keep Tauri commands as thin adapters and move internal responsibilities into these boundaries over the staged refactor:

- `profile/` — lifecycle transitions and `ProfileRuntime` shutdown;
- `vault/` — save coordination and existing vault-format internals;
- `database/` — schema/migrations and typed profile repositories;
- `ssh/` — connection/session operations and host-key verification boundary;
- `sftp/` — remote/local transfer operations;
- `monitor/` — monitor service and poller ownership;
- `transfer/` — QR/recovery/import staging integration.

The existing command names, argument names, event names, error prefixes, conflict sentinels, and platform refusals remain unchanged.

**Rationale**: `lib.rs` currently combines composition, persistence, CRUD, SSH workers, SFTP/local file operations, monitor adapters, and command registration. Moving adapters last makes the external contract stable while reducing direct cross-module access to `DbState` and `SshState`.

**Alternatives considered**:

- Split `lib.rs` by arbitrary line ranges — rejected because it would preserve the current coupling and make ownership less clear.
- Rename or redesign the IPC surface during the refactor — rejected because it expands scope and creates frontend migration risk.
- Introduce a new backend or account layer — rejected by the local-only constitution and feature scope.

## Decision 5 — Treat the command/event surface as a compatibility contract

**Decision**: Create a contract inventory for the existing Tauri commands, events, payload shapes, errors, and platform availability. The refactor may change internal module paths but must preserve the inventory.

Critical preserved examples include:

- `terminal-output-{tid}` carrying base64 payloads;
- fingerprint and keyboard-interactive prompt events with nonce handling;
- connection/session lifecycle events;
- SFTP transfer progress and `EXISTS:<path>` overwrite sentinel;
- tunnel, mirror, monitor, and QR state/log events;
- vault lock/background/migration events;
- bracketed error codes and Android desktop-only refusals.

**Evidence**: `src-tauri/src/lib.rs:10459-10745`; `src-tauri/src/ssh_manager.rs:23-42,258-349`; `src-tauri/src/tunnel.rs:34-212`; `src-tauri/src/mirror.rs:82-226`; `src-tauri/src/monitor.rs:119-180`; `src-tauri/src/qr_transfer.rs:465-469`; existing contract inventory in `specs/002-e2e-vault-migration/contracts/tauri-command-contract.md`.

**Alternatives considered**:

- Regenerate the interface contract from new service APIs — rejected because service APIs are internal and do not define compatibility.
- Let each extracted service define its own error/event translation — rejected because it would create drift and inconsistent renderer behavior.

## Decision 6 — Preserve security and platform boundaries without new dependencies

**Decision**: Use existing Rust/Tauri boundaries and dependencies. No new crate, capability, CSP origin, account system, telemetry, or network backend is required for this refactor. Keep desktop-only dependencies and calls behind existing target gates, keep Android bridge/keyring initialization unchanged, and retain Rust ownership of crypto, vault I/O, SSH/SFTP, local filesystem mutation, tunnels, mirrors, and Docker operations.

**Rationale**: The work is structural and reliability-focused. New dependencies or capabilities would create a separate governance decision and increase the chance of changing security behavior while moving code.

**Evidence**: `.specify/memory/constitution.md:180-299`; `src-tauri/Cargo.toml:59-70,183-230`; `src-tauri/src/lib.rs:10464-10576`; `src-tauri/src/android_bridge.rs`.

**Alternatives considered**:

- Add a task framework or service runtime dependency — rejected because Tokio and existing cancellation primitives are sufficient.
- Move privileged logic into the renderer during extraction — rejected by Principle II.
- Normalize desktop and Android into separate implementations — rejected by Principle III.

## Decision 7 — Verification uses focused regression tests plus an end-to-end smoke guide

**Decision**: Add focused proof for the newly clarified invariants while preserving existing tests:

- overlapping saves produce strictly increasing generations and no duplicate history names;
- failed saves leave cached generation unchanged;
- same-field accepted mutations retain deterministic final state;
- profile close prevents late task registration and awaits every owned resource;
- stale session/tunnel/transfer state cannot cross profile epochs;
- current and legacy vault workflows remain readable and writable as before;
- command/event/error/platform contract checks remain unchanged.

Use `cargo test --manifest-path src-tauri/Cargo.toml` and `npm run typecheck` as baseline checks. The quickstart adds manual profile-switch and representative SSH/SFTP/background-task scenarios because live SSH and platform-specific shutdown behavior are not fully covered by the in-crate tests.

**Rationale**: Existing tests cover vault format/keywrap/history, HLC, tunnel behavior, and path/name validation, but not the identified lifecycle races or async save ordering. Focused tests defend observable behavior without pinning implementation structure.

**Alternatives considered**:

- Rely only on the existing test suite — rejected because the identified races and teardown gaps are currently untested.
- Add broad UI automation — deferred because the repository has no browser test harness and the highest-value proof is native lifecycle/persistence behavior plus a manual smoke path.

## Resolved unknowns

- Language and runtime: Rust 2021, MSRV 1.89, Tokio/Tauri 2; no new dependency required.
- Persistence: existing SQLite-in-vault and sealed vault files; no schema or format change required by this refactor.
- Target: desktop and Android through the shared Rust library with existing `cfg` gates.
- Performance: expensive serialization/sealing remains off the Tokio worker path; profile close is bounded by existing operation timeouts but cannot report success before cancellation acknowledgement.
- Scope: staged internal refactor; no new user-facing workflow or external service.
