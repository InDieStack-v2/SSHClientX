# Quickstart: Rust Module Refactor Validation

**Feature**: `004-rust-module-refactor` | **Date**: 2026-09-10

This guide validates the staged refactor against the lifecycle, persistence, compatibility, and security outcomes in [spec.md](spec.md). It complements [data-model.md](data-model.md) and [contracts/tauri-command-contract.md](contracts/tauri-command-contract.md).

## Prerequisites

- Node 20+ and npm dependencies installed.
- Rust toolchain meeting the repository MSRV.
- A disposable backup of any local SSHClientX profile used for manual scenarios.
- For live workflow checks: a reachable test SSH server with a non-production account.
- For Android checks: the existing Android environment and USB/ADB setup.

## Baseline commands

Run from the repository root:

```bash
npm run typecheck
cargo test --manifest-path src-tauri/Cargo.toml
cargo check --manifest-path src-tauri/Cargo.toml
```

Expected outcomes:

- TypeScript type checking succeeds.
- All existing Rust tests pass.
- The Rust crate checks successfully without changing default feature behavior.

## Scenario A — Strict profile shutdown

1. Launch the application and open disposable profile A.
2. Start representative work where available: an SSH session, terminal, SFTP transfer, monitor, mirror, tunnel, Docker log stream, and QR transfer session.
3. Request profile close.
4. Expect each profile-owned operation to complete or acknowledge cancellation before close reports success.
5. If an operation reaches its existing timeout without acknowledgement, expect `ProfileRuntime::shutdown` to return the existing `[STATE]` close error, retain the profile in unavailable `Closing` state, and reject selection/deletion until a later close attempt resolves the remaining work.
6. Open profile B only after successful close; verify no profile-A event, transfer, session, tunnel, monitor, mirror, Docker, QR, or terminal work affects B.
7. Reuse a session identifier from A in B and verify no A-owned state is applied to B.

Covers: FR-001–FR-004, SC-001, SC-005.

## Scenario B — Overlapping saves and same-field ordering

1. Open a disposable profile.
2. Apply two distinct profile changes and trigger overlapping persistence requests.
3. Reopen the profile and verify both changes are present.
4. Apply two accepted changes to the same field in a controlled coordinator admission order.
5. Reopen the profile and verify the mutation with the later admission sequence is retained, regardless of save completion order.
6. Force or simulate a save failure before durable replacement where the focused test seam allows it.
7. Verify the failed attempt does not appear as the current revision and the cached generation does not advance.

Covers: FR-005–FR-007, SC-002, existing vault compatibility and history behavior.

## Scenario C — Existing workflow compatibility

With a disposable profile and test SSH server:

1. Connect and verify terminal output still arrives through the existing terminal event contract.
2. Approve and reject host-key prompts using the existing nonce flow.
3. Run an SFTP upload/download and verify progress, cancellation, and `EXISTS:<path>` conflict behavior.
4. Start and stop a tunnel, monitor, mirror, and Docker stream where supported.
5. Close the profile and verify all started work is included in strict shutdown.

Covers: FR-008–FR-012, SC-003–SC-005, [contracts/tauri-command-contract.md](contracts/tauri-command-contract.md).

## Scenario D — Profile lifecycle rejection paths

1. While profile A is unlocked, attempt to select profile B.
2. Expect selection of profile B and deletion of active profile A to be rejected until A has successfully closed and returned to the picker.
3. While profile A is active, attempt to delete A.
4. Expect active-profile deletion to be rejected.
5. After successful return to the picker, delete an inactive disposable profile.
6. Verify the inactive profile deletion behavior remains unchanged.

Covers: FR-001, FR-002, FR-009, SC-004.

## Scenario E — Security and platform regression

1. Verify vault unlock still requires the existing device factor and vault password behavior.
2. Verify legacy and current supported vault files open and save according to the existing compatibility rules.
3. Attempt an unsafe local path and an untrusted host key; expect existing rejection/verification behavior.
4. Confirm no new shell, filesystem, webview, CSP, capability, telemetry, backend, or credential-storage behavior is present.
5. On Android, verify shared-core workflows and existing desktop-only refusals remain unchanged.

Covers: FR-007, FR-010–FR-013, SC-003, SC-006, constitution Principles I–III.

## Phase gates

- **Gate 1 — Lifecycle**: Scenario A and D pass; focused lifecycle tests prove no late registration or stale epoch use; baseline Rust and TypeScript commands pass.
- **Gate 2 — Persistence**: Scenario B passes; focused save tests prove strictly increasing generations, no duplicate history revisions, and unchanged generation after failure; baseline Rust and TypeScript commands pass.
- **Gate 3 — Extraction**: Scenario C and E pass; contract inventory remains unchanged; baseline Rust and TypeScript commands pass.

Do not advance to the next gate after a failure. Preserve the last passing stage for rollback and diagnosis.

## Implementation evidence

Automated evidence for the current implementation:

- `cargo test --manifest-path src-tauri/Cargo.toml`: 136 tests passed.
- `cargo check --manifest-path src-tauri/Cargo.toml`: passed.
- `npm run typecheck`: passed.
- Capability, CSP, Android-gate, and renderer error-code surfaces were
  inspected without changes to the frozen contract.

Live Scenarios A, B, C, D, and E require a running Tauri window and, for
Scenarios A, C, and E, a reachable disposable SSH server. They are not
claimed as automated evidence here.
