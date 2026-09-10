---

description: "Task list for staged profile lifecycle, vault persistence, and Rust module refactor"
---

# Tasks: Rust Module Refactor

**Input**: Design documents from `/specs/004-rust-module-refactor/`

**Prerequisites**: `plan.md`, `spec.md`, `research.md`, `data-model.md`, `contracts/`, `quickstart.md`

**Tests**: Included because `FR-012` explicitly requires regression coverage for profile transitions, concurrent saves, shutdown cleanup, compatibility behavior, and security-sensitive rejection paths.

**Organization**: Tasks are grouped by user story. The staged dependencies preserve the clarified order: lifecycle safety, vault persistence, structural extraction, then cross-cutting security/platform verification.

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Establish the two ownership boundaries without changing the external command or event surface.

- [X] T001 [P] Create `src-tauri/src/profile_runtime.rs` with the concrete profile lifecycle state and runtime ownership types defined in `specs/004-rust-module-refactor/data-model.md`
- [X] T002 [P] Create `src-tauri/src/vault_store.rs` with the concrete save-coordinator and persistence-operation types defined in `specs/004-rust-module-refactor/data-model.md`
- [X] T003 Register `profile_runtime` and `vault_store` in `src-tauri/src/lib.rs` without changing the `generate_handler!` command names or managed-state behavior

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Define the shared lifecycle admission, resource-ownership, and persistence interfaces that user-story implementations will complete before integration.

**Critical**: User-story work depends on this phase.

- [X] T004 Define `ProfileLifecycle` states, transition APIs, and invalid-transition error types in `src-tauri/src/profile_runtime.rs`
- [X] T005 Define runtime epoch admission, resource registration, cancellation, and shutdown interfaces in `src-tauri/src/profile_runtime.rs`
- [X] T006 Define the `VaultSaveCoordinator` interface, ordered persistence-operation inputs, and generation-commit seam in `src-tauri/src/vault_store.rs`
- [X] T007 Add `ProfileRuntime` and `VaultSaveCoordinator` ownership to `DbState` and the Tauri-managed state wiring in `src-tauri/src/lib.rs`
- [X] T008 Add shared error and compatibility helpers for lifecycle/save adapters in `src-tauri/src/lib.rs` while preserving existing `[STATE]`, `[CRYPTO]`, `[VAULT]`, `[DATABASE]`, and `[FILE]` outcomes

---

## Phase 3: User Story 1 — Safely switch between profiles (Priority: P1) 🎯 MVP

**Goal**: Closing a profile becomes a strict isolation barrier, and selecting/deleting profiles cannot bypass lifecycle state.

**Independent Test**: Run Scenarios A and D in `specs/004-rust-module-refactor/quickstart.md`; profile close must wait for completion/cancellation acknowledgement, reject timeout completion, and prevent stale profile work from affecting the next profile.

### Tests for User Story 1

> Write these tests first and confirm they fail against the pre-change behavior where practical.

- [X] T009 [US1] Add lifecycle transition, stale-epoch admission, failed-close retention, shutdown-timeout retention/retry, and resource-registration tests in `src-tauri/src/profile_runtime.rs`
- [X] T010 [P] [US1] Add monitor stop-signal and awaited-poller shutdown tests in `src-tauri/src/monitor.rs`
- [X] T011 [P] [US1] Add Docker stream and QR session cancellation/ownership tests in `src-tauri/src/docker.rs` and `src-tauri/src/qr_transfer.rs`

### Implementation for User Story 1

- [X] T012 [US1] Implement the ordered `ProfileRuntime::shutdown` coordinator and strict close result in `src-tauri/src/profile_runtime.rs`
- [X] T013 [US1] Route `select_profile`, `close_profile`, and `delete_profile` through lifecycle admission; reject active-profile deletion unless the lifecycle is already `Picker` in `src-tauri/src/lib.rs`
- [X] T014 [US1] Invalidate `session_generation`, `session_tunnel_specs`, and late connect-worker registration on profile close in `src-tauri/src/lib.rs` and `src-tauri/src/ssh_manager.rs`
- [X] T015 [US1] Register monitor, mirror, and tunnel resources with the profile runtime and await their existing stop/join paths in `src-tauri/src/monitor.rs`, `src-tauri/src/mirror.rs`, and `src-tauri/src/tunnel.rs`
- [X] T016 [US1] Register SFTP transfers, terminal tasks, Docker streams, and QR host/guest sessions with the profile runtime and await cancellation in `src-tauri/src/lib.rs`, `src-tauri/src/ssh_manager.rs`, `src-tauri/src/docker.rs`, and `src-tauri/src/qr_transfer.rs`
- [X] T017 [US1] Define and preserve the shutdown-timeout path: `ProfileRuntime::shutdown` returns the existing `[STATE]` error, retains unavailable `Closing` state, releases the writer claim last, and allows a later close attempt to resume pending work in `src-tauri/src/lib.rs` and `src-tauri/src/profile_runtime.rs`
- [X] T018 [US1] Add end-to-end lifecycle assertions for profile-A-to-profile-B isolation in `src-tauri/src/profile_runtime.rs` and `src-tauri/src/lib.rs`
- [X] T019 [US1] Run focused lifecycle tests plus the complete Rust and TypeScript regression commands, then record Gate 1 results against `specs/004-rust-module-refactor/quickstart.md`

**Checkpoint**: User Story 1 is independently testable and can serve as the MVP.

---

## Phase 4: User Story 2 — Preserve vault changes during saves (Priority: P1)

**Goal**: Overlapping saves preserve distinct mutations, same-field mutations have deterministic last-accepted ordering, and failed saves do not commit generations.

**Independent Test**: Run Scenario B in `specs/004-rust-module-refactor/quickstart.md`; reopen the profile after overlapping saves and verify data, generation, history, and failure behavior.

### Tests for User Story 2

> Write these tests first and confirm they fail against the current async save race where practical.

- [X] T020 [P] [US2] Add overlapping-save serialization tests asserting strictly increasing generations in `src-tauri/src/vault_store.rs`
- [X] T021 [P] [US2] Add failed-save, atomic-replacement, history-name, and unchanged-generation tests in `src-tauri/src/vault.rs`
- [X] T022 [P] [US2] Add distinct-change and same-field tests asserting the coordinator admission sequence—not completion order—determines the retained mutation in `src-tauri/src/lib.rs`

### Implementation for User Story 2

- [X] T023 [US2] Implement the canonical per-profile `VaultSaveCoordinator` queue/lock, monotonic admission sequence, and generation reservation in `src-tauri/src/vault_store.rs`
- [X] T024 [US2] Migrate `save_vault_internal`, `save_vault_async`, and all ordinary mutation callsites to the coordinator in `src-tauri/src/lib.rs`
- [X] T025 [US2] Enforce mutation ordering at coordinator admission so same-field accepted mutations retain the later admission sequence regardless of save completion order in `src-tauri/src/lib.rs`
- [X] T026 [US2] Route close, fresh-create, unlock-resave, and legacy-migration persistence through the coordinator in `src-tauri/src/lib.rs`
- [X] T027 [US2] Preserve vault sealing, history rotation, rollback high-water, writer-claim, keystore classification, and error semantics while integrating the coordinator in `src-tauri/src/vault.rs` and `src-tauri/src/keystore.rs`
- [X] T028 [US2] Add current-format and legacy-format reopen/save regression coverage in `src-tauri/src/vault.rs` and `src-tauri/src/lib.rs`
- [X] T029 [US2] Run focused save tests plus the complete Rust and TypeScript regression commands, then record Gate 2 results against `specs/004-rust-module-refactor/quickstart.md`

**Checkpoint**: User Stories 1 and 2 are independently testable; profile isolation and durable save ordering are protected before structural extraction.

---

## Phase 5: User Story 3 — Preserve workflows and security boundaries (Priority: P2)

**Goal**: Extract internal repositories and command services without changing existing SSH, terminal, SFTP, tunnel, monitor, mirror, Docker, QR, profile-management, vault-security, or platform behavior.

**Independent Test**: Run Scenarios C and E in `specs/004-rust-module-refactor/quickstart.md` and compare command, event, conflict, security, platform, and error outcomes with the frozen contract.

### Tests for User Story 3

- [X] T030 [P] [US3] Add command-registry and event-payload regression fixtures for profile, terminal, fingerprint, KBI, SFTP, tunnel, mirror, monitor, Docker, QR, and vault events in `src-tauri/src/lib.rs` and `src-tauri/src/ssh_manager.rs`
- [X] T031 [P] [US3] Add workflow-preservation tests for SSH/session teardown, SFTP conflict/cancellation, tunnels, mirrors, and monitors in `src-tauri/src/ssh_manager.rs`, `src-tauri/src/tunnel.rs`, `src-tauri/src/mirror.rs`, and `src-tauri/src/monitor.rs`

### Implementation for User Story 3

- [X] T032 [US3] Extract typed schema/migration helpers and profile CRUD repositories into `src-tauri/src/database/mod.rs` and `src-tauri/src/database/repository.rs` without changing existing SQLite schema behavior
- [X] T033 [P] [US3] Extract thin SSH/session command adapters into `src-tauri/src/commands/ssh.rs` while preserving `src-tauri/src/ssh_manager.rs` TOFU and terminal behavior
- [X] T034 [P] [US3] Extract thin SFTP/local-transfer command adapters into `src-tauri/src/commands/sftp.rs` while preserving path guards, transfer events, cancellation, and `EXISTS:<path>` behavior
- [X] T035 [US3] Create thin profile/vault/recovery/QR/import command adapter modules in `src-tauri/src/commands/profile.rs` and `src-tauri/src/commands/transfer.rs`, delegating lifecycle and persistence work to existing owners
- [X] T036 [US3] Route profile, vault, recovery, QR, and import commands through `src-tauri/src/commands/profile.rs` and `src-tauri/src/commands/transfer.rs`, preserving lifecycle and persistence ownership
- [X] T037 [US3] Route Docker, monitor, tunnel, mirror, local filesystem, and about/update commands through `src-tauri/src/commands/operations.rs`, preserving event/error translation and secondary session IDs from `src-tauri/src/lib.rs`, `src-tauri/src/docker.rs`, `src-tauri/src/monitor.rs`, `src-tauri/src/tunnel.rs`, `src-tauri/src/mirror.rs`, and `src-tauri/src/about.rs`
- [X] T038 [US3] Wire the User Story 3 command/event/workflow compatibility matrix to the extracted adapters in `specs/004-rust-module-refactor/quickstart.md` and the frozen contract

### Security and platform regression tests for User Story 3

- [X] T039 [P] [US3] Add vault keywrap, legacy/current format, rollback, keystore classification, and recovery-sidecar regression coverage in `src-tauri/src/vault.rs`, `src-tauri/src/keystore.rs`, and `src-tauri/src/recovery.rs`
- [X] T040 [P] [US3] Add unsafe-path, TOFU/nonce, Docker allow-list, and protected-command rejection coverage in `src-tauri/src/lib.rs`, `src-tauri/src/ssh_manager.rs`, and `src-tauri/src/docker.rs`
- [X] T041 [US3] Audit extracted command/service boundaries against the capability and CSP contract in `src-tauri/capabilities/default.json`, `src-tauri/capabilities/desktop.json`, and `src-tauri/tauri.conf.json`
- [X] T042 [US3] Preserve desktop-only dependency gates, Android bridge/keyring initialization, and explicit platform refusals in `src-tauri/Cargo.toml`, `src-tauri/src/lib.rs`, and `src-tauri/src/android_bridge.rs`
- [X] T043 [US3] Verify renderer error-code parsing, retry behavior, and no-secret/no-credential persistence assumptions in `src/util/vaultErrors.ts` and the extracted command adapters under `src-tauri/src/commands/`
- [X] T044 [US3] Run the focused workflow, security, and platform tests and document Scenarios C and E results in `specs/004-rust-module-refactor/quickstart.md`
- [X] T045 [US3] Run the complete Rust and TypeScript regression commands, record Gate 3 results, and resolve any contract or platform regressions before polish

**Checkpoint**: All three selected user stories meet their independent acceptance criteria and the constitution gates remain satisfied.

---

## Phase 7: Polish & Cross-Cutting Concerns

**Purpose**: Remove refactor residue, align documentation, and perform final validation.

- [X] T046 [P] Resolve the unused `TransferSession.bind_addr` warning in `src-tauri/src/qr_transfer.rs` by removing it or enforcing it in the transfer contract
- [X] T047 [P] Update ownership, lifecycle, persistence, and module-boundary documentation in `ARCHITECTURE.md`
- [X] T048 Update `specs/004-rust-module-refactor/data-model.md`, `specs/004-rust-module-refactor/contracts/tauri-command-contract.md`, and `specs/004-rust-module-refactor/quickstart.md` to match final paths and behavior
- [X] T049 Run formatting and final static checks for `src-tauri/` and the renderer without changing generated or unrelated files
- [X] T050 Execute all phase gates and manual scenarios in `specs/004-rust-module-refactor/quickstart.md`, then record final acceptance evidence

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: T001–T003; no implementation dependency beyond the existing repository.
- **Foundational (Phase 2)**: T004–T008 depend on Setup and block all user-story work.
- **User Story 1 (Phase 3)**: T009–T019 depend on Foundational; this is the MVP and first safety gate.
- **User Story 2 (Phase 4)**: T020–T029 depend on User Story 1 because strict lifecycle ownership must exist before close/save integration is finalized.
- **User Story 3 (Phase 5)**: T030–T045 depend on User Stories 1 and 2; extraction and security/platform validation follow proven lifecycle and persistence boundaries.
- **Polish (Phase 7)**: T046–T050 depend on all three selected user stories and phase gates.

### User Story Dependencies

- **User Story 1 (P1)**: Depends only on Foundational; independently delivers the MVP.
- **User Story 2 (P1)**: Depends on User Story 1's lifecycle and close ordering; independently validates persistence after that prerequisite.
- **User Story 3 (P2)**: Depends on User Stories 1 and 2; extraction must use their runtime and save boundaries, then preserve security and platform contracts.

### Parallel Opportunities

- **Setup**: T001 and T002 can run in parallel; T003 follows both.
- **Foundational**: T004/T005 and T006 can be developed in parallel; T007/T008 integrate them.
- **User Story 1**: T010 and T011 can run in parallel with T009; T015 and T016 can proceed in parallel after T012, while T013/T014 remain serialized through `src-tauri/src/lib.rs`.
- **User Story 2**: T020, T021, and T022 can run in parallel; T023 must precede T024–T027.
- **User Story 3**: T030, T031, T039, and T040 can run in parallel; T033, T034, and T035 can run in parallel after the repository boundary is agreed, followed by T036/T037 and then T041–T045.
- **Polish**: T046–T048 can run in parallel after functional completion; T049/T050 are final gates.

## Parallel Execution Examples

### User Story 1

```text
Task: "Add monitor stop-signal and awaited-poller shutdown tests in src-tauri/src/monitor.rs"
Task: "Add Docker stream and QR session cancellation/ownership tests in src-tauri/src/docker.rs and src-tauri/src/qr_transfer.rs"
```

### User Story 2

```text
Task: "Add overlapping-save serialization tests in src-tauri/src/vault_store.rs"
Task: "Add failed-save and history tests in src-tauri/src/vault.rs"
Task: "Add mutation-order tests in src-tauri/src/lib.rs"
```

### User Story 3

```text
Task: "Extract SSH command adapters into src-tauri/src/commands/ssh.rs"
Task: "Extract SFTP command adapters into src-tauri/src/commands/sftp.rs"
Task: "Extract profile and transfer adapters into src-tauri/src/commands/profile.rs and src-tauri/src/commands/transfer.rs"
```

### User Story 3 — Security and platform coverage

```text
Task: "Add vault and keystore regression coverage in src-tauri/src/vault.rs, src-tauri/src/keystore.rs, and src-tauri/src/recovery.rs"
Task: "Add path, TOFU, and Docker rejection coverage in src-tauri/src/lib.rs, src-tauri/src/ssh_manager.rs, and src-tauri/src/docker.rs"
```

## Implementation Strategy

### MVP First — User Story 1

1. Complete Setup and Foundational phases.
2. Implement strict profile runtime admission and shutdown.
3. Validate profile switching, active-profile deletion, stale epochs, and resource cleanup.
4. Stop at Gate 1 and preserve the passing lifecycle boundary.

### Incremental Delivery

1. Add User Story 2 and validate serialized vault persistence at Gate 2.
2. Add User Story 3 and extract repositories/adapters while preserving workflow, security, and platform contracts at Gate 3.
3. Complete Polish only after all three selected story gates pass.

### Notes

- Every task has a checkbox, sequential ID, required parallel marker when applicable, story label in story phases, and an exact file path.
- Tests are placed before implementation within each story because the specification explicitly requires focused regression coverage.
- Avoid broad same-file parallel edits; serialize changes to `src-tauri/src/lib.rs` through the listed dependencies.
- Do not change vault constants, IPC names, event payloads, error prefixes, capability files, or platform behavior while extracting code.
