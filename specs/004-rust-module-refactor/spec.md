# Feature Specification: Rust Module Refactor

**Feature Branch**: `004-rust-module-refactor`

**Created**: 2026-09-10

**Status**: Draft

**Input**: User description: "review & refactor"

## Clarifications

### Session 2026-09-10

- Q: When profile closure encounters an active remote operation that does not stop immediately, should closure wait for every operation to finish or cancel before completing? → A: Require every profile-owned operation to finish or acknowledge cancellation before closure completes; report an error if the existing timeout is reached.
- Q: If two overlapping changes update the same profile field, which result should the system preserve? → A: Preserve the last accepted mutation in a deterministic order; distinct changes must still be retained.
- Q: Should this feature deliver the full refactor in one release, or stage the work so lifecycle and vault safety come first and structural module extraction follows? → A: Use staged delivery within one feature; make profile lifecycle and vault persistence mandatory first, then extract workflow modules with regression gates.


## User Scenarios & Testing *(mandatory)*

### User Story 1 - Safely switch between profiles (Priority: P1)

As a user, I can close one profile and open another without the previous profile continuing to perform work or receiving new operations.

**Why this priority**: Profile boundaries protect user data and are the highest-risk area identified during review.

**Independent Test**: Open a profile, start representative sessions and background work, close it, open a second profile, and verify that no work from the first profile remains active or affects the second profile.

**Acceptance Scenarios**:

1. **Given** an unlocked profile with active sessions, transfers, monitoring, mirroring, or other background work, **When** the user closes the profile, **Then** all work owned by that profile is completed or acknowledges cancellation before the profile is considered closed.
2. **Given** an unlocked profile, **When** the user attempts to select another profile or delete the active profile, **Then** the request is rejected until the current profile has successfully closed and returned to the picker.
3. **Given** profile A has been closed and profile B is opened, **When** a session identifier used by profile A is reused, **Then** no state or operation from profile A is applied to profile B.

---

### User Story 2 - Preserve vault changes during saves (Priority: P1)

As a user, I can make and save profile changes without one save overwriting another or leaving the profile with an incorrect revision state.

**Why this priority**: Vault persistence is the data-integrity boundary. A refactor must not introduce lost updates or inconsistent saved history.

**Independent Test**: Trigger overlapping saves containing distinct changes, reopen the profile, and verify that every completed change is present and the saved revision sequence is consistent.

**Acceptance Scenarios**:

1. **Given** two changes are being saved at overlapping times, **When** both saves complete successfully, **Then** reopening the profile shows both changes.
2. **Given** a save fails before its durable commit, **When** the profile is reopened, **Then** no partially committed revision is presented as the current profile state.
3. **Given** a profile uses a supported legacy or current vault file, **When** it is opened and saved, **Then** the existing compatibility and security behavior is preserved.
4. **Given** two overlapping changes update the same profile field, **When** both mutations are accepted by the save coordinator, **Then** the mutation admitted later by the coordinator's monotonic admission sequence is the value retained after reopening.

---

### User Story 3 - Preserve workflows and security boundaries (Priority: P2)

As a user, I can continue using SSHClientX workflows after the refactor without changes to terminal, file transfer, tunnel, monitoring, mirroring, Docker, vault security, or platform behavior.

**Why this priority**: The refactor exists to improve maintainability and safety, not to change supported product behavior or weaken security and cross-platform guarantees.

**Independent Test**: Exercise existing SSH, terminal, SFTP, tunnel, monitor, mirror, Docker, vault, path, host-key, and platform workflows from an unlocked profile and compare observable results with the pre-refactor contract.

**Acceptance Scenarios**:

1. **Given** a valid server profile, **When** the user connects and opens a terminal, **Then** the session establishes and terminal output remains available in the existing form.
2. **Given** a connected server and accessible files, **When** the user performs a supported file transfer, **Then** the transfer succeeds, reports existing conflict and error outcomes, and does not expose file bytes through unsupported paths.
3. **Given** configured tunnel, monitor, mirror, Docker, or QR operations, **When** the user starts and stops them, **Then** their existing lifecycle and user-visible status remain available and profile close includes their shutdown.
4. **Given** the refactored application, **When** a user performs vault, filesystem, SSH, SFTP, tunnel, mirror, or Docker operations, **Then** the operation remains protected by the existing security boundary.
5. **Given** a supported desktop or mobile environment, **When** the user performs the workflows available on that environment, **Then** platform-specific restrictions and capabilities remain unchanged.
6. **Given** an untrusted server key or unsafe local path, **When** the user attempts the operation, **Then** the existing verification or rejection behavior is preserved.

### Edge Cases

- A user attempts to select or delete a profile while the current profile is still unlocked.
- Two profile changes request persistence at the same time.
- Two overlapping changes update the same profile field.
- A save fails during serialization, encryption, history rotation, or file replacement.
- A profile is closed while a transfer, monitor poll, mirror action, tunnel, Docker stream, QR transfer, or terminal task is in progress.
- A session identifier or background task identifier is reused after switching profiles.
- A supported legacy vault is opened, saved, or migrated during the refactor.
- A remote connection is unavailable while profile shutdown is requested.
- A platform does not support a desktop-only capability.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST enforce an explicit, deterministic lifecycle for selecting, unlocking, locking, closing, and deleting profiles.
- **FR-002**: The system MUST reject deletion of the active profile unless the lifecycle is already in `Picker`; deletion of an inactive profile is allowed only after the active runtime has been fully closed.
- **FR-003**: The system MUST prevent operations owned by a closed profile from affecting a subsequently opened profile, including when identifiers are reused.
- **FR-004**: The system MUST require every profile-owned background operation to complete or acknowledge cancellation before reporting that profile closure has finished; the `ProfileRuntime::shutdown` coordinator owns the existing operation timeout, returns the existing `[STATE]` close error when the timeout expires, and leaves the lifecycle in unavailable `Closing` state until a later close attempt resolves the remaining work.
- **FR-005**: The system MUST serialize overlapping profile saves so that successful distinct changes are not lost, revision metadata remains consistent, and same-field conflicts retain the mutation with the later monotonic coordinator admission sequence, regardless of completion order.
- **FR-006**: The system MUST preserve atomicity and fail-closed behavior when a save cannot complete.
- **FR-007**: The system MUST preserve supported vault compatibility, including current and legacy readable formats, existing key protection rules, and existing history behavior.
- **FR-008**: The system MUST preserve existing user-visible SSH, terminal, SFTP, transfer, tunnel, monitor, mirror, Docker, QR transfer, recovery, and profile-management behavior unless explicitly superseded by this specification.
- **FR-009**: The system MUST preserve existing user-visible actions, notifications, error outcomes, and conflict behavior.
- **FR-010**: The system MUST keep privileged operations, secrets, vault data, local path enforcement, host-key verification, and remote command restrictions within their existing protected boundary.
- **FR-011**: The system MUST preserve supported desktop and mobile capability differences without introducing a second behavior implementation for the same workflow.
- **FR-012**: The system MUST provide regression coverage for profile transitions, concurrent saves, shutdown cleanup, compatibility behavior, and security-sensitive rejection paths after each refactor phase.
- **FR-013**: The refactor MUST NOT add an account system, backend service, telemetry, cloud synchronization, or a new cross-device data-sharing path.

### Key Entities

- **Profile Lifecycle**: The allowed states and transitions for a selected, unlocked, locked, closing, or inactive profile.
- **Profile Runtime**: The set of sessions, transfers, monitors, mirrors, tunnels, streams, and temporary operations owned by one active profile.
- **Vault Revision**: A durable saved representation of profile data with its associated integrity, compatibility, and ordering information.
- **Persistence Operation**: A requested save that moves profile changes from active state to a durable vault revision.
- **Compatibility Contract**: The externally observable command, event, error, vault-format, security, and platform behavior that the refactor must preserve.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: In 100 repeated profile-switch scenarios containing representative background work, zero operations owned by the closed profile affect the newly opened profile.
- **SC-002**: In 100 repeated overlapping-save scenarios with distinct changes, 100% of successfully completed changes are present after reopening the profile.
- **SC-003**: 100% of existing regression suites pass at each completed lifecycle, persistence, and extraction phase gate, with no increase in security-sensitive failures or compatibility failures.
- **SC-004**: All existing supported user workflows exercised in the regression matrix complete with the same observable command, event, conflict, and error outcomes as before the refactor.
- **SC-005**: In 100 profile-shutdown scenarios, profile close reports completion only after all profile-owned background activity has either completed or been cancelled.
- **SC-006**: No new capability, backend, telemetry, credential-storage, or cross-device-sharing behavior is introduced by the refactor.

## Assumptions

- The feature is an internal reliability and maintainability refactor; it does not add a new user-facing product workflow.
- Existing interface actions, notifications, error prefixes, vault compatibility rules, security rules, and platform restrictions are contractual inputs to the work.
- Existing supported workflows define the compatibility baseline; behavior changes require a separate specification.
- Remote operations may take time to stop because of existing connection or transfer timeouts, but `ProfileRuntime::shutdown` owns the timeout decision and must not report completion before every profile-owned operation has completed or acknowledged cancellation. If a timeout is reached, the close operation returns the existing `[STATE]` error, leaves the profile in unavailable `Closing` state, and a later close attempt resumes shutdown; selection and deletion remain rejected until shutdown succeeds.
- The project remains fully local and does not gain an account, backend, telemetry, or cloud synchronization service.
- Delivery is staged within this feature: profile lifecycle and vault persistence safety precede structural module extraction, and each stage must pass its regression gate before the next stage begins.
