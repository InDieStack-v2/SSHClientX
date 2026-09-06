# Feature Specification: Local-Only Mode (Remove Accounts & Backend API)

**Feature Branch**: `001-local-only-mode`

**Created**: 2026-09-06

**Status**: Draft

**Input**: User description: "review my codebase. I need to update my strategy for my app. first I don't need to support accounts/ backend api. this app will work without backend api. for security"

## Clarifications

### Session 2026-09-06

- Q: When a user who previously had a cloud account or a shared profile opens the app after this update, should the app show them any explanation of what changed? → A: No — the transition is silent. No in-app notice, migration screen, or explanatory message is shown; the account/cloud UI simply disappears.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Use the app with no account, ever (Priority: P1)

A person installs the app for the first time. They create and unlock a
local vault and start connecting to their servers immediately. At no
point are they asked to sign up, sign in, verify an email, or connect
to any online account.

**Why this priority**: This is the core of the new strategy — the app
must be fully usable, and marketed, as a product with no backend
account system at all. Every other change follows from this.

**Independent Test**: Fully disconnect the device from the internet,
install/launch the app, create a local vault, add a server, and
connect over SSH. The entire flow succeeds with zero network activity
to any account or sync backend (a pre-existing, unrelated update-check
call to a software-release host is expected and out of scope for this
feature — see FR-004).

**Acceptance Scenarios**:

1. **Given** a fresh install, **When** the user opens the app, **Then**
   they land directly on local vault creation/selection — there is no
   sign-up, sign-in, or "connect to cloud" step in the flow.
2. **Given** the device has no internet connectivity, **When** the
   user creates a vault, adds servers/credentials, and connects to a
   reachable host on the local network, **Then** every step succeeds.
3. **Given** the app is running, **When** network traffic is captured
   for a full session (vault creation, editing servers, connecting,
   transferring files), **Then** no requests are made to any account
   or sync backend host.

---

### User Story 2 - Existing local vaults keep working (Priority: P2)

A person who already used the app has one or more local vault files on
disk. After updating to the new version, they must still be able to
open those vaults and use all their saved servers, credentials, keys,
and notes exactly as before.

**Why this priority**: Removing the backend must not destroy or lock
users out of data that already lives safely on their device — that
would violate the product's own security promise.

**Independent Test**: Take a vault file created by the current
shipped version, open it in the updated app, and confirm all entities
(servers, credentials, folders, keys, commands, notes) are present and
usable.

**Acceptance Scenarios**:

1. **Given** an existing local vault file, **When** it is opened in
   the updated app with the correct master password, **Then** all
   previously saved data is intact and fully usable.
2. **Given** an existing vault that was previously linked to a cloud
   account, **When** the app is opened after the update, **Then** the
   vault opens normally as a standalone local vault and no longer
   shows any cloud-linked status, sharing state, or sync controls, and
   no in-app notice or migration message is shown about the change.

---

### User Story 3 - No leftover account/sharing surface (Priority: P3)

A person browsing the app's screens (profile picker, per-profile
settings, help/marketing copy) never encounters any mention of
accounts, cloud sign-in, multi-device sync, or sharing a profile with
another account.

**Why this priority**: Leftover UI, settings, or copy referencing a
removed backend would confuse users and misrepresent the security
model — it must be removed cleanly, not just disabled.

**Independent Test**: Walk every screen of the app and confirm no
control, label, or help text references signing in, cloud accounts,
multi-device sync, or inviting/sharing with another account.

**Acceptance Scenarios**:

1. **Given** the profile picker screen, **When** it is displayed,
   **Then** it offers only local actions (create, open, import,
   delete a local vault file) with no cloud sign-in option.
2. **Given** a profile is open, **When** its settings/status panel is
   viewed, **Then** it shows no sync status, share/invite controls, or
   account information.
3. **Given** the app's README/help content, **When** it is read,
   **Then** it describes the app as fully local/offline with no cloud
   account or sync feature.

---

### Edge Cases

- What happens to a user whose *only* copy of a profile currently
  lives on the backend (never downloaded to this device)? That data
  is not recoverable after the update; no export/download path is
  provided (accepted trade-off, see Assumptions).
- What happens to pending profile-share invitations that were sent or
  received before the update? They MUST be discarded; no partial
  sharing state should remain reachable in the UI.
- What happens if the app, post-update, still finds a leftover cloud
  session token file on disk from a previous version? It MUST be
  ignored and MAY be deleted; it MUST NOT trigger any network call.
- What happens to a profile that was shared between multiple accounts
  (owner/editor/viewer roles) before the update? Sharing simply ends;
  each device keeps only the data it already has locally as its own
  independent vault (no conversion tool is built).

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The application MUST allow a user to create, open, and
  use a local vault without creating an account, signing in, or
  performing any network-based authentication step.
- **FR-002**: The application MUST NOT present any sign-up, sign-in,
  magic-link, password-reset, or account-management interface.
- **FR-003**: The application MUST NOT transmit vault contents (in
  plaintext or ciphertext), credentials, or profile metadata to any
  remote server.
- **FR-004**: The application's only outbound network activity MUST be
  (a) connections the user explicitly initiates to their own SSH/SFTP
  targets, (b) other user-initiated actions that already open external
  links (e.g. opening a URL in a browser), and (c) the application's
  pre-existing, unrelated software-update check (which does not talk
  to any account/sync backend and is unaffected by this feature). No
  background or startup network calls to any account/sync backend are
  permitted.
- **FR-005**: The application MUST remove the proprietary backend's
  cloud synchronization and cross-account profile-sharing/invite
  functionality (and any UI built against that backend). This bars any
  sync/sharing mechanism that depends on a company-run account or
  sync server; it does not preclude a possible future backend-free
  mechanism (e.g. direct device-to-device pairing over the user's own
  cloud storage, with no account and no server ever seeing key
  material) — that would be a separate feature, out of scope here.
- **FR-006**: All previously-supported local functionality (SSH/SFTP
  connections, port forwarding/tunnels, terminal, credential and key
  storage, folder mirroring, notes, command snippets) MUST continue to
  work exactly as before, with no functional regression caused by
  removing the backend-dependent features.
- **FR-007**: Existing local vault files created by prior versions
  MUST continue to open and function correctly after the update, with
  no loss of previously saved data.
- **FR-008**: The application MUST ignore any leftover cloud session
  data (e.g. a saved account token) from prior versions on first run —
  it MUST NOT be read for any network purpose, and MUST NOT trigger a
  network call to validate or revoke it. Deleting the leftover file is
  OPTIONAL cleanup, not required.
- **FR-009**: User-facing documentation and in-app copy (README,
  onboarding, help text) MUST accurately describe the application as
  fully local/offline, with no cloud account or sync capability.
- **FR-010**: When a profile was previously shared between multiple
  accounts (owner/editor/viewer), sharing MUST simply end after the
  update: each device keeps only the data it already has locally, as
  its own independent vault. No conversion or migration tool is
  required.
- **FR-011**: A profile that exists only on the backend and was never
  downloaded to this device is out of scope for recovery: the
  application MUST NOT attempt to download or export such data, and
  its loss is an accepted consequence of removing the backend.
- **FR-012**: The application MUST NOT show any in-app notice,
  migration screen, or explanatory message about the removal of
  accounts, cloud sync, or profile sharing. The transition MUST be
  silent: the account/cloud UI simply stops being present.

### Key Entities *(include if feature involves data)*

- **Local Vault Profile**: The single, on-device, password-protected
  container for a user's data. After this change it is the *only*
  storage tier the product has — there is no cloud-hosted counterpart.
- **Server / Credential / SSH Key / Folder / Command / Note**: The
  existing data records a vault holds. Their behavior and content are
  unchanged; any fields that previously existed only to support cloud
  sync become inert (no longer read or written for a network purpose).
- **Account** *(removed)*: The email + token identity previously used
  to sign in and link a vault to the backend. This concept no longer
  exists in the product.
- **Profile Share / Invite** *(removed)*: The previous mechanism for
  granting another account owner/editor/viewer access to a shared
  profile. This concept no longer exists in the product.
- **Cloud Sync Session** *(removed)*: The previous push/pull exchange
  between a device and the backend that kept multiple devices'
  profiles in sync. This concept no longer exists in the product.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A new user can go from first launch to successfully
  connecting to an SSH server in under 2 minutes, with zero account
  or sign-in steps.
- **SC-002**: 100% of the application's connection, tunneling,
  mirroring, and terminal features work correctly with the device
  fully disconnected from the internet (aside from reaching the
  user's own target hosts).
- **SC-003**: A full-session network capture shows zero requests to
  any account or sync backend host, across create/edit/connect/close
  flows.
- **SC-004**: 100% of existing local vault files created by the prior
  version open successfully and retain all data after updating.
- **SC-005**: A walkthrough of every screen in the application finds
  zero remaining references to signing in, cloud accounts, multi-device
  sync, or profile sharing.

## Assumptions

- Each device already holds its own local vault file(s); this change
  does not need to invent a new first-time-setup flow beyond what
  local vault creation already provides.
- Any backend/server infrastructure the product previously talked to
  may keep existing or be decommissioned independently; that
  operational decision is out of scope for this specification, which
  covers only the application's behavior and user experience.
- Removing the backend's multi-device sync and profile sharing is an
  intentional, accepted product trade-off in exchange for the stronger
  security posture of having no backend at all; no backend-based
  replacement is being requested here. A backend-free replacement
  (device-to-device pairing over the user's own cloud storage) is a
  distinct, separately-tracked idea — see `docs/features/spec-00-e2e-vault.md`
  — and is out of scope for this spec.
- Users who want to move a vault between their own devices will do so
  by manually copying the local vault file, which is already possible
  today and needs no new feature.
- Data that exists only on the backend (never synced to a device) is
  accepted as lost; no final export/download tool is built. Likewise,
  profiles previously shared between accounts simply stop syncing —
  each device keeps its own last-known local copy, with no conversion
  or merge tool built for the transition.
