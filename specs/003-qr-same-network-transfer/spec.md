# Feature Specification: QR Same-Network Vault Transfer

**Feature Branch**: `003-qr-same-network-transfer`

**Created**: 2026-09-08

**Status**: Draft

**Input**: User description: "help me review docs/features/spec-02-qr-same-network.md, I need to implement this feature. related spec: 002-e2e-vault-migration"

**Source**: [docs/features/spec-02-qr-same-network.md](../../docs/features/spec-02-qr-same-network.md) (tech spec v1)

**Related**: [002-e2e-vault-migration](../002-e2e-vault-migration/spec.md) — this feature reuses that spec's vault key model (device-bound DEK in the OS secure store, `kid`, generation, import verification) and MUST NOT weaken it. It also implements the "explicit pairing" cross-device path that spec 002 and the constitution (Principle I) name as a future successor to the recovery kit — see Clarifications below.

## Clarifications

### Session 2026-09-08

- Q: Does the guest device need to already hold this vault's decryption key before it can use this QR transfer, or must this feature also be able to fully onboard a brand-new, key-less device? → A: This feature MUST also fully onboard a brand-new, key-less device in one step. Establishing the key on the guest is in scope, but the raw key MUST NOT be carried in the QR payload itself — it may only be established over the mutually-authenticated, encrypted session the QR bootstraps (QR-derived certificate pin + human-confirmed verification code), placed directly into the guest's own OS secure store, never persisted unprotected, and the guest still sets its own vault password afterward.
- Q: Is a key-less Android device allowed to receive full first-time onboarding through this QR flow, or is Android limited to already-paired devices only? → A: Android CAN act as host or guest for first-time key establishment via QR pairing, the same way it's already allowed to consume a recovery kit. This does not change Android's existing restriction against creating/migrating a vault through the general export/import flow, which stays desktop-only.
- Q: When a device that already has a local profile receives a vault via this QR transfer, should it always land as a new, separate profile (matching file-import's conservative default), or use new transfer-specific rules that update the existing profile more automatically since the sender is live and reachable? → A: New, transfer-specific rules: when the guest already holds a profile matching the incoming vault's `kid` and the incoming `generation` is strictly newer, update that profile in place automatically (no new-profile duplication, no prompt). If the incoming `generation` is not strictly newer (equal or older) than the guest's local copy, the automatic update is refused and the user is asked to confirm before anything is overwritten — mirroring file import's older/conflict confirmation for that case only. A `kid` the guest has never seen still always lands as a new profile. **Superseded during `/speckit-plan`, see below.**
- Q (superseded, during planning): Planning surfaced that file import already tried an in-place-overwrite landing once and explicitly reverted it (`git` commit "revert: import always lands as a new profile, never overwrites"), specifically to guarantee a backup/transfer can never clobber newer local changes — `import_vault_commit` today lands a same-`kid` match as a new, separately-named copy ("`<profile>` [IMPORT]") **regardless of generation**, never overwriting the original file. Given that precedent, should QR transfer's "strictly newer" case really overwrite in place (reintroducing the reverted pattern), or land as a same-pattern copy like file import already does? → A: Land as a copy, like file import. Reuse the existing copy-landing code unchanged for every generation relationship (newer, equal, older, conflicting); no prompt is needed either way since a copy can never destroy anything. This supersedes the previous answer's "update in place" behavior — see revised FR-011b below.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Send a vault to a brand-new device (Priority: P1)

A user has a sealed vault on their desktop or phone and wants to get it onto a second device (a new phone, a colleague's laptop) that has never held this vault's key before, and that is on the same Wi-Fi network or connected to a hotspot they're hosting. Instead of emailing a file, using a USB cable, or running the offline recovery kit, they open "Share" on the source device, show a QR code, and the receiving device scans it in-app to both establish the vault's key on itself and pull the vault content, device to device, in one step.

**Why this priority**: This is the core value of the feature — it replaces the manual export/copy/import-plus-recovery-kit flow with a fast, local, no-cloud-required handoff that works even for a device that has never seen this vault before. Without it, the feature doesn't exist.

**Independent Test**: On two devices joined to the same network, start a share on device A, scan the resulting QR on device B (which has no prior key for this vault), and confirm the vault appears on device B, its key is now held in device B's own secure store, and it unlocks after device B's user sets a vault password for that device. Delivers value on its own with no other story required.

**Acceptance Scenarios**:

1. **Given** device A is showing a share QR code and device B (no prior key for this vault) is on the same Wi-Fi, **When** device B scans the QR in-app, **Then** the session is mutually authenticated, the vault's key is established directly in device B's own OS secure store, the vault content transfers, its integrity is verified, and device B prompts its user to set a vault password for that device before the vault can be opened there.
2. **Given** a transfer is in progress, **When** it completes successfully, **Then** the transfer session closes automatically and cannot be reused.
3. **Given** the user is shown a short verification code on both screens, **When** the codes match, **Then** the user can confirm and proceed with confidence they're talking to the intended device.
4. **Given** device B already holds this vault's key and profile from an earlier pairing, **When** it scans a new QR from device A, **Then** the existing key is reused (no key is re-established) and the incoming content lands as a new, separately-named copy of device B's existing profile, without touching or prompting about the original — device B's original profile file is never overwritten by this flow.

---

### User Story 2 - Receive a vault from a nearby device (Priority: P2)

A user wants to pull a vault onto their own device by hosting the session and having someone else's device push their vault to them, or conversely wants to push their own vault to another device that is hosting a "receive" session. This is the same mechanism as Story 1 with the transfer direction reversed.

**Why this priority**: Needed for the "onboard a new device" and "hand a vault to a colleague" flows to work in both directions, but the underlying session mechanics are shared with Story 1, so it can ship shortly after.

**Independent Test**: Start a "receive" session on device A (host), scan its QR from device B (guest), and choose to upload B's vault. Confirm device A ends up with a verified copy of B's vault.

**Acceptance Scenarios**:

1. **Given** device A is hosting a "receive" session, **When** device B scans the QR and uploads its vault, **Then** device A verifies and stores the received vault.
2. **Given** an upload exceeds the maximum allowed transfer size, **When** the guest attempts to send it, **Then** the transfer is rejected with a clear reason and neither device's existing vault is affected.

---

### User Story 3 - Clear failure when devices aren't reachable (Priority: P3)

A user tries to scan a QR code from a device that isn't actually on the same network (e.g., guest is on cellular data, or the QR has expired), or scans an old/reused code.

**Why this priority**: Not the happy path, but essential so users aren't left staring at a spinner — they need to be told quickly what went wrong and what to do instead (use file export/import).

**Independent Test**: Attempt a scan with the guest device's Wi-Fi off (cellular only), and separately attempt to reuse a QR code after it has expired or already been used once. Confirm each produces a distinct, understandable error within a few seconds.

**Acceptance Scenarios**:

1. **Given** the guest device cannot reach the host (different network, firewall), **When** it attempts to connect, **Then** the user sees a "not reachable" message within a few seconds and is pointed to file export/import as an alternative.
2. **Given** a QR code is scanned after its validity window has passed, **When** the guest attempts to use it, **Then** the transfer is refused as expired and the user is told to generate a new code.
3. **Given** a QR code (or its one-time transfer code) has already been used for a completed transfer, **When** it is scanned or submitted again, **Then** the transfer is refused as already used.

---

### Edge Cases

- What happens if the host cancels or closes the app while a guest is mid-transfer? The session must end and the guest must see a clear failure, not a hang.
- What happens if the received bytes are corrupted or tampered with in transit? The transfer must be rejected and the host's existing vault must remain untouched.
- What happens if a user has multiple devices to onboard? They must be able to complete one transfer and immediately start a new session for the next device without restarting the app.
- What happens if there are repeated failed connection/authentication attempts against a host session? The host must shut the session down rather than allow indefinite retries.
- What happens if the host and guest are on the same Wi-Fi but the network isolates clients from each other (common on guest Wi-Fi)? Treated the same as "not reachable" — same error and same fallback advice.
- What happens if the guest tries to open the scanned link outside the app (e.g., by sharing it to a browser)? The transfer mechanism must not be usable that way.
- What happens if the guest already has a same-`kid` profile (e.g., the guest made its own local changes since the last sync)? The incoming transfer never touches that profile's file — it always lands as a separate, clearly-named copy, so a live pairing can never discard existing local changes, matching how file import already behaves for the same situation.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Users MUST be able to start a transfer session from either device — one device acts as host (shows the QR) and the other as guest (scans it) — for both sending a vault out and receiving one in.
- **FR-002**: The system MUST represent a transfer session as a single-use, time-limited code shown as a QR (with a numeric/text fallback for entry when scanning isn't possible).
- **FR-003**: A transfer session MUST expire on its own no later than 120 seconds after creation, and scanning an expired code MUST be refused distinctly from other errors.
- **FR-004**: The one-time code embedded in a session MUST be rejected if it is presented a second time, whether by replay or after a completed transfer.
- **FR-005**: Transfers MUST be restricted to devices reachable on the same local network (the host's Wi-Fi or a hotspot the host is providing). The system MUST refuse to advertise or connect to a public-internet address.
- **FR-006**: Scanning MUST happen inside the app; the transfer link MUST NOT be usable by handing it to an external browser or app.
- **FR-007**: Both host and guest MUST display a short human-comparable verification code tied to the session, and the guest MUST be able to confirm it matches the host's screen before/while the transfer proceeds.
- **FR-008**: The connection between host and guest MUST be encrypted and mutually verified (the guest confirms it is really talking to the host it scanned, not an impersonator on the same network).
- **FR-009**: The QR code itself MUST NOT contain the vault's decryption key, the user's vault password, or any other secret — only session connection and verification details (see source tech spec §4).
- **FR-009a**: When the guest does not yet hold this vault's key, the system MUST be able to establish it on the guest as part of the transfer (first-time onboarding), in addition to supporting guests that already hold the key (resync of an already-paired device).
- **FR-010**: Key establishment for a key-less guest MUST happen only inside the same mutually-authenticated, encrypted session validated by FR-007/FR-008 (QR-derived certificate pin plus human-confirmed verification code) — never before that verification, and never via the QR payload itself. The key MUST be written directly into the guest's own OS-managed secure store, consistent with the device-bound key model in [002-e2e-vault-migration](../002-e2e-vault-migration/spec.md); it MUST NOT be written to disk unprotected, logged, or persisted anywhere outside that secure store, on either device, at any point in the flow.
- **FR-010a**: After a key-less guest establishes the vault's key, the guest MUST be prompted to set its own vault password for that device before the vault can be opened there. The guest MUST NOT inherit, reuse, or be shown the host's vault password.
- **FR-011**: A received vault file MUST pass the same integrity and authenticity verification used for a manually imported vault file (format check, hash check, tamper-evident decryption check, key-identity check, generation check) before it is accepted; a failed check MUST leave the receiving device's existing vault(s) unchanged.
- **FR-011a**: If the receiving device has no existing profile for the incoming vault's `kid`, the transfer MUST land as a new profile.
- **FR-011b**: If the receiving device already has a profile for the incoming vault's `kid`, the transfer MUST land as a new, separately-named copy of that profile — never overwriting the original profile's file — regardless of whether the incoming `generation` is newer, equal to, or older than the existing profile's. This mirrors the landing policy already used for manual file import (same reasoning: a transfer must never be able to clobber existing local changes) and requires no prompt, since nothing already on the receiving device is ever at risk of being overwritten by it.
- **FR-012**: The system MUST enforce a maximum transfer size (default 8 MiB) and reject anything larger before accepting it.
- **FR-013**: A host session MUST close automatically when any of the following occurs: one transfer completes successfully, the session's expiry time is reached, the app is closed, or a small fixed number of failed connection/authentication attempts occurs (default 5).
- **FR-014**: The QR/scan screen and the verification-code confirmation screen MUST prevent the operating system from capturing a screenshot or screen recording of them.
- **FR-015**: When a guest cannot reach the advertised host (different network, blocked, or expired before connecting), the system MUST show a distinct, understandable error within a few seconds (no indefinite spinner) and suggest exporting/importing a vault file as a fallback.
- **FR-016**: Users MUST be able to complete a transfer with one device pair and then immediately start a new session with a different device, without restarting the app.
- **FR-017**: When the host and guest have no shared network available, the system MAY offer a secondary step (e.g., a hotspot join code) to get the guest onto the host's network before the transfer session is used.
- **FR-018**: Both host and guest roles, including first-time key establishment (FR-009a), MUST be available on Android as well as desktop — Android is not restricted to the resync case. This does not change Android's separate, pre-existing restriction against creating or migrating a vault through the general export/import flow, which remains desktop-only.

### Key Entities

- **Transfer Session**: A short-lived, single-use handoff between exactly one host and one guest device. Has a role (send-from-host or send-to-host), an expiry, a one-time code, and a verification code shown on both ends. Carries no vault content of its own — only enough information for the guest to locate and authenticate to the host.
- **Transferred Vault**: The sealed vault file moved between devices. Identified by the same key identity (`kid`) and generation concepts defined in [002-e2e-vault-migration](../002-e2e-vault-migration/spec.md).
- **Vault Key**: The device-bound decryption key for a vault (the DEK from [002-e2e-vault-migration](../002-e2e-vault-migration/spec.md)). Either already present in the guest's OS secure store (resync case), or established there for the first time during a paired session (first-time onboarding case, FR-009a/FR-010). Never appears in the QR code itself.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A user can complete a same-network vault transfer (scan to verified-and-unlockable on the receiving device) in under 30 seconds for a vault up to the maximum supported size, on a stable local network.
- **SC-002**: 100% of transfers where the transferred bytes are altered or corrupted in transit are rejected, and the receiving device's existing vault(s) remain unchanged.
- **SC-003**: 100% of attempts to reuse an already-used or expired transfer code are refused.
- **SC-004**: A guest device that cannot reach the host sees a clear, actionable error within 5 seconds of the connection attempt failing, in 100% of attempts.
- **SC-005**: At least 95% of users complete a transfer using only the in-app scanner, without needing to manually type a network address.
- **SC-006**: Users can transfer to a third device immediately after finishing a transfer to a second device, without restarting the app, in 100% of attempts.
- **SC-007**: 100% of transfers where the receiving device already has a profile for the incoming vault land as a separate copy, with the receiving device's pre-existing profile file byte-for-byte unchanged afterward.
- **SC-008**: Given a full network capture of a pairing session between a host and a key-less guest, the vault's decryption key is not recoverable from that capture in 100% of attempts.

## Assumptions

- Both devices have the app installed and are signed into (or have created) a local profile capable of holding a vault; account/profile creation itself is out of scope here.
- "Same network" covers a shared Wi-Fi router and a host-provided hotspot; it does not cover VPNs, mobile hotspots relayed through a third network, or any cloud relay — those are explicitly out of scope per the source tech spec's non-goals.
- The 8 MiB default maximum transfer size and 120-second maximum session lifetime from the source tech spec are adopted as-is; they may be tuned later without being a scope change.
- The source tech spec calls the QR-code payload itself off-limits for the decryption key (non-negotiable, kept as FR-009); but per this spec's Clarifications, this feature does take on first-time key establishment for a key-less guest — the source tech spec's "separate, explicit pair-key flow" — as in scope, transmitted only over the already-authenticated session rather than the QR text.
- Multi-frame/optical "QR movie" air-gapped file transfer is out of scope, per the source tech spec's non-goals.
- This feature reuses the device-bound vault key model (DEK held in the OS secure store, `kid`, generation, import verification) already specified in [002-e2e-vault-migration](../002-e2e-vault-migration/spec.md), and extends it with the one new capability that spec anticipates but doesn't build: establishing that key on a second device via explicit pairing instead of only via the offline recovery kit.
- Because this expands the device-bound key model with a new key-establishment path, it will need to be checked against the constitution's Principle I/V during planning (a new capability of this kind is flagged there as a possible Governance matter, not assumed pre-cleared by this spec).
