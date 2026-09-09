# Feature Specification: End-to-End Encrypted Vault Migration

**Feature Branch**: `002-e2e-vault-migration`

**Created**: 2026-09-06

**Status**: Ready for implementation — clarifications closed, Governance cleared (constitution v5.1.0)

**Input**: User description: "Migrate the vault export/import from the current password-derived-key model to the spec-00 end-to-end encrypted vault model (docs/features/spec-00-e2e-vault.md, spec-01-export-import.md)."

---

## Constitutional Prerequisites *(read first)*

This feature **cannot be implemented under constitution v2.0.0**. Four rules must be
amended through Governance before any code lands. Spec Kit rules resolve conflicts in
favour of the constitution, so this section is a hard gate, not a caveat.

**Status: RESOLVED.** The constitution now stands at **v5.1.0** — v3.0.0 covered all four
rows below, v3.1.0 extended the dependency allowance the design turned out to need, and
v5.1.0 permits Android to create fresh sealed vaults. The four conflicts described here are
historical, recorded so the reason for the amendment stays legible. This spec is actionable.

| Constitution rule | Conflict |
| --- | --- |
| III. One Core, Every Platform — "Vault files MUST remain platform-portable: unlock on Windows, macOS, Linux, or Android with the same master password." | The entire point of the target model is that a vault does **not** open on another device without pairing or a recovery kit. This principle is being deliberately reversed. |
| III. One Core, Every Platform — "Android and desktop MUST ship the same vault format." | Both platforms read both formats and create fresh vaults in the current sealed format; only legacy migration remains desktop-only. |
| I. Device-Bound Secrets — "sealed with AES-256-GCM" | Target model prefers XChaCha20-Poly1305, with AES-256-GCM as the secondary algorithm. |
| Technology Constraints — "On-disk vault: magic `OMNV`" · Development Workflow — "changing Argon2/AES parameters … is a constitution-level change" | New container magic, new header, and a changed role for Argon2 (wrapping a key instead of being the key). |

The amendment was a **MAJOR** version bump (a NON-NEGOTIABLE rule was redefined), landed as
v3.0.0 and extended by v3.1.0.

---

## Clarifications

### Session 2026-09-06

- Q: When a user recovers their vault on a second device using the recovery kit, which
  password opens it there? → A: ~~The kit is sealed under the original password.~~
  **Superseded below** — see the vault-password-locality entry.
- Q: Should the vault password travel between devices? → A: No. Vault passwords are
  device-local and never leave the device. A recovery kit is sealed under its own
  recovery passphrase instead, and the receiving device sets its own vault password during
  recovery. A stolen kit plus a stolen vault file is still not enough to read anything.
- Q: What physical form does the recovery kit take when the app hands it to the user? →
  A: Both a printable recovery phrase and a downloadable recovery file, chosen by the
  user at creation time. The receiving device accepts either.
- Q: After the user unlocks a profile, when should the app lock it again on its own? →
  A: All of the triggers spec-00 §8.4 lists — idle timeout, OS screen lock or sleep, app
  backgrounded, main window losing focus — plus explicit user lock.
- Q: When the vault locks while SSH sessions, tunnels, transfers, or monitors are
  running, what happens to them? → A: They keep running. Their output and any vault
  content is concealed behind the lock screen and restored on unlock.
- Q: Is the explicit vault-key rotation action (FR-008) actually needed in this release?
  → A: No. FR-008 is dropped. The sealed format keeps the key identifier so rotation can
  be added later without a format change or a second migration.
- Q: After an automatic lock, what does the user do to get back in? → A: Platform
  authentication (biometric or OS credential) re-unlocks while the app is running; a full
  password unlock is required on app start, after the idle timeout, and after an OS screen
  lock. This is also what "identity confirmation" means everywhere in this spec.
- Q: What should happen if the same profile is opened by two copies of the app at once? →
  A: One writer at a time. The second instance is refused with a distinct "already open
  elsewhere" outcome. Read-only access for the second instance is out of scope.
- Q: If the secure store is present but refuses one request (prompt dismissed, keychain
  locked), is that the same as having no secure store? → A: No. A denied or
  temporarily-unavailable request is a separate, retryable outcome. Only a genuinely
  absent secret service produces the terminal refusal.
- Q: If an old copy of the vault file is restored directly into place, should the app
  notice it has gone backwards? → A: Yes. The highest revision ever written is recorded
  next to the key; opening a lower revision is reported as a possible rollback and the
  user chooses whether to accept it or restore a newer revision from local history.
- Q: When migration, recovery, import, or unlock fails, what should the app have written
  down for support? → A: The outcome code, timestamp, revision numbers, key-identifier
  prefix, and file hash prefix. Never hostnames, paths, filenames, or content.
- Q: When a vault file is imported and its key is already owned by a profile on this
  device, does import restore over (overwrite) that profile? → A: No, never. It always
  lands as a new, separately-named copy ("X [IMPORT]", auto-suffixed on a further
  collision) that shares the matched key, so a bad or stale import can never clobber
  local changes — the owning profile's own file is untouched. The copy gets its own
  key-wrap sidecar and device-factor keystore entry (copied from the owning profile's,
  not shared by reference) so it opens independently with that profile's own password —
  an earlier attempt at this that only wrote the vault file, without also giving the copy
  its own key material, left it permanently unopenable. Because nothing is ever
  overwritten, an older or content-conflicting incoming revision needs no special
  confirmation either (FR-033 is dropped, on the same precedent as FR-008). A file
  matching an unclaimed key (no profile owns it yet) still creates a new profile that
  owns that key outright, per FR-032.

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 - My vault stops being a portable password-locked file (Priority: P1)

A user who already has profiles on this machine opens the app after updating. Their
existing vault is re-sealed so that the key that protects it now lives in this
computer's own secure store rather than being re-derived from their password on any
machine that has the file. From their side the app still opens the same way and shows
the same servers, keys, and history — but a copy of that file taken to another computer
no longer opens with the password alone.

**Why this priority**: Nothing else in this feature exists without it. It is also the
single change that alters the product's security guarantee, so it must be delivered as
one deliberate, reversible-until-confirmed step rather than as a side effect of an
export or import change.

**Independent Test**: Take a machine with existing profiles, update, unlock each
profile, confirm all content is intact, then copy the vault file to a second machine and
confirm it is refused with a message that names the reason. Deliverable value: the
stolen-file threat is closed even for an attacker who later learns the password.

**Acceptance Scenarios**:

1. **Given** an existing profile in the current on-disk format, **When** the user
   unlocks it with the correct password for the first time after updating, **Then** the
   vault is re-sealed under a new device-held key, all previously saved content is
   readable, the app verifies the re-sealed vault opens, and the pre-migration file is
   retained until the user dismisses the one-time migration notice — at which point it is
   deleted, since a file in the old format would otherwise still open with the password
   alone on any machine.
2. **Given** an existing profile in the current on-disk format, **When** the user enters
   the wrong password, **Then** no migration is attempted and the pre-migration file is
   untouched.
3. **Given** a legacy-extension profile file, **When** it is unlocked, **Then** it
   migrates by the same path and is renamed to the current extension.
4. **Given** a migrated profile, **When** its file is copied to a second device and
   opened there, **Then** it is refused with a distinct "sealed with another device's
   key" outcome and no content is revealed — not a generic wrong-password error.
5. **Given** a device whose operating system provides no secret store at all, **When** the
   user tries to create or migrate a vault, **Then** the operation refuses with a
   distinct "no secure store" outcome that says what would have to change on the machine,
   and the app never writes an unprotected key to disk as a fallback.
6. **Given** a migrated profile, **When** the user saves any change, **Then** the vault's
   revision counter advances and the previous five revisions remain recoverable locally.
7. **Given** a migrated profile whose sealed file has had a single byte altered,
   **When** the user unlocks, **Then** the app reports damage-or-tampering and offers the
   most recent intact revision instead of failing to a blank vault.
8. **Given** an unlocked profile, **When** the idle timeout elapses, the operating system
   locks the screen or sleeps, the app is backgrounded, the main window loses focus, or
   the user locks explicitly, **Then** the vault locks and no vault content remains on
   screen.
9. **Given** a locked vault, **When** anyone inspects the running application, **Then**
   no profile contents, server names, credentials, command history, or retained terminal
   output are visible, and reopening requires a full unlock.
10. **Given** unsaved vault changes and any lock trigger, **When** the lock occurs,
    **Then** those changes are sealed first or the lock waits for that save, and no
    partially written vault results.
11. **Given** a vault that locked while the user was in a particular view, **When** they
    unlock, **Then** they are returned to that view.
12. **Given** a running SSH session, port forward, file transfer, folder mirror, or
    monitor, **When** the vault locks, **Then** it keeps running, its output is concealed,
    and it is usable again on unlock without reconnecting.
13. **Given** a file transfer that finishes while the vault is locked, **When** the user
    looks at the locked app, **Then** they can see that background work completed or
    failed without any hostname, path, or transferred content being shown.
14. **Given** a vault locked because the window lost focus, **When** the user returns to
    the app, **Then** platform authentication alone restores access and the password is
    not requested.
15. **Given** a vault locked by the idle timeout, by an OS screen lock, by an explicit
    lock, or by the app restarting, **When** the user returns, **Then** the password is
    required and platform authentication alone is refused.
16. **Given** a device with no platform authentication available or enrolled, **When** any
    lock occurs, **Then** the password unlocks it and no feature is withheld.
17. **Given** repeated platform-authentication failures, **When** the user gives up on it,
    **Then** the password still unlocks the vault and no attempt limit has made it
    permanently unopenable.
18. **Given** a profile already open in one running instance, **When** a second instance
    tries to open it, **Then** it is refused with an "already open elsewhere" message
    naming the profile, and the first instance's vault is untouched.
19. **Given** an instance that crashed while holding a profile open, **When** the user
    launches the app again and opens that profile, **Then** it opens without requiring
    them to delete anything by hand.
20. **Given** a working secret store, **When** the user dismisses its prompt or the
    keychain is locked, **Then** the app reports a retryable outcome and offers to try
    again, distinct from the no-secure-store refusal, and any pending changes remain
    intact for the retry.
21. **Given** an older vault file restored into place by backup software or by hand,
    **When** the user opens that profile, **Then** the app reports a possible rollback
    naming both revisions and does not proceed until the user accepts the older vault or
    restores a newer revision from local history.
22. **Given** a possible rollback the user deliberately accepts, **When** they confirm,
    **Then** the vault opens and the warning does not reappear on subsequent opens.

---

### User Story 2 - I can still move my vault to a second computer (Priority: P2)

Before or after migration, the user can produce a one-time offline recovery kit that,
together with a recovery passphrase they choose for it, re-establishes the same vault key
on a second machine they own. Their vault password never leaves the first machine. This is the only supported way to move a vault between devices in this release;
device-to-device pairing is a later feature.

**Why this priority**: Story 1 removes an ability people rely on today. Shipping it
without a replacement path turns an update into data loss for anyone running the app on
more than one machine. This story is what makes Story 1 safe to release.

**Independent Test**: Create a recovery kit on machine A, migrate, then use the kit plus
its recovery passphrase on a clean machine B to open a vault file exported from A, and
confirm the same attempt without the passphrase fails. Machine A's vault password is never
entered on B. Deliverable value: multi-machine users keep
working.

**Acceptance Scenarios**:

1. **Given** a migrated vault, **When** the user chooses to create a recovery kit,
   **Then** the app asks the user to choose a recovery passphrase for the kit, produces it
   only after confirming the user's identity, seals it under that passphrase, presents it
   for offline storage, and warns in plain language that the kit plus the vault file plus
   the recovery passphrase grants full access to every secret.
2. **Given** the app has never been asked for a recovery kit, **When** the user browses
   settings or completes migration, **Then** no kit exists anywhere on disk — it is
   created only on explicit request.
3. **Given** a recovery kit, a vault file from machine A, and the kit's recovery
   passphrase, **When** all three are supplied on machine B, **Then** machine B prompts for
   a vault password of its own, establishes the same vault key in its own secure store as
   an unclaimed key, and importing the file creates the profile that owns it.
4. **Given** a recovery kit and a vault file but not the recovery passphrase, **When**
   recovery is attempted on machine B, **Then** it fails, no vault key is established, and
   no content is revealed.
5. **Given** a recovery kit, **When** it is used on machine B, **Then** machine B's copy
   of the key is protected by machine B's own secure store and the vault password set on
   B, not by the kit remaining on disk.
6. **Given** the user completes migration for the first time, **When** migration
   finishes, **Then** they are told once, explicitly, that this file will no longer open
   on their other machines and are offered the recovery kit at that moment.
7. **Given** a recovery kit, a vault file from a migrated desktop, and the kit's recovery
   passphrase, **When** all three are supplied to the Android app's recovery flow, **Then**
   Android prompts for its own vault password and the vault opens, remaining usable and
   saveable there afterwards.
8. **Given** an Android device that has not been given a recovery kit, **When** a
   migrated vault file is placed on it, **Then** it is refused as sealed for another
   device's key and the message points at the recovery flow.
9. **Given** a valid kit and the wrong recovery passphrase, **When** it is used on machine
   B, **Then** the app reports the wrong passphrase for that kit rather than a corrupt kit.
10. **Given** the user chooses the phrase form, **When** the kit is created, **Then** the
    phrase is displayed for transcription, the app states that the vault file will also be
    needed, and that phrase typed on machine B together with the vault file and the
    recovery passphrase completes recovery.
11. **Given** the user chooses the file form, **When** the kit is created, **Then** it is
    saved through a system save dialog whose default location is neither cloud-synced nor
    backed up, and the same file, picked on machine B with the recovery passphrase,
    completes recovery.
12. **Given** a recovery phrase entered with a mistyped or missing word, **When** it is
    submitted, **Then** the app reports a phrase-entry problem before asking for the
    recovery passphrase, distinctly from a wrong-passphrase outcome.
13. **Given** a completed recovery on machine B, **When** the user later changes the vault
    password on machine A, **Then** machine B is unaffected and continues to open with its
    own password.

---

### User Story 3 - I can export a backup I can identify later (Priority: P3)

The user exports a profile to a file they keep on a USB stick or in a folder. The
exported file is the sealed vault exactly as stored — the app never unlocks it just to
re-lock it — and its name tells the user which point in time it captures.

**Why this priority**: Export already works today; this story upgrades it. The failure
it fixes is real but non-destructive — today two backups of the same profile are
distinguishable only by file timestamp.

**Independent Test**: Export the same profile twice with a change in between and confirm
the two filenames are distinguishable and ordered, and that neither file reveals key
material when opened as text.

**Acceptance Scenarios**:

1. **Given** a profile, **When** the user exports it, **Then** the app first confirms the
   user's identity, even though the exported bytes are already encrypted.
2. **Given** a profile, **When** the user exports it, **Then** the exported file is the
   already-sealed vault; the app does not unlock the vault as part of exporting.
3. **Given** a profile at a known revision, **When** it is exported, **Then** the
   suggested filename identifies the app, the date, the time, and the revision.
4. **Given** an export completes or is cancelled, **When** the user inspects temporary
   and cache locations, **Then** no working copy created by the app remains.
5. **Given** an export completes, **When** the user inspects the app's diagnostic log,
   **Then** it records the revision and a short fingerprint of the file, and no vault
   content.
6. **Given** an exported file, **When** it is opened in a text editor or previewed by the
   operating system, **Then** no private key, password, or host detail is visible.

---

### User Story 4 - Import tells me exactly why a file was rejected (Priority: P4)

The user imports a vault file. Every file — whatever route it arrived by — passes
through one verification path that checks the file is genuine, undamaged, and meant for
this device's key. Each failure has its own clear outcome. Import never overwrites an
existing profile: a file matching an unclaimed key becomes a new profile that owns it, and
a file matching a key an existing profile already owns lands as a new, separately-named
copy sharing that key — the profile that already owns the key is never touched, however
the incoming revision compares to what's already there.

**Why this priority**: Import works today for the only case it supports (create a new
profile). This story adds real verification, the case where an incoming file's key is
already owned by an existing profile, and the distinct failure outcomes. It is also the
story that establishes the single verification path the later same-network and cloud
transports will reuse.

**Independent Test**: Feed the importer a genuine file, a file with one byte flipped, and
a file sealed for a different key, and confirm three distinct outcomes with the local
vault unchanged in the two failure cases.

**Acceptance Scenarios**:

1. **Given** a genuine file sealed for a key already owned by a profile on this device,
   **When** the user imports it, **Then** it lands as a new, separately-named profile
   sharing that key, written atomically, and the owning profile's own file is untouched.
2. **Given** a file that is not a vault file at all, **When** it is imported, **Then** the
   user is told it is not a vault file and nothing is written.
3. **Given** a file in a format version this release does not understand, **When** it is
   imported, **Then** the user is told the version is unsupported and nothing is written.
4. **Given** a file with any altered byte, **When** it is imported, **Then** the user is
   told it is damaged or tampered with and the local vault is unchanged.
5. **Given** a file sealed for a different device's key, **When** it is imported,
   **Then** the app does not decrypt it, says it was sealed with another device's key,
   and points the user at the recovery-kit path.
6. **Given** a file older than the profile owning its key, **When** the user imports it,
   **Then** it still lands as a new, separately-named copy — no confirmation is needed,
   since the owning profile's own (newer) content is never at risk.
7. **Given** a file at the same revision as the profile owning its key but with different
   content, **When** the user imports it, **Then** it still lands as a new,
   separately-named copy — no conflict to resolve, since nothing is overwritten.
8. **Given** any import, **When** it completes or fails, **Then** the app's own copies of
   the picked file are removed from temporary and cache locations.
9. **Given** the user cancels the identity confirmation during import, **When** the
   cancellation happens, **Then** the app reports a cancelled-unlock outcome and writes
   nothing.
10. **Given** a vault file arrives by a route added later, **When** it is processed,
    **Then** it passes through the same verification path with the same outcomes.
11. **Given** a file matching an unclaimed key established by a recovery kit, **When** the
    user imports it, **Then** a new profile is created that owns that key, and no other
    profile's key is involved.
12. **Given** a file matching a key an existing profile already owns, **When** the user
    imports it, **Then** the app names the owning profile, lands the import as a new,
    separately-named copy sharing that key, and never overwrites the owning profile.
13. **Given** a device holding several profiles, **When** a file is imported, **Then** it
    is matched against every key the device holds, and the correct profile is identified
    without the user selecting one first.

---

### Edge Cases

- **Secure store present at migration, missing later** (OS reinstall, keychain reset,
  user deletes the entry): the vault becomes unreadable. Without a recovery kit this is
  permanent, by design. The app MUST say so in those words rather than reporting a
  generic failure, and MUST NOT delete the file.
- **Two profiles on one device**: each profile is independently sealed and independently
  identified; importing profile A's file over profile B is an unknown-key rejection, not
  a conflict.
- **Migration interrupted** (crash, power loss, app killed mid-re-seal): on next launch
  either the pre-migration file or the new sealed file is intact and openable; there is
  no state in which both are unusable.
- **User migrates on machine A and machine B independently** from copies of the same
  original file: two unrelated keys now exist. Neither machine's exports open on the
  other. The unknown-key message must make this diagnosable.
- **Same file imported twice**: the second import is a same-revision-same-content case
  and is a no-op, not a conflict.
- **App crashes while holding a profile open**: the writer claim is stale, not valid. The
  next launch must detect the owning instance is gone and open normally — a claim that
  outlives its process would lock a user out of their own vault.
- **Two OS users on one machine**: each has their own secure store and their own profile
  storage, so they hold unrelated vaults rather than contending for one. The single-writer
  rule is about two launches by the same user, not about multi-user machines.
- **A recovery kit is consumed but no vault file is ever imported**: the unclaimed key sits
  in the secure store owning nothing. The app MUST show that a recovered key is waiting
  for its vault file, and MUST let the user discard it, so it does not accumulate
  invisibly.
- **Multiple profiles on this device share one key** — the normal outcome of FR-032a, not
  an error: a key already owned by a profile lands every further import of it as another
  new, separately-named copy, never as a conflict. A kit re-consumed for a key some
  profile here already owns is the one path that can also leave a stale `.unclaimed`
  entry alongside a real owner for the same `kid`; `resolve_key_lookup` prefers the
  owner, so it still resolves normally rather than needing to be treated as "twice over."
- **Revision counter at its maximum**, or a file claiming an implausibly high revision:
  refused as damaged rather than accepted as newest.
- **Export while another save is in flight**: the exported file is one complete
  revision, never a half-written one.
- **User running the current release opens a migrated file**: rejected as an unsupported
  version with a message naming the required app version, not as damage.
- **A migrated vault file placed on Android before the recovery kit has been used**
  there: refused as sealed for another device's key, with the message pointing at the
  recovery-kit restore — not an unsupported-version or damaged-file outcome.
- **An Android user with only an existing-format vault and no desktop**: has no path to
  the new format at all this release. The app MUST NOT nag them to migrate, and their
  vault MUST keep working unchanged.
- **User forgets the password but the secure store entry is intact** (or the reverse):
  the vault is unreadable either way, because both are required. Each case MUST name
  which half is missing.
- **User holds a recovery kit but has forgotten its recovery passphrase**: the kit is
  inert and the vault is unrecoverable through it. This MUST be stated when the kit is
  created, not discovered at recovery time.
- **User forgets one device's vault password but not another's**: only that device is
  lost. The other device keeps working, and a recovery kit re-establishes the key on a
  replacement. Vault passwords being per device is what makes this survivable.
- **A file-form kit is left in a synced or backed-up folder**: the app cannot prevent
  this, but MUST NOT steer the user into it — the save dialog's default location must not
  be such a folder, and the exposure must be stated at the moment the form is chosen.
- **A phrase-form kit is photographed or transcribed by a bystander**: equivalent to
  losing the file form. The password remains the second factor in both cases, which is
  what keeps either loss survivable.

---

## Requirements *(mandatory)*

### Functional Requirements

**Vault sealing and device key**

- **FR-001**: The system MUST protect each vault with a randomly generated 256-bit vault
  key that is stored in the operating system's own secure store for the current user,
  marked so it is not carried to other devices by operating-system backup or sync.
- **FR-002**: The system MUST NOT write the vault key, in unprotected form, anywhere on
  disk — in particular never alongside the vault file — and MUST NOT include it in logs
  or diagnostic output.
- **FR-003**: When the operating system provides no secret store at all, the system MUST
  refuse to create, migrate, or save a vault and MUST report a distinct no-secure-store
  outcome describing what the user would have to change on the machine. It MUST NOT fall
  back to storing the key unprotected.
- **FR-003a**: When a secret store exists but a single request to it is denied or
  temporarily unavailable — the user dismissed the prompt, the keychain is locked, the
  secret service is not running yet — the system MUST report a distinct, retryable outcome
  and MUST offer to try again in place. It MUST NOT present this as the machine being
  unable to run the application.
- **FR-003b**: A denied or unavailable request during a save MUST leave the pending
  changes intact in the running session so the user can retry. The system MUST NOT discard
  unsaved work because a secure-store request was declined, and MUST NOT write an
  unprotected fallback copy of anything.
- **FR-004**: The system MUST derive a stable 128-bit key identifier from the vault key
  and record it in every sealed file it writes.
- **FR-005**: The system MUST maintain a revision counter per vault that increases by
  exactly one on every successful save and MUST bind that counter, the key identifier,
  and the format identity into the sealed file such that altering any of them invalidates
  the file.
- **FR-006**: The system MUST retain the five most recent local revisions of each vault
  and MUST be able to open any of them if the current file fails verification.
- **FR-007**: The system MUST continue to require the user's vault password to open a
  profile on that device. The password MUST NOT be the vault key and MUST NOT be used to derive it —
  the vault key is independently generated per FR-001.
- **FR-007a**: Opening a vault MUST require both the device's secure store and the
  user's password. A party holding the vault file plus the full contents of the device's
  secure store, but not the password, MUST NOT be able to read vault content; a party
  holding the vault file plus the password, but not that device's secure store, MUST NOT
  be able to read vault content either.
- **FR-007b**: This release ships no way to change a vault password, so this is a
  forward-looking constraint on any future change-password flow rather than behaviour to
  build now: changing a vault password MUST NOT change the vault key or the key
  identifier, MUST NOT invalidate previously exported files, MUST NOT invalidate any
  recovery kit (kits are sealed under a separate recovery passphrase, FR-019a), and MUST
  affect only the device it was changed on (FR-021a).
**Lock lifecycle**

- **FR-043**: The system MUST drop the vault key from its own process memory on every
  lock, without exception, and MUST NOT retain any cached copy of it.
- **FR-043a**: On a lock caused by the idle timeout, an OS screen lock or sleep, or an
  explicit user lock, the system MUST additionally release any platform-authentication-
  gated reference to the key, such that restoring access requires a full unlock. The app
  exiting is deliberately not one of these triggers — the reference MAY survive a restart
  (FR-054).
- **FR-043b**: On a lock caused by the main window losing focus or the app being
  backgrounded, the system MAY retain a reference to the key that is held by the operating
  system's secure store and gated on platform authentication. The key itself MUST remain
  outside the application's memory while locked.
- **FR-044**: The system MUST lock automatically on every one of: an idle timeout
  elapsing, the operating system locking the screen or entering sleep, the application
  being backgrounded, and the main window losing focus. It MUST also offer an explicit
  user-initiated lock.
- **FR-045**: The idle timeout MUST be user-configurable between 1 and 60 minutes, with a
  default of 15 minutes. It MUST NOT be disableable and MUST NOT accept a value above the
  maximum.
- **FR-046**: While locked, the system MUST NOT display any vault content — no profile
  contents, server names, credentials, command history, or retained terminal output.
- **FR-047**: Locking MUST NOT discard unsaved vault changes. The system MUST seal
  pending changes before dropping the key, or defer the lock until that save completes,
  and MUST NOT leave a partially written vault.
- **FR-048**: On unlock, the system MUST return the user to the view they were in when
  the lock occurred.
- **FR-049**: Locking MUST NOT terminate live SSH sessions, port forwards, file
  transfers, folder mirrors, or monitor pollers. They continue running while the vault is
  locked and are usable again on unlock.
- **FR-050**: While locked, the system MUST conceal the output and state of those live
  activities per FR-046, and MUST restore them on unlock without reconnecting.
- **FR-051**: While locked, the system MAY indicate that background activity is in
  progress and whether it succeeded or failed, and MUST NOT reveal hostnames, paths,
  credentials, or transferred content in doing so.
- **FR-052**: An operation that runs while locked and needs vault content it does not
  already hold MUST fail or wait rather than causing an unlock prompt, and MUST NOT read
  the vault key back into memory.

**Unlock and identity confirmation**

- **FR-053**: A **full unlock** requires the user's password together with the device's
  secure store, per FR-007a. The system MUST require a full unlock after an idle-timeout
  lock, after an OS screen-lock or sleep lock, on the first-ever unlock of a profile, and
  on app start when no platform-authentication-gated reference is available for the
  selected profile. App start MAY instead offer a quick re-unlock (FR-054) when such a
  reference already exists.
- **FR-054**: A **quick re-unlock** uses platform authentication — the device's biometric
  or OS credential prompt. The system MUST accept a quick re-unlock after a focus-loss or
  backgrounded lock while the app is still running, and MUST also accept one when
  reopening a profile whose platform-authentication-gated reference is still present in
  the OS secure store, including after an app restart (FR-054a). It MUST NOT accept one in
  any other situation FR-053 covers.
- **FR-054a**: The profile-selection screen MUST offer a quick re-unlock for a given
  profile only when a platform-authentication-gated reference already exists for it (i.e.
  it has been fully unlocked at least once since that reference was last released) and
  platform authentication is available on this device. Otherwise it MUST show the password
  form only. This is subject to FR-057's consecutive-failure fallback like every other
  quick re-unlock.
- **FR-055**: Wherever this specification requires **identity confirmation** — creating a
  recovery kit (FR-020), exporting (FR-023), and importing — it MUST be satisfied by
  platform authentication or by the password. An in-app confirmation dialog alone MUST NOT
  satisfy it.
- **FR-056**: Where the device offers no platform authentication, or the user has not
  enrolled any, the system MUST fall back to the password for both quick re-unlock and
  identity confirmation, and MUST NOT disable the affected features.
- **FR-057**: Repeated platform-authentication failure MUST fall back to the password
  rather than locking the user out of their own vault. The system MUST NOT impose an
  attempt limit that can render a vault permanently unopenable.

**Single writer**

- **FR-058**: A profile MUST be open for writing in at most one running instance of the
  application at a time. A second instance attempting to open the same profile MUST be
  refused with a distinct "already open elsewhere" outcome, naming the profile.
- **FR-059**: The writer claim MUST be taken when a profile is opened and released when
  the profile is closed or the application exits. A lock (FR-044) MUST NOT release it —
  the instance is still running and still owns the profile.
- **FR-060**: A claim left behind by a crashed or killed instance MUST NOT block the
  profile permanently. The system MUST detect that the claiming instance is gone and allow
  the user to proceed, without requiring them to find and delete a file by hand.
- **FR-061**: The system MUST NOT advance the revision counter or write a vault from any
  instance that does not hold the writer claim.

**Rollback detection**

- **FR-062**: The system MUST record, per vault, the highest revision counter it has ever
  written, and MUST hold that record in the operating-system secure store alongside the
  vault key.
- **FR-063**: The system MUST NOT store the high-water record inside the vault file, or
  anywhere that restoring an old vault file would also restore an old copy of the record.
- **FR-064**: On opening a vault whose revision is lower than the recorded high-water
  mark, the system MUST report a possible-rollback outcome, naming both revisions, and
  MUST NOT proceed until the user chooses either to accept the older vault or to restore a
  newer revision from local history.
- **FR-065**: When the user accepts an older vault, the system MUST reset the high-water
  record to that vault's revision so the warning does not repeat on every subsequent open.
- **FR-066**: The possible-rollback outcome MUST be distinct from the damaged-file and
  unknown-key outcomes, and MUST state plainly that work may be missing.

**Diagnostics**

- **FR-067**: The system MUST record a local diagnostic entry for every failed migration,
  recovery-kit consumption, import, and unlock, containing the outcome code, a timestamp,
  the revision numbers involved, a short prefix of the key identifier, and a short prefix
  of the file hash.
- **FR-068**: Diagnostic entries MUST NOT contain hostnames, file paths, user-chosen
  filenames, usernames, credentials, recovery-phrase words, or any vault content. FR-002
  already forbids the vault key.
- **FR-069**: Diagnostic entries MUST remain on the device and MUST NOT be transmitted
  anywhere, consistent with the project's no-telemetry rule.
- **FR-070**: The system MAY record successful migrations, recoveries, imports, and
  unlocks at the same level of detail and under the same restrictions.

**Sealed file format**

- **FR-009**: The system MUST write one single sealed file format, used identically for
  local storage and for export, carrying: format identity, format version, key
  identifier, revision counter, creation time, an opaque per-device sender identifier,
  a display-only sender name, the algorithm used, the encryption nonce, the encrypted
  payload, the authentication tag, and an integrity hash of everything preceding it.
- **FR-010**: The system MUST NOT define a second sealed format for any other transport.
- **FR-011**: The system MUST use the sender identifier as a random per-device value that
  is not derived from any hardware serial or other identifier that persists across a
  reinstall.
- **FR-012**: The sealed file MUST NOT contain the vault key, any passphrase, the
  protected form of the vault key, or any recovery material.

**Migration from the existing format**

- **FR-013**: On **desktop platforms**, on the first successful unlock of a vault in the
  existing format after update, the system MUST re-seal it into the new format under a
  newly generated vault key, preserving all existing content. Android MUST leave such a
  vault in its existing format and refuse migration under FR-039.
- **FR-014**: The system MUST NOT begin migration until the user's existing password has
  successfully decrypted the existing vault.
- **FR-015**: The system MUST verify that the migrated vault opens before treating
  migration as complete, MUST retain the pre-migration file until the user dismisses the
  one-time migration notice, and MUST leave that file untouched if migration fails at any
  step.
- **FR-015a**: Once the user dismisses the migration notice, the system MUST delete the
  pre-migration file. A retained file in the existing format opens with the password
  alone on any machine, so leaving one behind would nullify the device-binding this
  feature exists to establish.
- **FR-016**: The system MUST migrate legacy-extension vault files by the same path and
  leave the result under the current extension.
- **FR-017**: On completing a user's first migration, the system MUST state once,
  explicitly, that the vault file will no longer open on their other devices using the
  password alone, and MUST offer the recovery-kit flow at that moment.
- **FR-018**: The system MUST be able to read and open files in the existing format for
  as long as unmigrated files can exist, and MUST NOT require the user to migrate in
  order to read their data.

**Recovery kit**

- **FR-019**: The system MUST provide an opt-in, offline recovery kit that allows the
  vault key to be re-established on another device the user controls.
- **FR-019a**: The recovery kit MUST be sealed under a **recovery passphrase** chosen by
  the user at the moment the kit is created. That passphrase is specific to the kit and
  MUST NOT be the device's vault password. Consuming a kit MUST require the recovery
  passphrase. A party holding the kit and the vault file but not the recovery passphrase
  MUST NOT be able to establish the vault key or read any content.
- **FR-019a1**: A vault password MUST NOT be written into a recovery kit, an exported
  file, or any other artefact that leaves the device. The vault password is device-local
  and MUST NOT be required on, or transferred to, any other device.
- **FR-019b**: A recovery-passphrase mismatch when consuming a kit MUST be reported as the
  wrong passphrase for that kit, not as a damaged kit. A kit MUST remain usable with its
  recovery passphrase regardless of any later change to a vault password on any device —
  the two secrets are unrelated.
- **FR-019c**: The system MUST offer the kit in two forms and MUST let the user choose
  between them when creating one: a printable recovery phrase of a fixed word count,
  displayed for transcription or printing, and a recovery file saved through a system save
  dialog. Both forms MUST be sealed under the recovery passphrase per FR-019a.
- **FR-019d**: The receiving device MUST accept either form: typed or pasted phrase
  words, or a picked recovery file.
- **FR-019g**: Recovery using the **phrase** form MUST require the vault file to be
  supplied alongside it, on every platform. The phrase carries only the wrapped key; the
  values needed to unwrap it are derived from the key identifier inside the vault file.
  The **file** form is self-contained and MAY be consumed without the vault file on
  desktop.
- **FR-019h**: When the phrase form is created, the system MUST state that the phrase alone
  is not sufficient and that the vault file will also be needed. Discovering this at
  recovery time is a failure of this requirement.
- **FR-019e**: The recovery phrase MUST be verifiable on entry, such that a
  mistranscribed or incomplete phrase is reported as a phrase-entry error before any
  recovery-passphrase attempt, and is distinguishable from a wrong passphrase.
- **FR-019f**: When the user chooses the file form, the system MUST state that the file
  is subject to whatever backup, sync, and malware exposure its chosen location has, and
  MUST NOT default the save location to a cloud-synced or backed-up folder.
- **FR-020**: The system MUST NOT create a recovery kit unless the user explicitly asks
  for one, MUST require identity confirmation first, and MUST warn that the kit, the
  vault file, and the recovery passphrase together grant full access to every secret.
- **FR-021**: When a recovery kit is used on a second device, that device MUST place the
  recovered key into its own operating-system secure store and MUST prompt the user to set
  a vault password **for that device**, protecting the key by that device's secure store
  and that password per FR-007a. Continued access MUST NOT depend on the kit remaining
  present.
- **FR-021a**: Vault passwords are per device. The system MUST NOT transfer, derive, or
  reuse one device's vault password on another. A user MAY choose to type the same
  password on both devices; that is their choice and MUST NOT be implemented as
  propagation.
- **FR-022**: The system MUST NOT transmit, upload, or back up a recovery kit anywhere.

**Export**

- **FR-023**: The system MUST confirm the user's identity before exporting, even though
  the exported bytes are encrypted.
- **FR-024**: The system MUST export the vault as already sealed on disk and MUST NOT
  unlock the vault as part of exporting.
- **FR-025**: The system MUST suggest an export filename that identifies the
  application, the date, the time, and the revision.
- **FR-026**: The system MUST present a system save dialog and MUST NOT send an exported
  file anywhere without the user choosing a destination.
- **FR-027**: The system MUST remove any temporary or cached copy it created during
  export, on both the success and failure paths.
- **FR-028**: The system MAY record the revision and a short hash prefix of an export in
  its diagnostic log, and MUST NOT record any vault content.

**Import and verification**

- **FR-029**: The system MUST route every incoming vault file through one verification
  procedure that checks, in order: format identity, format version, integrity hash,
  authentication, key identifier, and revision policy.
- **FR-030**: The system MUST copy an incoming file into its own storage before reading
  it, and MUST validate the copy it will actually use rather than re-reading the source.
- **FR-031**: The system MUST match an incoming file's key identifier against every vault
  key the device holds, not against one profile's key. It MUST NOT decrypt a file whose
  key identifier matches none of them, and MUST direct the user to the recovery-kit path
  in that case.
- **FR-031a**: A vault key established by consuming a recovery kit, for which no profile
  exists on this device yet, is an **unclaimed key**. It MUST be held in the secure store
  like any other vault key and MUST be included in the FR-031 match.
- **FR-032**: When an incoming file matches an unclaimed key, the system MUST offer to
  import it as a new profile, and that new profile MUST become that key's sole owner —
  no other profile shares an unclaimed key's ownership.
- **FR-032a**: When an incoming file matches a key already owned by a profile on this
  device, the system MUST NOT overwrite that profile. It MUST land the import as a new,
  separately-named profile instead (auto-suffixed on a further name collision) that
  shares the owning profile's key, and MUST name the owning profile in the offer so the
  user understands why the two are related.
- **FR-032b**: A profile created by FR-032a MUST be independently unlockable with the
  owning profile's own vault password from the moment import completes — its key-wrap
  sidecar and device-factor keystore entry MUST be established for it directly (not left
  pointing at the owning profile's own identifiers), the same guarantee FR-032 already
  makes for a profile created from an unclaimed key.
- **FR-034**: The system MUST write an accepted import atomically, such that an
  interruption leaves either no new file or a complete one, never a partial file.
- **FR-035**: The system MUST remove its own copies of an imported file from temporary
  and cache locations when import completes or fails.
- **FR-036**: The system MUST surface each distinct verification failure — not a vault
  file, unsupported version, damaged or tampered, sealed for another key, unlock
  cancelled — as its own outcome, and MUST NOT collapse them into a single generic
  error. (Older and same-revision-conflict are no longer failures per FR-032a/FR-033.)

**Platform and integration**

- **FR-037**: The system MUST register the vault file type with the operating system so
  the file is recognised, and MUST ensure the operating system does not generate content
  previews of vault files.
- **FR-038**: Android MUST be able to create, open, use, and save a vault in the new
  format. A vault whose key was established through a recovery kit MUST remain usable.
- **FR-039**: Android MUST NOT migrate an existing-format vault. The action MUST refuse
  with a message saying migration must be performed on a desktop machine, not with a
  generic failure.
- **FR-040**: The general export and import file flows MUST remain unavailable on
  Android in this release and MUST refuse with a message stating that.
- **FR-041**: The Android recovery-kit flow MUST accept a vault file alongside the
  recovery kit as a single restore action, so that a user whose desktop has migrated can
  reach their vault on Android without the general import flow. This restore MUST use
  the same verification procedure as FR-029.
- **FR-042**: Both platforms MUST read both the existing and the new vault format for as
  long as unmigrated vaults can exist.

### Key Entities

- **Vault key**: the 256-bit secret that seals one vault. Independently generated, never
  derived from the password. Reaching it requires both the device's secure store and the
  user's password. Identified publicly by a derived key identifier. Never leaves the
  device except via an explicit recovery kit.
- **Vault password**: the user's credential for a profile **on one device**. Unrelated to
  how the vault key is generated, but required to reach it. Device-local: never written to
  any file that leaves the device, never transferred to or required on another device.
- **Recovery passphrase**: a separate secret chosen when a recovery kit is created, used
  only to seal and open that kit. Distinct from any vault password, and unaffected by
  changing one.
- **Key identifier**: a short public value derived from the vault key. Appears in every
  sealed file. Determines whether a given file can possibly be opened by this device.
- **Sealed vault file**: the single encrypted container used both as the on-disk vault
  and as an exported file. Carries the key identifier, revision counter, provenance
  fields, and its own integrity hash.
- **Revision counter**: a per-vault number that only increases, used to order two files
  of the same vault and to detect downgrade and conflict.
- **Revision history**: the five most recent local sealed states of a vault, kept so a
  damaged current file or an unwanted restore is recoverable.
- **Revision high-water mark**: the highest revision ever written for a vault, held in the
  secure store beside the key so that restoring an old vault file cannot also restore an
  old copy of it. The basis for rollback detection.
- **Recovery kit**: an opt-in, user-held, offline artefact that re-establishes a vault
  key on another device. Sealed under its own recovery passphrase, so it is one of two
  factors rather than a bearer token, and carries no vault password. Issued in either of two interchangeable
  forms carrying the same sealed material — a printable phrase or a saved file — chosen
  by the user at creation. Not created by default; never transmitted.
- **Profile**: a named vault as the user sees it in the picker. One profile, one vault
  key, one key identifier, one revision counter. A device may hold several, each with its
  own key.
- **Unclaimed key**: a vault key established by consuming a recovery kit for which no
  profile exists on this device yet. It participates in key-identifier matching and
  becomes owned by the profile created from the first file that matches it.

---

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of existing profiles on a machine open with the same content after
  migration; zero profiles are left unreadable by the update.
- **SC-002**: A vault file copied to a machine that has never held its key cannot be
  opened, with or without the original password, in 100% of attempts.
- **SC-003**: An exported file examined by any means outside the app reveals zero private
  key, password, or hostname strings.
- **SC-004**: Every one of the seven defined import failure situations produces a
  distinct, self-explanatory message; a tester who has not read this spec can state the
  cause of each rejection from the message alone.
- **SC-005**: In 100% of rejected imports and 100% of interrupted imports, the existing
  local vault opens afterwards with unchanged content.
- **SC-006**: A user with two machines can move a vault from the first to the second
  using only the in-app recovery-kit flow, unaided by documentation, in under 10 minutes.
- **SC-007**: A full unlock of a migrated vault is no slower than unlocking the same
  vault before migration. A quick re-unlock after a focus-loss lock completes in under 2
  seconds from the user's action, including the platform authentication prompt.
- **SC-008**: A single altered byte anywhere in a vault file is detected in 100% of
  cases, and a previous revision opens successfully in 100% of those cases.
- **SC-009**: No file written anywhere on disk by the app contains the vault key in
  unprotected form, verified by searching every app-written path after a full
  create–save–export–lock cycle.
- **SC-010**: Zero recovery kits exist on disk for a user who never explicitly requested
  one.
- **SC-011**: Given the vault file and a full copy of the device's secure store but not
  the password, and separately given the vault file and the password but not that
  device's secure store, vault content is unreadable in 100% of attempts.
- **SC-012**: A user whose desktop has migrated can reach that vault on their Android
  device using the recovery kit, the vault file, and the kit's recovery passphrase,
  without any desktop-only step beyond producing the kit, and without entering the
  desktop's vault password on the phone.
- **SC-013**: Given a recovery kit and a vault file but not the kit's recovery passphrase,
  vault content is unreadable and no vault key is established, in 100% of attempts.
- **SC-013a**: No vault password appears in any recovery kit, exported file, or other
  artefact leaving the device, verified by inspecting every such artefact after a full
  create–export–kit cycle.
- **SC-014**: Both kit forms complete recovery in 100% of attempts, and a kit created in
  one form is accepted when supplied in the other form of the same kit.
- **SC-015**: Each of the five lock triggers locks the vault in 100% of attempts, and no
  vault content is visible or recoverable from the running app afterwards without a full
  unlock.
- **SC-016**: Across repeated lock cycles with unsaved changes pending, zero changes are
  lost and zero partially written vaults occur.
- **SC-017**: A file transfer running across at least 20 lock/unlock cycles completes
  successfully, with zero dropped connections attributable to locking.
- **SC-018**: A user who alt-tabs away and back 20 times in a working session is asked
  for their password zero times, and for platform authentication each time.
- **SC-019**: On a device with no platform authentication, every feature remains
  reachable using the password alone, with zero features withheld.
- **SC-020**: Two instances writing the same profile is impossible: across repeated
  attempts, zero saves are lost and zero duplicate revision numbers are produced.
- **SC-021**: After an instance is killed while holding a profile open, the profile opens
  on the next launch in 100% of attempts with no manual file cleanup.
- **SC-022**: Dismissing a secure-store prompt never loses unsaved work and never
  produces the no-secure-store refusal; retrying succeeds in 100% of attempts once the
  user allows the request.
- **SC-023**: An older vault file restored into place is detected in 100% of attempts and
  never silently becomes the working vault.
- **SC-024**: For any failed migration, recovery, import, or unlock, the local diagnostic
  record is sufficient to identify which failure occurred and which file was involved,
  without a support conversation needing to ask the user to reproduce it.
- **SC-025**: A full read of the diagnostic log after a complete
  create–save–export–import–recover–fail cycle reveals zero hostnames, paths,
  user-chosen filenames, credentials, phrase words, or vault content.
- **SC-026**: On a device holding several profiles, an imported file is routed to the
  correct profile in 100% of attempts without the user identifying it first, and zero
  imports ever produce two profiles sharing one key.

---

## Assumptions

- **Governance first.** The constitution amendment described in Constitutional
  Prerequisites lands before implementation. If it is rejected, this feature is
  cancelled, not reduced.
- **Story 1 does not ship without Story 2.** Story 1 removes cross-device portability;
  releasing it without the recovery kit would strand multi-machine users. They may be
  built in order but must reach users together.
- **Android creates, desktop migrates.** macOS, Windows, Linux, and Android create fresh
  vaults in the new format. Android can open, use, and save a new-format vault whose key
  arrived via the recovery kit, but cannot migrate an existing-format vault; general export
  and import flows remain unavailable. Two vault formats are live simultaneously on both
  platforms and both must remain readable.
- **The Android recovery-kit restore is a deliberate carve-out.** Without it, an Android
  user whose desktop has migrated could obtain the vault key but never the vault file,
  because general import is refused there. Restoring a kit plus a file is treated as one
  recovery action rather than as the general import feature.
- **Vault passwords are device-local, recovery kits carry their own secret.** A vault
  password is never written into a kit, an export, or anything else that leaves the
  device, and is never required on a second device. A kit is sealed under a recovery
  passphrase chosen for it. A user may type the same string as their password on a second
  device if they wish — that is reuse by choice, never propagation by the system.
- **The password is a genuine second factor, not a UI gate.** It no longer derives the
  vault key, but the vault cannot be opened without it. This is stricter than the
  referenced spec-00, which treats passphrase and device unlock as alternatives; here
  they are both required. The same rule extends to the recovery kit, which is sealed
  under its own recovery passphrase rather than being a bearer token.
- **Linux without a secret service is unsupported for new vaults.** Such a machine can
  still read an unmigrated vault but cannot create or migrate one. This is treated as
  correct fail-closed behaviour, not a bug. A secret service that exists but is not yet
  running is the retryable case (FR-003a), not this one.
- **Losing the secure store entry with no recovery kit is permanent data loss**, and is
  accepted — it is the same bargain the constitution already makes for forgotten
  passwords. The app's obligation is to say so clearly, in advance and at the moment of
  failure.
- **Device-to-device pairing is out of scope.** The recovery kit is the only cross-device
  path in this release. The sealed format reserves the fields pairing will need so that
  adding it later does not change the format.
- **Read-only access for a second instance is out of scope.** A profile already open
  elsewhere is refused outright (FR-058). Building a read-only mode means a second code
  path through every view for a case a user can resolve by switching windows.
- **Changing a vault password is out of scope, because the product has never had it.**
  No such command exists in the codebase today. FR-007b and the second half of FR-019b are
  therefore forward-looking constraints, not work items — they exist so this feature does
  not foreclose adding the flow later.
- **Vault-key rotation is out of scope.** No story in this feature needs it. The sealed
  format carries the key identifier, so rotation can be added later without a format
  change or a second migration. Until it exists, a user who believes their kit or a
  device is compromised has no in-app remedy beyond creating a new profile — an accepted
  gap for this release.
- **Same-network transfer and cloud storage are out of scope**, but the single
  verification procedure required by FR-029 is designed so those transports plug into it
  without a second format or a second code path.
- **Revision history depth is five**, matching the referenced specs; there is no user
  setting for it.
- **Two kit forms is a deliberate cost.** Offering both a phrase and a file means two
  creation paths, two entry paths, and two sets of failure messages. It was chosen over a
  single form so that users who refuse to keep a secret on disk and users who refuse to
  transcribe words are both served.
- **The two forms are not interchangeable in what they require.** A transcribable word list
  holds about 32 bytes; a self-contained kit needs roughly twice that. Rather than make the
  phrase a hundred-plus characters, the phrase carries only the wrapped key and takes the
  rest from the vault file's key identifier — so phrase recovery needs the vault file
  (FR-019g). This costs nothing in practice: a recovered key with no vault file opens
  nothing anyway. See `research.md` Decision 10 for the encoding analysis and the rejected
  alternative.
- **Focus-loss locking will fire often, and that is accepted.** In a terminal app that
  users keep open beside a browser, locking on window focus loss means many locks per
  day. It was chosen deliberately for the security posture. Two things make it liveable:
  FR-049, locking conceals rather than disconnects, and FR-054, returning to the window
  costs a fingerprint rather than a password. Re-unlock latency is a first-class concern —
  see SC-007 and SC-018 — because the user pays it repeatedly.
- **The password's job is reconstituting the key from disk, not gating the window.** That
  is why platform authentication can cover a focus-loss return, and — once a profile has
  been fully unlocked at least once — an app restart too (FR-054, FR-054a), while the
  password is still mandatory after idle and after an OS screen lock (FR-053), and on app
  start whenever no such cached reference exists yet. A stolen powered-off machine still
  needs the password at least once before any quick re-unlock becomes possible, so FR-007a
  and SC-011 hold.
- **Concealment is a UI obligation, not only a key-memory one.** FR-046 and FR-050 mean
  retained terminal scrollback must be hidden while locked, not merely left un-refreshed.
- **Existing vaults are small enough** that re-sealing during migration completes within
  a normal unlock without a separate progress experience.

---

## Resolved Decisions

**D1 — The vault password stays, decoupled from the vault key.** *(FR-007, FR-007a,
FR-007b, SC-011)* The user keeps logging in with their password, and the password is no
longer the vault key nor an input to deriving it. It remains cryptographically load
bearing: opening a vault requires the device's secure store **and** the password, and
neither alone suffices. This is deliberately stricter than the referenced spec-00, where
passphrase and device unlock are alternatives. The alternative reading — a password that
gates only the interface — was rejected because it would let anyone with the machine's
secure-store contents read the vault without knowing the password, which is weaker than
what ships today.

**Amended:** vault passwords are **per device** and never travel (FR-019a1, FR-021a). The
recovery kit is sealed under its own recovery passphrase rather than under a device's vault
password, so nothing in an exported artefact depends on a password from another machine.

**D2 — Android creates, desktop migrates legacy vaults.** *(FR-038 – FR-042, SC-012)*
All platforms create fresh vaults in the new format. Android gains enough secure-store support
to open, use, and save a new-format vault whose key arrived via the recovery kit, but cannot
migrate an existing-format vault; the general export and import flows stay refused there. The
Android recovery-kit restore accepts a vault file as part of the same action — without that
carve-out an Android user could obtain the key but never the file. Android users with no desktop
can create a new sealed vault; users with an existing-format vault keep it unmigrated and
un-nagged.
