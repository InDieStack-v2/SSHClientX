# Data Model: End-to-End Encrypted Vault Migration

**Feature**: `002-e2e-vault-migration` | **Date**: 2026-09-06 | **Spec**: [spec.md](spec.md)

Derived from the spec's Key Entities and Functional Requirements. Field names here are
logical, not wire or API names — the byte layout lives in
[contracts/sealed-container.md](contracts/sealed-container.md).

---

## 1. Entity overview

```
                    ┌──────────────────┐
                    │   Profile        │ 1 ── owns ──► 1  VaultKey
                    │  (named vault)   │ 1 ── has ───► 1  RevisionCounter
                    └────────┬─────────┘ 1 ── has ───► 1  HighWaterMark
                             │           1 ── has ───► 0..5 RevisionHistory
                             │           1 ── has ───► 0..1 WriterClaim
                             │
                             │ sealed as
                             ▼
                    ┌──────────────────┐
                    │ SealedVaultFile  │ ── carries ──► KeyIdentifier
                    │  (disk + export) │ ── carries ──► RevisionCounter
                    └──────────────────┘

   VaultKey ── derived ──► KeyIdentifier (kid)
   VaultKey ── exported as ──► RecoveryKit (0..n, opt-in)
   VaultKey with no Profile ──► "unclaimed key" state
```

---

## 2. Entities

### 2.1 VaultKey

The 256-bit secret that seals one vault.

| Field | Type | Notes |
| --- | --- | --- |
| `material` | 32 bytes | CSPRNG at creation. Never derived from the password (FR-007). |
| `kid` | 16 bytes | Derived from `material`; see KeyIdentifier. |
| `owner_profile` | Profile name or `null` | `null` ⇒ **unclaimed** (FR-031a). |

**Storage**: OS secure store only, marked this-device-only / non-syncing (FR-001).
Never on disk in unprotected form, never in logs (FR-002).

**Access rule (FR-007a)**: reaching `material` requires **both** the device secure store
**and** that device's vault password (device-local, FR-021a). Neither alone suffices. This is a two-of-two, not a choice
of two paths — it is stricter than spec-00 §3.

**Lifecycle**:

| From | Event | To |
| --- | --- | --- |
| — | vault created (desktop only) | owned, on this device |
| — | legacy vault migrated (desktop only) | owned, on this device |
| — | recovery kit consumed | **unclaimed** |
| unclaimed | file matching its `kid` imported | owned by the new Profile (FR-032) |
| unclaimed | user discards it | destroyed |
| owned | profile deleted | destroyed |

**Not in this release**: rotation. `material` never changes for the life of a profile.

---

### 2.2 KeyIdentifier (`kid`)

| Field | Type | Notes |
| --- | --- | --- |
| `value` | 16 bytes | Stable function of the VaultKey (FR-004). |

Public. Appears in every sealed file written. Its only job is answering "could this device
possibly open this file?" before any decryption is attempted (FR-031).

**Uniqueness**: a `kid` is either unclaimed or owned by exactly one Profile on a device —
never both, never two Profiles. Observing otherwise is a damaged-state outcome, not a
conflict (spec Edge Cases).

---

### 2.3 Profile

A named vault as the user sees it in the picker.

| Field | Type | Notes |
| --- | --- | --- |
| `name` | string | Existing validation rules apply (unchanged). |
| `vault_key` | VaultKey | Exactly one. |
| `revision` | u64 | Current RevisionCounter. |
| `high_water` | u64 | See HighWaterMark. |
| `history` | RevisionHistory | Up to 5 prior sealed states. |
| `claim` | WriterClaim or `null` | Held while open. |

**Invariant**: one Profile, one VaultKey, one `kid`, one RevisionCounter. A device may hold
several Profiles, each with its own key (FR-031).

---

### 2.4 SealedVaultFile

The single container used **identically** for the on-disk vault and for export (FR-009,
FR-010). Byte layout: [contracts/sealed-container.md](contracts/sealed-container.md).

| Field | Type | Source |
| --- | --- | --- |
| `format_identity` | 8 bytes | Constant. |
| `format_version` | u16 | Bumped only by a versioned migration. |
| `kid` | 16 bytes | Owning VaultKey. |
| `revision` | u64 | RevisionCounter at seal time. |
| `created_at` | i64 | Unix ms. |
| `sender_id` | 16 bytes | Random per device, not a hardware serial, not stable across reinstall (FR-011). |
| `sender_name` | UTF-8 | Display only. Untrusted — never used for a filesystem path or as a decision input. |
| `algorithm` | u8 | AEAD in use. |
| `nonce` | bytes | Unique per seal. |
| `ciphertext` | bytes | Sealed payload. |
| `tag` | 16 bytes | AEAD tag. |
| `integrity_hash` | 32 bytes | Over all preceding bytes. |

**Bound into the AEAD as associated data**: format identity, format version, `kid`,
`revision` — so altering any of them invalidates the file (FR-005).

**Payload**: the existing zstd-compressed SQLite serialisation. Unchanged by this feature —
what changes is the container around it.

**Must never contain** (FR-012): the vault key, the password, the password-wrapped key, or
any recovery material.

---

### 2.5 RevisionCounter

| Field | Type | Notes |
| --- | --- | --- |
| `value` | u64 | +1 on every successful save (FR-005). |

**Rules**:
- Advances only from the instance holding the WriterClaim (FR-061).
- Orders two files of the same vault, and is the input to downgrade and conflict detection.
- A file claiming an implausibly high value is refused as damaged, not accepted as newest
  (spec Edge Cases).

---

### 2.6 HighWaterMark

| Field | Type | Notes |
| --- | --- | --- |
| `value` | u64 | Highest revision ever written for this vault (FR-062). |

**Storage**: OS secure store, beside the VaultKey (FR-062). **Never** inside the vault file
or anywhere restoring an old vault file would also restore an old copy of it (FR-063) —
that placement is the entire mechanism.

**Comparison at open**:

| Condition | Outcome |
| --- | --- |
| `file.revision >= high_water` | normal open; `high_water` advances on next save |
| `file.revision < high_water` | **possible rollback** — user must accept or restore newer (FR-064) |

On acceptance, `high_water` resets to the opened file's revision so the warning does not
repeat (FR-065).

---

### 2.7 RevisionHistory

| Field | Type | Notes |
| --- | --- | --- |
| `entries` | ordered list, max 5 | Prior SealedVaultFiles (FR-006). |

Retention is fixed at five; no user setting. Used when the current file fails verification,
when a restore is unwanted, and as the "restore newer" option in rollback detection.

---

### 2.7a Passwords and passphrases

Two distinct secrets, deliberately not interchangeable.

| Secret | Scope | Role | Travels? |
| --- | --- | --- | --- |
| **Vault password** | One profile **on one device** | Second factor in the two-of-two unwrap of that device's `dek.wrap` | **Never.** Not in any file that leaves the device, never required on another device (FR-019a1, FR-021a) |
| **Recovery passphrase** | One recovery kit | Seals and opens that kit | Only in the user's head; the kit itself carries no password |

A user may type the same string for both, or the same vault password on two devices. That
is reuse by choice; the system never propagates or derives one from the other.

---

### 2.8 RecoveryKit

Opt-in, offline, user-held. Not created by default (FR-020).

| Field | Type | Notes |
| --- | --- | --- |
| `wrapped_key` | bytes | VaultKey sealed under the kit's own recovery passphrase (FR-019a). |
| `kdf_salt` | bytes | For the recovery-passphrase wrap. |
| `kid` | 16 bytes | So a kit can be matched to a file before the recovery passphrase is asked. |
| `form` | `phrase` \| `file` | User's choice at creation (FR-019c). |

**Both forms carry identical sealed material** and are interchangeable on consumption
(FR-019d). The phrase form is checksummed so a mistranscription is reported as a
phrase-entry error *before* any password attempt, distinctly from a wrong password
(FR-019e).

**Security properties**:
- Kit alone, or kit + vault file without the recovery passphrase, yields nothing
  (FR-019a, SC-013).
- A kit carries **no vault password** (FR-019a1) and stays valid under its recovery
  passphrase regardless of any vault-password change on any device; a mismatch reports
  "wrong passphrase for this kit", not "damaged kit" (FR-019b).
- Never transmitted, uploaded, or backed up (FR-022).

**Consumption** produces an **unclaimed** VaultKey in the consuming device's own secure
store and prompts for a vault password **for that device**; continued access does not
depend on the kit remaining present (FR-021, FR-021a).

---

### 2.9 WriterClaim

| Field | Type | Notes |
| --- | --- | --- |
| `profile` | Profile name | What is claimed. |
| `holder` | running instance | Must be provably alive. |

**Rules**:
- At most one instance holds a Profile's claim at a time (FR-058).
- Taken on open, released on close or app exit. A lock (FR-044) does **not** release it —
  the instance is still running and still owns the profile (FR-059).
- A claim whose holder is gone MUST NOT block the profile, and recovery MUST NOT require
  the user to delete a file by hand (FR-060). This makes automatic OS-level release on
  process death the required property, not merely a convenient one.
- No claim ⇒ no revision advance and no vault write (FR-061).

---

### 2.10 LockState

Not persisted — process state. Governs whether vault content is reachable.

| State | Vault key in app memory | Content visible | Live sessions |
| --- | --- | --- | --- |
| `unlocked` | yes | yes | running |
| `locked_soft` | **no** (FR-043) | no (FR-046) | running (FR-049) |
| `locked_hard` | **no** | no | running (FR-049) |

`locked_soft` is reached by a focus-loss or backgrounded lock and may retain a
platform-authentication-gated *reference* held by the OS secure store — never the key itself
(FR-043b). `locked_hard` is reached by idle timeout, OS screen lock or sleep, or explicit
lock, and releases that reference too (FR-043a). The app exiting does **not** release it —
a restarted process starts at `unlocked` with no profile open (this state machine has not
even begun), but the reference itself survives in the OS secure store, and the
profile-selection screen may use it for a quick re-unlock of that profile (FR-054, FR-054a)
without going through this table at all.

**Transitions**:

| From | Event | To |
| --- | --- | --- |
| `unlocked` | window focus lost, app backgrounded | `locked_soft` |
| `unlocked` | idle timeout, OS screen lock/sleep, explicit lock | `locked_hard` |
| `locked_soft` | platform authentication succeeds | `unlocked` |
| `locked_soft` | idle timeout, OS screen lock/sleep, explicit lock | `locked_hard` |
| `locked_hard` | full unlock (password + secure store) | `unlocked` |

Locking never discards unsaved changes: pending changes are sealed first, or the lock waits
for that save (FR-047). On unlock the user returns to the view they left (FR-048).

**Idle timeout**: user-configurable 1–60 minutes, default 15, not disableable (FR-045).

---

### 2.11 DiagnosticEntry

Local only; never transmitted (FR-069).

| Field | Type | Notes |
| --- | --- | --- |
| `outcome_code` | enum | From the outcome vocabulary in the contracts. |
| `timestamp` | i64 | |
| `revisions` | u64 pair | Local and incoming, where applicable. |
| `kid_prefix` | short hex | Not the full identifier. |
| `hash_prefix` | short hex | Of the file involved. |

**Must never contain** (FR-068): hostnames, file paths, user-chosen filenames, usernames,
credentials, recovery-phrase words, or any vault content. FR-002 separately forbids the
vault key.

Written for every failed migration, recovery-kit consumption, import, and unlock (FR-067);
successes may be recorded under the same restrictions (FR-070).

---

## 3. Legacy entity (read-only after this feature)

### LegacyVaultFile (`OMNV`)

| Field | Type |
| --- | --- |
| `magic` | 4 bytes `OMNV` |
| `version` | u8 |
| `salt` | 16 bytes |
| `nonce` | 12 bytes |
| `ciphertext` | AES-256-GCM over zstd(SQLite) |

The key is `Argon2id(password, salt)` — the password *is* the key. This is exactly the
property being removed.

**Rules**: remains readable for as long as unmigrated files can exist (FR-018, FR-042);
migrated on first successful unlock (FR-013); the file is retained until the user dismisses
the migration notice and then **deleted** (FR-015, FR-015a), because a retained copy opens
with the password alone on any machine and would nullify the feature.

---

## 4. Cross-entity validation rules

| Rule | Source |
| --- | --- |
| An incoming file is matched against **every** key the device holds, not one profile's key | FR-031 |
| A file matching no held key is never decrypted | FR-031 |
| A file matching an unclaimed key may create a new Profile that then owns that key | FR-032 |
| A file matching an owned key never overwrites it — always lands as a new Profile sharing that key, naming the owning Profile | FR-032a |
| That new Profile gets its own key-wrap sidecar and device-factor entry (copied, not shared), so it unlocks independently with the owning Profile's password | FR-032b |
| Revision/content differences vs. the owning Profile (older, conflicting) require no confirmation — nothing is ever overwritten | FR-032a |
| Accepted writes are atomic | FR-034 |
| Every distinct verification failure is its own outcome, never collapsed | FR-036 |
