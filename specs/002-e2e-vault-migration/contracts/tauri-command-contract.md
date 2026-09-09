# Contract: Tauri command and event surface

**Feature**: `002-e2e-vault-migration` | **Date**: 2026-09-06

The IPC boundary between the React renderer and the Rust core. Per constitution Principle II
the renderer is a renderer: every item below performs its crypto, keystore, and file work in
Rust and returns decisions, never key material.

**Invariants for every command here**

- No vault key, password-wrapped key, recovery material, or plaintext payload ever crosses
  this boundary, and **no vault password ever leaves the device** (FR-019a1). Recovery
  *phrase words* cross once, outbound, at creation only.
- Errors are the outcome codes from [sealed-container.md](sealed-container.md) §5, returned
  as the code plus a user-facing message. The renderer switches on the code; it never parses
  the message.
- Commands that mutate a vault require the writer claim (FR-061) and return `VAULT_BUSY`
  without it.

---

## 1. Changed commands

### `list_profiles() -> Vec<ProfileSummary>`

Was `Vec<String>`. Now carries what the picker needs without opening anything.

| Field | Notes |
| --- | --- |
| `name` | |
| `format` | `sealed` \| `legacy` — drives the migration hint |
| `revision` | From the file header; readable without any key |
| `busy` | Another instance holds the claim |

Reading a header needs no key, so this stays cheap and lock-free.

### `select_profile(name) -> SelectOutcome`

Now also **acquires the writer claim** (FR-058). Returns `VAULT_BUSY` if another live
instance holds it. A claim left by a dead process must not block (FR-060).

`SelectOutcome`: `{ exists, format, needs_migration }`.

### `close_profile()`

Now also **releases the writer claim** (FR-059). A lock does not release it.

### `setup_master_db(password) -> UnlockOutcome`

The unlock path, and the only place migration is triggered.

| Outcome | Meaning |
| --- | --- |
| `Opened` | Sealed vault opened normally |
| `Migrated { from_revision }` | Legacy vault re-sealed; the notice is now owed (FR-017) |
| `Rollback { file_revision, high_water }` | Must be resolved before use (FR-064) |

Errors: `VAULT_AUTH`, `VAULT_CORRUPT`, `VAULT_UNKNOWN_KID`, `VAULT_NO_KEYSTORE`,
`VAULT_KEYSTORE_DENIED`, `VAULT_KDF`, `VAULT_BUSY`.

Migration runs only after the password has successfully decrypted the legacy vault (FR-014),
and leaves the legacy file untouched on any failure (FR-015).

### `export_profile(name) -> Option<String>`

Now requires identity confirmation first (FR-023), and packs the stored sealed blob without
unlocking (FR-024). Suggested filename per sealed-container.md §6. Returns the chosen path,
or `None` if the user cancelled the save dialog.

Errors: `BOX_AUTH`, `VAULT_NO_KEYSTORE`, `VAULT_KEYSTORE_DENIED`.

Desktop only; Android returns the platform refusal.

### `import_profile_pick() -> Option<ImportPreview>` · `import_profile_save(...)`

Replaced by the two-step flow in §2. The old pair sniffed 5 bytes and copied a file; neither
signature survives verification, disposition, and conflict handling.

---

## 2. New commands — import

### `import_vault_pick(source_path?, key_password?, retry_staging_id?) -> Option<StagedImport>`

Desktop opens the native picker when `source_path` is absent. Android requires `source_path`
from its in-app file browser. Rust guards that path and bounded-copies at most 64 MiB into the
app sandbox before `verify_and_import` runs; source bytes never transit the renderer
(FR-029, FR-030).

`StagedImport`: `{ staging_id, disposition, profile?, confirmation_needed, incoming_revision, sender_name, created_at }`

`disposition`: `create_profile` | `restore_over` | `no_op` | `needs_password`. `profile` names
the matched profile for `restore_over`/`needs_password`/`no_op`; null for `create_profile`.

Errors: the full `BOX_*` set. `BOX_UNKNOWN_KEY` carries a pointer to the recovery-kit flow.

### `import_vault_commit(staging_id, name?, key_password?) -> String`

Performs the write decided at staging, returning the profile name the import actually
landed on. `name` only for `CreateProfile` (the caller's chosen name; auto-suffixed on a
collision is never silent — a hand-picked name that collides is refused outright).
`key_password` is the password for whichever key `import_vault_pick` matched, when one
was needed (FR-032a's key material read comes from that profile's own keywrap).

`RestoreOver { profile }` never overwrites `profile`'s own file — it always lands as a
new, separately-named copy ("`profile` [IMPORT]", auto-suffixed on a further collision)
that gets its own key-wrap sidecar and device-factor entry, copied from `profile`'s own,
so it is independently unlockable with `profile`'s vault password from the moment this
returns (FR-032a, FR-032b). Because nothing is ever overwritten, `confirmation_needed`
from the staging step is informational only here — commit never refuses on it (FR-033
dropped).

Write is atomic (FR-034).

### `import_vault_discard(staging_id) -> ()`

Removes the staged copy. Staged copies are also removed on commit and on app exit (FR-035).

---

## 3. New commands — recovery kit

### `recovery_kit_create(form: "phrase" | "file", recovery_passphrase) -> RecoveryKitOutput`

Requires identity confirmation (FR-020). Seals the key under `recovery_passphrase` — a
secret chosen for this kit, **not** the device's vault password (FR-019a). No vault
password may enter the output (FR-019a1).

- `form = "phrase"` → returns the word list for display. **The only outbound secret on this
  boundary.** The renderer must display it and must not persist it anywhere.
- `form = "file"` → shows a save dialog whose default location is neither cloud-synced nor
  backed up (FR-019f); returns the chosen path.

### `recovery_kit_consume(source, recovery_passphrase, vault_file?, new_vault_password, name?) -> { kid, profile? }`

`source` is typed phrase words or a picked kit file — both accepted, interchangeably
(FR-019d). Establishes an **unclaimed** key in this device's secure store, protected by
that store and `new_vault_password`, which the user sets during recovery (FR-021,
FR-021a). The originating device's vault password is never supplied here.

Phrase checksum is validated before the passphrase is used, so `KIT_MALFORMED` is returned
without a passphrase attempt (FR-019e).

`vault_file` is **required for the phrase form on every platform**, because the phrase carries
only 32 bytes and the Argon2id salt is derived from the `kid` inside the vault file
(research.md Decision 10). It is optional for the file form: after establishing its unclaimed
key, either platform may import the matching vault through the general import flow.

Now written into the spec as FR-019g and FR-019h.

**Single-action restore (FR-041).** When both `vault_file` and `name` are supplied, this
also lands that file as a brand-new profile named `name` in the same call — verified
through the identical `verify_and_import` pipeline the general import flow uses (FR-029),
against the key just recovered. `profile` in the response names the landed profile (equal
to `name` — never auto-suffixed, so a collision fails the whole call outright rather than
picking a different name silently); omitted when landing wasn't attempted (`name` not
supplied — desktop's own call site never passes one, so its established-only behavior is
unchanged). The key is still established either way even if landing then fails or was
never attempted — a caller can always retry against it later via the general import flow,
or claim/discard it via `unclaimed_key_claim`/`unclaimed_keys_list`/`unclaimed_key_discard`
below.

Errors: `KIT_MALFORMED`, `KIT_WRONG_PASSPHRASE`, `KIT_KID_MISMATCH`, `VAULT_NO_KEYSTORE`,
`VAULT_KEYSTORE_DENIED`, plus the full `BOX_*` set when landing was attempted and failed.

### `unclaimed_key_claim(kid_hex, key_password, vault_file, name) -> String`

Finishes claiming an already-established unclaimed key outside the original
`recovery_kit_consume` call — the retry path when a single-action land either wasn't
attempted (desktop's own `recovery_kit_consume` call never passes `name`, so this is
always its route to actually landing a key) or failed (most commonly Android: the name
collided). `key_password` is the device password chosen when the key was established
(the same "unclaimed key's own password" `resolve_key_lookup`'s unclaimed-store branch
already unwraps with for the general import flow's `needs_password` retry). Runs the same
`verify_and_import` pipeline as everything else (FR-029) and the same claim step as
`recovery_kit_consume`'s single-action land, sharing its implementation
(`land_recovered_key`). Returns the landed profile's name (equal to `name` — never
auto-suffixed).

Reachable from the locked picker screen (unclaimed keys are device-wide, tied to no
profile — the one screen guaranteed reachable regardless of platform or whether any
profile exists yet) and from Settings → Vault Security once one does.

Errors: the full `BOX_*` set, `VAULT_AUTH` (wrong `key_password`), `VAULT_UNKNOWN_KID`
(no unclaimed key for `kid_hex` on this device).

### `unclaimed_keys_list() -> Vec<String>` · `unclaimed_key_discard(kid_hex) -> ()`

A kit consumed but never landed (or landed and then abandoned before a name was picked)
leaves a key owning nothing — visible and disposable rather than invisible clutter (spec
Edge Cases), instead of accumulating unnoticed. `unclaimed_keys_list` returns each such
key's `kid`, hex-encoded (plain strings, not a richer `UnclaimedKey` type — there's nothing
else about an unclaimed key worth surfacing yet); `unclaimed_key_discard` removes one's
key-wrap sidecar and keystore device-factor entry for good. Surfaced on the locked picker
and in Settings → Vault Security.

---

## 4. New commands — lock lifecycle

### `vault_lock(hard: bool) -> ()`

Explicit lock. `hard` is always true from the UI's lock button; the soft path is driven by
window events, not by the renderer.

### `vault_unlock_quick() -> ()`

Platform authentication only. Valid solely from `locked_soft` (FR-054); returns `VAULT_AUTH`
from `locked_hard`, which is what forces the password in the cases FR-053 lists.

### `vault_unlock_full(password) -> ()`

Password plus secure store. Valid from either locked state.

### `vault_lock_state() -> LockState`

`unlocked` | `locked_soft` | `locked_hard`. For render-on-mount; steady state comes from the
event in §6.

### `idle_timeout_get() -> u32` · `idle_timeout_set(minutes) -> ()`

1–60, default 15, not disableable (FR-045). Out-of-range is rejected rather than clamped.

---

## 5. New commands — migration and rollback

### `migration_notice_ack(name) -> ()`

The user has seen the one-time notice. **Deletes the pre-migration legacy file** (FR-015a).
Until this is called the legacy file remains, and it is the only thing standing between a
crash mid-migration and a lost vault.

### `rollback_resolve(name, choice) -> ()`

`choice`: `AcceptOlder` — opens the older file and resets the high-water mark so the warning
stops (FR-065); or `RestoreNewer { revision }` — restores that revision from local history.

---

## 6. Events (Rust → renderer)

| Event | Payload | Purpose |
| --- | --- | --- |
| `vault-lock-state` | `{ state }` | Drives concealment. The renderer must hide content on `locked_*`, including retained terminal scrollback (FR-046, FR-050) |
| `vault-background-activity` | `{ kind, status }` | Lets a locked screen show that work completed or failed, with no hostname, path, or content (FR-051) |
| `vault-migration-notice` | `{ name, from_revision }` | Raises the one-time notice (FR-017) |

Live SSH sessions, tunnels, transfers, mirrors, and monitors keep running across every lock
(FR-049) and are not torn down or reconnected by any command here.

---

## 7. Platform availability

| Command | Desktop | Android |
| --- | --- | --- |
| `export_profile` | yes | refuse, naming the platform (FR-040) |
| `import_vault_*` | yes | yes — bytes supplied by the in-app file browser (FR-040) |
| `recovery_kit_consume` | yes | yes — may land the selected vault as a single restore action (FR-041) |
| profile creation | yes | yes — creates a fresh sealed vault through the shared path (FR-038) |
| `recovery_kit_create` | yes | yes |
| lock lifecycle, unlock | yes | yes |

Android creates, opens, uses, saves, and imports sealed vaults (FR-038, FR-040), reads both
formats (FR-042), and refuses legacy-vault migration with a desktop-naming message (FR-039).
