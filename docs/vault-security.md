# Vault security model

**Applies to:** desktop app and mobile app · **Implements:** [`specs/002-e2e-vault-migration/`](../specs/002-e2e-vault-migration/spec.md)

This is the "how it actually works" reference for the device-bound vault —
the code-level companion to the [README](../README.md#security)'s
user-facing summary and [ARCHITECTURE.md](../ARCHITECTURE.md#vault-format)'s
one-paragraph overview. Read those first for the pitch; read this for the
mechanism.

---

## 1. Key model: the two-of-two unlock

The vault key (DEK — data-encryption key) is never derived from the
password. It's 32 random bytes, generated once, then sealed under two
independent factors combined together:

```
KEK        = Argon2id(password, salt)     // what the user types
K_device   = 32 random bytes               // OS keystore, this device only
K_combined = SHA-256(K_device ‖ KEK)
dek.wrap   = AEAD(K_combined, DEK)         // <profile>.sshclientx.keywrap, next to the vault file
```

**Neither factor alone reconstructs `K_combined`.** A stolen vault file plus
a guessed password gets nothing without this device's keystore entry; a
stolen keystore entry gets nothing without the password. This is a strict
two-of-two, not a choice of either path (`vault.rs::KeyWrapFile::unwrap_dek`).

A failed unwrap can't distinguish "wrong password" from "wrong device
factor" — both look like an AEAD authentication failure, and that's
intentional: from the caller's side both just mean "you don't have what
this vault needs."

### 1.1 Three separate OS-keystore entries, per profile (`keystore.rs`)

| Entry | Holds | Cleared when |
| --- | --- | --- |
| `devicefactor` | `K_device` | Profile deleted |
| `highwater` | Highest revision ever written (rollback detection) | Profile deleted |
| `quickunlock` | A **raw copy of the unlocked DEK** | Every hard lock, and app exit |

The third entry is what makes Touch ID / Windows Hello re-unlock possible —
see §2.

### 1.2 Lock lifecycle (`lock.rs`)

Three process-only states (never persisted — a relaunched app always starts
`unlocked` with no profile open yet):

| State | DEK in memory | `quickunlock` keystore entry | Recoverable via |
| --- | --- | --- | --- |
| `unlocked` | yes | — | — |
| `locked_soft` | no | **retained** | platform auth (Touch ID/Hello) *or* full password |
| `locked_hard` | no | **released** | full password only |

```
unlocked ──focus lost / backgrounded──────────▶ locked_soft
unlocked ──idle timeout / OS lock+sleep / explicit lock──▶ locked_hard
locked_soft ──platform auth succeeds──────────▶ unlocked
locked_soft ──idle timeout / OS lock+sleep / explicit lock──▶ locked_hard
locked_hard ──password + device factor────────▶ unlocked
```

Idle timeout is user-configurable 1–60 min (default 15), **not disableable**.
Locking never discards unsaved changes and never touches live SSH
sessions/tunnels/transfers/mirrors/monitors — those keep running through
every lock.

### 1.3 Where the password actually matters

Touch ID/Windows Hello (`platform_auth.rs`, macOS/Windows only — Linux has
no portable equivalent and always falls back to the password) is a
**shortcut for `locked_soft` only**. It is not a replacement for the
password:

- Every app launch starts with `quickunlock` empty (cleared on the previous
  exit), so the very first unlock of a session is always the full password
  + device-factor path.
- Every idle timeout, OS screen lock/sleep, or explicit lock drops straight
  to `locked_hard`, where platform auth is a no-op and only the password
  works.

So on macOS/Windows the password is skippable only for "switched away and
came back within the idle window without the screen locking" — everything
else, on every platform, requires it.

---

## 2. Recovery kit: moving the key to a second device

Opt-in, offline, user-held — not created by default. Lets a *second* device
the user controls recover the same DEK, without ever exposing the
originating device's vault password (`recovery.rs`).

### 2.1 Why not AEAD

A 24-word BIP39 phrase caps out at 256 bits of entropy. A 32-byte DEK sealed
with AES-256-GCM/XChaCha20-Poly1305 needs the DEK *plus* a mandatory 16-byte
tag — 48 bytes, which doesn't fit in 32. Instead, a **one-time pad**:

```
KEK_recovery = Argon2id(recovery_passphrase, salt)
wrapped      = DEK XOR SHA-256(KEK_recovery ‖ "sshclientx-recovery-pad-v1")
```

Authentication comes from recomputing `kid` (a stable public hash of the
DEK) from whatever the unwrap produces and comparing it to the target —
never from a tag. Sound specifically because the pad is used for exactly
one message, ever, under a key that exists for exactly one kit.

### 2.2 Two interchangeable forms

- **Phrase**: 24 BIP39 words. Carries no salt of its own — the salt is
  derived from the vault's `kid`, so **consuming a phrase kit requires the
  vault file too** (only it can supply that `kid`). A malformed/mistyped
  word fails the BIP39 checksum *before* any passphrase is tried, so it's
  reported distinctly from a wrong passphrase.
- **File**: self-contained (`RKIT` magic + `kid` + random salt + wrapped
  bytes) — needs nothing else to consume.

Both forms carry identical sealed material and recover the same DEK.

### 2.3 Consumption → an unclaimed key

Consuming a kit does **not** import any vault content. It establishes the
recovered DEK on the new device exactly like a fresh profile key would be:
a brand-new random device factor in that device's own keystore, and a new
`.keywrap` sidecar sealed under a **new vault password chosen for this
device** — never the originating device's password. It's filed under
`.unclaimed/<kid>.keywrap`, visible to the user as "a recovered key waiting
for its vault file," and discardable if never used.

A kit alone, or a kit plus the vault file without the right passphrase,
yields nothing. A kit stays valid under its own passphrase forever,
regardless of any device's vault password ever changing.

---

## 3. Profile import & claiming

How an unclaimed key (§2.3) — or any vault file from anywhere — actually
becomes an open profile, or restores over an existing one. Two-stage
command pair, `import_vault_pick` then `import_vault_commit`
(`lib.rs`), sharing one verification pipeline, `vault::verify_and_import`.

### 3.1 Pick: verify and stage

1. The picked file is copied into app-private staging storage; only that
   copy is ever verified from here on (closes a TOCTOU window against the
   original being swapped mid-flow).
2. `verify_and_import` runs, in strict order — a `kid` this device doesn't
   hold is **never decrypted**:
   1. Parse the sealed container (magic/format/length/integrity-hash).
   2. Look up `kid` against every key this device holds (open profile's
      key, or an unclaimed key given its password) — never just "the"
      current profile's key.
      - No match → refused (`BOX_UNKNOWN_KEY`).
      - Matches an **unclaimed** key → `Disposition::CreateProfile`.
      - Matches an **owned** profile's key → `Disposition::RestoreOver`,
        plus a revision comparison against that profile's current content:
        - incoming newer → proceed, no extra confirmation.
        - incoming **older** → `ConfirmationNeeded::Older`.
        - same revision, different content → `ConfirmationNeeded::Conflict`.
        - same revision, same content → `Disposition::NoOp`.
   3. AEAD open with the matched key.

The disposition and any confirmation needed are returned to the UI so it
can ask "create a new profile named ___?" / "this is an older backup —
restore anyway?" / "conflicting content — overwrite?" before anything is
written.

### 3.2 Commit: write

Re-runs `verify_and_import` from scratch on the same staged bytes — never
trusts the pick step's cached decision, so a stale or replayed commit
re-derives and re-refuses identically. `Older`/`Conflict` without the
matching confirmation flag is refused again here, logged as a diagnostic.

- **`CreateProfile`**: takes a claim on the destination path *before*
  checking it doesn't already exist (closes a race between two concurrent
  imports of the same new name), writes atomically (tmp file + rename),
  then deletes the `.unclaimed/<kid>.keywrap` bookkeeping — the keystore
  device-factor entry itself stays, since the new profile's future unlocks
  read from it. This is what turns an unclaimed key into a real profile.
- **`RestoreOver`**: proves exclusive access (existing in-memory claim if
  it's the currently-open profile, otherwise acquire-and-drop a fresh one),
  rotates the existing file into revision history, then writes atomically.
- **`NoOp`**: nothing written.

**Net effect:** an unclaimed key can only ever become a *new* profile
(never silently merge into an existing one), and an existing profile's key
can only ever be *restored over* (never spawn a duplicate profile for a key
already owned) — `verify_and_import`'s `kid`-first lookup is what enforces
both directions.

---

## Where the code lives

| File | Owns |
| --- | --- |
| `vault.rs` | Sealed container format, key-wrap (two-of-two), revision history, `verify_and_import` pipeline, writer claims |
| `keystore.rs` | OS secure-store reads/writes (device factor, high-water mark, quick-unlock cache), error classification |
| `lock.rs` | Lock state machine, idle-timeout, per-platform lock triggers |
| `platform_auth.rs` | Touch ID / Windows Hello prompt, consecutive-failure fallback to password |
| `recovery.rs` | Recovery kit create/consume (both forms), unclaimed-key bookkeeping |
| `lib.rs` | Tauri commands wiring all of the above (`vault_unlock_quick`/`_full`, `recovery_kit_create`/`_consume`, `import_vault_pick`/`_commit`, …) |

Full functional-requirement-level detail (FR-xxx references, edge cases,
threat model) lives in [`specs/002-e2e-vault-migration/spec.md`](../specs/002-e2e-vault-migration/spec.md)
and [`data-model.md`](../specs/002-e2e-vault-migration/data-model.md).
