# Phase 0 Research: End-to-End Encrypted Vault Migration

**Feature**: `002-e2e-vault-migration` | **Date**: 2026-09-06 | **Spec**: [spec.md](spec.md)

Crate versions, licences, MSRVs and error-mapping behaviour below were read from published
crate sources and vendor documentation, not recalled. Items still open are marked.

---

## Decision 1 — Keep the payload exactly as it is

**Decision**: The sealed payload stays `zstd(SQLite serialisation)`, byte for byte. This
feature replaces the *container*, not the contents.

**Rationale**: The payload is orthogonal to every requirement here. Changing both at once
would make a failed migration impossible to attribute, and the existing compress-then-encrypt
ordering is already correct (compressing after encryption is useless against AEAD output).

**Alternatives considered**: Moving to CBOR per spec-00 §6 — rejected, that section describes
a key-material document this app does not have; its vault is a SQLite database and always
has been.

---

## Decision 2 — Format discrimination by magic length

**Decision**: Test the first 8 bytes for `SSHCLTX1`; failing that, the first 4 for `OMNV`;
failing that, `BOX_BAD_MAGIC`.

**Rationale**: The two magics cannot collide — `OMNV` is 4 bytes and the legacy byte at
offset 4 is a version number, never `L`. One ordered test, no ambiguity, no version registry.

**Alternatives considered**: A shared envelope with a discriminator byte — rejected, it would
require rewriting every existing legacy file to add it, which is precisely what migration is
supposed to do gradually.

---

## Decision 3 — Two-of-two unlock: combine, don't chain

**Decision**: The DEK is wrapped once under a key combined from both factors:

```
KEK       = Argon2id(password, salt)          // salt in app private storage
K_device  = 32 random bytes                   // OS secure store
K_combined = SHA-256(K_device || KEK)
dek.wrap  = AEAD(K_combined, DEK)             // app private storage
```

Neither factor alone yields `K_combined`, so FR-007a and SC-011 hold in both directions.

**Rationale**: `sha2` is already a direct dependency, so combining costs no new crate. Both
inputs are already uniformly random 32-byte secrets — the password has *already* been through
Argon2id — so a plain hash is the right primitive here, not a second password KDF.

**Alternatives considered**:
- *Nested wrap* `AEAD(KEK, AEAD(K_device, DEK))` — equivalent security, two AEAD operations
  and two nonces to manage instead of one. No benefit.
- *HKDF* — the correct textbook combiner, but `hkdf` was deliberately removed from this
  project in feature 001. Re-adding a crate to hash two 32-byte secrets fails Principle V.
- *Store the DEK directly in the keystore, password as UI gate only* — rejected during
  clarification (spec D1): anyone with the keystore contents would read the vault.

---

## Decision 4 — Soft lock keeps a biometric-gated keystore entry, never memory

**Decision**: A full unlock additionally writes the DEK into the secure store under a
short-lived, platform-authentication-gated entry. A **soft** lock (focus loss, backgrounded)
drops the DEK and KEK from process memory but leaves that entry, so a quick re-unlock is a
keystore read behind a biometric prompt. A **hard** lock (idle, OS screen lock, explicit,
exit) deletes it.

**Rationale**: This is the only construction that satisfies FR-054 (no password on an
alt-tab return) and FR-043 (key never cached in app memory) simultaneously. Rebuilding the
DEK from `dek.wrap` requires the password, so a quick re-unlock cannot go through that path.

**Accepted exposure**: while the app runs, a gated DEK entry exists in the keystore. An
attacker who defeats platform authentication on a *running, already-unlocked* machine gets
it. That is spec-00 §2.2's explicitly out-of-scope "malware on an unlocked device", and it is
why the entry is deleted on every hard lock and on exit.

---

## Decision 5 — `keyring` 4.2 for the secure store, with a `secret-service` downcast

**Decision**:

```toml
keyring = "4.2"                                  # MIT OR Apache-2.0
[target.'cfg(all(unix, not(any(target_os="macos", target_os="android"))))'.dependencies]
secret-service = { version = "5", default-features = false }   # error downcast only
```

keyring 4.x is a rewrite over `keyring-core` plus per-platform store crates; its default `v1`
feature restores the familiar `Entry::new(service, user)` API. `Entry::set_secret(&[u8])` /
`get_secret()` take raw bytes, so a 32-byte key needs no encoding wrapper.

| Platform | Backend | Non-syncing |
| --- | --- | --- |
| macOS | legacy `SecKeychain` via `security-framework` | by construction — legacy keychain items never reach iCloud |
| Windows | Credential Manager, `CredWriteW`, non-roaming | user scope, correct |
| Linux | Secret Service over `zbus`, pure-Rust crypto | no sync concept |

**FR-003 vs FR-003a — the distinction the spec insisted on.** `keyring_core::Error` is too
coarse: its Linux mapping sends the "no service at all" case into the same `PlatformFailure`
arm as genuine bugs. The boxed source is the real `secret_service::Error`, so downcasting
recovers it — and it takes **two** checks, not one:

| Source | Meaning | Outcome |
| --- | --- | --- |
| `Error::Unavailable` | no D-Bus session address, or socket missing (headless, plain SSH) | `VAULT_NO_KEYSTORE` |
| `Error::Locked` / `Prompt` / `PromptDisconnected` | keyring locked, prompt dismissed, service died mid-prompt | `VAULT_KEYSTORE_DENIED` |
| `Zbus(MethodError(ServiceUnknown \| NameHasNoOwner))` | D-Bus is up but no keyring provider installed | `VAULT_NO_KEYSTORE` |

`Unavailable` is narrower than its name suggests — it does *not* cover "D-Bus running,
gnome-keyring absent", which is why the third row exists. Windows
(`ERROR_NO_SUCH_LOGON_SESSION`) and macOS (`errSecNotAvailable`) both surface as
`NoStorageAccess` and need no downcast.

**Rationale for cross-platform over per-platform**: going direct to `security-framework` /
`windows-sys` / `secret-service` means reimplementing the attribute schemas and the
`CredWriteW` blob handling those store crates already do, with no error-model gain — the same
downcast would still be needed. The `secret-service` direct dependency costs no extra
compilation because keyring already pulls it in; cargo unifies them.

**Rejected**: the macOS `protected` store (data-protection keychain with
`SecAccessControl` + `USER_PRESENCE`). It requires a provisioning profile and a
`keychain-access-groups` entitlement, which breaks unsigned `tauri dev` runs. The
user-presence gate comes from Decision 6 instead, which also works on Windows where no
keychain equivalent exists. The documented upgrade path stays open: depend on `keyring-core`
directly and call `set_default_store()`.

---

## Decision 6 — `robius-authentication` for platform auth; Linux has none

**Decision**: `robius-authentication = "0.3.1"` (MIT) on macOS and Windows. On Linux,
`#[cfg]` the path out entirely and always use the password (FR-056).

**No Tauri plugin covers desktop.** `tauri-plugin-biometric` 2.3.3 supports Android and iOS
only; its support table lists Linux, Windows and macOS as unsupported. This matters
constitutionally too — using a crate rather than a plugin avoids a second Governance step
under Principle II.

**Linux is genuinely unavailable, not merely awkward.** robius does implement polkit, but it
requires installing a `.policy` XML file into `/usr/share/polkit-1/actions/` as root — dead
for AppImage, tarball, or `cargo install` distribution — *and* a running authentication agent,
which many minimal and tiling setups lack. Polkit also answers "is this subject authorized for
this action", not "prove you are the logged-in user"; it is the wrong primitive. `fprintd`
exists but is optional and unevenly configured. The spec's password fallback is the answer,
and this is exactly the case FR-056 was written for.

**Why not hand-roll the FFI**: the crate already encodes correctness that would otherwise be
rediscovered through bug reports — on Windows, the WinRT activation-factory route (the naive
`CoCreateInstance` fails with "Class not registered"), a dedicated COM MTA thread, a mandatory
`CheckAvailabilityAsync()` first call *without which verification hangs*, and a foreground
hack because the Hello prompt otherwise appears behind the window; on macOS, a fresh
`LAContext` per call (reusing one silently skips the prompt — a security bug), a guard against
the empty reason string that raises an ObjC exception and aborts the process, and a
`catch_unwind` so a panic cannot unwind across an ObjC frame.

**Threading**: the API is callback-based with no async variant; bridge to the Tauri command
with a `tokio::sync::oneshot`. macOS `LAContext` carries no main-thread marker, so it is safe
from a Tauri async command. Treat `LAError -1004` (not interactive / not foreground) and the
reported first-call-after-login "UI activation timed out" as **retryable**, not as auth
failure.

**Known cost**: robius pins `windows = "0.56"` while this tree already carries `windows`
0.61.3 and 0.62.2 via Tauri/tao — a third concurrent major, paid in Windows compile time and
binary size. macOS adds nothing (`objc2` 0.6.4, `objc2-foundation` 0.3.2, `block2` 0.6.2 are
already present via tao at the versions robius wants).

**Plan**: take the crate as-is, measure the Windows build. If it hurts, vendor the two
platform files (~400 lines, MIT, attribution required) against the `windows` 0.62.2 already in
the tree — `windows::core::factory` has the same signature there, so the port is mechanical —
and pass the real Tauri window HWND instead of `GetDesktopWindow()`, which is the proper fix
for the z-order problem rather than the foreground hack.

---

## Decision 7 — MSRV declaration must move 1.85 → 1.88

**Decision**: Bump `rust-version` in `src-tauri/Cargo.toml` to `1.88` and update the comment,
which currently attributes the 1.85 floor to russh 0.63.

**Rationale**: `keyring` 4.2.0 declares `rust-version = "1.88.0"` and `edition = "2024"`.

**Verified, not assumed**: this is a documentation-accuracy fix, **not** a CI breakage. The
local toolchain is 1.98.1 and both release workflow jobs use
`dtolnay/rust-toolchain@stable`, so no runner pins a version below 1.88. Leaving the
declaration at 1.85 would simply be false.

---

## Decision 8 — Toolchain stays OpenSSL-free and Perl-free

**Verified**: `Cargo.lock` (744 packages) contains zero `openssl` / `openssl-sys` entries, and
none of the above introduces one.

**Guard rails**, since cargo features are additive across the whole graph:

- `secret-service` has a `crypto-openssl` feature. keyring pins the pure-Rust `crypto-rust`
  backend. The direct `secret-service` dependency exists **only** for the error type, so it
  must carry `default-features = false` and enable nothing — any crypto feature named there
  unifies into keyring's copy and could pull OpenSSL in through the back door.
- keyring's `cli` feature pulls a store with `features = ["vendored"]`, compiling libdbus from
  C source. It is not in `default`; never enable it.
- `cc` is already a build requirement (rusqlite `bundled`, zstd-sys, ring), so no change
  there. No Perl is introduced — that was the OpenSSL-specific pain.
- On Linux, `libdbus-sys` is already in the tree via tao, so the zbus backend adds no new
  native library.

---

## Decision 9 — `chacha20poly1305` 0.10, matching the existing `aead` family

**Decision**: `chacha20poly1305 = "0.10"`. Adds exactly one crate — every transitive
dependency is already in the lockfile.

**Rationale**: the tree already carries two `aead` majors (0.5.2 via `aes-gcm` 0.10, 0.6.1 via
`ssh-key`/`ssh-cipher`), and it compiles. That is survivable, but two ciphers used through one
generic helper must sit on the *same* one. 0.10 lands on `aead` 0.5.2, matching the
`aes-gcm` 0.10 already in use, so `encrypt_with_key`/`decrypt_with_key`
(`src-tauri/src/lib.rs:178-195`) can be made generic over `Aead` with **zero migration**.
`aead::Payload { msg, aad }` exists in both 0.5 and 0.6, so the AAD requirement is met either
way. Pure Rust, no C toolchain.

**Alternative rejected for now**: bump `aes-gcm` to 0.11 and take `chacha20poly1305` 0.11,
both on `aead` 0.6. Forward-looking and MSRV-aligned, but it is a breaking API migration
(`AeadInPlace` → `AeadInOut`, `inout` in the signatures) **on the vault decrypt path** — the
one code path where a subtle mistake means unopenable vaults. It also dedups nothing, since
`ssh-cipher` keeps `aead` 0.5 in the tree regardless. Wire format is identical either way, so
this move stays available later at no cost.

**The real gotcha is not the cipher.** `NONCE_LEN` is a fixed `12` and `parse_vault_blob`
(`lib.rs:197`) assumes it. XChaCha needs 24. **Version the container's nonce length, not the
cipher choice** — which the new `alg` byte already does.

---

## Decision 10 — Recovery phrase: 24 words, with the vault file supplying the salt

> **This is the one decision in this plan that changes a written requirement and should be
> signed off before implementation.**

**The conflict**: FR-019c says the phrase form is "a printable recovery phrase … a
fixed-length word list". `bip39` 2.2.2 hard-caps entropy at **32 bytes / 24 words**
(`BadEntropyBitCount` otherwise). A self-contained kit needs roughly salt(16) + wrapped
DEK(48) + version ≈ 65 bytes. **That cannot be a word list.** Meanwhile FR-012 forbids putting
recovery material in the sealed vault file, so the overflow cannot simply live there.

**Decision**: carry exactly 32 bytes in the phrase — the DEK encrypted under
`Argon2id(recovery_passphrase, salt = SHA-256(kid)[0..16])` with a deterministic nonce — and
take `kid` from the vault file the user supplies at recovery. The `recovery_passphrase` is
the kit's own secret, **not** any device's vault password (FR-019a): vault passwords are
device-local and never travel. Authentication comes from recomputing the key identifier from
the unwrapped DEK and comparing it to the file's `kid`: a mismatch is `KIT_WRONG_PASSPHRASE`,
and a phrase that fails bip39's own checks is `KIT_MALFORMED`, raised before any passphrase
attempt (FR-019e). Deriving the salt from `kid` is sound — a salt must be *unique*, not
secret, and `kid` is unique per vault.

**Consequence that must be written back into the spec**: phrase-form recovery **requires the
vault file**. `recovery_kit_consume`'s `vault_file` parameter becomes mandatory for the phrase
form on desktop, not just on Android. The file form stays self-contained.

**Alternative if that consequence is unacceptable**: drop the word list and use
`bech32 = "0.12"` (zero dependencies) for a fully self-contained ~65-byte kit — 104 characters
plus checksum, grouped in fours. Its BCH checksum is *stronger* than bip39's 8-bit one
(guaranteed detection of ≤4 substitutions, ~1e-9 false accept vs ~1/256), but 104 characters is
materially worse to hand-transcribe than 24 words, and it gives no "which word is wrong"
pointer. FR-019c would need rewording either way.

**Ruled out**: `mnemonic` (no checksum at all — fails FR-019e outright); `pricklybird`
(one word per byte, so 32–80 words, CRC-8 only); `ms-codec`/codex32 (technically ideal, but
published this month by a single author — too new to carry a recovery path); `slip39`
(untouched since 2020).

---

## Decision 11 — Writer claim via `File::try_lock` on a sidecar

**Decision**: `std::fs::File::try_lock` on a per-profile `<name>.sshclientx.lock` sidecar.
**Zero new dependencies.**

**Rationale**: this delivers FR-060 for free. It is `flock(LOCK_EX|LOCK_NB)` on Unix and
`LockFileEx(…|FAIL_IMMEDIATELY)` on Windows, and **the kernel releases the lock when the
process dies — crash or `SIGKILL` included — on all three desktop platforms.** No PID file, no
heartbeat, no stale-claim cleanup code to write or to get wrong.

**Stabilised in Rust 1.89** (`file_lock`); local toolchain is 1.98.1 and CI is `@stable`.

**`tauri-plugin-single-instance` is the wrong tool**, checked rather than assumed: it keys on
`config().identifier` (overridable only on Linux), so it cannot be made per-profile, and it
*terminates* the second process — exactly wrong when that launch wants a different profile.
Avoiding it also avoids a Governance step under Principle II.

**Implementation constraints**:
- Lock the **sidecar**, never the vault file — atomic-rename-on-save replaces the inode and
  would orphan the lock.
- Unix `flock` is advisory, Windows `LockFileEx` is mandatory on the byte range. Using a
  sidecar makes that asymmetry irrelevant.
- Hold exactly one guard; std documents re-locking from a handle that already holds the lock
  as *"unspecified and platform dependent, including the possibility that it will deadlock."*
- Open the sidecar with `.read(true)`/`.write(true)` — append-only fails on Windows.
- **Synced folders**: `flock` over NFS/SMB is unreliable, and Dropbox/iCloud/OneDrive give no
  cross-machine locking at all. If a profiles directory can live in a synced folder, the claim
  protects against a second local process only. That warrants a UI warning, not more code.

**Fallback if the MSRV move were unwanted**: `fd-lock = "4.0.4"` — its `rustix` and
`windows-sys` ranges are already satisfied by the lockfile, so one new crate. Not needed here.
`fs2` is from 2018; `fs4` is its maintained successor.

---

## Decision 12 — Lock triggers: Tauri gives focus only; write ~100 lines for the rest

**Decision**: take `Focused(bool)` from Tauri's `on_window_event`; implement idle time and OS
screen-lock/sleep per platform. Only new dependency is `x11rb` 0.14 (`screensaver` feature),
Linux-only — `objc2`, `objc2-foundation`, `objc2-app-kit`, `objc2-core-graphics`,
`windows-sys` and `zbus` are all already in the lockfile.

**Rationale**: Tauri 2.11's `WindowEvent` has exactly eight variants and none cover
occlusion, visibility, suspend, or resume; `RunEvent` covers none either, and no official
plugin exists for idle, lock, or power.

> **Safety finding — do not use the obvious crates.** `user-idle` 0.6.0 **and all three of its
> forks** share a macOS double-`IOObjectRelease` that over-releases a Mach port and crashes
> with `EXC_GUARD` on modern macOS. `tauri-plugin-idlemonitor` has a Linux path that cannot
> compile against its own declared `zbus` 5 and a Windows path watching for a message that
> never reaches the queue. `tauri-plugin-screen-lock-status` is Tauri v1 and dead.

| | Idle time | Lock / sleep |
| --- | --- | --- |
| macOS | `CGEventSource::seconds_since_last_event_type` — **needs no Accessibility or Input-Monitoring permission**, unlike the IOKit route every crate takes | `NSDistributedNotificationCenter` on `com.apple.screenIsLocked`/`Unlocked`, plus `NSWorkspaceWillSleep`/`DidWake`; register via `run_on_main_thread` |
| Windows | `GetLastInputInfo` + `GetTickCount`; clamp the 49.7-day wrap and negative deltas. Session-scoped, so a locked workstation reads as idle — which is what we want | Message-only `HWND_MESSAGE` window + `WTSRegisterSessionNotification`. `WTS_SESSION_LOCK`/`UNLOCK` are **not exported by windows-sys** — define them |
| Linux X11 | `x11rb` `screensaver_query_info(root).ms_since_user_input` — exact ms, pure Rust, no Xlib | logind over `zbus`: `Manager.PrepareForSleep`, `Session.Lock`/`Unlock`/`LockedHint` — same code on X11 and Wayland |
| Linux Wayland | `ext-idle-notify-v1` (Mutter ≥ GNOME 50, KWin 6.6, sway, Hyprland, COSMIC, niri). **Edge-triggered, not a clock** — register a threshold, synthesise elapsed time | as X11 |

**Both `WM_WTSSESSION_CHANGE` and `WM_POWERBROADCAST` must be handled inside the WndProc** —
they are `SendMessage`-delivered and never appear in the message queue. This is the exact bug
that makes the existing plugin non-functional.

**Wayland has no elapsed-idle-time API.** `org.freedesktop.ScreenSaver.GetActiveTime` — used
by every `user-idle*` crate as its D-Bus path — returns how long the *screensaver* has run,
which is 0 while the user is merely idle. It is simply the wrong value. Since FR-045 only needs
"has the user been away past T", `ext-idle-notify-v1` is sufficient and covers every modern
compositor.

---

## Decision 13 — MSRV moves to 1.89, once

**Decision**: set `rust-version = "1.89"` in `src-tauri/Cargo.toml`, superseding Decision 7's
1.88.

**Rationale**: `keyring` 4.2 needs 1.88, `File::try_lock` needs 1.89. One bump covers both.
Verified non-breaking: local toolchain 1.98.1, both release-workflow jobs use
`dtolnay/rust-toolchain@stable`, no runner pins anything lower.

---

## Risks carried into implementation

| Risk | Detail | Mitigation |
| --- | --- | --- |
| macOS legacy keychain is deprecated | `SecKeychain` is on Apple's deprecation list | Works across all supported macOS versions today; the `protected` store is the documented migration when signing infrastructure exists |
| macOS keychain ACL prompts in development | Legacy items are ACL-bound to the signing identity; unsigned dev builds reading items written by a signed build trigger a password prompt | Expected, not a bug — document it so it is not chased |
| `store_status()` caches once per process | A user who launches before gnome-keyring is up gets a permanent failure for that process lifetime | Never cache a "no secret store" verdict from it; re-probe with a real operation before telling the user their store is gone |
| Secret Service unlock prompts block the calling thread | `unlock_all` pops a GUI prompt and blocks | All keyring calls go through `spawn_blocking`, never the async runtime |
| `keyring_core::Error` is `#[non_exhaustive]` | New variants can appear in a minor release | Catch-all arm required |
| `Error::Ambiguous` on Linux | Multiple Secret Service items matching the same attributes — easy to hit if an earlier version wrote a different schema | Handle explicitly, not as a generic failure |
| ~~Unverified: macOS code-signing requirement for `evaluatePolicy`~~ — **resolved (T119)**: works unsigned | An unsigned `cargo run --example` binary calling `Context::authenticate` with the `DeviceOwnerAuthentication` policy successfully initiated the system prompt (`canEvaluatePolicy_error` succeeded, no immediate error) on Apple Silicon. No code-signing entitlement is required for this call. | None — no release-time surprise to plan around |
| Nonce length is hard-coded | `NONCE_LEN = 12` and `parse_vault_blob` assume it; XChaCha needs 24 | Version it through the container's `alg` byte, which already implies the length |
| Profiles directory inside a synced folder | `flock` gives no cross-machine exclusion; two machines could both hold "the" claim | UI warning; the rollback and conflict machinery is the real backstop |
| Third `windows` crate major | `robius-authentication` pins `windows` 0.56 alongside the tree's 0.61.3 and 0.62.2 | Ship it, measure the Windows build; vendor ~400 lines against 0.62.2 only if it hurts |
| Wayland idle is edge-triggered | `ext-idle-notify-v1` reports crossings, not elapsed time | Synthesise elapsed time from the threshold events; FR-045 only needs a threshold |
| **Unverified**: `com.apple.screenIsLocked` under App Sandbox | No authoritative source found | Moot unless this ships to the Mac App Store; verify then |
