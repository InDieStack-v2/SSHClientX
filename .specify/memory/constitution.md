<!--
Sync Impact Report (v3.2.0)
- Version change: 3.1.0 → 3.2.0 (MINOR — materially expanded guidance; no
  principle removed or redefined)
- Modified principles:
  - I. Device-Bound Secrets — renamed "profile password" to "vault password"
    to match the specs, and added the device-locality rules the feature had
    been carrying alone: a vault password never travels, is never written into
    an export or a recovery kit, is per device rather than per vault, and MUST
    NOT be a constant embedded in the binary. Recovery kits MUST be sealed
    under their own recovery passphrase, never a device's vault password.
  - III. One Core, Every Platform — "the password" → "a vault password" for
    consistency with the above.
- Added sections: none. Removed sections: none.
- Notes: driven by `specs/002-e2e-vault-migration/`. These properties existed
  only in that feature's spec (FR-019a1, FR-021a), which left the constitution
  less specific than the design it governs — a later feature could have
  contradicted them without tripping any gate. The embedded-constant
  prohibition is recorded because it was raised as a design option and
  rejected: a secret shipped in every binary is extractable and adds no
  entropy, so it would have made the two-of-two unlock claim false.

Sync Impact Report (v3.1.0)
- Version change: 3.0.0 → 3.1.0 (MINOR — materially expanded guidance; no
  principle removed or redefined)
- Modified sections:
  - Technology & Architecture Constraints — the dependency bullet was stale the
    moment it was written: v3.0.0 authorised two new dependencies, but the
    feature's own clarification rounds then added platform authentication and
    the recovery-phrase form, which need four more. Replaced with an exhaustive
    six-row table giving the required reason per dependency under Principle V,
    plus the rule that a seventh is a Governance matter. MSRV corrected from a
    stale 1.70 to 1.89 (secure-store binding needs 1.88, `File::try_lock` needs
    1.89), with the floor pinned to those two causes.
- Added sections: none. Removed sections: none. Principles I–V unchanged.
- Notes: driven by `specs/002-e2e-vault-migration/plan.md`, whose Constitution
  Check failed Principle V against v3.0.0 for exactly this reason. Linux gets
  no platform authentication (no portable mechanism exists) and falls back to
  the password. Crates are preferred over Tauri plugins throughout, since a
  plugin would trigger a further Governance step under Principle II.

Sync Impact Report (v3.0.0)
- Version change: 2.0.0 → 3.0.0 (MAJOR)
- Modified principles:
  - I. Device-Bound Secrets (NON-NEGOTIABLE) — the vault sealing key is no
    longer derived from the user's password. It is now a CSPRNG DEK held in
    the OS secure store (this-device-only), with the password wrapped through
    Argon2id into a KEK that protects it. Unlock now requires BOTH the secure
    store AND the password; neither alone suffices. Sealing cipher widened
    from AES-256-GCM only to XChaCha20-Poly1305 (preferred) or AES-256-GCM.
    Fail-closed rule added for machines with no usable secure store. The
    recovery clause is amended: an opt-in, offline, user-held recovery kit is
    now permitted (recovery email, plaintext escrow, and server-held wrapping
    keys remain forbidden). Permanent-data-loss disclosure duty added.
  - III. One Core, Every Platform — REVERSES the platform-portability
    guarantee. Vault files are now device-bound: a copy plus the password no
    longer opens on another device, and that case must be refused distinctly
    from a wrong password. Cross-device access is via the recovery kit only.
    The same-vault-format-on-every-platform rule becomes a transitional
    asymmetry: both platforms read both formats, desktop creates and migrates,
    Android consumes only. Rationale rewritten — "one encrypted profile across
    devices" is no longer the product.
- Modified sections:
  - Technology & Architecture Constraints — on-disk vault bullet rewritten for
    the SSHCLTX1 sealed container (kid, generation, AAD, SHA-256 trailer) with
    OMNV retained as a readable legacy format; one-sealed-format rule added;
    five-revision retention added; dependency bullet extended with an
    XChaCha20-Poly1305 implementation and an OS secure-store binding, with the
    Principle V justification stated; extension/magic bullet updated.
  - Development Workflow — sealed container format and vault key model added
    to the list of constitution-level changes requiring Governance.
- Added sections: none.
- Removed sections: none.
- Follow-up TODOs:
  - TODO(ANDROID_PARITY): Principle III's desktop-creates/Android-consumes
    asymmetry is time-limited. When Android gains create-and-migrate support,
    that clause MUST be removed by a further amendment. It is not an
    open-ended exception.
  - TODO(PAIRING): recovery-kit-only transfer is the interim cross-device
    path. Device-to-device pairing (docs/features/spec-02-qr-same-network.md)
    is expected to supersede it and MUST reuse the same sealed format; revisit
    Principle I's recovery clause when it lands.
- Notes: driven by `specs/002-e2e-vault-migration/` (End-to-End Encrypted
  Vault Migration), which adopts `docs/features/spec-00-e2e-vault.md` and
  `docs/features/spec-01-export-import.md`. Four rules in v2.0.0 forbade that
  feature; this amendment is the precondition for implementing it. Principles
  II (Rust Owns Privilege) and IV (Explicit Trust Boundaries) were reviewed
  and are unaffected — no sentence in either is contradicted by these changes.
  The dormant sync schema (`uuid`/`updated_at`/`deleted`/`edited_by` columns,
  `sync_tombstones`/`sync_flags`/`sync_meta` tables) is untouched and stays
  dormant. Local-only remains absolute: the recovery kit is offline and
  user-held, and no backend is reintroduced.
-->

# SSHClientX Constitution

## Core Principles

### I. Device-Bound Secrets (NON-NEGOTIABLE)

The key that seals a vault (the DEK) MUST be a 256-bit CSPRNG value generated
on-device. It MUST NOT be derived from the user's password. The DEK MUST be
held in the operating system's own secure store for the current user, marked
this-device-only and non-syncing: Keychain with `synchronizable = false` on
macOS and iOS, DPAPI/CNG at user scope on Windows, libsecret or the kernel
keyring on Linux, Android Keystore with `allowBackup=false`. Where no usable
secure store exists the app MUST fail closed — refuse to create, migrate, or
save a vault — and MUST NOT persist an unprotected key as a fallback. The DEK
MUST NOT be written unprotected anywhere on disk, MUST NOT sit next to the
vault file, and MUST NOT appear in logs or crash output.

The user's vault password remains mandatory to open a profile. Opening a
vault MUST require BOTH the device secure store AND the vault password;
neither alone suffices. The vault password is wrapped on-device through
Argon2id into a KEK that protects the DEK — it is not the DEK and MUST NOT
derive it. This is deliberately stricter than
`docs/features/spec-00-e2e-vault.md` §3, which treats passphrase and device
unlock as alternatives.

A vault password is **device-local and MUST NOT travel**. It MUST NOT be
written into an exported vault file, a recovery kit, or any other artefact
that leaves the device, and MUST NOT be required on, or transferred to, another
device. Vault passwords are per device: the system MUST NOT propagate, derive,
or reuse one device's vault password on another. A user typing the same string
on two devices is reuse by their choice and MUST NOT be implemented as
propagation. A vault password MUST NOT be a constant embedded in the
application — a value shipped in every copy of the binary is not a secret and
contributes no entropy. Changing a vault password MUST NOT change the DEK or
its key identifier, MUST NOT invalidate previously exported files or any
recovery kit, and MUST affect only the device on which it was changed. Argon2id parameters (`m_cost` 64 MiB, `t_cost` 3,
`p_cost` 4, 32-byte output) MUST NOT change without a versioned re-key
migration.

Profile content (servers, credentials, keys, tunnels, notes, mirrors) MUST be
zstd-compressed and sealed with an authenticated cipher before it touches
disk: XChaCha20-Poly1305 preferred, AES-256-GCM accepted. Secrets that outlive
a single call MUST live in `Zeroize` wrappers, and the password and KEK MUST
be wiped as soon as the DEK is available.

Forgotten vault passwords are unrecoverable by design. MUST NOT add a vault
recovery email, escrow-of-plaintext, or server-held wrapping key. An opt-in,
offline, user-held recovery kit that re-establishes the DEK on another device
the user controls IS permitted, and is the only sanctioned cross-device path
in this release. A kit MUST NOT be created unless the user explicitly asks for
one, MUST require identity confirmation first, and MUST NOT be transmitted,
uploaded, or backed up anywhere. A kit MUST be sealed under a recovery
passphrase chosen for that kit, never under a device's vault password, so that
a stolen kit is one factor rather than a bearer token and no vault password
leaves the device. A device that consumes a kit MUST place the
recovered key into its own secure store; continued access MUST NOT depend on
the kit remaining on disk. Losing the secure store entry with no recovery kit
is permanent data loss — the same bargain already accepted for forgotten
passwords — and the app MUST state this in advance and again at the moment of
failure rather than reporting a generic error.

The application MUST NOT depend on any backend or account service: there is no
sign-up, sign-in, or server-side identity, and a vault MUST NOT be uploaded,
synced, or shared with another device except by the user manually moving the
vault file together with an explicit recovery kit or, in future, an explicit
pairing. MUST NOT add analytics, telemetry, or crash reporters that send data
off-device.

Rationale: a stolen ciphertext file MUST be worthless even to an attacker who
later learns the password. That is only achievable if the sealing key lives in
hardware-backed device storage rather than in the user's head. There is no
backend to breach, and now no password that alone reconstructs the key.

### II. Rust Owns Privilege

SSH, SFTP, crypto, vault I/O, local filesystem mutation, port forwards,
folder mirror, and Docker remote commands MUST run in Rust Tauri commands. The
webview is a renderer: it MUST NOT implement cryptography, MUST NOT persist
credentials in `localStorage` / `sessionStorage` / IndexedDB, and MUST NOT
spawn shells. Capability files MUST stay minimal: `shell:*`, `fs:*`, and
`webview:*` MUST NOT be granted. `capabilities/default.json` is the
cross-platform ACL; desktop-only plugins (window-state) MUST stay in
`capabilities/desktop.json` so Android validation does not fail. New
permissions require a comment in the capability file stating why they are
needed; "just in case" grants are forbidden. CSP in `tauri.conf.json` MUST
keep `default-src 'self'`, `script-src 'self'`, `frame-src 'none'`,
`object-src 'none'`, and `connect-src` limited to `self` and Tauri IPC only —
there is no network origin to allow-list.

Rationale: XSS via terminal output or a compromised renderer is in scope.
Privilege lives behind IPC so a renderer bug cannot open a shell, rewrite
`C:\`, or exfiltrate the vault key.

### III. One Core, Every Platform

Shared behavior MUST live in `src-tauri/src/lib.rs::run()` and the modules it
owns. `src-tauri/src/main.rs` MUST remain a thin desktop shim. Desktop-only
crates (`rfd`, `open`, `tauri-plugin-window-state`) and call sites MUST be
`cfg(not(target_os = "android"))`. Features that cannot map to a platform
(folder mirror on Android today) MUST be cfg-gated or UI-hidden, not forked
into a second codebase. Default `cargo build` MUST stay OpenSSL/Perl-free
(`default = []`). Release and CI bundles MUST pass `--features
full-ssh-algos` so production binaries speak RSA host keys and legacy KEX/MAC.

Vault files are device-bound. A vault MUST open only on a device that holds
its key. Copying a vault file to another device and supplying a vault password
MUST NOT be sufficient to open it, and that case MUST be refused as
sealed-for-another-key, distinctly from a wrong-password error. Cross-device
access is via the opt-in recovery kit only. Device-to-device pairing is a
future feature and MUST reuse the same sealed format when it arrives.

Platform write capability is asymmetric for a transitional period:

- Both platforms MUST read both the legacy `OMNV` format and the current
  sealed format, for as long as unmigrated vaults can exist.
- Desktop (macOS, Windows, Linux) creates and migrates vaults in the current
  sealed format.
- Android MAY open, use, and save a sealed vault whose key arrived via a
  recovery kit, but MUST NOT create or migrate one. Both actions MUST refuse
  with a message naming desktop as the place to perform them. The general
  export and import file flows remain unavailable on Android.
- This asymmetry lapses when Android gains create-and-migrate support, at
  which point this clause MUST be removed by a further amendment. It is not an
  open-ended exception.

Rationale: the product is one encrypted profile per device with an explicit,
user-driven path between devices — not one profile that floats freely between
them. A platform fork would still split the threat model, which is why both
platforms share the sealed format and the reader even while their write
capabilities differ for one release.

### IV. Explicit Trust Boundaries

TOFU host-key pinning is mandatory: first-use MUST show a fingerprint and
subsequent connections MUST bind the pin (including per-connection nonce
binding that resists prompt-race). Bytes from a remote host — SFTP names,
paths, terminal output — are untrusted. Directory-entry names MUST pass
`is_safe_dir_entry_name` before being joined onto a local path. Live-edit /
drag staging MUST use the unpredictable `app_temp_root` and
`safe_temp_leaf_name`. Local FS commands the UI can invoke MUST pass
`guard_local_path` (refuse filesystem root and OS system directories).
Terminal output MUST NOT be interpreted as HTML. Untrusted input MUST NOT be
concatenated into shell strings; remote Docker/Info actions MUST use argument
arrays or equivalent, not string-built `sh -c`.

Rationale: the SSH peer and the renderer are both hostile. Path traversal,
zip-slip, `/tmp` pre-create, and XSS through ANSI/HTML are known classes; each
new FS or terminal path MUST reuse the existing guards.

### V. Native and Lean

SSHClientX MUST remain a Tauri 2 + Rust + React application. MUST NOT migrate
to Electron or add a second Chromium runtime. MUST NOT add dependencies that
are already transitive without a documented reason, or plugins whose APIs the
app does not call. New SSH/SFTP/crypto behavior MUST extend existing modules
(`ssh_manager`, `tunnel`, `mirror`, `docker`, `hlc`) rather than growing
ad-hoc JavaScript. A new network backend, account system, or cloud sync MUST
NOT be reintroduced without a new constitution amendment — see Principle I.
Complexity requires a concrete current use; YAGNI applies. Frontend stack is
React 18, TypeScript, Tailwind, xterm.js — new UI libraries need a gap these
do not cover.

Rationale: startup time, RAM, and installer size are user-visible. Unused
plugins widen the XSS blast radius (Principle II).

## Technology & Architecture Constraints

- Product name is SSHClientX; Rust package is `sshclientx`; library target is
  `sshclientx_lib`. Workspace folder name is not a public identifier.
- Frontend: React 18, TypeScript, Tailwind CSS, xterm.js, Vite. Backend: Rust
  2021 (MSRV 1.89), Tauri 2, russh, rusqlite (bundled), aes-gcm, argon2, zstd,
  zeroize. The MSRV floor is set by the secure-store binding (1.88) and by
  `std::fs::File::try_lock` (1.89); it MUST NOT be lowered while either is in
  use. `reqwest` + `rustls` is used only for the update check against GitHub
  releases (no OpenSSL on the default path); it MUST NOT be used to add any
  account/sync backend call.
- The device-bound vault required by Principle I needs six dependencies beyond
  that baseline. Principle V requires a documented reason for each; these are
  the reasons. **This list is exhaustive — adding a seventh is a Governance
  matter, not a code review.**

  | Dependency | Why it MUST exist | Why nothing already present will do |
  | --- | --- | --- |
  | XChaCha20-Poly1305 implementation | Principle I names it the preferred seal | `aes-gcm` cannot produce it; it MUST sit on the same `aead` major as the `aes-gcm` already in the tree, or the two cannot share one generic seal path |
  | OS secure-store binding | Principle I mandates a CSPRNG DEK held in the platform store, fail-closed when none exists | No stdlib equivalent; the three platform APIs share nothing |
  | Secret Service error type (Linux only) | Principle I's fail-closed rule MUST distinguish "no store exists at all" (terminal) from "this request was denied or is unavailable" (retryable); the cross-platform error enum collapses them | Already in the tree via the secure-store binding, so it costs no compilation — but the distinction is unreachable without naming it. MUST carry `default-features = false`: cargo features are additive, and naming a crypto feature here would unify OpenSSL into the store binding's copy |
  | Platform authentication (macOS, Windows) | The lock lifecycle requires re-entry without a password after a focus-loss lock | No Tauri plugin covers desktop; hand-rolled FFI reproduces known traps (WinRT activation-factory route, mandatory availability pre-check, a fresh authentication context per call) |
  | Recovery-phrase encoding | The recovery kit MUST offer a transcribable form whose checksum fails before any password attempt | Hand-rolling a checksummed word encoding is inventing format code on a recovery path |
  | X11 idle query (Linux only) | The idle timeout MUST NOT be disableable, so idle MUST be measurable on every desktop platform | No cross-platform idle crate is safe to ship; the widely-used one and its forks carry a macOS over-release that crashes the process |

  Platform authentication MUST be compiled out on Linux, where no portable
  mechanism exists, and MUST fall back to the password there. Adding a Tauri
  *plugin* for any of the above remains a separate Governance matter under
  Principle II — crates are preferred precisely because they do not widen the
  plugin surface.
- On-disk vault, current format: writers MUST produce the sealed container
  defined in `docs/features/spec-01-export-import.md` §2.1 — magic
  `SSHCLTX1`, format version, key identifier (`kid`), monotonic `generation`
  counter, `created_at`, sender id and display name, algorithm byte, nonce,
  ciphertext, AEAD tag, and a SHA-256 of all preceding bytes, with
  AAD = `magic || format || kid || generation`.
- On-disk vault, legacy format: `OMNV` magic, versioned header, per-profile
  salt, per-save nonce, AES-256-GCM over zstd(SQLite). It MUST remain readable
  and is migrated to the sealed format on first successful unlock. Readers
  MUST keep older versions readable when a writer bumps the format.
- Exactly one sealed format exists. A second format MUST NOT be introduced for
  export, same-network transfer, or cloud storage. Every transport MUST route
  through the one verification procedure: magic, format, integrity hash, AEAD,
  `kid`, then generation policy.
- The vault MUST retain the five most recent local revisions so that a damaged
  current file or an unwanted restore is recoverable.
- Dormant sync schema: `folders`, `ssh_keys`, `credentials`, `servers`,
  `commands`, `notes`, and `monitor_configs` still carry `uuid`,
  `updated_at`, `deleted`, and `edited_by` columns, and the
  `sync_tombstones`/`sync_flags`/`sync_meta` tables still exist, from the era
  before local-only mode. They MUST NOT be dropped (no destructive migration
  exists for them) and MUST NOT be read or written for any network purpose.
  The local HLC (`hlc.rs`) and its DB triggers keep stamping
  `updated_at`/`uuid` for local row-ordering, which is the only reason they
  still run.
- Bundle identifier is `com.sshclientx.app`. On-disk profile files use the
  `.sshclientx` extension (legacy `.submarine` still readable). The magic
  written is `SSHCLTX1`; `OMNV` is still read.
- License is MIT for code. The SSHClientX name and logo are project marks and
  MUST NOT be treated as transferred by the MIT license.
- There is no outbound network beyond the user's own SSH/SFTP targets, a
  user-initiated URL open, and the update check against GitHub releases. MUST
  NOT phone home for any other purpose.

## Development Workflow

- Specs, plans, and tasks produced under Spec Kit MUST comply with this
  constitution. A conflict is resolved in favor of this document.
- TypeScript MUST typecheck (`npm run typecheck` / `npm run build`). Rust
  changes that touch vault, sync, path guards, or host-key handling MUST
  include or update module tests in the same crate (see existing
  `sync_trigger_tests` and `lib.rs` tests).
- Desktop-only behavior MUST compile out of the Android target; Android CI/dev
  scripts MUST keep working after desktop-only additions.
- Release artifacts are produced from `v*` tags via
  `.github/workflows/release.yml` with `--features full-ssh-algos`. Version
  stamps in `package.json`, `src-tauri/Cargo.toml`, and `tauri.conf.json` MUST
  match the tag.
- Pull requests and agent-produced diffs MUST be reviewed against every Core
  Principle. Privilege, CSP, capability, and crypto changes require an
  explicit note in the PR/review of which principle is preserved.
- Introducing a new Tauri plugin, widening CSP, changing Argon2/AES
  parameters, changing the sealed container format or the vault key model, or
  adding a network origin is a constitution-level change: it MUST go through
  Governance, not a silent code edit.

## Governance

This constitution supersedes informal practice, README shorthand, and agent
defaults. Where README marketing copy conflicts with code-backed rules here,
this document and the implementation win.

Amendments:

1. Propose a diff to `.specify/memory/constitution.md` that states the
   principle or section being changed, the reason, and any migration (vault
   version, CSP, capabilities, sync schema).
2. Bump **Version** using semantic versioning:
   - MAJOR: remove or redefine a principle, or weaken a NON-NEGOTIABLE rule
     (secrets, privilege, trust boundaries).
   - MINOR: add a principle or section, or materially expand guidance.
   - PATCH: clarification, wording, typos, non-semantic refinement.
3. Set **Last Amended** to the amendment date (ISO `YYYY-MM-DD`).
   **Ratified** stays the original adoption date.
4. Prepend or update the Sync Impact Report HTML comment (version old → new,
   renamed principles, added/removed sections, deferred TODOs).
5. Land only after review confirms no unexplained placeholder tokens remain
   and every principle is still declarative and testable.

Compliance:

- Every feature spec/plan/task MUST be checkable against Principles I–V.
- Unjustified complexity, new plugin surface, or crypto/CSP/ACL drift MUST
  block merge until resolved or explicitly amended here.
- Runtime development follows this file; do not fork a parallel "guidance"
  document that can silently diverge.

**Version**: 3.2.0 | **Ratified**: 2026-09-03 | **Last Amended**: 2026-09-06
