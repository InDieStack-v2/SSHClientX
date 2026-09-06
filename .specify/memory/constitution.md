<!--
Sync Impact Report
- Version change: 1.0.2 → 2.0.0
- Modified principles:
  - I. Device-Bound Secrets (NON-NEGOTIABLE) — removed the cloud-sync
    ciphertext-upload clause and the account-auth/vault-key separation
    clause (nothing left to constrain); added an explicit NON-NEGOTIABLE
    clause that the application MUST NOT depend on any backend or
    account service.
  - II. Rust Owns Privilege — CSP `connect-src` no longer allow-lists a
    cloud API origin (self + Tauri IPC only).
  - III. One Core, Every Platform — cross-platform parity clause no
    longer mentions a shared "sync protocol" (there is none).
  - V. Native and Lean — the extend-don't-grow module list drops
    `cloud` and `identity` (both deleted).
- Added sections: none.
- Removed sections: none (Technology & Architecture Constraints bullets
  were rewritten in place, not removed as a whole section).
- Follow-up TODOs: none.
- Notes: reflects `specs/001-local-only-mode/` (Local-Only Mode)
  shipping — accounts, cloud sync, and profile sharing are removed from
  the product for security (no backend to breach). Sync-related DB
  schema (`uuid`/`updated_at`/`deleted`/`edited_by` columns,
  `sync_tombstones`/`sync_flags`/`sync_meta` tables) is kept but dormant
  for backward-compatible vault reads, per that feature's research.md
  Decision 1. On-disk vault extension is `.sshclientx`; leftover
  `.submarine` files are still opened. Magic OMNV unchanged.
-->

# SSHClientX Constitution

## Core Principles

### I. Device-Bound Secrets (NON-NEGOTIABLE)

The vault master password MUST be derived on-device with Argon2id and
MUST be wiped from memory as soon as the 256-bit key exists. Profile
content (servers, credentials, keys, tunnels, notes, mirrors) MUST be
zstd-compressed and sealed with AES-256-GCM before it touches disk.
Forgotten vault passwords are unrecoverable by design — MUST NOT
add a vault recovery email, escrow-of-plaintext, or server-held wrapping
key. Secrets that outlive a single call MUST live in `Zeroize` wrappers.
Argon2 parameters (`m_cost` 64 MiB, `t_cost` 3, `p_cost` 4, 32-byte
output) MUST NOT change without a versioned re-key migration. The
application MUST NOT depend on any backend or account service: there is
no sign-up, sign-in, or server-side identity, and a vault MUST NOT be
uploaded, synced, or shared with another device except by the user
manually copying the vault file themselves. MUST NOT add analytics,
telemetry, or crash reporters that send data off-device.

Rationale: there is no backend to breach. A stolen ciphertext file, or
a stolen device, MUST be equivalent to stealing a random blob — and the
strongest way to guarantee that is to have no server that could ever
receive it in the first place.

### II. Rust Owns Privilege

SSH, SFTP, crypto, vault I/O, local filesystem mutation, port forwards,
folder mirror, and Docker remote commands MUST run in Rust Tauri
commands. The webview is a renderer: it MUST NOT implement cryptography,
MUST NOT persist credentials in `localStorage` / `sessionStorage` /
IndexedDB, and MUST NOT spawn shells. Capability files MUST stay
minimal: `shell:*`, `fs:*`, and `webview:*` MUST NOT be granted.
`capabilities/default.json` is the cross-platform ACL; desktop-only
plugins (window-state) MUST stay in `capabilities/desktop.json` so
Android validation does not fail. New permissions require a comment in
the capability file stating why they are needed; "just in case" grants
are forbidden. CSP in `tauri.conf.json` MUST keep `default-src 'self'`,
`script-src 'self'`, `frame-src 'none'`, `object-src 'none'`, and
`connect-src` limited to `self` and Tauri IPC only — there is no
network origin to allow-list.

Rationale: XSS via terminal output or a compromised renderer is in
scope. Privilege lives behind IPC so a renderer bug cannot open a
shell, rewrite `C:\`, or exfiltrate the vault key.

### III. One Core, Every Platform

Shared behavior MUST live in `src-tauri/src/lib.rs::run()` and the
modules it owns. `src-tauri/src/main.rs` MUST remain a thin desktop
shim. Android and desktop MUST ship the same vault format and SSH
stack. Desktop-only crates (`rfd`, `open`,
`tauri-plugin-window-state`) and call sites MUST be
`cfg(not(target_os = "android"))`. Features that cannot map to a
platform (folder mirror on Android today) MUST be cfg-gated or UI-hidden,
not forked into a second codebase. Default `cargo build` MUST stay
OpenSSL/Perl-free (`default = []`). Release and CI bundles MUST pass
`--features full-ssh-algos` so production binaries speak RSA host keys
and legacy KEX/MAC. Vault files MUST remain platform-portable: unlock
on Windows, macOS, Linux, or Android with the same master password.

Rationale: one encrypted profile across devices is the product. A
platform fork would split the threat model and the vault.

### IV. Explicit Trust Boundaries

TOFU host-key pinning is mandatory: first-use MUST show a fingerprint
and subsequent connections MUST bind the pin (including per-connection
nonce binding that resists prompt-race). Bytes from a remote host —
SFTP names, paths, terminal output — are untrusted. Directory-entry
names MUST pass `is_safe_dir_entry_name` before being joined onto a
local path. Live-edit / drag staging MUST use the unpredictable
`app_temp_root` and `safe_temp_leaf_name`. Local FS commands the UI can
invoke MUST pass `guard_local_path` (refuse filesystem root and OS
system directories). Terminal output MUST NOT be interpreted as HTML.
Untrusted input MUST NOT be concatenated into shell strings; remote
Docker/Info actions MUST use argument arrays or equivalent, not
string-built `sh -c`.

Rationale: the SSH peer and the renderer are both hostile. Path
traversal, zip-slip, `/tmp` pre-create, and XSS through ANSI/HTML are
known classes; each new FS or terminal path MUST reuse the existing
guards.

### V. Native and Lean

SSHClientX MUST remain a Tauri 2 + Rust + React application. MUST NOT
migrate to Electron or add a second Chromium runtime. MUST NOT add
dependencies that are already transitive without a documented reason,
or plugins whose APIs the app does not call. New SSH/SFTP/crypto
behavior MUST extend existing modules (`ssh_manager`, `tunnel`,
`mirror`, `docker`, `hlc`) rather than growing ad-hoc JavaScript. A new
network backend, account system, or cloud sync MUST NOT be
reintroduced without a new constitution amendment — see Principle I.
Complexity requires a concrete current use; YAGNI
applies. Frontend stack is React 18, TypeScript, Tailwind, xterm.js —
new UI libraries need a gap these do not cover.

Rationale: startup time, RAM, and installer size are user-visible.
Unused plugins widen the XSS blast radius (Principle II).

## Technology & Architecture Constraints

- Product name is SSHClientX; Rust package is `sshclientx`; library
  target is `sshclientx_lib`. Workspace folder name is not a public
  identifier.
- Frontend: React 18, TypeScript, Tailwind CSS, xterm.js, Vite.
  Backend: Rust 2021 (MSRV 1.70), Tauri 2, russh, rusqlite (bundled),
  aes-gcm, argon2, zstd, zeroize. `reqwest` + `rustls` is used only for
  the update check against GitHub releases (no OpenSSL on the default
  path); it MUST NOT be used to add any account/sync backend call.
- On-disk vault: magic `OMNV`, versioned header, per-profile salt,
  per-save nonce, AES-256-GCM over zstd(SQLite). Readers MUST keep
  older versions readable when a writer bumps the format.
- Dormant sync schema: `folders`, `ssh_keys`, `credentials`, `servers`,
  `commands`, `notes`, and `monitor_configs` still carry `uuid`,
  `updated_at`, `deleted`, and `edited_by` columns, and the
  `sync_tombstones`/`sync_flags`/`sync_meta` tables still exist, from
  the era before local-only mode. They MUST NOT be dropped (no
  destructive migration exists for them) and MUST NOT be read or
  written for any network purpose. The local HLC (`hlc.rs`) and its DB
  triggers keep stamping `updated_at`/`uuid` for local row-ordering,
  which is the only reason they still run.
- Bundle identifier is `com.sshclientx.app`. On-disk profile files
  use the `.sshclientx` extension (legacy `.submarine` still readable)
  and `OMNV` magic.
- License is MIT for code. The SSHClientX name and logo are project
  marks and MUST NOT be treated as transferred by the MIT license.
- There is no outbound network beyond the user's own SSH/SFTP targets,
  a user-initiated URL open, and the update check against GitHub
  releases. MUST NOT phone home for any other purpose.

## Development Workflow

- Specs, plans, and tasks produced under Spec Kit MUST comply with this
  constitution. A conflict is resolved in favor of this document.
- TypeScript MUST typecheck (`npm run typecheck` / `npm run build`).
  Rust changes that touch vault, sync, path guards, or host-key handling
  MUST include or update module tests in the same crate (see existing
  `sync_trigger_tests` and `lib.rs` tests).
- Desktop-only behavior MUST compile out of the Android target; Android
  CI/dev scripts MUST keep working after desktop-only additions.
- Release artifacts are produced from `v*` tags via
  `.github/workflows/release.yml` with `--features full-ssh-algos`.
  Version stamps in `package.json`, `src-tauri/Cargo.toml`, and
  `tauri.conf.json` MUST match the tag.
- Pull requests and agent-produced diffs MUST be reviewed against every
  Core Principle. Privilege, CSP, capability, and crypto changes require
  an explicit note in the PR/review of which principle is preserved.
- Introducing a new Tauri plugin, widening CSP, changing Argon2/AES
  parameters, or adding a network origin is a constitution-level change:
  it MUST go through Governance, not a silent code edit.

## Governance

This constitution supersedes informal practice, README shorthand, and
agent defaults. Where README marketing copy conflicts with code-backed
rules here, this document and the implementation win.

Amendments:

1. Propose a diff to `.specify/memory/constitution.md` that states the
   principle or section being changed, the reason, and any migration
   (vault version, CSP, capabilities, sync schema).
2. Bump **Version** using semantic versioning:
   - MAJOR: remove or redefine a principle, or weaken a NON-NEGOTIABLE
     rule (secrets, privilege, trust boundaries).
   - MINOR: add a principle or section, or materially expand guidance.
   - PATCH: clarification, wording, typos, non-semantic refinement.
3. Set **Last Amended** to the amendment date (ISO `YYYY-MM-DD`).
   **Ratified** stays the original adoption date.
4. Prepend or update the Sync Impact Report HTML comment (version
   old → new, renamed principles, added/removed sections, deferred
   TODOs).
5. Land only after review confirms no unexplained placeholder tokens
   remain and every principle is still declarative and testable.

Compliance:

- Every feature spec/plan/task MUST be checkable against Principles I–V.
- Unjustified complexity, new plugin surface, or crypto/CSP/ACL drift
  MUST block merge until resolved or explicitly amended here.
- Runtime development follows this file; do not fork a parallel
  "guidance" document that can silently diverge.

**Version**: 2.0.0 | **Ratified**: 2026-09-03 | **Last Amended**: 2026-09-06
