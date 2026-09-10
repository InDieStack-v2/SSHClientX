# Contract: Tauri Command, Event, and Platform Surface

**Feature**: `004-rust-module-refactor` | **Date**: 2026-09-10

This contract freezes the observable renderer/native boundary while implementations move behind lifecycle, persistence, repository, and service owners.

## Boundary invariants

- Commands remain snake_case with existing camelCase argument serialization.
- The shared `src-tauri/src/lib.rs::run()` entry point remains the desktop and Android composition root.
- Privileged work remains in the Rust side; no crypto, vault I/O, SSH/SFTP, local filesystem mutation, tunnel, mirror, Docker, or credential persistence moves into the renderer.
- Existing bracketed error codes and sentinels remain stable. The renderer continues to branch on codes rather than message text.
- No vault password, DEK, keywrap plaintext, or other protected key material crosses the command boundary.
- Existing writer-claim, path-guard, host-key, Docker allow-list, capability, CSP, and platform rules remain in force.

## Profile and persistence commands

The following command names and externally visible behavior remain stable:

| Command | Contract that must remain stable |
|---|---|
| `list_profiles` | Existing profile summaries, format/revision metadata, and busy indication |
| `select_profile` | Existing normalization, writer-claim behavior, and active-profile selection; refactor adds lifecycle enforcement without changing its command name |
| `setup_master_db` | Existing password/device-factor unlock, legacy migration, rollback, and error outcomes |
| `persist_vault` | Existing success/error behavior with serialized revision ordering |
| `close_profile` | Strict close barrier; successful completion means all profile-owned work completed or acknowledged cancellation |
| `delete_profile` | Rejects the active profile unless lifecycle state is already `Picker`; inactive deletion behavior unchanged |
| `vault_lock`, `vault_unlock_*`, `vault_lock_state` | Existing lock state and background-activity semantics |

Close lifecycle details:

- `close_profile` enters `Closing` and invalidates the current runtime epoch
  before cancellation begins.
- Selection, active-profile deletion, and new profile work are rejected while
  the runtime is not `Picker`.
- A successful close drains profile-owned registries, waits for cancellation
  acknowledgements up to the configured timeout, and releases the writer
  claim last. Timeout or cleanup failure keeps the runtime unavailable for a
  later retry.

## Existing command groups

The complete registry remains in `src-tauri/src/lib.rs` and must retain all current entries:

- profile, vault, migration, rollback, recovery, QR transfer, import/export;
- server, credential, key, folder, command-history, note, and profile CRUD;
- connection, fingerprint, keyboard-interactive, terminal, SFTP, local filesystem, and drag staging;
- tunnel, mirror, monitor, Docker, Android directory, SSH config, and about/update commands.

Extraction may change Rust module paths and internal function signatures but not registered command names, argument names, return JSON shapes, or platform refusal behavior.

## Event contract

Existing names and payload shapes remain stable. Representative frozen events:

| Event | Required payload behavior |
|---|---|
| `terminal-output-{tid}` | Base64 terminal payload; no JSON byte-array replacement |
| `terminal-closed-{tid}` | Existing empty/close payload |
| `fingerprint-prompt-{sid}` | Existing host/key/fingerprint/mismatch/nonce fields; response nonce remains required |
| `kbi-prompt-{sid}` | Existing nonce, name, instructions, prompt echo metadata, and dismissal behavior |
| `connection-success-{sid}` / `connection-failed-{sid}` / `session-disconnected-{sid}` | Existing IDs, reason/auth fields, and lifecycle timing semantics |
| `sftp-transfer-{sid}` | Existing transfer ID/name/kind/bytes/total/status/error fields |
| `tunnel-update-{sid}` / `tunnel-log-{sid}` | Existing tunnel status/log payloads |
| `mirror-update-{sid}` / `mirror-log-{sid}` | Existing mirror status/log payloads |
| monitor status/sample/outage/recovered events | Existing node IDs, timestamps, values/errors/texts, and outage metadata |
| `qr-transfer-state-{sid}` | Existing state and outcome-code fields |
| `vault-lock-state` / `vault-background-activity` / `vault-migration-notice` | Existing lock, activity, and migration payloads |

Session-scoped IDs remain meaningful, including secondary IDs such as `${id}::sftp` and `${id}::fwd`.

## Error and conflict contract

Preserve existing error families and renderer handling, including:

- `[SYSTEM]`, `[CRYPTO]`, `[VAULT]`, `[DATABASE]`, `[STATE]`, `[FILE]`, `[SSH]`, `[UPDATE]`, `[OPEN]` and existing specialized prefixes;
- vault outcome codes such as `VAULT_AUTH`, `VAULT_CORRUPT`, `VAULT_ROLLBACK`, `VAULT_BUSY`, and keystore distinctions;
- SFTP overwrite sentinel `EXISTS:<path>`;
- existing QR, recovery, SSH, SFTP, and validation errors;
- Android-specific refusal behavior for desktop-only operations.

## Platform contract

- Desktop-only dependencies and calls remain target-gated.
- Android continues to use the shared Rust core and existing Android bridge/keyring initialization.
- Android detection remains capability-based; viewport width is not a platform capability signal.
- No capability-file, CSP, shell, filesystem, or webview permission expansion is allowed.
