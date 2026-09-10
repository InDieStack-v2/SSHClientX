# Data Model: Rust Module Refactor

**Feature**: `004-rust-module-refactor` | **Date**: 2026-09-10

This refactor adds logical ownership boundaries but does not introduce a new on-disk vault format or database schema. Existing SQLite tables, sealed vault files, keywrap sidecars, history revisions, and keystore entries remain compatibility contracts.

## Profile Lifecycle

Represents the allowed state of the application profile context.

| State | Meaning | Allowed transitions |
|---|---|---|
| `Picker` | No profile is active; no profile-owned runtime is admitted | `Selected` |
| `Selected` | A profile identity and writer claim are selected, but the vault is not unlocked | `Unlocked`, `Picker` |
| `Unlocked` | Database, DEK, profile path, generation, and runtime are active | `Locked`, `Closing` |
| `Locked` | Profile remains selected but protected content is unavailable under existing lock semantics | `Unlocked`, `Closing` |
| `Closing` | New profile-owned work is rejected; shutdown is draining or has failed | `Picker` only after successful shutdown; remains unavailable after timeout/error |

### Validation rules

- Only one active profile context exists in the process.
- Selecting another profile requires the current context to be in `Picker` or to complete `Closing` first.
- Deleting the active profile is rejected until the active context has successfully returned to `Picker`.
- A failed close does not release the profile as selectable or deletable.

## Profile Runtime

Owns every session-derived task, handle, cancellation source, and epoch associated with one active profile.

| Field | Description |
|---|---|
| `profile_name` | Canonical active profile identity |
| `runtime_epoch` | Monotonic admission token invalidated during close |
| `state` | Lifecycle state for accepting or rejecting work |
| `resources` | Registered sessions, transfers, monitors, mirrors, tunnels, streams, QR operations, and terminal tasks |
| `shutdown_status` | Pending, completed, or failed with the blocking resource/error |

### Relationships

- One `ProfileLifecycle` owns at most one `ProfileRuntime`.
- One runtime owns zero or more `RuntimeResource` instances.
- Every resource registration records the runtime epoch it joined.
- A resource with a stale epoch cannot register new session state, emit profile-owned success, or become active after close begins.

## Runtime Resource

A profile-owned asynchronous operation or handle.

| Resource category | Required shutdown behavior |
|---|---|
| Interactive session | Invalidate generation, stop tunnels/mirrors, close SFTP and SSH handles, drain prompts |
| Terminal task | Close channel and await task completion or cancellation acknowledgement |
| SFTP/local transfer | Set cancellation flag, await command/task completion, remove cancellation entry |
| Monitor poller | Signal stop, await poller exit, then remove registry entry |
| Mirror | Signal stop and await worker/watcher/transfer joins |
| Tunnel | Signal stop and await listener/bridge ownership available to the subsystem |
| Docker stream | Abort stream and await task exit; remove stream ownership |
| QR host/guest | Cancel session, close accept loop/handlers, clear held DEK/profile metadata |

## Vault Revision

A durable sealed representation of the active profile.

| Attribute | Rule |
|---|---|
| `generation` | Strictly advances only after a successful durable save |
| `kid` | Existing device-bound key identifier; unchanged by this feature |
| `profile_data` | Existing SQLite serialization; no schema redesign in this feature |
| `history` | Existing bounded revision history and naming; no duplicate generation names |
| `integrity` | Existing authenticated sealing, nonce, AAD, temporary-file sync, and atomic replacement |
| `high_water` | Existing rollback protection and best-effort post-rename update semantics |

## Persistence Operation

An accepted profile mutation and its save request.
- **Admission sequence**: Monotonic per-profile sequence assigned when the coordinator accepts the mutation; determines the same-field winner and generation-reservation order.

### State transitions

```text
Accepted mutation
  → coordinator assigns the next monotonic admission sequence
  → ordered under the active database/mutation boundary
  → snapshot and serialize
  → seal and rotate history
  → sync temporary file and atomically replace current file
  → commit generation
```

Failure at any step before durable replacement:

- returns the existing error category/message contract;
- does not advance the cached generation;
- does not expose the failed revision as current;
- leaves the active in-memory mutation semantics unchanged unless the existing command contract already reports the mutation separately.

Same-field accepted mutations use the later coordinator admission sequence, regardless of completion order. Distinct accepted mutations are retained.

## Compatibility Contract

Represents observable behavior that must remain stable across extraction:

- Tauri command names, camelCase argument serialization, return shapes, and error codes;
- event names, IDs, payload shapes, and terminal base64 encoding;
- vault current/legacy readability, keywrap/keystore semantics, history, and rollback behavior;
- path guards, TOFU verification, Docker allow-lists, capability files, CSP, and platform gates.

## No New Persistent Entities

This feature does not add:

- SQLite tables or columns;
- a new vault format or key derivation scheme;
- a backend/account identity;
- cloud synchronization or telemetry;
- a second cross-device sharing path.
