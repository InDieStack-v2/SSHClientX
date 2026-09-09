# Phase 1 Data Model: QR Same-Network Vault Transfer

**Feature**: `003-qr-same-network-transfer` | **Date**: 2026-09-08 | **Spec**: [spec.md](spec.md)

This feature introduces exactly one new stateful entity (`TransferSession`, in-memory only,
never persisted) and one new wire format (`QrTicket`, transient text). Everything else it
touches — the vault file, the DEK, the device factor, the keywrap sidecar, a profile — is an
existing entity from `002-e2e-vault-migration`'s data model, reused by reference, not
reintroduced or reshaped here.

## 1. `QrTicket` (wire format, not persisted)

The `|`-separated text a QR code encodes, per source tech spec §4, with the `fp`/`cf` collapse
from research.md Decision 7.

| Field | Type | Rule |
| --- | --- | --- |
| version | literal `v1` | Reject any other value as `QR_BAD` |
| url | `https://<ip>:<port>/s/<sid>` | `ip` MUST be RFC1918 (v4), link-local (v4/v6), or ULA (v6) — reject a public address as `QR_IP_FORBIDDEN` before ever attempting to connect |
| `tok` | 16 random bytes, hex | Single-use (see `TransferSession.token_state`) |
| `kid` | 16 bytes, hex, **optional** | Present whenever the host already owns the vault being shared (always true in the "share" direction; may be present or absent in the "receive" direction depending on whether the host already holds *a* vault at all — irrelevant to that direction's own key, since in "receive" the guest is the vault owner). UX-only: lets the scanning side recognize "I already have this" before connecting. Never security-load-bearing — `kid` is already public (constitution: it's in the sealed container's AAD). |
| `fp` | 32 bytes, hex (SHA-256) | The host's per-session certificate fingerprint. Guest pins its TLS connection against this exact value (`TLS_PIN` on mismatch) AND both screens render a short human form of it (research.md Decision 7) |
| `exp` | Unix seconds | `now + 90` at generation, hard cap `now + 120`; reject a scan after this instant as `QR_EXPIRED` |
| `role` | `pull` \| `push` | From the **guest's** perspective: `pull` = guest downloads a vault from host; `push` = guest uploads its vault to host |
| `sid` | 16 random bytes, hex | Session identifier, embedded in the URL path too (redundant by design — the guest never trusts the URL's `sid` alone without matching the ticket's own field) |
| `lbl` | UTF-8 bytes, hex-encoded, **optional**, ≤64 decoded bytes | A short, non-secret display label for the host — the host's currently active profile name, or the OS hostname if none is open. Hex-encoded (matching the `tok`/`fp`/`sid`/`kid` convention already used in this grammar) so it can never collide with the `\|` delimiter. Not security-load-bearing — purely so `qr_transfer_guest_scan` (§4) can show "connecting to `<label>`" on the confirm screen *before* any network round-trip, which is why it must live in the ticket itself rather than being fetched from `/meta`. Absent entirely (not an empty field) if the host has no name to offer, in which case the confirm screen shows a generic "the scanned device" instead. |

**Validation order** (guest side, before any network call): version → `exp` → `url` scheme
(`https` only) → `url` host is a private/link-local/ULA literal address (never resolve a
hostname — the source tech spec's grammar only ever has a literal IP here) → well-formed `tok`/
`fp`/`sid` hex. Any failure is `QR_BAD` except the two called out with their own code
(`QR_EXPIRED`, `QR_IP_FORBIDDEN`).

## 2. `TransferSession` (in-memory, host-side and guest-side, never written to disk)

One instance per active pairing attempt. Held in Tauri-managed state (`tauri::State`), the same
pattern `ImportStagingState`/`DbState` already use elsewhere in `lib.rs` — not a new persistence
mechanism.

| Field | Type | Notes |
| --- | --- | --- |
| `sid` | `[u8; 16]` | |
| `role` | `Pull \| Push` | Host's role is the mirror of the QR's `role` field |
| `token_state` | `Unused \| Consumed` | Starts `Unused`; flips to `Consumed` on `POST /done` or on session teardown for any reason — never rechecked to `Unused` (single-use, spec FR-004) |
| `expires_at` | instant | Session is torn down at this instant regardless of activity (spec FR-003) |
| `fail_count` | `u8` | Incremented on any failed auth/connection attempt against this session; teardown at 5 (spec FR-013) |
| `bind_addr` | `IpAddr` | The one RFC1918/link-local/ULA address chosen at session start (research.md Decision 6); the server binds to this address specifically, not `0.0.0.0` |
| `cert` | `rcgen` cert + key | Freshly generated per session (research.md Decision 2); discarded with the session, never reused across sessions |
| `key_status` | `Owned([u8; 32] kid, DEK) \| NotHeld` | What the **local** side of this session holds for the vault in play — determines whether a `/key` exchange happens at all, and in which direction (see contracts/qr-transfer-protocol.md §2) |
| `max_body_bytes` | `u64` | 8 MiB default (spec FR-012) |

### Lifecycle

```
Created ──(bind + cert ready)──> Advertising (QR shown)
Advertising ──(scan + first valid request)──> Connected
Connected ──(cert pin + human confirm)──> Verified
Verified ──(key exchange if needed, then file exchange)──> Transferring
Transferring ──(verify_and_import + land succeeds)──> Completed ──> torn down
     │                                                                  ▲
     └──(any failure: TLS_PIN, TOK_USED, BOX_*, VAULT_*, size cap)──> Failed ──┘
Advertising/Connected/Verified/Transferring ──(expires_at reached)──> Expired ──> torn down
Advertising/Connected/Verified/Transferring ──(fail_count reaches 5)──> Failed ──> torn down
any state ──(user cancels, or app exits)──> Cancelled/torn down
```

A session never transitions back toward `Advertising` — a failed or completed session is dead;
a new device pair means a new `TransferSession` (spec FR-016), which is exactly why nothing here
needs to be persisted across app restarts.

## 3. Reused entities (unchanged — see `002-e2e-vault-migration/data-model.md` for full detail)

| Entity | Where it's defined | How this feature touches it |
| --- | --- | --- |
| DEK (device-bound vault key) | `vault::generate_dek`, `vault::derive_kid` | Read (host side, to serve over `/key`) or written fresh into the keystore via `recovery::establish_unclaimed_key` (guest side, first-time onboarding only) — never generated, re-derived, or modified by this feature |
| Device factor | `keystore::store_device_factor`/`load_device_factor` | Only ever touched indirectly, through `establish_unclaimed_key` — this feature never calls `keystore.rs` directly |
| Keywrap sidecar | `vault::KeyWrapFile` | Same — only touched through `establish_unclaimed_key` and the existing commit helpers |
| Sealed vault file | `vault::SealedVaultFile` | The literal bytes moved over `GET`/`PUT /s/{sid}/file`, verified with `vault::verify_and_import` unchanged |
| Profile / `Disposition` (`CreateProfile` / `RestoreOver` / `NoOp`) | `vault::verify_and_import`, `claim_unclaimed_key_as_new_profile`, `land_as_restore_over_copy` | Landing decision and execution are entirely delegated here — see research.md Decision 9 |

## 4. New `Outcome` variants

Added to the existing `Outcome` enum in `vault.rs` (same enum, same `code()`/`message()`
pattern already used for every other error family — no new error type):

| Variant | Code | Meaning |
| --- | --- | --- |
| `QrBad` | `QR_BAD` | Malformed ticket (source tech spec §8) |
| `QrExpired` | `QR_EXPIRED` | `exp` has passed |
| `QrIpForbidden` | `QR_IP_FORBIDDEN` | Ticket's host address is not private/link-local/ULA |
| `NetUnreachable` | `NET_UNREACHABLE` | TCP/TLS connect failed (different network, firewall, client isolation) |
| `TlsPin` | `TLS_PIN` | Connected, but the certificate's fingerprint didn't match the ticket's `fp` |
| `TokUsed` | `TOK_USED` | Token already consumed for this session |

Every other outcome this feature can produce is an existing variant, unchanged:
`BoxUnknownKey`/`BoxCorrupt`/`BoxOlder`/`BoxConflict`/`BoxAuth` (file verification, from
`verify_and_import`), `VaultKdf`/`VaultKeystoreDenied`/`VaultNoKeystore` (key establishment,
from `establish_unclaimed_key`).
