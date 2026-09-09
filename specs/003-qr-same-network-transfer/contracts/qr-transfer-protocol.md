# Contract: QR Transfer Protocol & Tauri Command Surface

**Feature**: `003-qr-same-network-transfer` | **Date**: 2026-09-08

## 1. QR ticket grammar

See [data-model.md §1](../data-model.md#1-qrticket-wire-format-not-persisted) for the field
table. Text form, `|`-separated, matching the source tech spec's grammar with the `fp`/`cf`
collapse from research.md Decision 7:

```
v1|https://<ip>:<port>/s/<sid>|tok=<hex32>|kid=<hex32>|fp=<hex64>|exp=<unix>|role=pull|sid=<hex32>|lbl=<hex>
```

`kid=` is omitted entirely (not an empty field) when the host has no vault key of its own to
advertise (only possible in the `push`/receive direction, when the host is a fresh device with
nothing yet). `lbl=` is likewise omitted entirely when the host has no display name to offer
(data-model.md §1) — never sent as an empty field.

## 2. HTTP endpoints (host-run session server)

Every endpoint below requires `Authorization: Bearer <tok>` except where noted; a missing or
wrong token increments `TransferSession.fail_count` (session dies at 5, spec FR-013) and
responds `401` with body `TOK_USED` if the token was valid-but-already-consumed, or a generic
`401` otherwise (never distinguish "wrong token" from "unknown session" — that distinction is
attacker-useful information, not user-useful).

| Method | Path | Direction it serves | Body |
| --- | --- | --- | --- |
| `GET` | `/s/{sid}/meta` | Both | Response: `{ "kid": "<hex>" \| null, "generation": u64 \| null, "size": u64 \| null, "sha256_prefix": "<hex8>" \| null, "needs_key": bool }`. `needs_key` is **from the responder's own point of view** — true if the responder does not currently hold this vault's key at all. The requester uses this, plus its own local knowledge, to decide whether a `/key` exchange happens next. |
| `GET` | `/s/{sid}/key` | `role=pull`, when the **guest** determines locally (its own keystore/unclaimed-key check, never transmitted to the host) that it needs the host's key | Response body: raw 32 bytes (`application/octet-stream`), the host's DEK. Host only serves this once it has confirmed (via the human-verified fingerprint step, §3) that this is a legitimate paired session — never before. |
| `PUT` | `/s/{sid}/key` | `role=push`, when the **host** needs the guest's key (host has no vault of this kind yet) — signaled to the guest via `meta`'s `needs_key` | Request body: raw 32 bytes, the guest's DEK. |
| `GET` | `/s/{sid}/file` | `role=pull` | Response: the sealed vault file bytes (`application/x-sshclientx`), capped at `max_body_bytes` |
| `PUT` | `/s/{sid}/file` | `role=push` | Request body: the sealed vault file bytes, capped at `max_body_bytes`; a body over the cap is rejected (`413`) before being fully buffered — never read-then-reject |
| `POST` | `/s/{sid}/done` | Both | No body. Marks `token_state = Consumed` and schedules the session for teardown. The client MUST call this on both success and give-up; the server also tears itself down on `expires_at` regardless |

**`needs_key` is only actionable in `role=push`.** Because the host is always the HTTP server
(both directions), `needs_key` in the `meta` response always describes the **host's** own key
status. That's the exact signal `role=push` needs (does the *host* need the guest's key?). In
`role=pull` it is not the relevant question at all — whether the *guest* needs a key is
determined purely locally on the guest (never transmitted), per the `GET /s/{sid}/key` row
above. An implementation MUST NOT branch pull-direction key-fetch logic on `meta`'s `needs_key`.

**Single-use token, across up to two body fetches**: research.md Decision 9's open-risk item —
the token stays valid for the sequence of calls one legitimate session needs (`meta`, optionally
`key`, `file`, `done`), and is revoked at `POST /done` or `expires_at`, not after the first body
call. Replay across a **separate** session (a different `sid`/`tok` pair, or a resend of a
tok already marked `Consumed`) is what FR-004 actually requires to fail — not a cap on in-session
call count, which the existing session bounds (expiry, one completed session, 5 failed
attempts) already provide.

## 3. Mutual verification (both directions, before any `/key` or `/file` call)

1. Guest computes SHA-256 of the certificate presented during the TLS handshake and compares it
   byte-for-byte to the ticket's `fp`. Mismatch → abort, `TLS_PIN`, no further calls attempted.
2. Guest calls `GET /meta` (this doubles as the "first successful request" that proves the
   token/session are live).
3. Both screens render the same short human form of `fp` (research.md Decision 7 — e.g. the
   first 6 hex characters of `fp`, grouped in pairs). The user visually confirms a match before
   the guest proceeds past `meta`. This is a **UI gate**, not a server-enforced one — the server
   has no way to know whether the human looked — but the contract requires the guest-side Tauri
   command sequence to make the confirm step mandatory before calling `key`/`file` (see §4:
   `qr_transfer_guest_confirm` is a distinct command from `qr_transfer_guest_scan`, precisely so
   there is a step in between the UI cannot skip).

## 4. Tauri command surface

| Command | Direction | Input | Output |
| --- | --- | --- | --- |
| `qr_transfer_host_start` | Host | `{ action: "share" \| "receive" }` (share → ticket `role=pull`; receive → ticket `role=push`) | `{ session_id, qr_svg, verification_code, expires_at }` |
| `qr_transfer_host_cancel` | Host | `{ session_id }` | `Ok(())` — tears down the server/session immediately |
| `qr_transfer_host_events` | Host | (Tauri event channel, not a command) | Emits session state transitions (`connected`, `verifying`, `transferring`, `completed`, `failed { outcome_code }`) — same event-based pattern already used for terminal output / mirror progress elsewhere in `lib.rs`, not a new mechanism |
| `qr_transfer_guest_scan` | Guest | `{ ticket_text }` (from `jsqr`, webview-decoded, or typed manually — see §6) | Ticket parsed and validated per §1's rules (no network call yet); on success, `{ session_id, verification_code, host_label }` for the confirm screen — `host_label` is the ticket's `lbl` field hex-decoded (data-model.md §1), or `null` when the ticket has none (UI shows a generic "the scanned device" in that case). Failure returns one of `QR_BAD`/`QR_EXPIRED`/`QR_IP_FORBIDDEN`. |
| `qr_transfer_guest_confirm` | Guest | `{ session_id }` (called only after the user confirms the verification code matches) | Performs the pinned connect (§3), the key exchange if needed, the file exchange, `verify_and_import`, and lands the result via the existing commit helpers (research.md Decision 9). Returns `{ landed_profile_name, disposition: "create_profile" \| "restore_over_copy" \| "no_op" }` on success, or an `Outcome` code on failure (any of the new QR/TLS/token codes, or the existing `BOX_*`/`VAULT_*` codes). |
| `qr_transfer_guest_cancel` | Guest | `{ session_id }` | `Ok(())` — calls `POST /done` if a connection was made, otherwise just discards local state |

No command returns key material to the webview at any point — `qr_transfer_guest_confirm`'s
success payload is a profile name and a disposition label, the same shape `import_vault_commit`
already returns today.

## 5. Error code summary (new codes only — see data-model.md §4 for the full `Outcome` mapping)

| Code | HTTP-level trigger (if any) | User-facing message shape (matches source tech spec §6) |
| --- | --- | --- |
| `QR_BAD` | n/a (ticket parse, before any network call) | "This code isn't a valid transfer code." |
| `QR_EXPIRED` | n/a (ticket parse) | "This code has expired. Ask the other device to show a new one." |
| `QR_IP_FORBIDDEN` | n/a (ticket parse) | Never shown as such to the user — treated the same as `QR_BAD`, since a forbidden IP can only mean a malformed or malicious ticket, not a legitimate transient state |
| `NET_UNREACHABLE` | TCP/TLS connect failure or timeout | "Not on the same Wi-Fi. Export a .sshclientx file instead." (source tech spec §6, verbatim) |
| `TLS_PIN` | Certificate fingerprint mismatch | "Could not verify the other device. Try scanning again." |
| `TOK_USED` | `401` with that body | "This code was already used. Ask the other device to show a new one." |

## 6. Manual entry fallback (spec FR-002)

`qr_transfer_guest_scan`'s `ticket_text` input is the literal `|`-separated grammar of §1 — it
makes no distinction between text decoded from a camera frame and text a user typed or pasted
by hand. This is what makes the fallback free: the host renders the same ticket string as
copyable/selectable plain text next to the QR (`QrHostPanel.tsx`), and the guest offers a text
field that submits straight to `qr_transfer_guest_scan` exactly like the camera path. No second
command, no second parser, no second validation path — one input, two ways to produce it.
