---

description: "Task list for QR Same-Network Vault Transfer"
---

# Tasks: QR Same-Network Vault Transfer

**Input**: Design documents from `/specs/003-qr-same-network-transfer/`

**Prerequisites**: [plan.md](plan.md), [spec.md](spec.md), [research.md](research.md),
[data-model.md](data-model.md), [contracts/](contracts/), [quickstart.md](quickstart.md)

**Tests**: Included, and **not optional here** — plan.md's Technical Context already commits to
`cargo test` coverage for "the pure/protocol parts of `qr_transfer.rs`," the same posture
002's tasks took for its own vault change. Tests follow the repo's existing convention — in-file
`#[cfg(test)]` modules (see `keystore.rs`, `recovery.rs`), not a separate `tests/` tree. Two-device
network scenarios (data actually crossing a real LAN) are **not** automated — see
[quickstart.md](quickstart.md), same posture as 002's own quickstart.

**Organization**: Grouped by user story from spec.md (US1/US2/US3). Setup, Foundational, and
Polish carry no story label.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependency on incomplete work)
- **[Story]**: US1, US2, US3 from spec.md
- **T053–T054** were added by `/speckit-analyze` remediation and sit in execution position (both
  Foundational, alongside T020–T024), not ID order — existing IDs were left stable so the
  Dependencies section and any external references stay valid.

## Path Conventions

Tauri 2 single repository. Rust core in `src-tauri/src/`, React renderer in `src/`. Paths below
are repository-relative and exact.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Dependencies and module scaffolding. Nothing here changes behaviour.

- [ ] T001 Add `rcgen = "0.14"`, `qrcode = "0.14"`, `if-addrs = "0.14"` to `[dependencies]` in `src-tauri/Cargo.toml`, each with a comment naming its constitution v5.0.0 Technology & Architecture Constraints table row (spec 003 four-row table)
- [ ] T002 Promote `hyper` (features `server`, `http1`), `hyper-util` (features `tokio`, `server`), `tokio-rustls`, and `rustls` from transitive to direct dependencies in `src-tauri/Cargo.toml`, with a comment noting all four are already fully resolved via `reqwest` → `hyper-rustls` (research.md Decision 1) — adds zero new crates
- [ ] T003 [P] Add `jsqr` (`^1.4.0`) to `package.json` for the frontend QR decode path (research.md Decision 5)
- [ ] T004 Create `src-tauri/src/qr_transfer.rs` and declare `mod qr_transfer;` in `src-tauri/src/lib.rs`
- [ ] T005 [P] Run `cargo tree --manifest-path src-tauri/Cargo.toml -i openssl-sys` after adding T001's dependencies and confirm it still finds nothing (research.md Decision 8's OpenSSL-free guard, re-checked for the new crates)

**Checkpoint**: Builds clean, no behaviour change, no new native/OpenSSL dependency.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: The QR ticket format, the session state machine, the TLS/cert plumbing, the host
server scaffold, and the camera/QR display commands every user story needs.

**⚠️ CRITICAL**: No user story can begin until this phase is complete — every story needs a live,
verified session before it can move a single byte of vault content.

### QR ticket & outcomes

- [ ] T006 [P] Add the 6 new `Outcome` variants (`QrBad`, `QrExpired`, `QrIpForbidden`, `NetUnreachable`, `TlsPin`, `TokUsed`) with `code()`/`message()` arms in `src-tauri/src/vault.rs`, per data-model.md §4
- [ ] T007 Implement `QrTicket` parse/serialize in `src-tauri/src/qr_transfer.rs` per contracts/qr-transfer-protocol.md §1 and data-model.md §1: version, url, `tok`, `kid` (optional), `fp`, `exp`, `role`, `sid`, `lbl` (optional, hex-encoded UTF-8 label, data-model.md §1); validation order version → `exp` → URL scheme (`https` only, literal IP, never a hostname) → private/link-local/ULA address check → well-formed hex fields
- [ ] T008 [P] Implement RFC1918/link-local/ULA address classification plus LAN interface enumeration via `if-addrs` in `src-tauri/src/qr_transfer.rs`, selecting the single `bind_addr` a session advertises and binds to (research.md Decision 6)
- [ ] T009 [P] Add `#[cfg(test)]` tests in `src-tauri/src/qr_transfer.rs`: `QrTicket` round-trips; a bad version, an already-past `exp`, a public IP, and malformed hex each map to `QR_BAD`/`QR_EXPIRED`/`QR_IP_FORBIDDEN` correctly and in the right precedence order

### Session lifecycle & crypto plumbing

- [ ] T010 Implement `TransferSession` (fields per data-model.md §2: `sid`, `role`, `token_state`, `expires_at`, `fail_count`, `bind_addr`, `cert`, `key_status`, `max_body_bytes`) and its state machine in `src-tauri/src/qr_transfer.rs`, held in a new `QrTransferState` Tauri-managed state (same pattern as `ImportStagingState` in `lib.rs`)
- [ ] T011 [P] Implement per-session self-signed certificate generation and its SHA-256 fingerprint via `rcgen` in `src-tauri/src/qr_transfer.rs` (research.md Decision 2)
- [ ] T012 Implement `rustls::ServerConfig` assembly from the T011 certificate for the host's server (research.md Decision 1)
- [ ] T013 Implement the custom `rustls::client::danger::ServerCertVerifier` that pins against a `QrTicket`'s `fp`, wired into a preconfigured `reqwest::Client` via `ClientBuilder::use_preconfigured_tls` for the guest (research.md Decision 3)
- [ ] T014 Implement single-use token bookkeeping (`token_state` `Unused → Consumed` on `POST /done` or teardown), `fail_count` increment with teardown at 5, and `expires_at` teardown (≤120s) in `src-tauri/src/qr_transfer.rs` (spec FR-003, FR-004, FR-013)
- [ ] T015 [P] Add `#[cfg(test)]` tests in `src-tauri/src/qr_transfer.rs` for `TransferSession` lifecycle: token is `Consumed` after `done` and rejects reuse; `fail_count` reaching 5 tears the session down; `expires_at` tears it down independent of activity — all against the pure state machine, no real socket

### Host session server scaffold

- [ ] T016 Implement the `hyper` + `tokio-rustls` accept loop in `src-tauri/src/qr_transfer.rs`, binding only to the session's `bind_addr` from T008/T010 (never `0.0.0.0`), serving via `hyper::server::conn::http1` + `hyper_util::rt::TokioIo` + a hand-written `service_fn` router (research.md Decision 1)
- [ ] T017 Implement bearer-token auth in the T016 router: constant-time comparison against `tok`, incrementing `fail_count` on any mismatch, responding with `TOK_USED` specifically when the token was valid-but-already-consumed and a generic `401` otherwise (Principle IV guard; contracts/qr-transfer-protocol.md §2)
- [ ] T018 Implement `GET /s/{sid}/meta` in the T016 router returning `{ kid, generation, size, sha256_prefix, needs_key }` per contracts/qr-transfer-protocol.md §2
- [ ] T019 Implement `POST /s/{sid}/done` in the T016 router, marking `token_state = Consumed` and scheduling session teardown

### QR display & scan commands

- [ ] T020 [P] Implement QR SVG generation from a `QrTicket::to_string()` via the `qrcode` crate in `src-tauri/src/qr_transfer.rs` (research.md Decision 4)
- [ ] T021 [P] Add the `android.permission.CAMERA` permission to `src-tauri/gen/android/app/src/main/AndroidManifest.xml`, required for `getUserMedia` camera capture on Android (spec FR-018)
- [ ] T022 [P] Implement `src/components/QrScanCamera.tsx`: `getUserMedia` capture to a `<canvas>`, `jsqr` frame decode, emitting the decoded ticket text to its caller and nothing else (research.md Decision 5) — no `localStorage`/`sessionStorage` use
- [ ] T023 Implement `qr_transfer_guest_scan` Tauri command in `src-tauri/src/lib.rs`: parses and validates ticket text via T007 (no network call yet), returning `{ session_id, verification_code, host_label }` on success (`host_label` = the ticket's `lbl` field hex-decoded, or `null` when absent) or a `QR_BAD`/`QR_EXPIRED`/`QR_IP_FORBIDDEN` outcome (contracts/qr-transfer-protocol.md §4). The ticket's `url` MUST NOT be passed to `tauri_plugin_opener`'s `open_url` (already wired up elsewhere in `lib.rs` for About-panel links) or any other external-open API, in this command or any caller — document this as a doc-comment on the command itself (spec FR-006), since it is an architectural invariant nothing here can unit-test on its own
- [ ] T024 [P] Implement `qr_transfer_host_cancel` and `qr_transfer_guest_cancel` Tauri commands in `src-tauri/src/lib.rs`: tear down the session/server immediately; the guest variant best-effort calls `POST /done` if a connection was ever made
- [ ] T053 [P] Implement screenshot/screen-recording prevention on the QR/scan and verification-code confirmation screens (spec FR-014): `FLAG_SECURE` on Android via `src-tauri/src/android_bridge.rs`'s existing JNI bridge, applied for the lifetime of `QrHostPanel.tsx`/`QrGuestScanPanel.tsx`; document in a code comment that no equivalent OS-level API exists on desktop platforms, so this is Android-only by necessity, not by omission
- [ ] T054 Implement the manual-entry fallback for `qr_transfer_guest_scan` (spec FR-002, contracts/qr-transfer-protocol.md §6): render the T007 ticket string as copyable/selectable plain text alongside the QR in `QrHostPanel.tsx`, and add a text-entry field in `QrGuestScanPanel.tsx` that submits directly to the same `qr_transfer_guest_scan` command T023 already implements — no new command, no second parser

**Checkpoint**: A session can be created, advertised as a QR, scanned, and mutually verified
(fingerprint pin + human-comparable code available on both sides) — no vault content or key
moves yet. User story work can begin.

---

## Phase 3: User Story 1 — Send a vault to a brand-new device (Priority: P1) 🎯 MVP

**Goal**: Host shares (role=`pull`); guest establishes the vault's key if it doesn't already
hold one, pulls the vault content, and lands it — as a brand-new profile (first-time
onboarding) or as a same-pattern copy (already-paired resync), per research.md Decision 9.

**Independent Test**: [quickstart.md](quickstart.md) Scenarios A and B — two devices on the
same Wi-Fi, one with no prior key for the vault and one already paired, both complete a "Share"
transfer independently of Push/error-handling work.

- [ ] T025 [US1] Implement `GET /s/{sid}/key` in the T016 router: serve the host's raw DEK bytes, only once the session has reached the `Verified` state, only for `role=pull` (contracts/qr-transfer-protocol.md §2)
- [ ] T026 [US1] Implement `GET /s/{sid}/file` in the T016 router: serve the sealed vault file bytes (`application/x-sshclientx`), capped at `max_body_bytes`
- [ ] T027 [US1] Implement `qr_transfer_host_start` for `{ action: "share" }` in `src-tauri/src/lib.rs`: creates a `TransferSession` (`role=pull`, `key_status=Owned`), starts the T016 server, sets the ticket's `lbl` from the active profile's name (or the OS hostname if none is open), returns `{ session_id, qr_svg, verification_code, expires_at }` (contracts/qr-transfer-protocol.md §4)
- [ ] T028 [US1] Implement the guest's pinned connect and `GET /meta` call in `src-tauri/src/qr_transfer.rs`, using the T013 client
- [ ] T029 [US1] Implement the guest's local "do I already hold this key?" check (query `keystore`/`recovery::unclaimed_dir` for the ticket's `kid`) and, when the key is missing, `GET /s/{sid}/key` followed by `recovery::establish_unclaimed_key()` with the received DEK (research.md Decisions 8–9) — the DEK exists only in local variables between receipt and this call, never written to a file or logged
- [ ] T030 [US1] Implement the guest's `GET /s/{sid}/file` fetch, rejecting a response whose `Content-Length` exceeds `max_body_bytes` before fully buffering it (same early-rejection discipline as T036's `PUT` side), then `vault::verify_and_import()`, then land via the existing `claim_unclaimed_key_as_new_profile()` or `land_as_restore_over_copy()` per the returned `Disposition` — call these unmodified (research.md Decision 9)
- [ ] T031 [US1] Implement `qr_transfer_guest_confirm` in `src-tauri/src/lib.rs` wiring T028–T030 end to end, returning `{ landed_profile_name, disposition }` on success or an `Outcome` code on failure (contracts/qr-transfer-protocol.md §4)
- [ ] T032 [US1] [P] Implement `src/components/QrHostPanel.tsx`: QR display (from T020's SVG), verification code, countdown to `expires_at`, cancel button, "share" action
- [ ] T033 [US1] [P] Implement `src/components/QrGuestScanPanel.tsx`: renders `QrScanCamera`, shows the verification code from `qr_transfer_guest_scan` for mandatory user confirmation *before* calling `qr_transfer_guest_confirm` (contracts/qr-transfer-protocol.md §3 — this confirm step is a UI gate, not server-enforced), then progress/result, prompting for a new vault password on this device when the result's `disposition` is `create_profile` with no password yet set
- [ ] T034 [US1] Wire T029's "already holds the key" fast path into `QrGuestScanPanel.tsx`'s messaging — skip any password-for-new-device prompt when no key establishment happened (spec User Story 1, Acceptance Scenario 4)

**Checkpoint**: User Story 1 fully functional and independently testable — first-time
onboarding and already-paired resync, both landing correctly, both in the "share"/pull
direction.

---

## Phase 4: User Story 2 — Receive a vault from a nearby device (Priority: P2)

**Goal**: Host receives (role=`push`) — the mirror image of US1, with the host as the party
that may lack the key and lands the incoming vault.

**Independent Test**: [quickstart.md](quickstart.md) Scenario C — host chooses "Receive", guest
sends its vault, independently of the Share/error-handling work.

- [ ] T035 [US2] Implement `PUT /s/{sid}/key` in the T016 router: accept 32 raw bytes from the guest and call `recovery::establish_unclaimed_key()` on the **host** side when the host does not hold this `kid` (role=`push`)
- [ ] T036 [US2] Implement `PUT /s/{sid}/file` in the T016 router: accept the sealed vault bytes, capped at `max_body_bytes` and rejected with `413` **before** being fully buffered on an over-cap `Content-Length`, then run `vault::verify_and_import()` and land via the existing commit helpers on the host side (same reuse as T030, now server-side)
- [ ] T037 [US2] Implement `qr_transfer_host_start` for `{ action: "receive" }` in `src-tauri/src/lib.rs`: creates a `TransferSession` (`role=push`, `key_status` computed from the host's own local state for whatever `kid` it may already hold), ticket carries `role=push` and the same `lbl` sourcing as T027
- [ ] T038 [US2] Implement the guest's push flow in `src-tauri/src/qr_transfer.rs`: when the host's `/meta` reports `needs_key`, `PUT /s/{sid}/key` with the guest's own DEK, then `PUT /s/{sid}/file` — symmetric to T029/T030
- [ ] T039 [US2] Extend `qr_transfer_guest_confirm` in `src-tauri/src/lib.rs` to branch on the ticket's `role` (T028–T030's pull path vs. T038's push path)
- [ ] T040 [US2] [P] Extend `QrHostPanel.tsx` with the "receive" action and `QrGuestScanPanel.tsx` with the "send my vault" action for `role=push`

**Checkpoint**: User Stories 1 and 2 both work independently — pull and push directions both
functional.

---

## Phase 5: User Story 3 — Clear failure when devices aren't reachable (Priority: P3)

**Goal**: Every failure named in spec.md's Edge Cases and contracts/qr-transfer-protocol.md §5
surfaces quickly and distinctly — no indefinite spinners, no ambiguous errors.

**Independent Test**: [quickstart.md](quickstart.md) Scenarios D, E, F — unreachable guest,
expired code, reused token — independently of the Share/Receive transfer logic itself.

- [ ] T041 [US3] Implement a connect timeout in the guest's pinned client (T013) bounding `NET_UNREACHABLE` to within 5 seconds of the attempt (spec FR-015, SC-004)
- [ ] T042 [US3] Implement the `TLS_PIN` path: a fingerprint mismatch aborts immediately, before any `meta`/`key`/`file` call, with no retry loop (contracts/qr-transfer-protocol.md §3 step 1)
- [ ] T043 [US3] Re-check `QrTicket.exp` immediately before the guest's first network call (not only at initial scan), closing the race where a code expires between scan and confirm
- [ ] T044 [US3] Ensure a connect that is refused or times out (including client-isolated Wi-Fi) surfaces identically to `NET_UNREACHABLE` — no separate, more confusing error for that case (spec Edge Cases)
- [ ] T045 [US3] [P] Map every code in contracts/qr-transfer-protocol.md §5 to its exact user-facing message in `QrGuestScanPanel.tsx`/`QrHostPanel.tsx`
- [ ] T046 [US3] [P] Add `#[cfg(test)]` tests in `src-tauri/src/qr_transfer.rs`: a session's `fail_count` reaching 5 tears it down and further requests are refused; a `Consumed` token is rejected on any later request against a fresh session with the same value; a ticket whose `exp` has already passed is rejected before any connect attempt is made

**Checkpoint**: All three user stories independently functional; every protocol-level error has
a distinct, tested outcome and a user-facing message.

---

## Phase 6: Polish & Cross-Cutting Concerns

- [ ] T047 [P] Verify desktop camera consent prompts (WebView2 on Windows, WebKitGTK on Linux, WKWebView on macOS) actually surface for `QrScanCamera.tsx` — research.md open risk
- [ ] T048 [P] Verify `if-addrs` enumerates interfaces correctly on Android; if it does not, fall back to reading interface data through the existing `src-tauri/src/android_bridge.rs` JNI bridge instead — research.md open risk
- [ ] T049 Run `cargo tree --manifest-path src-tauri/Cargo.toml -e normal | grep x509-parser` after T001; if `rcgen`'s default features pulled in cert-verification support this feature never uses, trim to the minimal feature set that still provides generation + fingerprinting — research.md Decision 2 open item
- [ ] T050 Run [quickstart.md](quickstart.md) Scenarios A–H manually across two real devices (including at least one Android run in both host and guest roles) and record results
- [ ] T051 [P] Security pass over `src-tauri/src/qr_transfer.rs`: confirm T017's bearer-token comparison is genuinely constant-time (no short-circuiting byte compare), and confirm every DEK value handled between T025/T029/T035/T038 and its destination uses a `Zeroize`/`Zeroizing` wrapper with no intermediate `Vec<u8>` left unwiped
- [ ] T052 Add a one-line status note to `docs/features/spec-02-qr-same-network.md` pointing at `specs/003-qr-same-network-transfer/` as its implementing feature, so the original tech spec and the shipped feature don't silently drift apart

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — start immediately.
- **Foundational (Phase 2)**: Depends on Setup — BLOCKS all user stories (nothing can verify a
  session without T007–T019).
- **User Stories (Phase 3–5)**: All depend on Foundational completion.
  - US1 (P1) has no dependency on US2/US3.
  - US2 (P2) shares the T016 router and T028/T030-shaped logic with US1 (the push path is
    symmetric, not dependent) — implementable in parallel with US1 by a second developer, but
    listed after it here since US1 is the MVP.
  - US3 (P3) touches the same files as US1/US2 (the guest client, the router) but adds
    error-path behavior only — no new endpoint, so it can proceed once Foundational is done,
    independent of whether US1/US2 are finished.
- **Polish (Phase 6)**: Depends on whichever user stories are in scope for the release being
  validated.

### Within Each User Story

- Host endpoint handlers before the Tauri command that starts the session using them.
- Guest network calls before the Tauri command that wires them end to end.
- Backend command before its frontend consumer.

### Parallel Opportunities

- T001–T003, T005 (Setup) in parallel.
- T006, T008, T009, T011, T013, T015 (Foundational, distinct files/concerns) in parallel.
- T020–T022, T024, T053 (Foundational, distinct files) in parallel. T054 depends on T007/T020/T023.
- Once Foundational is done: US1 and US2's backend work can proceed in parallel (different
  HTTP methods on largely the same router file, but logically independent handlers); US3 can
  proceed in parallel with both, since it only adds guards and messages.
- T032/T033 (US1 frontend), T040 (US2 frontend), T045 (US3 frontend) in parallel with each
  other and with any in-flight backend task in a different phase.

---

## Parallel Example: Foundational Phase

```bash
# Once T004 exists, these can run together (distinct concerns within qr_transfer.rs, or
# distinct files):
Task: "Add the 6 new Outcome variants in src-tauri/src/vault.rs"
Task: "Implement RFC1918/link-local/ULA classification + if-addrs enumeration in src-tauri/src/qr_transfer.rs"
Task: "Implement per-session rcgen certificate + fingerprint in src-tauri/src/qr_transfer.rs"
Task: "Implement the pinning ServerCertVerifier + preconfigured reqwest client in src-tauri/src/qr_transfer.rs"
Task: "Implement QR SVG generation via qrcode in src-tauri/src/qr_transfer.rs"
Task: "Add the android.permission.CAMERA entry to the Android manifest"
Task: "Implement src/components/QrScanCamera.tsx"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup.
2. Complete Phase 2: Foundational (CRITICAL — blocks everything).
3. Complete Phase 3: User Story 1 (share/pull, both first-time onboarding and resync).
4. **STOP and VALIDATE**: run quickstart.md Scenarios A and B on two real devices.
5. Ship the "Share" direction alone if that's enough value for a first release — spec.md's own
   User Story priorities already treat US1 as a complete, independently valuable MVP.

### Incremental Delivery

1. Setup + Foundational → a session can be created, scanned, and mutually verified.
2. + User Story 1 → "Share" works end to end, onboarding included (MVP).
3. + User Story 2 → "Receive" works end to end.
4. + User Story 3 → every failure path is fast and clear, not just the happy path.
5. + Polish → Android parity confirmed, dependency footprint trimmed, docs cross-referenced.

### Parallel Team Strategy

With two developers: one takes US1 (T025–T034) while the other starts US2's router handlers
(T035–T036, which don't depend on US1's completion, only on Foundational) and US3's guard work
(T041–T046, which also only depends on Foundational) — merge before Polish.
