# Quickstart: QR Same-Network Vault Transfer

**Feature**: `003-qr-same-network-transfer` | **Date**: 2026-09-08

Manual validation scenarios covering spec.md's Success Criteria (SC-001–SC-008). Several need
two physical devices on the same Wi-Fi and cannot be automated — same posture as
`002-e2e-vault-migration/quickstart.md`.

**Prerequisites**: two devices (any mix of the desktop platforms and Android) on the same Wi-Fi
network, each running this build. Device A has an existing unlocked vault for scenarios 1–3.

## Scenario A — First-time onboarding (SC-001, SC-006, SC-008)

1. On device A (owns a vault), choose "Share" → confirm "Recommended" flow → observe the QR,
   fingerprint code, and countdown.
2. On device B (never seen this vault, no local profile for it), open the in-app scanner and
   scan A's QR.
3. Confirm the fingerprint code shown on B matches A's screen.
4. Expect: within 30 s, B reports a landed profile; B's local secure store now holds a fresh
   device factor + keywrap sidecar for this vault's `kid`; B prompts for (and requires) a new
   vault password for **this device** before the vault opens there.
5. Immediately start a new session from A to a **third** device without restarting A's app —
   expect it to work with no cleanup step (SC-006).
6. (SC-008, needs packet capture tooling) Capture the full session's network traffic; confirm
   the DEK is not recoverable from the capture — it only ever appears inside the TLS session
   the capture cannot decrypt.

## Scenario B — Resync to an already-paired device (spec User Story 1, Acceptance Scenario 4)

1. Repeat Scenario A once, so device B already holds A's vault's key.
2. On A, make a small change and save (bumps `generation`).
3. Start a new "Share" session on A; scan from B again.
4. Expect: no password prompt on B (key reused), no key exchange over the wire at all, and the
   incoming content lands as a **new, separately-named copy** of B's existing profile — B's
   original profile file is byte-for-byte unchanged (SC-007). This is the corrected behavior
   from spec.md's Clarifications (superseded answer) — confirm it does **not** silently update
   the existing profile in place.

## Scenario C — Push direction / "Receive" role

1. On device A, choose "Receive" instead of "Share".
2. On device B (any key state), scan A's QR — note the ticket's `role=push`.
3. B chooses to send its own vault; confirm the fingerprint code on both screens.
4. Expect: A ends up with a verified copy of B's vault, landed via the same rules as Scenario A
   or B above depending on whether A already held that `kid`.

## Scenario D — Not reachable (SC-004)

1. Start a "Share" session on device A.
2. On device B, disable Wi-Fi and enable cellular data only, then scan A's QR (e.g. by
   photographing it and importing the image, or by manually re-entering the numeric fallback).
3. Expect: `NET_UNREACHABLE` surfaced within 5 seconds of the connection attempt, with the
   "export a .sshclientx file instead" fallback message — no indefinite spinner.

## Scenario E — Expired code (spec User Story 3, Acceptance Scenario 2)

1. Start a session on A; wait over 120 seconds without scanning.
2. Scan the (now-expired) QR on B.
3. Expect: `QR_EXPIRED`, distinct from `QR_BAD` or `NET_UNREACHABLE`.

## Scenario F — Reused token (spec User Story 3, Acceptance Scenario 3; SC-003)

1. Complete Scenario A or B fully once.
2. Re-scan the same (now-consumed) QR code again — or, using a developer tool, replay the
   captured `GET /meta` request with the same `tok` value against a fresh session.
3. Expect: `TOK_USED`, no data served.

## Scenario G — Tampered bytes (spec Edge Cases; SC-002)

1. Start a transfer (Scenario A or B).
2. Using a proxy/dev tool between the two devices, flip one byte of the vault file response/
   request body in transit.
3. Expect: the guest reports a `BOX_CORRUPT`-shaped failure (via `verify_and_import`), and the
   host's own vault file is confirmed unchanged afterward.

## Scenario H — Android role parity (spec FR-018)

1. Repeat Scenario A with device B (or A) being an Android device, in both directions (Android
   as host, Android as guest), including the first-time-onboarding path.
2. Expect: identical behavior to the desktop-only run of Scenario A — this is the check for the
   Constitution Check's Governance item 2 (Android exception extended to pairing-established
   keys), and for research.md's open risk on `if-addrs`/camera-permission behavior on Android.

## Traceability

| Scenario | Success Criteria covered |
| --- | --- |
| A | SC-001, SC-005, SC-006, SC-008 |
| B | SC-007 |
| C | (User Story 2 acceptance) |
| D | SC-004 |
| E, F | SC-003 |
| G | SC-002 |
| H | FR-018 (Android parity) |
