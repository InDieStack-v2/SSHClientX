# Implementation Plan: QR Same-Network Vault Transfer

**Branch**: `003-qr-same-network-transfer` | **Date**: 2026-09-08 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/003-qr-same-network-transfer/spec.md`

## Summary

Let a user move a vault between two devices on the same LAN/hotspot by scanning an in-app QR
code — no cloud, no cable, and (per this spec's Clarifications) no requirement that the
receiving device already hold the vault's key. One device hosts a short-lived, single-use HTTPS
session and shows a QR; the other scans it in-app, and the two devices mutually verify each
other (pinned per-session certificate + a human-compared code both screens derive from the same
value) before any bytes move.

Technical approach: a new `qr_transfer.rs` module owns the whole feature — QR ticket
encode/decode, the host's `hyper`-on-`rustls` session server, the guest's pinned `reqwest`
client, and session-lifecycle bookkeeping (expiry, single-use token, failed-attempt limit). It
deliberately does **not** reimplement key establishment or vault landing: when the guest lacks
the vault's key, it calls the existing `recovery::establish_unclaimed_key()` (spec 002) with the
DEK received over the pinned channel; every received vault file, in either direction, is
verified and landed through the existing `vault::verify_and_import()` pipeline and its existing
commit helpers, unchanged. See research.md Decisions 8–9 for why this reuse is safe and why it
is the largest single simplification in this design.

**Gates are clear.** The constitution stands at v5.0.0: v4.0.0 conditionally passed this
design pending Governance sign-off, and v5.0.0 supplies it (explicit pairing named in
Principle I, Android exception widened in Principle III, dependency table extended, local
server named as a sanctioned capability). See Constitution Check.

## Technical Context

**Language/Version**: Rust 2021 for `src-tauri/` (MSRV stays 1.89 — nothing here needs newer).
TypeScript + React 18 for `src/`. Tauri 2.

**Primary Dependencies**: Added as **direct** dependencies, all already resolved in
`Cargo.lock` today via `reqwest` → `hyper-rustls`, so this adds **zero new crates** for these
four, only enables features already compiled in: `hyper` 1.8 (`server`, `http1`), `hyper-util`
0.1 (`tokio`, `server` features), `tokio-rustls` 0.26, `rustls` 0.23 (direct, for
`ServerConfig`/`dangerous()` client verifier). Genuinely new: `rcgen` 0.14 (self-signed
per-session cert, `ring` backend matching `rustls`'s own), `qrcode` 0.14 (QR SVG generation),
`if-addrs` 0.14 (LAN interface enumeration). Frontend: `jsqr` 1.4.0 (npm, zero deps, QR decode
from camera frames). Reused unchanged: `reqwest` (guest HTTP client, now with a pinning
verifier), `keyring`/`keystore.rs`, `recovery.rs` (`establish_unclaimed_key`), `vault.rs`
(`verify_and_import`, `SealedVaultFile`, existing commit helpers), `sha2`, `rand`, `zeroize`.

**Storage**: No new storage format. A received vault lands through the exact same on-disk
artifacts a manual import produces (sealed vault file, keywrap sidecar, keystore device-factor
entry) — see research.md Decision 9. No new database tables, no new file format.

**Testing**: `cargo test` for the pure/protocol parts of `qr_transfer.rs` — ticket
encode/decode, expiry/single-use bookkeeping, RFC1918/link-local/ULA filtering — everything that
doesn't need two real devices on a real network. [quickstart.md](quickstart.md) carries the
two-device manual scenarios (cannot be automated, same posture as 002's quickstart). `npm run
typecheck` / `npm run build` for the frontend.

**Target Platform**: macOS, Windows, Linux, **and Android**, both host and guest roles, per
spec FR-018 — this feature does not carry 002's desktop-creates/Android-consumes asymmetry.
Camera-based scanning must work on a desktop webcam and on Android.

**Project Type**: Desktop + mobile application, Tauri 2 + Rust core + React renderer, single
repository (same shape as 002).

**Performance Goals**: SC-001 — scan-to-verified-and-unlockable in under 30 s for a vault up to
8 MiB on a stable LAN. SC-004 — an unreachable guest sees an error within 5 s of the connection
attempt failing.

**Constraints**: The DEK is never written to disk unprotected and never logged, on either
device, at any point (FR-010) — in transit it exists only as a `GET`/`PUT /s/{sid}/key` HTTP
body inside the pinned TLS session, and on receipt goes directly into
`recovery::establish_unclaimed_key()`, never a temp file. The session server binds only to a
RFC1918/link-local/ULA address (FR-005) and is torn down on completion, expiry (≤120 s), app
exit, or 5 failed attempts (tech spec §5.3/§5.4). The webview only ever sees the plaintext QR
ticket string (Decision 5) — it never touches key material, session tokens' cryptographic use,
or the HTTP(S) traffic itself.

**Scale/Scope**: 22 functional requirements, 3 user stories. Rust: one new module
(`qr_transfer.rs`, host+guest+protocol), ~6 new Tauri commands, 6 new `Outcome` variants
(`QR_BAD`, `QR_EXPIRED`, `QR_IP_FORBIDDEN`, `NET_UNREACHABLE`, `TLS_PIN`, `TOK_USED` — mirroring
the source tech spec's §8 error table); zero changes to `vault.rs`/`recovery.rs`/`keystore.rs`
internals, only new call sites into their existing public functions. Frontend: two new screens
(host share/receive QR + countdown, guest scan + verification-code confirm) and a small
camera-capture component.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-checked after Phase 1 design.*

Evaluated against **constitution v4.0.0**; re-evaluated below against **v5.0.0**, amended for
this feature specifically (see "Post-design re-check").

- **Principle I (Device-Bound Secrets, NON-NEGOTIABLE)** — **PASS, exercising a clause the
  constitution already anticipates but hasn't yet named a real feature for.** Principle I's own
  text permits cross-device vault access "by the user manually moving the vault file together
  with an explicit recovery kit **or, in future, an explicit pairing**." This feature *is* that
  future explicit pairing. The DEK is still a CSPRNG value generated on the owning device,
  never derived from a password; when established on a key-less guest it goes through the
  unmodified `establish_unclaimed_key()` path (fresh device factor, keywrap sidecar under a
  vault password the guest's user chooses for that device, never the host's). What's genuinely
  new relative to v4.0.0's constitution text: the DEK now transits a network channel (LAN-only,
  mutually pinned, human-verified), not just a file the user carries by hand. v4.0.0's text
  doesn't forbid this, but doesn't explicitly say it either. **Governance follow-up required**
  (below) — **now resolved in v5.0.0**.
- **Principle II (Rust Owns Privilege)** — **PASS, with one named exception**, the same shape
  as 002's recovery-phrase exception: QR pixel decoding happens in the webview
  (`getUserMedia` + `jsqr`), because no Rust/Tauri-plugin path covers Android *and* desktop
  webcams (research.md Decision 5). Bounded by contract: the decoded ticket is a public,
  non-secret string, inert until a Rust command validates and acts on it; nothing crypto-,
  vault-, or secure-store-related ever runs in JS. The session server, the QR *generator*, TLS,
  certificate pinning, and all key/vault handling are Rust. No new Tauri plugin is introduced.
- **Principle III (One Core, Every Platform)** — **PASS, but the written text needs to catch
  up**, same class of issue as Principle I. This feature deliberately gives Android host **and**
  guest roles, including first-time key establishment (spec FR-018) — going beyond v4.0.0's
  Android carve-out, which named only "a key [that] arrived via a recovery kit." A
  pairing-established key is the same *shape* of exception (fresh device factor + keywrap
  sidecar on Android, exactly like a recovery kit consumption already does), just not the
  literal path v4.0.0's sentence named. **Governance follow-up required** (below) — **now
  resolved in v5.0.0**. Everything else in Principle III (shared core in `lib.rs`'s modules,
  `cfg`-gated desktop-only code) is satisfied by construction — `qr_transfer.rs` has no
  desktop-only dependency.
- **Principle IV (Explicit Trust Boundaries)** — **PASS, with new guards this plan names
  explicitly** (the principle's own pattern: "each new FS or terminal path MUST reuse the
  existing guards" — this is a new *network* path, so it needs its own, named here rather than
  assumed): the QR ticket string is untrusted input parsed strictly field-by-field, never used
  to build a path or interpreted as markup; the bearer token comparison MUST be constant-time;
  every byte of a received vault file still goes through the unmodified, already-hardened
  `verify_and_import()` before any of it is trusted; the server's HTTP parsing surface is
  `hyper`'s own (not hand-rolled), and request routing is a fixed match on 6 known paths, not a
  generic router that could be tricked into serving something unintended.
- **Principle V (Native and Lean)** — **PASS as of v5.0.0.** Four of the seven crates this
  feature needs are already fully resolved in `Cargo.lock` (research.md Decision 1) and cost
  nothing new to promote to direct dependencies. Three are genuinely new: `rcgen`, `qrcode`,
  `if-addrs` (plus `jsqr` on the npm side). Each has a documented, single reason (research.md
  Decisions 2/4/6) and no lighter alternative was found; all four now have their own exhaustive
  dependency-table row in the constitution. Against v4.0.0 alone, the gate that actually failed
  wasn't dependency count — it was Development Workflow's rule that "adding a network origin...
  is a constitution-level change: it MUST go through Governance." **Resolved in v5.0.0** (below).

**Overall**: **PASS against constitution v5.0.0.** Against v4.0.0 this gate was conditional —
design work (Phase 0/1 below) was allowed to proceed, but implementation was blocked pending an
amendment, the same process 002 itself went through (its own Principle V gate failed against
v3.0.0 until v3.1.0 named its six dependencies). That amendment has now landed as v5.0.0
(`.specify/memory/constitution.md`, Sync Impact Report at the top of the file), covering all
four items that were open:

1. Principle I now names `specs/003-qr-same-network-transfer` as the "explicit pairing" its
   Device-Bound Secrets section already anticipated, and states that the DEK MAY transit a
   mutually-authenticated, human-verified, same-network channel as part of that pairing
   (distinct from, and not loosening, the "never travels" rule for a *vault password*, which
   this feature does not touch).
2. Principle III's Android exception now covers a key established via this explicit-pairing
   flow, not only one that arrived via a recovery kit.
3. The Technology & Architecture Constraints section now carries an exhaustive four-row
   dependency table for `rcgen`, `qrcode`, `if-addrs`, and `jsqr`, mirroring the vault feature's
   six-row table format.
4. The new local HTTPS server is now explicitly named as a sanctioned capability — a LAN-bound
   listening socket the app itself hosts for this feature only, distinct from (and not an
   expansion of) the existing outbound-only `reqwest` allowance for the GitHub update check.

Nothing blocks `/speckit-tasks`.

### Post-design re-check

Phase 1 (below) surfaced one course-correction, already folded into spec.md: planning found
that file import had already tried, and explicitly reverted
(commit `e75df91`, "import always lands as a new profile, never overwrites"), an
overwrite-capable landing for exactly the risk this feature's own landing behavior could have
reintroduced. Resolved by reusing the existing, already-hardened copy-landing path unchanged for
every generation relationship (research.md Decision 9) — no constitutional consequence, and no
new code for this part at all.

No other gate changed shape during design. The four Governance items above are unchanged by
Phase 1 and remain the blocker before `/speckit-tasks`.

## Project Structure

### Documentation (this feature)

```text
specs/003-qr-same-network-transfer/
├── plan.md                          # This file
├── research.md                      # Phase 0 — 9 decisions
├── data-model.md                    # Phase 1 — entities, QR ticket format, state machine
├── quickstart.md                    # Phase 1 — 2-device validation scenarios
├── contracts/
│   └── qr-transfer-protocol.md      # Phase 1 — QR ticket grammar, HTTP endpoints, Tauri
│                                     #   command surface, error codes
├── checklists/
│   └── requirements.md              # Spec quality checklist (16/16)
└── tasks.md                         # Phase 2 (/speckit-tasks — not created here)
```

### Source Code (repository root)

```text
src-tauri/
├── Cargo.toml               # rcgen, qrcode, if-addrs added; hyper/hyper-util/tokio-rustls/
│                             #   rustls promoted from transitive to direct with server features
└── src/
    ├── qr_transfer.rs       # NEW — QR ticket encode/decode, session state (sid, tok, exp,
    │                        #   role, fail count), host session server (hyper+rustls+rcgen),
    │                        #   guest pinned client (reqwest + custom rustls verifier),
    │                        #   RFC1918/link-local/ULA interface filtering (if-addrs)
    ├── recovery.rs           # UNCHANGED — establish_unclaimed_key() called, not modified
    ├── vault.rs               # UNCHANGED — verify_and_import() and commit helpers called,
    │                         #   not modified
    ├── keystore.rs            # UNCHANGED
    └── lib.rs                 # ~6 new #[tauri::command]s (qr_transfer_host_start/cancel,
                              #   qr_transfer_guest_scan/confirm/cancel); 6 new Outcome variants

src/
├── components/
│   ├── QrHostPanel.tsx       # NEW — QR display (SVG from Rust), verification code, countdown
│   ├── QrGuestScanPanel.tsx  # NEW — getUserMedia + jsqr camera capture, verification-code
│   │                         #   confirm step, progress/result
│   └── QrScanCamera.tsx      # NEW — thin camera-capture component jsqr reads frames from
```

**Structure Decision**: Single new Rust module, following the precedent already set by
`hlc.rs`/`mirror.rs`/`tunnel.rs`/`recovery.rs`: one cohesive concern, own file, calling into
`vault.rs`/`recovery.rs`/`keystore.rs` rather than duplicating anything from them. No change to
those three files' internals — every integration point is a call to an already-public function.
Frontend gets exactly the two screens spec.md's User Stories describe, plus one shared
camera-capture piece, following `LockScreen.tsx`/`RecoveryKitPanel.tsx`'s precedent of one
component per user-facing flow rather than folding into `ProfileSelectPage.tsx`.

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| New local HTTPS server (Governance item 4) | The feature's entire mechanism (spec-02 tech spec) is a host serving a short-lived session over HTTPS; there is no way to do device-to-device transfer over a pinned, mutually-verified channel without one endpoint listening | A cloud relay was explicitly ruled out (spec Assumptions, source tech spec §7 "no STUN, TURN, or cloud relay") — the only remaining shape is one device listening on the LAN |
| 3 new Rust crates + 1 new npm dependency (Governance item 3) | `rcgen` (cert generation), `qrcode` (QR generation), `if-addrs` (interface enumeration), `jsqr` (QR decode) each cover a gap nothing already in the tree closes (research.md Decisions 2/4/5/6) | Hand-rolling any of the four means reimplementing DER cert construction, QR error-correction encoding, or platform interface enumeration — all format/protocol code on a security-adjacent path, the same class of alternative 002's research already rejected for its own recovery-phrase encoding |
| QR decode in the webview (Principle II exception) | No Rust/Tauri-plugin path covers desktop webcams *and* Android (research.md Decision 5) | Splitting mobile (a plugin) from desktop (something else) would mean two implementations of one behavior — worse than one bounded, non-privileged webview path |
| Android gets full host+guest parity, unlike 002's asymmetry (Governance item 2) | Spec FR-018, decided in Clarifications: onboarding a brand-new Android device is a first-class scenario for this feature, not a future extension | Restricting Android to guest-resync-only was considered during clarification and rejected — it would leave "hand a colleague an Android vault" unsupported for no security reason, since the mechanism (fresh device factor + keywrap sidecar) is identical to what recovery-kit consumption already does on Android today |
