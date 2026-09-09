# Phase 0 Research: QR Same-Network Vault Transfer

**Feature**: `003-qr-same-network-transfer` | **Date**: 2026-09-08 | **Spec**: [spec.md](spec.md)

Crate versions, licences, and what's already resolved in this tree were checked against
crates.io/docs.rs directly and against `src-tauri/Cargo.lock`, not recalled.

---

## Decision 1 — HTTPS server: raw `hyper` 1.x + `hyper-util` + `tokio-rustls`, no framework

**Decision**: Build the host's session server (`GET /s/{sid}/meta`, `GET/PUT /s/{sid}/key`,
`GET/PUT /s/{sid}/file`, `POST /s/{sid}/done`) directly on `hyper::server::conn::http1` +
`hyper_util::rt::TokioIo` + `tokio_rustls::TlsAcceptor` wrapping a `rustls::ServerConfig`, with
a hand-written `service_fn` matching on `(method, path)`. No `axum`, no `warp`, no `tiny_http`.

**Why this is the lean choice, not just "a" choice**: `hyper` 1.8.1, `hyper-util` 0.1.19,
`tokio-rustls` 0.26.4, and `rustls` 0.23.40 are **already fully resolved in `Cargo.lock`** —
pulled in transitively today via `reqwest` 0.12.28 → `hyper-rustls` 0.27.9 (the update-check
HTTP client). Adding them as **direct** dependencies with `server`/`http1` features enabled adds
**zero new crates**, only enables cargo features on crates already in the tree — the same
pattern this `Cargo.toml` already uses for `windows`/`objc2` ("already resolved elsewhere in
this exact tree"). `hyper-rustls`'s own repo ships a framework-free server example doing exactly
this: `TcpListener::accept` → `TlsAcceptor::accept` → `TokioIo::new` →
`http1::Builder::new().serve_connection(io, service_fn(...))`.

**Alternatives considered**:
- `axum` — also sits on `hyper`+`tower` (already resolved), so it isn't much heavier
  crate-count-wise, but it adds itself plus routing machinery (`matchit`, `axum-core`) for 6
  static, hand-matchable paths that need no real router. Rejected: no expressiveness gain here,
  and Principle V explicitly singles out avoiding a framework the app doesn't need.
- `tiny_http` — genuinely tiny, but **synchronous**; every request would need `spawn_blocking`
  to coexist with the app's Tokio runtime, and its TLS story is a bolt-on feature, not the
  `rustls::ServerConfig` this app already builds elsewhere. Rejected in favor of staying on the
  async stack already in use everywhere else in `lib.rs`.

**Constitution fit**: Rust-owned (Principle II) — the server lives entirely in a new
Tauri-managed background task, never the webview. Not a Tauri plugin, so no Principle II
plugin-surface Governance trigger. **Flag carried into Constitution Check**: "adding a network
origin" is called a constitution-level change in Development Workflow; this is a same-device
**listening** socket bound to a LAN/hotspot interface only, which the webview never talks to
directly (only Rust does) — a different shape from the reqwest-to-GitHub outbound call that
bullet was written for. Recorded as a documented new capability, not assumed pre-cleared.

---

## Decision 2 — Self-signed per-session cert: `rcgen` 0.14

**Decision**: `rcgen = "0.14"` (0.14.10, MSRV 1.88, **MIT OR Apache-2.0**) generates a fresh
self-signed X.509 cert + key pair per session for the `rustls::ServerConfig`.

**Rationale**: rcgen's default crypto backend is **`ring`** — the exact backend `rustls` 0.23.40
already uses in this tree (`ring` 0.17.14 is already resolved via `rustls`'s own dependency
chain; `aws-lc-rs` 1.18.1 is present too, but from elsewhere, not from `rustls` here). Taking
rcgen's default features keeps exactly one crypto backend behind both TLS and cert generation —
the same two-crypto-backend problem 002's `secret-service` note (research.md Decision 8, spec
002) was written to avoid.

**Cost, stated plainly**: rcgen's default `ring` feature also pulls `x509-parser` (optional
verification support) which is **not currently in `Cargo.lock`** — a handful of genuinely new
transitive crates (`x509-parser`, `der-parser`, `nom`, `oid-registry`, `pem`), not just rcgen
itself. **Open item for implementation**: check whether rcgen's feature graph allows `crypto` +
`ring` + `pem` without the verify extra; if not, accept it — self-signed generation with no
external verification story is still correct here, the verify path just isn't needed.

**Alternatives considered**: hand-rolling DER/ASN.1 cert construction — rejected outright, same
"inventing format code on a security-adjacent path" reasoning 002's research already applied to
the recovery-kit encoding (Decision 10).

**Constitution fit**: Rust-owned, one new direct dependency — added to the Technology &
Architecture Constraints dependency table alongside the vault's six (see Constitution Check).

---

## Decision 3 — Guest-side TLS client with certificate pinning: reuse `reqwest`, no new crate

**Decision**: The guest's calls to the host (`GET /meta`, `GET`/`PUT /key`, `GET`/`PUT /file`,
`POST /done`) go through the **already-present** `reqwest` 0.12 client, configured with
`ClientBuilder::use_preconfigured_tls(..)` supplying a custom `rustls::client::danger::
ServerCertVerifier` that checks the connecting cert's SHA-256 fingerprint against the QR-derived
`fp` value instead of validating against a CA root.

**Rationale**: `reqwest` is already a direct dependency (rustls-tls feature); `rustls`'s
`dangerous()` client-config API for a custom verifier is the standard mechanism for TLS pinning
in this exact stack. Zero new crates.

**Alternatives considered**: hand-rolling HTTP/1.1 over a raw `tokio_rustls::TlsStream` —
rejected, reqwest already solves multipart/streaming-body semantics needed for the file
GET/PUT and there's no reason to reimplement it when the same pinning primitive works either
way.

**Constitution fit**: Rust-owned (Principle II). Zero new dependency footprint.

---

## Decision 4 — QR code generation: Rust `qrcode` crate → SVG string over IPC, no new npm dependency

**Decision**: `qrcode = "0.14"` (0.14.1, **MIT OR Apache-2.0**) encodes the session ticket string
into an SVG in Rust; the Tauri command returns the SVG text directly, and React renders it
(`<img src="data:image/svg+xml,...">` or inline).

**Rationale**: the session ticket (`v1|https://...|tok=...|fp=...|...`) is constructed in Rust
anyway (it embeds the freshly-generated session token and cert fingerprint, which only Rust
has). Generating the QR image in the same place avoids round-tripping that data into the webview
before display, and needs no new npm dependency — "new UI libraries need a gap the existing
stack does not cover," and a Rust-side SVG string closes that gap without one.

**Alternatives considered**: an npm QR-generation package rendering client-side — rejected only
on the "don't add a frontend dependency when Rust already covers it for free" ground; not a
correctness difference either way.

**Constitution fit**: Rust-owned. One new, self-contained Rust dependency (no crypto backend of
its own).

---

## Decision 5 — QR code scanning: webview `getUserMedia` + `jsqr` (npm), decoded text handed to Rust immediately

**Decision**: No Rust-side or Tauri-plugin path covers both desktop and Android, so scanning
happens in the webview: `navigator.mediaDevices.getUserMedia({video: ...})` captures camera
frames to a `<canvas>`, and **`jsqr`** (npm, 1.4.0, pure JS, zero dependencies, MIT) decodes each
frame locally. The decoded ticket **text** (not secret material — FR-009) is passed to a Tauri
command immediately; every privileged step after that (TLS connect, cert pinning, session auth,
key establishment) happens in Rust per Decisions 1–3.

**Verified there is no cross-platform plugin**: the official `tauri-plugin-barcode-scanner`
(`@tauri-apps/plugin-barcode-scanner`) **supports Android and iOS only** — its own docs list
desktop (Linux/Windows/macOS) as unsupported. Since this feature needs Android **and** desktop
webcam scanning (FR-018), that plugin alone can't cover the requirement, and no cross-platform
equivalent exists. Using it for mobile and something else for desktop would mean two code paths
for one behavior — worse than one webview path that already works everywhere Tauri's webview
runs.

**Why the webview here doesn't violate Principle II**: the Rust-owns-privilege list is
SSH/SFTP/crypto/vault I/O/local FS mutation/port forwards/mirror/Docker — QR pixel decoding is
none of those; it's parsing a public, non-secret ticket string out of an image, the same class
of exception the 002 plan already accepted for recovery-phrase display crossing IPC once
("unavoidable... bounded by contract"). The bound here: decoded text is inert until a Rust
command validates and acts on it — no crypto, vault, or secure-store operation ever happens in
JS.

**Rationale for `jsqr` specifically**: pure JS, no dependencies, MIT-licensed, widely used,
small. Needs only a `<canvas>` `ImageData` — no WASM toolchain, no new Vite build-step
complexity.

**Open risk, unresolved by this research pass**: camera permission wiring per platform (Android
`CAMERA` manifest permission; desktop WebView2/WebKitGTK camera consent) is untested — flag for
implementation/quickstart verification.

**Constitution fit**: webview may capture and decode camera frames (non-privileged); it MUST NOT
persist the decoded ticket beyond handing it to the Rust command (no `localStorage`/
`sessionStorage`, consistent with Principle II's existing credential-storage ban). No CSP change
needed — `getUserMedia` is a browser permission prompt, not a CSP directive, and `jsqr` runs from
the app's own bundled `'self'` script, no CDN. No new Tauri plugin, so no plugin-surface
Governance trigger from this path.

---

## Decision 6 — LAN IP enumeration and filtering: `if-addrs` crate + already-stable `std::net` filtering

**Decision**: `if-addrs = "0.14"` (0.14.0, dual **MIT OR BSD-3-Clause**) enumerates the host's
network interfaces to find candidate LAN/hotspot addresses. Filtering to RFC1918/link-local/
ULA-only (FR-005) uses **already-stable stdlib**, zero new crate: `Ipv4Addr::is_private()` /
`is_link_local()`, `Ipv6Addr::is_unique_local()`.

**Rationale**: no stdlib API enumerates interfaces (the private/link-local *classification* is
stable stdlib, but *listing what's on the machine* is not), and nothing already in the tree does
either — `socket2` (already present, used for SSH TCP keepalive) only augments an existing
socket, it doesn't enumerate interfaces. `if-addrs` is small and single-purpose, versus a
heavier alternative like `pnet` (packet-capture-oriented, far more than needed).

**Open risk**: `if-addrs`'s docs describe itself as "Posix and windows systems" without
explicitly confirming Android. Android is Linux-based/POSIX (Bionic implements `getifaddrs`
since API 24), so it will very likely work, but needs an on-device check before relying on it
for the Android host/guest roles FR-018 requires. Fallback if it doesn't: read interface data
through the existing `android_bridge.rs` JNI bridge instead.

**Constitution fit**: Rust-owned. One new, narrowly-scoped dependency.

---

## Decision 7 — QR fields: fold the human verification code and the TLS pin into one value

**Decision**: The QR's `fp` field carries the **full SHA-256 hex fingerprint of the host's
per-session certificate** and serves double duty: the guest's HTTP client uses it verbatim as
the pin (Decision 3), and both screens render a short, human-comparable form derived from the
same value (e.g. the first 6 hex characters, grouped) for the visual confirmation FR-007
requires. There is no separate `cf=` field — the source tech spec's `fp`/`cf` split (§4/§5.1) is
deliberately collapsed into one, since a `kid`-derived `fp` (the source spec's original meaning)
doesn't work once first-time onboarding means the guest may not have a `kid` to derive it from
yet (spec Clarifications, Q1).

**Rationale**: one value, one purpose, checked automatically (pin) and visually (human compare)
— matches the "safety number" pattern used by other QR-bootstrapped E2E pairing flows (e.g.
Signal/WhatsApp linked devices), and avoids maintaining two fingerprints that are supposed to
agree with each other by construction. `kid` stays in the QR too (when the host already has one
— it always does, since the host is the vault owner in the sharing direction) purely as a UX
optimization so the guest can recognize "I already have this" before connecting; it is not
security-load-bearing since `kid` is already public (it's in the sealed container's AAD).

**Alternatives considered**: keeping `fp` (kid-derived) and `cf` (cert fingerprint) as two
separate fields as the source tech spec describes — rejected because `fp` as originally defined
can't exist before a `kid` does, which first-time onboarding requires.

---

## Decision 8 — Key transport: raw DEK bytes over the pinned session, no extra wrap layer

**Decision**: When key establishment is needed (spec FR-009a/FR-010), the DEK's 32 raw bytes are
the `GET`/`PUT /s/{sid}/key` body, protected by nothing beyond the mutually-pinned TLS session
from Decisions 2–3 plus the human-verified code from Decision 7. No additional AEAD wrap layer
around the DEK for transport.

**Rationale**: the channel already carries two independent factors of assurance — a
cryptographic one (TLS 1.3 + exact-match certificate pinning against a value that arrived over
an out-of-band camera scan, not the network) and a human one (the user visually compares the
same value on both screens before proceeding). That is structurally the same class of guarantee
this project already accepts for the two-of-two DEK unwrap (research.md Decision 3, spec 002:
"both inputs are already uniformly random... a plain hash is the right primitive here") — adding
a third wrap here would be defense-in-depth against a TLS/pinning failure this app doesn't
otherwise treat as a live threat, at the cost of new key-derivation code on a security-critical
path. Consistent with the ladder: don't add a mechanism beyond what the two already-accepted
factors provide.

**Alternatives considered**: deriving a session key from a QR-only secret (never sent over the
network at all) to additionally AEAD-wrap the DEK payload — considered as genuine
defense-in-depth, but rejected for this pass: it duplicates protection the pinned channel already
provides, adds a new KDF invocation and wire field to get right on the one path in this feature
that moves a raw root key, and nothing in the spec's Success Criteria (SC-008) requires it — a
network capture without breaking TLS pinning already can't recover the DEK. Revisit only if a
concrete key-establishment threat model surfaces that pinning + human verification don't cover.

**Constitution fit**: reuses existing primitives (`rustls`, existing `sha2` for the fingerprint
compare) — no new crypto crate for this specific step. The DEK is written directly into
`recovery::establish_unclaimed_key` (already exists, spec 002) immediately on receipt; it is
never written to a temp file, logged, or held longer than the one in-memory hand-off, matching
FR-010's "never persisted outside the secure store" requirement.

---

## Decision 9 — Landing/verification: reuse `vault::verify_and_import` and the existing copy-landing path unchanged

**Decision**: The received vault bytes (whichever endpoint they arrived over) are verified with
the existing `vault::verify_and_import()` — no new verification code. Landing reuses the
existing commands unchanged:
- No local key at all yet → `recovery::establish_unclaimed_key()` (already exists, spec 002)
  runs first, using the DEK from Decision 8; this makes the registry lookup return
  `KeyLookup::Unclaimed`, and `verify_and_import` naturally yields `Disposition::CreateProfile`
  → land via `claim_unclaimed_key_as_new_profile()` (already exists).
- Local key already held, matching `kid` → `KeyLookup::Owned` → `Disposition::RestoreOver` (or
  `NoOp` on an identical match) → land via `land_as_restore_over_copy()` (already exists),
  **regardless of the incoming generation** — this is what `import_vault_commit` already does
  for file import today (verified by reading `src-tauri/src/lib.rs` directly, not assumed), and
  spec.md's Clarifications record the same choice for this feature after this exact discovery
  during planning: file import deliberately reverted an overwrite-capable landing once (commit
  `e75df91`, "import always lands as a new profile, never overwrites") specifically so a
  transfer can never clobber local changes.

**Rationale**: this is the single largest reuse win in this feature — the entire "what happens
when the bytes verify" decision tree (new profile / copy-landing / no-op) already exists,
already has test coverage (`verify_and_import_tests` in `vault.rs`), and already encodes the
exact safety property (never overwrite) the spec now calls for. Zero new logic for this part;
the only new code is *getting bytes to this pipeline* (the session server/client) and, when
needed, establishing the key first (Decision 8, reusing `establish_unclaimed_key`).

**Constitution fit**: routes through "the one verification procedure" the constitution's
Technology & Architecture Constraints section requires every transport to use. No new format,
no second verification path.

---

## Open risks

- **rcgen's default feature set** may pull `x509-parser` and friends even though this feature
  never needs certificate *verification* (only generation + fingerprinting) — check the actual
  `Cargo.lock` diff once `rcgen` is added; trim features if a leaner combination exists.
- **`if-addrs` on Android** is unverified — POSIX `getifaddrs` should work via Bionic but hasn't
  been checked in this repo's actual Android build.
- **Camera permission prompts** (Android manifest `CAMERA` permission; desktop WebView2/
  WebKitGTK camera consent) for the `getUserMedia` scanning path are unverified.
- **hyper/hyper-util exact feature flags** (`server`, `http1`, `tokio` on `hyper-util`) weren't
  pinned to the byte here — verify against the `hyper-rustls` example's actual `Cargo.toml` at
  implementation time.
- **Single-use token semantics across two body fetches**: the source tech spec's "after one
  successful body GET or PUT, revoke tok" (§5.3.4) was written for a single-payload transfer.
  First-time onboarding now needs up to two body fetches (`/key` then `/file`) in one session.
  Resolved in [contracts/qr-transfer-protocol.md](contracts/qr-transfer-protocol.md): the token
  is revoked on `POST /done` or session expiry, not after the first body fetch — replay across
  *separate* sessions is what single-use actually needs to prevent, and the existing
  session-level bounds (expiry, one completed session, 5-failed-attempt limit) already bound a
  single legitimate session's call count.
