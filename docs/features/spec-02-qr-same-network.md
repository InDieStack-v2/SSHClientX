# Tech spec 2 — QR scan transfer (same network)

**Status:** v1  
**Applies to:** desktop app and mobile app  
**Related:** [Export / import](spec-01-export-import.md), [Cloud sync](spec-03-cloud-storage.md)

---

## 1. Purpose

Transfer a sealed `*.sshclientx` vault between two devices that can reach each other on the **same LAN** or a **host hotspot**.

The QR code is a **short-lived session ticket** (URL + token). The vault file does **not** ride inside the QR.

---

## 2. Non-goals

- Air-gap “QR movie” / multi-frame optical file transfer (not v1).
- Cross-network transfer (use export/import or cloud).
- Putting the DEK in the QR (except a separate, explicit pair-key flow — out of scope for this spec).

---

## 3. Roles

| Role | Behavior |
| --- | --- |
| **Host** | Starts a local HTTPS server, shows QR, serves or receives one `*.sshclientx` |
| **Guest** | Scans QR **inside the app**, connects, pull or push |

One session = two devices. More devices = repeat sessions.

---

## 4. QR payload

Single QR, version `v1`, UTF-8 text, `|`-separated fields:

```
v1|<https-url>|tok=<hex>|kid=<hex>|fp=<hex>|exp=<unix>|role=pull|sid=<hex>
```

`role=push` when the guest will upload to the host.

| Field | Rule |
| --- | --- |
| `https-url` | `https://<ipv4-or-ipv6>:<port>/s/<sid>` |
| `sid` | 128-bit random session id |
| `tok` | 128-bit random, **single use** |
| `kid` | 16-byte vault key id (hex) |
| `fp` | First 8 bytes of SHA-256(`kid`), hex, shown on both screens |
| `exp` | Unix seconds; `now + 90`, maximum lifetime **120 s** |
| Host IP | RFC1918, link-local, or IPv6 ULA only |

### 4.1 Optional hotspot QR

If there is no shared router, host may show a second QR (or a second line):

```
WIFI:T:WPA2;S:<ssid>;P:<password>;;
```

Guest joins that AP, then uses the session URL.

### 4.2 Forbidden in QR

- Vault ciphertext
- DEK, passphrase, `dek.wrap`
- Public internet unicast IPs (reject `8.8.8.8` and similar)
- HTTP (non-TLS) URLs

---

## 5. Host stack

### 5.1 Bind

- Listen HTTPS on the interface that owns the advertised IP (Wi-Fi or hotspot).
- Do not advertise a global unicast address.
- Per-session self-signed certificate. Guest pins the cert fingerprint (include in QR derivation or as extra field `cf=`).

### 5.2 Endpoints

All require `Authorization: Bearer {tok}`.

| Method | Path | Action |
| --- | --- | --- |
| `GET` | `/s/{sid}/meta` | Size, `generation`, `kid`, `sha256` prefix |
| `GET` | `/s/{sid}/file` | Download `*.sshclientx` (`role=pull`) |
| `PUT` | `/s/{sid}/file` | Upload `*.sshclientx` (`role=push`) |
| `POST` | `/s/{sid}/done` | Close session |

`Content-Type: application/x-sshclientx`

### 5.3 Session lifecycle

1. User taps **Show QR** / **Receive**.
2. Create `sid`, `tok`, cert, bind port.
3. Show QR + `fp` + numeric URL fallback.
4. After **one** successful body `GET` or `PUT`, revoke `tok`.
5. Idle timeout **120 s** or process death → close port.
6. Max body: **8 MiB** (configurable). Reject larger.

### 5.4 Rate limit

Drop session after **5** failed tokens or auth errors.

---

## 6. Guest stack

1. In-app scanner only (do not hand the URL to the system browser).
2. Parse QR; reject unknown version, expired `exp`, non-HTTPS, non-private IP.
3. Show host label + `fp`; user confirms match with host screen.
4. TLS connect; **pin** session cert.
5. `GET /meta` → show size and generation.
6. `GET` or `PUT` the `.sshclientx` body.
7. Run **import verify** from spec 1 §5 (`magic`, hash, AEAD, `kid`, generation).
8. `POST /done`. Tear down.

If TCP/TLS fails: `NET_UNREACHABLE` —  
“Not on the same Wi-Fi. Export a .sshclientx file instead.”

---

## 7. Security constraints

- `FLAG_SECURE` / disable screenshots on the QR and confirm screens.
- Token not reusable across sessions or after success.
- No redirects off the advertised host.
- DEK never leaves the OS keystore in this flow.
- Same-network only: no STUN, TURN, or cloud relay.

---

## 8. Errors

| Code | Meaning |
| --- | --- |
| `QR_BAD` | Payload malformed |
| `QR_EXPIRED` | `exp` passed |
| `QR_IP_FORBIDDEN` | Host not a private address |
| `NET_UNREACHABLE` | Different network / firewall |
| `TLS_PIN` | Certificate mismatch |
| `TOK_USED` | Token already consumed |
| `FILE_*` | Import errors from spec 1 |

---

## 9. Acceptance tests

1. Host and guest on Wi-Fi A: pull completes; `sha256` matches; vault unlocks with local DEK (`kid` match).
2. Guest on cellular only: `NET_UNREACHABLE`, no hang > 5 s after timeout.
3. Rescan of QR after 90–120 s: `QR_EXPIRED`.
4. Replay of a used token: `TOK_USED`.
5. Tampered downloaded bytes: import `BOX_CORRUPT`; host vault unchanged.

---

## 10. UX minimum

- Host: QR, fingerprint, cancel, countdown.
- Guest: scan, fingerprint confirm, progress, result.
- Multi-device: finish A↔B, then start a new session for A↔C.
