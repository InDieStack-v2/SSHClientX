# Tech spec 1 — Export / import (`*.sshclientx`)

**Status:** v1  
**Applies to:** desktop app and mobile app  
**Related:** [QR same-network](spec-02-qr-same-network.md), [Cloud sync](spec-03-cloud-storage.md)

---

## 1. Purpose

Move a sealed vault between devices when they are **not** on the same network and **not** using cloud. The user carries a file (`USB`, Files app, AirDrop, chat, disk).

The file is ciphertext only. The encryption key (DEK) stays in each device’s OS keystore.

---

## 2. File format: `*.sshclientx`

| Item | Value |
| --- | --- |
| Extension | `.sshclientx` |
| MIME | `application/x-sshclientx` |
| Magic | `SSHCLTX1` (8 bytes) |
| Example name | `AppName-20260903-1446-g14.sshclientx` |

### 2.1 Layout

| Field | Type | Notes |
| --- | --- | --- |
| `magic` | 8 bytes | `SSHCLTX1` |
| `format` | u16 | `1` |
| `kid` | 16 bytes | Vault / DEK identity |
| `generation` | u64 | Monotonic per successful save |
| `created_at` | i64 | Unix milliseconds |
| `sender_id` | 16 bytes | Random device id (not hardware serial) |
| `sender_name` | UTF-8 (length-prefixed u16) | Display only |
| `alg` | u8 | `1` = XChaCha20-Poly1305, `2` = AES-256-GCM |
| `nonce` | 24 bytes (`alg=1`) or 12 bytes (`alg=2`) | Unique per package |
| `ciphertext` | bytes (u32 length prefix) | Encrypted vault payload |
| `tag` | 16 bytes | AEAD tag |
| `sha256` | 32 bytes | SHA-256 of **all bytes before this field** |

**AAD** for AEAD: `magic || format || kid || generation`.

### 2.2 What is inside ciphertext

App-defined vault CBOR/JSON: SSH keys, host config, metadata.

### 2.3 What must never be in the file

- Raw DEK
- Passphrase
- `dek.wrap`
- OAuth tokens
- OS keystore exports

---

## 3. Local key storage (not part of the file)

| Item | Storage |
| --- | --- |
| DEK (32 bytes) | OS keystore / Secure Enclave / StrongBox / DPAPI, `ThisDeviceOnly` |
| Unlock | Biometric or device lock screen; optional passphrase via Argon2id KEK |
| `dek.wrap` | App private storage, wrapped DEK |
| Backup of DEK | Explicit recovery-kit flow only, default off |

Android: `allowBackup=false` for key material.  
iOS: `kSecAttrSynchronizable = false`.

---

## 4. Export

### 4.1 Trigger

Settings → **Export vault**.

### 4.2 Steps

1. Require recent user auth (biometric / OS lock), even when exporting ciphertext only.
2. Prefer **locked export**: pack the last stored sealed blob. Do not unwrap the DEK just to re-encrypt.
3. Build `*.sshclientx` with current `kid`, `generation`, `sender_*`.
4. Present OS Save dialog or share sheet only. No silent upload to Drive.
5. Suggested filename: `{App}-{YYYYMMDD}-{HHmm}-g{generation}.sshclientx`.
6. Delete temp files the app created.
7. Log `generation` and `sha256` prefix (12 hex chars). Never log payload.

### 4.3 Must not

- Embed DEK or passphrase.
- Auto-attach the file to cloud sync as a “convenience copy” from this flow.
- Leave copies under cache/`tmp`.

---

## 5. Import

### 5.1 Trigger

Settings → **Import vault** → system file picker filtered to `.sshclientx` / `application/x-sshclientx`.

### 5.2 Steps

1. Copy the picked file into the app sandbox, then read.
2. Verify `magic == SSHCLTX1`, `format == 1`, `sha256`, then AEAD.
3. Compare `kid` to the local DEK id:
   - **Match:** require biometric/lock; decrypt in RAM.
   - **Unknown `kid`:** do not decrypt. Message: vault was sealed with another device key. Offer pair-key or recovery kit.
4. Generation policy:
   - Remote `generation` > local → normal import.
   - Remote `generation` < local → warn **older vault**; user must confirm.
   - Equal `generation`, different `sha256` → treat as conflict; do not overwrite without keeping the current file.
5. Atomic replace: write `vault.tmp` → fsync → rename. Keep last **5** local generations.
6. Delete picker/cache copies the app controls.
7. Relock DEK when the app backgrounds.

### 5.3 Errors

| Code | User text |
| --- | --- |
| `BOX_BAD_MAGIC` | Not an `.sshclientx` vault file |
| `BOX_UNSUPPORTED` | File version not supported |
| `BOX_CORRUPT` | File damaged or tampered |
| `BOX_UNKNOWN_KEY` | Encrypted for another key |
| `BOX_OLDER` | Older than the vault on this device |
| `BOX_CONFLICT` | Same generation, different content |
| `BOX_AUTH` | Unlock cancelled |

---

## 6. Security constraints

- Treat every exported file as **public** once it leaves the device.
- Recovery kit (raw/wrapped DEK) is a **separate** spec and default **off**.
- Fail closed on any verify error.
- Do not preview vault contents in OS file previews.

---

## 7. Acceptance tests

1. Device A export → USB → device B import (same `kid`) restores identical plaintext after unlock.
2. Opening the file as text does not reveal private key material.
3. Flip one byte → `BOX_CORRUPT`; local vault unchanged.
4. Import of unknown `kid` never writes decrypted secrets.
5. Import of older generation requires explicit confirm and keeps the previous file.

---

## 8. Implementation note

QR transfer and cloud pull **must** call the same verify/import pipeline defined in §5 after bytes land on disk.
