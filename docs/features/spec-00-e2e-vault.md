# Tech spec 0 — End-to-end encrypted vault

**Status:** v1  
**Applies to:** desktop app and mobile app  
**Related:** [Export / import](spec-01-export-import.md) · [QR same-network](spec-02-qr-same-network.md) · [Cloud storage](spec-03-cloud-storage.md)

---

## 1. Purpose

Hold SSH keys and related secrets so that:

- Plaintext exists only in RAM after the user unlocks.
- Disk, export files, QR sessions, and cloud replicas contain **ciphertext only**.
- The data-encryption key (DEK) never leaves the device except via an explicit pairing or recovery flow.
- Google / Microsoft / a stolen `.sshclientx` cannot read keys.

Cloud and QR are transports. They are not the vault.

---

## 2. Threat model

### 2.1 In scope (must resist)

| Threat | Mitigation |
| --- | --- |
| Cloud provider reads stored bytes | AEAD ciphertext; no DEK in object store |
| Stolen `.sshclientx` / USB copy | Same; KDF on wrap if they also steal `dek.wrap` |
| LAN observer during QR transfer | TLS + token; body is already sealed |
| Tamper / bit flip of file | SHA-256 + AEAD fail closed |
| Silent vault downgrade | Monotonic `generation` |
| Accidental iCloud / Android backup of DEK | `ThisDeviceOnly`, `allowBackup=false` |
| Shoulder-surf of QR | QR is session ticket only, 90 s TTL |

### 2.2 Out of scope (accepted)

- Malware on an **unlocked** device
- User screenshots a pairing QR of a wrapped DEK
- Weak passphrase + stolen `dek.wrap` (offline KDF attack)
- Compelled unlock while the app is open

---

## 3. Key hierarchy

```
User passphrase (optional)     Device lock / biometric
         │                              │
         ▼                              ▼
   Argon2id KEK                    OS keystore unwrap
         │                              │
         └──────────┬───────────────────┘
                    ▼
              dek.wrap  ──unwrap──►  DEK (32 bytes)
                                        │
                                        ▼
                                 vault plaintext
                              (only in process memory)
```

| Key | Size | Lifetime | Storage |
| --- | --- | --- | --- |
| **DEK** | 32 bytes CSPRNG | Until lock / process death | OS keystore handle; never a file in the vault folder |
| **KEK** | 32 bytes | Unlock moment only | Derived; wipe after unwrap |
| **Device wrap key** | OS-managed | Device lifetime | Secure Enclave / StrongBox / DPAPI / Keychain |
| **Pairing secret P** | 32 bytes | ≤ 60–120 s, one use | RAM on both devices during pair; then wipe |
| **Recovery kit** | Wrapped DEK or age identity | Offline, user-held | Paper / separate file; default not created |

`kid` = 16-byte identifier derived as `SHA-256(DEK)[0..16)` (or independent random bound to DEK at creation). All `.sshclientx` files carry `kid` so a device refuses foreign ciphertext.

---

## 4. Platform keystore (mandatory)

| Platform | Store | Required flags |
| --- | --- | --- |
| Android | Android Keystore AES-GCM | StrongBox if present; `setUserAuthenticationRequired`; not exported; `allowBackup=false` |
| iOS | Keychain + Secure Enclave | `WhenUnlockedThisDeviceOnly`; `synchronizable = false`; access control biometry or passcode |
| macOS | Keychain | Same as iOS; no iCloud Keychain for DEK |
| Windows | CNG / DPAPI + Credential Manager | User scope; optional Windows Hello |
| Linux | libsecret or kernel keyring | Fail closed if no secret service |

If the OS store is unavailable: **do not persist a raw DEK**. Refuse “save key as key.bin.”

---

## 5. KDF (passphrase wrap)

When a passphrase is enabled:

| Param | v1 value |
| --- | --- |
| Algorithm | Argon2id |
| Salt | 16 bytes CSPRNG, stored next to `dek.wrap` |
| Memory | ≥ 64 MiB |
| Iterations | ≥ 3 |
| Parallelism | 1 (mobile-safe default) |
| Output | 32-byte KEK |

`dek.wrap` = AEAD_encrypt(KEK, DEK) with its own nonce.  
Change passphrase = unwrap DEK with old KEK, wrap with new KEK; DEK itself does not rotate unless the user chooses **Rotate vault key**.

---

## 6. Vault plaintext (inside ciphertext)

Logical document (CBOR preferred; JSON allowed in v1). Schema version `vault_plain = 1`.

```
{
  "vault_plain": 1,
  "updated_at": 1756870000000,
  "items": [
    {
      "id": "<uuid>",
      "type": "ssh_private_key" | "ssh_public_key" | "ssh_config" | "note",
      "label": "github-desktop",
      "algo": "ed25519",
      "private_pem": "...",      // only in RAM after unlock
      "public": "ssh-ed25519 AAAA...",
      "fingerprint": "SHA256:...",
      "comment": ""
    }
  ]
}
```

Rules:

- Prefer **one SSH key pair per device**; synced private keys are backups.
- After unlock, import the active key into `ssh-agent` / platform keystore when possible; do not leave PEM on disk.
- Do not store DEK, OAuth, or cloud refresh tokens in this document.

---

## 7. Sealed package (on disk and on the wire)

Same object as transport specs: `*.sshclientx`.

| Field | Type | Notes |
| --- | --- | --- |
| `magic` | 8 bytes | `SSHCLTX1` |
| `format` | u16 | `1` |
| `kid` | 16 bytes | Bound to DEK |
| `generation` | u64 | +1 on every successful plaintext save |
| `created_at` | i64 | Unix ms |
| `sender_id` | 16 bytes | Random per device |
| `sender_name` | UTF-8 | Display |
| `alg` | u8 | `1` XChaCha20-Poly1305 (preferred), `2` AES-256-GCM |
| `nonce` | 24 or 12 bytes | Unique per seal |
| `ciphertext` | bytes | Encrypted §6 document |
| `tag` | 16 bytes | AEAD |
| `sha256` | 32 bytes | Hash of all prior bytes |

**AAD** = `magic || format || kid || generation`.

Libraries: libsodium / Tink / platform AEAD. No homegrown XOR.

Local working copy lives in app sandbox as `current.sshclientx` plus `revisions/` (last 5).

---

## 8. Lifecycle

### 8.1 Create vault

1. CSPRNG DEK → insert into OS keystore.  
2. Compute `kid`.  
3. Optional: wrap DEK with Argon2id(passphrase) → `dek.wrap`.  
4. Seal empty item list → `generation = 1`.  
5. Prompt optional recovery kit (default skip).

### 8.2 Unlock

1. Biometric / lock screen / passphrase.  
2. Unwrap DEK into memory (or keystore handle).  
3. AEAD-open `current.sshclientx`.  
4. Fail closed on tag or hash mismatch.  
5. Wipe KEK and passphrase buffers.

### 8.3 Save

1. Must be unlocked.  
2. `generation += 1`.  
3. New nonce; seal; write temp → fsync → rename.  
4. Rotate local revisions (keep 5).  
5. Mark dirty for cloud push if cloud enabled.

### 8.4 Lock

- On background, screen off, idle timeout, or explicit lock.  
- Drop DEK from process memory.  
- UI shows locked vault; no item preview.

### 8.5 Rotate DEK

Explicit setting. Generate new DEK + `kid`. Re-seal. Old `.sshclientx` files with previous `kid` become import-blocked until the user still holds the old key. Pair other devices again.

---

## 9. Pairing another device (DEK agree)

Not part of daily QR file transfer.

1. Device A holds DEK. Generate one-time `P`.  
2. QR (≤ 60–120 s): `pair | kid | wrap(DEK, P) | fp(DEK)`.  
3. Both screens show `fp`. User confirms.  
4. Device B unwraps, imports DEK into **B’s** keystore, wraps with B’s device key + optional passphrase.  
5. Burn `P`.  
6. After this, A and B can exchange `.sshclientx` via QR-LAN, cloud, or export.

`FLAG_SECURE` on this screen. Never loop this QR. Never upload wrap(DEK, P) to Drive.

---

## 10. How the three transports use the vault

| Transport | Moves | Needs same `kid` | Needs both online |
| --- | --- | --- | --- |
| Export / import `.sshclientx` | Sealed file | Yes to decrypt | No |
| QR same LAN | Sealed file over HTTPS | Yes to decrypt | Yes, same network |
| Cloud app folder | Sealed `current.sshclientx` | Yes to decrypt | No |

One function: `verify_and_import(bytes) → Result`.  
Checks magic, format, sha256, AEAD, `kid`, generation policy. Used by all three.

---

## 11. Security requirements (normative)

1. DEK is never written next to the vault file, never logged, never put in crash reports.  
2. Secrets are not stored in `String` on JVM/Android if avoidable; wipe buffers.  
3. Pairing and QR ticket screens block screenshots.  
4. Import of unknown `kid` does not decrypt.  
5. Equal `generation` + different hash = conflict; do not clobber.  
6. Lower `generation` = no silent downgrade.  
7. Recovery kit is opt-in and offline.  
8. Per-device SSH keys preferred; revoke `authorized_keys` on lost device.  
9. Debug builds may have an “export DEK” switch; release builds must not.

---

## 12. Errors

| Code | Meaning |
| --- | --- |
| `VAULT_LOCKED` | Operation needs unlock |
| `VAULT_AUTH` | Biometric / passphrase cancelled or failed |
| `VAULT_CORRUPT` | Hash or AEAD failed |
| `VAULT_UNKNOWN_KID` | Ciphertext not for this DEK |
| `VAULT_DOWNGRADE` | Older generation |
| `VAULT_NO_KEYSTORE` | OS secret store missing; refuse persist |
| `VAULT_KDF` | Passphrase wrap failed |

---

## 13. Acceptance tests

1. Create vault → lock → unlock → plaintext matches.  
2. Copy `current.sshclientx` off device; without DEK it does not decrypt.  
3. Flip one byte of file → `VAULT_CORRUPT`; previous revision still opens.  
4. Pair B via QR wrap; B opens a file exported from A.  
5. Cloud-only replica of `.sshclientx` does not contain PEM substrings `BEGIN OPENSSH PRIVATE KEY`.  
6. After lock, heap dump of a release build must not contain the DEK as a contiguous 32-byte value that still unwraps the file (best-effort; document limitation).  
7. Factory reset of phone: DEK gone (`ThisDeviceOnly`); old cloud file will not open until recovery or re-pair.

---

## 14. Implementation notes

- Preferred AEAD: XChaCha20-Poly1305 (`alg = 1`).  
- Preferred KDF: Argon2id as specified.  
- Preferred interchange: same `*.sshclientx` as specs 1–3.  
- Do not invent a second sealed format for cloud vs export.
