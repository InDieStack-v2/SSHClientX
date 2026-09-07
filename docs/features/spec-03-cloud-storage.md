# Tech spec 3 — Sync via cloud storage

**Status:** v1  
**Applies to:** desktop app and mobile app  
**Related:** [Export / import](spec-01-export-import.md), [QR same-network](spec-02-qr-same-network.md)

---

## 1. Purpose

Replicate the sealed vault when devices are **not** online at the same time and **not** on the same LAN.

OneDrive or Google Drive stores `*.sshclientx` ciphertext only. The provider is a dumb object store. The DEK never leaves the device keystore.

---

## 2. Non-goals

- Using Drive/OneDrive as a plaintext folder of SSH keys.
- Field-level / CRDT merge of vault contents in v1.
- Sharing links (“anyone with the link”).
- Full-drive OAuth scopes when an app folder exists.

---

## 3. Providers and scopes

| Provider | API | Scope (v1) |
| --- | --- | --- |
| Microsoft OneDrive | Microsoft Graph | `Files.ReadWrite.AppFolder` (or equivalent app-folder) |
| Google Drive | Drive API v3 | `appDataFolder` |

Auth: OAuth 2 with **PKCE**. Refresh token stored in the OS keystore, not in the vault folder.

User can disconnect the account. Cloud sync then disables; local vault and export/import still work.

---

## 4. Remote layout

App folder only (not the user’s visible `Documents` tree unless product later opts in).

```
/vault/current.sshclientx
/vault/meta.json
/vault/revisions/{generation}.sshclientx
```

Keep last **5** remote revisions.

### 4.1 `meta.json`

```json
{
  "kid": "<hex 32 chars>",
  "generation": 14,
  "sha256": "<hex 64 chars>",
  "updated_at": 1756870000000,
  "sender_id": "<hex>",
  "sender_name": "Desktop",
  "format": 1
}
```

Trust **`generation` + `sha256`**, not only `updated_at`.

---

## 5. Local state

| Item | Where |
| --- | --- |
| Current vault | App private store as `.sshclientx` bytes + last import generation |
| DEK | OS keystore (`ThisDeviceOnly`) |
| Cloud eTag | App private store |
| OAuth refresh | OS keystore |
| Push queue | Flag: dirty local generation not yet uploaded |

---

## 6. Push (local newer)

1. Load remote `meta.json` (or 404 = empty).
2. If local `kid` ≠ remote `kid` and remote exists → **do not overwrite**. `CLOUD_FOREIGN_KID`.
3. If local `generation` > remote `generation` (or remote missing):
   - If previous `current.sshclientx` exists, copy it to `revisions/{oldGen}.sshclientx`.
   - Upload local file as `current.sshclientx` with **if-match** eTag when present.
   - Write `meta.json`.
4. If if-match fails → conflict path (§8).
5. Drop oldest revisions beyond 5.

Placeholder / Files On-Demand: upload from a fully local byte copy.

---

## 7. Pull (remote newer)

Triggers: app launch, manual “Sync now”, OS background fetch if enabled.

1. Read `meta.json` via `delta` / `changes.list` or GET.
2. If remote `kid` ≠ local `kid` → `CLOUD_FOREIGN_KID`; keep local.
3. If remote `generation` > local:
   - Download `current.sshclientx` **fully**.
   - Run **import verify** (spec 1 §5): magic `SSHCLTX1`, sha256, AEAD, `kid`.
   - Atomic replace local vault; keep previous generation on disk.
4. If remote `generation` < local → skip pull; consider push.
5. If generations equal and hashes differ → §8.

---

## 8. Conflicts (v1)

| Situation | Action |
| --- | --- |
| Higher `generation` | That side wins |
| Same `generation`, different `sha256` | Keep local as current; save remote as `revisions/conflict-{timestamp}.sshclientx`; notify user |
| Foreign `kid` | Ignore remote for auto-sync |
| Corrupt remote hash/AEAD | `CLOUD_CORRUPT`; keep local |

No automatic merge of SSH key lists in v1.

---

## 9. Security constraints

- Upload **ciphertext only**. Never DEK, `dek.wrap`, passphrase, or OAuth next to the vault objects.
- Disable sharing / link creation on these objects.
- Assume the provider can read bytes, size, and timestamps.
- Background sync still verifies AEAD on device before replacing local vault.
- Refuse to treat a cloud placeholder as a completed download.
- Disconnect account must not delete the local vault.

---

## 10. Errors

| Code | User text / behavior |
| --- | --- |
| `CLOUD_AUTH` | Sign in again |
| `CLOUD_QUOTA` | Stop push; keep local |
| `CLOUD_CONFLICT` | Two files, same generation |
| `CLOUD_FOREIGN_KID` | Cloud file is not for this key |
| `CLOUD_CORRUPT` | Remote file failed verify; local kept |
| `CLOUD_NETWORK` | Retry with backoff |

---

## 11. Acceptance tests

1. Desktop save → upload → phone on another network pulls → same plaintext after unlock (same `kid`).
2. Phone in airplane mode: local vault works; push queues until network returns.
3. Attacker replaces `current.sshclientx` with random bytes → `CLOUD_CORRUPT`; local intact.
4. Attacker uploads an older valid file with lower `generation` → no silent downgrade.
5. OAuth revoke → `CLOUD_AUTH`; secrets still unlock locally.

---

## 12. Implementation note

Cloud download and QR download both finish by calling the same `.sshclientx` import verifier as manual import. One parser, three transports.
