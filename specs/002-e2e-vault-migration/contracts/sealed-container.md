# Contract: Sealed vault container and verification

**Feature**: `002-e2e-vault-migration` | **Date**: 2026-09-06

This is the on-disk and on-the-wire contract. It is normative for FR-009 through FR-012 and
FR-029 through FR-036. Source of truth for the layout is
`docs/features/spec-01-export-import.md` §2.1; this document pins the details that file
leaves open and defines the single verification procedure every transport must use.

**One format only** (FR-010). Export, and later same-network transfer and cloud storage, all
write and read exactly this container. A second sealed format must not be introduced.

---

## 1. Byte layout

All integers little-endian. Offsets are from the start of the file.

| Offset | Size | Field | Value / notes |
| --- | --- | --- | --- |
| 0 | 8 | `magic` | ASCII `SSHCLTX1` |
| 8 | 2 | `format` | u16, currently `1` |
| 10 | 16 | `kid` | Key identifier |
| 26 | 8 | `generation` | u64, the revision counter |
| 34 | 8 | `created_at` | i64, Unix milliseconds |
| 42 | 16 | `sender_id` | Random per device |
| 58 | 2 | `sender_name_len` | u16, byte length, max 255 |
| 60 | *n* | `sender_name` | UTF-8, display only |
| 60+*n* | 1 | `alg` | `1` = XChaCha20-Poly1305, `2` = AES-256-GCM |
| 61+*n* | 24 or 12 | `nonce` | 24 bytes for `alg=1`, 12 for `alg=2` |
| … | 4 | `ciphertext_len` | u32 |
| … | *m* | `ciphertext` | Sealed payload |
| … | 16 | `tag` | AEAD tag |
| … | 32 | `sha256` | SHA-256 of **all** preceding bytes |

`sender_name` is untrusted display text. It must never be used to build a filesystem path,
never be interpreted as markup, and never influence a decision. Reject a `sender_name_len`
above 255 or a non-UTF-8 body as `BOX_CORRUPT`.

### 1.1 Associated data

```
AAD = magic || format || kid || generation
```

Exactly the first 34 bytes. Binding these means altering the key identifier or the revision
counter invalidates the AEAD, which is what makes FR-005 hold.

### 1.2 Payload

The existing zstd-compressed SQLite serialisation, unchanged. This feature replaces the
container, not the contents.

### 1.3 Algorithm selection

Writers emit `alg = 1` (XChaCha20-Poly1305). Readers must accept both `1` and `2`. `alg = 2`
exists so a future constrained platform can write AES-256-GCM without a format break; nothing
in this release writes it.

---

## 2. Format discrimination

A reader is handed bytes and must decide what it is holding, before anything else:

| Test, in order | Result |
| --- | --- |
| first 8 bytes == `SSHCLTX1` | sealed container — continue at §3 |
| first 4 bytes == `OMNV` | legacy vault — legacy path, migrate on unlock (FR-013) |
| otherwise | `BOX_BAD_MAGIC` |

The two magics cannot collide: `OMNV` is 4 bytes and `SSHCLTX1` is 8, and the legacy byte at
offset 4 is a version number, never `L`.

---

## 3. Verification procedure

`verify_and_import(bytes) -> Result` (FR-029). Every route into the app — the import file
picker, the recovery-kit restore, and later QR and cloud — calls this, on bytes already
copied into the app's own storage (FR-030). It never validates one copy and then uses
another.

Checks run **in this order**, and the first failure returns; later checks must not run on
data an earlier check rejected.

| # | Check | Failure outcome |
| --- | --- | --- |
| 1 | Magic per §2 | `BOX_BAD_MAGIC` |
| 2 | `format` is supported | `BOX_UNSUPPORTED` |
| 3 | Length is self-consistent (declared lengths fit the buffer, no trailing slack) | `BOX_CORRUPT` |
| 4 | `sha256` over all preceding bytes matches | `BOX_CORRUPT` |
| 5 | `kid` matches **some** key the device holds, owned or unclaimed (FR-031) | `BOX_UNKNOWN_KEY` |
| 6 | Caller is authorised — identity confirmation per FR-055 | `BOX_AUTH` |
| 7 | AEAD open with the AAD of §1.1 | `BOX_CORRUPT` |
| 8 | Revision policy per §4 | `BOX_OLDER` / `BOX_CONFLICT` |

Step 5 before step 7 is deliberate: a file for a key this device does not hold is never
decrypted (FR-031). Step 4 before step 7 means a truncated or tampered file is reported as
damage rather than as an authentication failure, which is the difference between a message a
user can act on and one they cannot.

### 3.1 Success shape

On success the caller receives the opened payload plus the decided disposition:

| Disposition | When |
| --- | --- |
| `CreateProfile` | `kid` matched an **unclaimed** key (FR-032) |
| `RestoreOver(profile)` | `kid` matched a key owned by `profile` (FR-032a) |
| `NoOp` | same revision, identical content — importing the same file twice |

`CreateProfile` is never offered for a `kid` an existing profile owns; the caller is told
which profile owns it instead.

---

## 4. Revision policy

Comparing incoming `generation` against the target profile's current revision:

| Condition | Outcome |
| --- | --- |
| incoming > local | proceed |
| incoming == local, identical content hash | `NoOp` |
| incoming == local, different content | `BOX_CONFLICT` — never overwrite without a separate explicit choice |
| incoming < local | `BOX_OLDER` — proceed only on explicit confirmation, preserving the newer state as a recoverable revision |

Separately, at **open** time (not import), the profile's own file is compared against the
high-water mark held in the secure store:

| Condition | Outcome |
| --- | --- |
| file revision >= high-water | normal open |
| file revision < high-water | `VAULT_ROLLBACK` (FR-064) |

`VAULT_ROLLBACK` is distinct from `BOX_OLDER`: the former means the file underneath the app
went backwards without an import, the latter means the user is importing an older file
deliberately.

---

## 5. Outcome vocabulary

Every one of these is a distinct, separately worded outcome. They must not be collapsed into
a generic error (FR-036).

### 5.1 File and import outcomes

| Code | Meaning |
| --- | --- |
| `BOX_BAD_MAGIC` | Not a vault file |
| `BOX_UNSUPPORTED` | Format version this release does not understand |
| `BOX_CORRUPT` | Damaged or tampered with |
| `BOX_UNKNOWN_KEY` | Sealed for a key this device does not hold — points at the recovery kit |
| `BOX_OLDER` | Older than the vault on this device |
| `BOX_CONFLICT` | Same revision, different content |
| `BOX_AUTH` | Identity confirmation cancelled |

### 5.2 Vault outcomes

| Code | Meaning |
| --- | --- |
| `VAULT_LOCKED` | Operation needs an unlock |
| `VAULT_AUTH` | Password or platform authentication failed or was cancelled |
| `VAULT_CORRUPT` | Hash or AEAD failed on the local vault |
| `VAULT_UNKNOWN_KID` | Local file is not for any key held here |
| `VAULT_ROLLBACK` | Local file is older than the recorded high-water mark |
| `VAULT_NO_KEYSTORE` | No OS secret store exists at all — terminal (FR-003) |
| `VAULT_KEYSTORE_DENIED` | Secret store exists; this request was denied or is unavailable — **retryable** (FR-003a) |
| `VAULT_KDF` | Password wrap or unwrap failed |
| `VAULT_BUSY` | Profile is already open in another instance (FR-058) |

`VAULT_NO_KEYSTORE` and `VAULT_KEYSTORE_DENIED` are the pair the spec was explicit about:
the first says the machine cannot run the app as configured, the second says a prompt was
dismissed and offers a retry. Collapsing them tells a user who mis-clicked that their
machine is broken.

### 5.3 Recovery-kit outcomes

| Code | Meaning |
| --- | --- |
| `KIT_MALFORMED` | Phrase failed its checksum, or the file is not a kit — raised **before** any recovery-passphrase attempt (FR-019e) |
| `KIT_WRONG_PASSPHRASE` | Kit is intact; this is not the recovery passphrase it was sealed under (FR-019b) |
| `KIT_KID_MISMATCH` | Kit and the supplied vault file are for different keys |

---

## 6. Export filename

```
SSHClientX-{YYYYMMDD}-{HHmm}-g{generation}.sshclientx
```

Suggested in the save dialog only; the user may change it (FR-025). The app must not depend
on a filename it later reads back — `kid` and `generation` inside the file are authoritative.

---

## 7. File type registration

| Property | Value |
| --- | --- |
| Extension | `.sshclientx` (legacy `.submarine` still opens) |
| MIME | `application/x-sshclientx` |
| OS content preview | Must be suppressed (FR-037) |

---

## 8. What must never appear in the file

The vault key, the password, the password-wrapped key, any recovery material (FR-012). A
release build must have no path that writes any of them into a container.
