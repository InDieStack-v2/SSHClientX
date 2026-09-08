//! End-to-end encrypted vault (spec 002-e2e-vault-migration).
//!
//! Owns the `SSHCLTX1` sealed container (read + write), the single
//! `verify_and_import` pipeline every transport routes through, migration
//! from the legacy `OMNV` password-derived format, the per-vault revision
//! counter and five-deep local history, rollback detection against a
//! high-water mark held in the OS secure store, and the per-profile writer
//! claim.
//!
//! See `specs/002-e2e-vault-migration/contracts/sealed-container.md` for the
//! normative byte layout and verification order this module implements.

/// Every distinct outcome this module (and the commands built on it) can
/// report. Per FR-036, these must never collapse into a generic error — the
/// renderer switches on `code()`, never parses the message.
///
/// Grouped exactly as `contracts/sealed-container.md` §5 groups them:
/// file/import outcomes, vault outcomes, recovery-kit outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    // --- §5.1 File and import outcomes ---
    /// Not a vault file at all (bad magic on both the sealed and legacy check).
    BoxBadMagic,
    /// A `format` version this build does not understand.
    BoxUnsupported,
    /// Damaged or tampered — hash mismatch, truncation, or AEAD failure.
    BoxCorrupt,
    /// Sealed for a key this device does not hold, owned or unclaimed.
    BoxUnknownKey,
    /// Older than the local vault; requires explicit confirmation to accept.
    BoxOlder,
    /// Same revision, different content; requires a separate explicit choice.
    BoxConflict,
    /// Identity confirmation was cancelled before decryption.
    BoxAuth,

    // --- §5.2 Vault outcomes ---
    /// Operation needs an unlock first.
    VaultLocked,
    /// Password or platform authentication failed or was cancelled.
    VaultAuth,
    /// Hash or AEAD failed on the local (not imported) vault.
    VaultCorrupt,
    /// The local file is not for any key held on this device.
    VaultUnknownKid,
    /// The local file's revision is lower than the recorded high-water mark.
    VaultRollback,
    /// No OS secret store exists at all. Terminal — refuse to create,
    /// migrate, or save (FR-003).
    VaultNoKeystore,
    /// A secret store exists but this one request was denied or is
    /// temporarily unavailable. Retryable (FR-003a).
    VaultKeystoreDenied,
    /// Password wrap or unwrap failed.
    VaultKdf,
    /// The profile is already open for writing in another running instance.
    VaultBusy,

    // --- §5.3 Recovery-kit outcomes ---
    /// The recovery phrase failed its checksum, or the file is not a kit.
    /// Raised before any passphrase attempt (FR-019e).
    KitMalformed,
    /// The kit is intact; this is not the recovery passphrase it was sealed
    /// under (FR-019b).
    KitWrongPassphrase,
    /// The kit and the supplied vault file are for different keys.
    KitKidMismatch,
}

impl Outcome {
    /// Stable machine-readable code. The renderer matches on this string,
    /// never on `message()`.
    pub const fn code(self) -> &'static str {
        match self {
            Outcome::BoxBadMagic => "BOX_BAD_MAGIC",
            Outcome::BoxUnsupported => "BOX_UNSUPPORTED",
            Outcome::BoxCorrupt => "BOX_CORRUPT",
            Outcome::BoxUnknownKey => "BOX_UNKNOWN_KEY",
            Outcome::BoxOlder => "BOX_OLDER",
            Outcome::BoxConflict => "BOX_CONFLICT",
            Outcome::BoxAuth => "BOX_AUTH",
            Outcome::VaultLocked => "VAULT_LOCKED",
            Outcome::VaultAuth => "VAULT_AUTH",
            Outcome::VaultCorrupt => "VAULT_CORRUPT",
            Outcome::VaultUnknownKid => "VAULT_UNKNOWN_KID",
            Outcome::VaultRollback => "VAULT_ROLLBACK",
            Outcome::VaultNoKeystore => "VAULT_NO_KEYSTORE",
            Outcome::VaultKeystoreDenied => "VAULT_KEYSTORE_DENIED",
            Outcome::VaultKdf => "VAULT_KDF",
            Outcome::VaultBusy => "VAULT_BUSY",
            Outcome::KitMalformed => "KIT_MALFORMED",
            Outcome::KitWrongPassphrase => "KIT_WRONG_PASSPHRASE",
            Outcome::KitKidMismatch => "KIT_KID_MISMATCH",
        }
    }

    /// Plain-language message for the outcome, with no vault content, path,
    /// hostname, or credential ever interpolated into it (FR-068).
    pub const fn message(self) -> &'static str {
        match self {
            Outcome::BoxBadMagic => "Selected file is not a SSHClientX vault.",
            Outcome::BoxUnsupported => {
                "This vault uses a format version this app doesn't understand yet. Update SSHClientX."
            }
            Outcome::BoxCorrupt => "File is damaged or has been tampered with.",
            Outcome::BoxUnknownKey => {
                "This vault was sealed with another device's key. Use a recovery kit to open it here."
            }
            Outcome::BoxOlder => "This file is older than the vault already on this device.",
            Outcome::BoxConflict => {
                "This file is the same age as the local vault but the contents differ."
            }
            Outcome::BoxAuth => "Cancelled.",
            Outcome::VaultLocked => "Vault is locked. Unlock it first.",
            Outcome::VaultAuth => "Wrong password, or authentication was cancelled.",
            Outcome::VaultCorrupt => "Vault file is damaged or has been tampered with.",
            Outcome::VaultUnknownKid => "This vault is not for any key held on this device.",
            Outcome::VaultRollback => {
                "This vault file is older than the last one this device saved. It may have been restored from a backup."
            }
            Outcome::VaultNoKeystore => {
                #[cfg(target_os = "macos")]
                {
                    "macOS Keychain is not available. Unlock your login keychain in Keychain Access, then try again. SSHClientX cannot create or open a vault without it."
                }
                #[cfg(target_os = "windows")]
                {
                    "Windows Credential Manager is not available in this session. Sign in with a local user account. SSHClientX cannot create or open a vault without it."
                }
                #[cfg(target_os = "android")]
                {
                    "Android Keystore is not available on this device. SSHClientX cannot create or open a vault without it."
                }
                #[cfg(all(unix, not(any(target_os = "macos", target_os = "android"))))]
                {
                    "No Secret Service provider is available. Install and start GNOME Keyring or KWallet, then try again. SSHClientX cannot create or open a vault without one."
                }
            }
            Outcome::VaultKeystoreDenied => {
                "The secure credential store declined this request. Try again."
            }
            Outcome::VaultKdf => "Could not derive the vault key from the password.",
            Outcome::VaultBusy => "This profile is already open in another running copy of the app.",
            Outcome::KitMalformed => "This isn't a valid recovery phrase or recovery file.",
            Outcome::KitWrongPassphrase => "Wrong recovery passphrase for this kit.",
            Outcome::KitKidMismatch => "This recovery kit does not match the supplied vault file.",
        }
    }
}

impl std::fmt::Display for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code(), self.message())
    }
}

impl std::error::Error for Outcome {}

#[cfg(test)]
mod outcome_tests {
    use super::*;

    #[test]
    fn every_outcome_has_a_distinct_code_and_nonempty_message() {
        let all = [
            Outcome::BoxBadMagic, Outcome::BoxUnsupported, Outcome::BoxCorrupt,
            Outcome::BoxUnknownKey, Outcome::BoxOlder, Outcome::BoxConflict, Outcome::BoxAuth,
            Outcome::VaultLocked, Outcome::VaultAuth, Outcome::VaultCorrupt,
            Outcome::VaultUnknownKid, Outcome::VaultRollback, Outcome::VaultNoKeystore,
            Outcome::VaultKeystoreDenied, Outcome::VaultKdf, Outcome::VaultBusy,
            Outcome::KitMalformed, Outcome::KitWrongPassphrase, Outcome::KitKidMismatch,
        ];
        let mut codes: Vec<&str> = all.iter().map(|o| o.code()).collect();
        let before = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), before, "duplicate outcome code found");
        for o in all {
            assert!(!o.message().is_empty());
        }
    }

    #[test]
    fn no_keystore_and_keystore_denied_are_distinct_outcomes() {
        // FR-003 vs FR-003a: collapsing these tells a user who dismissed a
        // prompt that their machine can't run the app.
        assert_ne!(Outcome::VaultNoKeystore.code(), Outcome::VaultKeystoreDenied.code());
        assert_ne!(Outcome::VaultNoKeystore.message(), Outcome::VaultKeystoreDenied.message());
    }

    #[test]
    fn rollback_is_distinct_from_older_and_corrupt() {
        assert_ne!(Outcome::VaultRollback.code(), Outcome::BoxOlder.code());
        assert_ne!(Outcome::VaultRollback.code(), Outcome::VaultCorrupt.code());
    }

    #[test]
    fn kit_malformed_is_distinct_from_wrong_passphrase() {
        // FR-019e: a mistranscribed phrase must be reported before any
        // passphrase attempt, distinctly from a wrong passphrase.
        assert_ne!(Outcome::KitMalformed.code(), Outcome::KitWrongPassphrase.code());
    }
}

// ---------------------------------------------------------------------------
// Legacy format (magic `OMNV`): password-derived key, AES-256-GCM only.
//
// Moved here verbatim from lib.rs (T008) — behavior is unchanged. This is
// read-only from the app's perspective once migration exists: a legacy vault
// is decrypted with these functions, then re-sealed into the new container
// (see migration, below) and never written in this format again.
// ---------------------------------------------------------------------------

pub(crate) const LEGACY_MAGIC: &[u8; 4] = b"OMNV";
pub(crate) const LEGACY_VERSION: u8 = 1;
pub(crate) const LEGACY_SALT_LEN: usize = 16;
/// Nonce length for the legacy format specifically. Fixed forever at 12
/// bytes because every `OMNV` file ever written used AES-256-GCM — this is
/// NOT the same constant as the new sealed container's nonce length, which
/// varies by algorithm (see `SEALED_NONCE_LEN`, T014).
pub(crate) const LEGACY_NONCE_LEN: usize = 12;
pub(crate) const LEGACY_HEADER_LEN: usize = 4 + 1 + LEGACY_SALT_LEN;

pub(crate) const LEGACY_ARGON2_M_COST: u32 = 64 * 1024;
pub(crate) const LEGACY_ARGON2_T_COST: u32 = 3;
pub(crate) const LEGACY_ARGON2_P_COST: u32 = 4;

/// Derive the legacy AES-256-GCM key directly from the password. This is
/// exactly the property the new format removes — kept only so an unmigrated
/// vault can still be opened and then migrated.
pub(crate) fn legacy_derive_key(password: &str, salt_bytes: &[u8]) -> Result<[u8; 32], String> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(
        LEGACY_ARGON2_M_COST,
        LEGACY_ARGON2_T_COST,
        LEGACY_ARGON2_P_COST,
        Some(32),
    )
    .map_err(|e| format!("[CRYPTO] ARGON2_PARAMS: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt_bytes, &mut key)
        .map_err(|e| format!("[CRYPTO] HASH_FAILED: {}", e))?;
    Ok(key)
}

#[cfg(test)]
pub(crate) fn legacy_encrypt(plaintext: &[u8], key: &[u8; 32]) -> Result<(Vec<u8>, [u8; LEGACY_NONCE_LEN]), String> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
    let cipher = Aes256Gcm::new(key.into());
    let mut nonce_bytes = [0u8; LEGACY_NONCE_LEN];
    rand::thread_rng().fill(&mut nonce_bytes[..]);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("[CRYPTO] ENCRYPT_FAILED: {}", e))?;
    Ok((ciphertext, nonce_bytes))
}

pub(crate) fn legacy_decrypt(
    ciphertext: &[u8],
    nonce_bytes: &[u8],
    key: &[u8; 32],
) -> Result<Vec<u8>, String> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
    if nonce_bytes.len() != LEGACY_NONCE_LEN {
        return Err("[CRYPTO] NONCE_LEN_INVALID".into());
    }
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ciphertext).map_err(|e| {
        format!(
            "[CRYPTO] DECRYPT_FAILURE: Possible wrong key or corrupted data. Details: {}",
            e
        )
    })
}

/// Returns (salt, nonce, ciphertext) parsed out of a legacy on-disk blob.
pub(crate) fn legacy_parse_blob(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
    if data.len() < LEGACY_HEADER_LEN + LEGACY_NONCE_LEN {
        return Err("[VAULT] INVALID_FORMAT: Data too short".into());
    }
    if &data[..4] != LEGACY_MAGIC {
        return Err("[VAULT] BAD_MAGIC".into());
    }
    if data[4] != LEGACY_VERSION {
        return Err(format!("[VAULT] UNSUPPORTED_VERSION: {}", data[4]));
    }
    let salt = data[5..5 + LEGACY_SALT_LEN].to_vec();
    let nonce = data[LEGACY_HEADER_LEN..LEGACY_HEADER_LEN + LEGACY_NONCE_LEN].to_vec();
    let ct = data[LEGACY_HEADER_LEN + LEGACY_NONCE_LEN..].to_vec();
    Ok((salt, nonce, ct))
}

#[cfg(test)]
pub(crate) fn legacy_write_blob(salt: &[u8; LEGACY_SALT_LEN], nonce: &[u8; LEGACY_NONCE_LEN], ciphertext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(LEGACY_HEADER_LEN + LEGACY_NONCE_LEN + ciphertext.len());
    out.extend_from_slice(LEGACY_MAGIC);
    out.push(LEGACY_VERSION);
    out.extend_from_slice(salt);
    out.extend_from_slice(nonce);
    out.extend_from_slice(ciphertext);
    out
}

/// True if `data` starts with the legacy `OMNV` magic. Used by format
/// discrimination (T013) before the sealed-container check.
pub(crate) fn is_legacy_blob(data: &[u8]) -> bool {
    data.len() >= 4 && &data[..4] == LEGACY_MAGIC
}

pub(crate) fn vault_compress(plaintext: &[u8]) -> Result<Vec<u8>, String> {
    const VAULT_COMPRESS_LEVEL: i32 = 3;
    zstd::stream::encode_all(plaintext, VAULT_COMPRESS_LEVEL)
        .map_err(|e| format!("[VAULT] COMPRESS_FAILED: {}", e))
}

pub(crate) fn vault_decompress(compressed: &[u8]) -> Result<Vec<u8>, String> {
    const MAX_DECOMPRESSED: usize = 64 * 1024 * 1024;
    let mut out = Vec::new();
    let mut decoder = zstd::stream::Decoder::new(compressed)
        .map_err(|e| format!("[VAULT] DECOMPRESS_INIT_FAILED: {}", e))?;
    use std::io::Read;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = decoder
            .read(&mut buf)
            .map_err(|e| format!("[VAULT] DECOMPRESS_FAILED: {}", e))?;
        if n == 0 {
            break;
        }
        if out.len() + n > MAX_DECOMPRESSED {
            return Err("[VAULT] DECOMPRESS_TOO_LARGE: refusing to inflate past 64 MiB".into());
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Sealed container (magic `SSHCLTX1`).
//
// Byte layout, verification order, and outcome mapping are normative in
// `specs/002-e2e-vault-migration/contracts/sealed-container.md`. This is the
// ONE sealed format (FR-010) — export, local storage, and every future
// transport read and write exactly this.
// ---------------------------------------------------------------------------

pub const SEALED_MAGIC: &[u8; 8] = b"SSHCLTX1";
pub const SEALED_FORMAT: u16 = 1;
pub const KID_LEN: usize = 16;
pub const SENDER_ID_LEN: usize = 16;
pub const TAG_LEN: usize = 16;
pub const SHA256_LEN: usize = 32;
/// Cap on `sender_name`'s byte length. `sender_name` is untrusted display
/// text — never used to build a path, never interpreted as markup, never a
/// decision input. A length above this, or a non-UTF-8 body, is `BOX_CORRUPT`.
pub const SENDER_NAME_MAX_LEN: usize = 255;

/// Algorithm byte. `XChaCha20Poly1305` (1) is what every writer in this
/// release emits; `Aes256Gcm` (2) exists so a future constrained platform
/// can write it without a format break (contracts §1.3) — nothing here
/// writes it yet, but readers must accept it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealAlg {
    XChaCha20Poly1305 = 1,
    Aes256Gcm = 2,
}

impl SealAlg {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(SealAlg::XChaCha20Poly1305),
            2 => Some(SealAlg::Aes256Gcm),
            _ => None,
        }
    }

    fn as_byte(self) -> u8 {
        self as u8
    }

    /// Nonce length for this algorithm. This is what T014 replaces the old
    /// fixed `NONCE_LEN` constant with — the sealed container's nonce length
    /// is a function of `alg`, not a single global constant, because unlike
    /// the legacy format this container is designed to carry more than one
    /// cipher over its lifetime.
    pub const fn nonce_len(self) -> usize {
        match self {
            SealAlg::XChaCha20Poly1305 => 24,
            SealAlg::Aes256Gcm => 12,
        }
    }
}

/// One seal/open operation's key material and algorithm choice. Callers
/// (vault save/load, migration, export, import) construct this once and
/// pass it through; it never crosses the Tauri IPC boundary.
pub struct SealKey<'a> {
    pub alg: SealAlg,
    pub key: &'a [u8; 32],
}

/// AEAD-seal `plaintext` under `key.alg`/`key.key`, binding `aad`. Returns
/// (nonce, ciphertext_without_tag, tag) — the three fields the wire format
/// keeps separate (contracts §1).
fn seal_generic(key: &SealKey, aad: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>, [u8; TAG_LEN]), String> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    let nonce_len = key.alg.nonce_len();
    let mut nonce = vec![0u8; nonce_len];
    rand::thread_rng().fill(&mut nonce[..]);

    let combined = match key.alg {
        SealAlg::XChaCha20Poly1305 => {
            use chacha20poly1305::{XChaCha20Poly1305, XNonce};
            let cipher = XChaCha20Poly1305::new(key.key.into());
            let n = XNonce::from_slice(&nonce);
            cipher
                .encrypt(n, Payload { msg: plaintext, aad })
                .map_err(|e| format!("[CRYPTO] SEAL_FAILED: {}", e))?
        }
        SealAlg::Aes256Gcm => {
            use aes_gcm::{Aes256Gcm, Nonce};
            let cipher = Aes256Gcm::new(key.key.into());
            let n = Nonce::from_slice(&nonce);
            cipher
                .encrypt(n, Payload { msg: plaintext, aad })
                .map_err(|e| format!("[CRYPTO] SEAL_FAILED: {}", e))?
        }
    };

    if combined.len() < TAG_LEN {
        return Err("[CRYPTO] SEAL_OUTPUT_TOO_SHORT".into());
    }
    let split_at = combined.len() - TAG_LEN;
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&combined[split_at..]);
    let ciphertext = combined[..split_at].to_vec();
    Ok((nonce, ciphertext, tag))
}

/// Reassemble ciphertext+tag and AEAD-open under `key.alg`/`key.key`,
/// verifying `aad`. Step 7 of the verification procedure — must only be
/// reached after the `kid` check (step 5) and the hash check (step 4) pass.
fn open_generic(
    key: &SealKey,
    aad: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    tag: &[u8; TAG_LEN],
) -> Result<Vec<u8>, ()> {
    // Plain `()` on failure deliberately: this primitive serves two
    // different callers (the container's `open`, and `KeyWrapFile::unwrap_dek`)
    // that need DIFFERENT business-outcome mappings for an AEAD failure —
    // `BoxCorrupt` for a tampered container, `VaultAuth`/`VaultKdf` for a
    // wrong password. The mapping is each caller's job, not this one's.
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    if nonce.len() != key.alg.nonce_len() {
        return Err(());
    }
    let mut combined = Vec::with_capacity(ciphertext.len() + TAG_LEN);
    combined.extend_from_slice(ciphertext);
    combined.extend_from_slice(tag);

    let result = match key.alg {
        SealAlg::XChaCha20Poly1305 => {
            use chacha20poly1305::{XChaCha20Poly1305, XNonce};
            let cipher = XChaCha20Poly1305::new(key.key.into());
            let n = XNonce::from_slice(nonce);
            cipher.decrypt(n, Payload { msg: &combined, aad })
        }
        SealAlg::Aes256Gcm => {
            use aes_gcm::{Aes256Gcm, Nonce};
            let cipher = Aes256Gcm::new(key.key.into());
            let n = Nonce::from_slice(nonce);
            cipher.decrypt(n, Payload { msg: &combined, aad })
        }
    };
    result.map_err(|_| ())
}

use rand::Rng;

/// A parsed (or about-to-be-written) `SSHCLTX1` container. Field names match
/// `data-model.md` §2.4; wire names match `contracts/sealed-container.md`.
#[derive(Debug, Clone)]
pub struct SealedVaultFile {
    pub format: u16,
    pub kid: [u8; KID_LEN],
    pub generation: u64,
    pub created_at: i64,
    pub sender_id: [u8; SENDER_ID_LEN],
    pub sender_name: String,
    pub alg: SealAlg,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub tag: [u8; TAG_LEN],
}

impl SealedVaultFile {
    /// Associated data bound into the AEAD: `magic || format || kid ||
    /// generation`, exactly 34 bytes (contracts §1.1). Binding these means
    /// altering the key identifier or the revision invalidates the seal.
    fn aad(kid: &[u8; KID_LEN], generation: u64, format: u16) -> [u8; 8 + 2 + KID_LEN + 8] {
        let mut aad = [0u8; 8 + 2 + KID_LEN + 8];
        aad[0..8].copy_from_slice(SEALED_MAGIC);
        aad[8..10].copy_from_slice(&format.to_le_bytes());
        aad[10..10 + KID_LEN].copy_from_slice(kid);
        aad[10 + KID_LEN..].copy_from_slice(&generation.to_le_bytes());
        aad
    }

    /// Seal `plaintext` (already compressed) into a new container. Generates
    /// a fresh nonce every call — callers must never reuse a `SealedVaultFile`
    /// across two different plaintexts.
    pub fn seal(
        key: &SealKey,
        kid: [u8; KID_LEN],
        generation: u64,
        sender_id: [u8; SENDER_ID_LEN],
        sender_name: &str,
        plaintext: &[u8],
    ) -> Result<Self, String> {
        if sender_name.len() > SENDER_NAME_MAX_LEN {
            return Err("[VAULT] SENDER_NAME_TOO_LONG".into());
        }
        let aad = Self::aad(&kid, generation, SEALED_FORMAT);
        let (nonce, ciphertext, tag) = seal_generic(key, &aad, plaintext)?;
        Ok(SealedVaultFile {
            format: SEALED_FORMAT,
            kid,
            generation,
            created_at: current_unix_millis(),
            sender_id,
            sender_name: sender_name.to_string(),
            alg: key.alg,
            nonce,
            ciphertext,
            tag,
        })
    }

    /// Serialize per the wire layout in contracts §1, ending with the
    /// SHA-256 trailer over everything before it.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(SEALED_MAGIC);
        out.extend_from_slice(&self.format.to_le_bytes());
        out.extend_from_slice(&self.kid);
        out.extend_from_slice(&self.generation.to_le_bytes());
        out.extend_from_slice(&self.created_at.to_le_bytes());
        out.extend_from_slice(&self.sender_id);
        let name_bytes = self.sender_name.as_bytes();
        out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(name_bytes);
        out.push(self.alg.as_byte());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&(self.ciphertext.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&self.tag);
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(&out);
        out.extend_from_slice(&hash);
        out
    }

    /// Parse and structurally validate a buffer as a sealed container,
    /// WITHOUT opening the AEAD (that is step 7 of `verify_and_import`, a
    /// separate call). Checks: magic, format, declared-length
    /// self-consistency (no trailing slack), `sender_name` length/UTF-8, and
    /// the trailing SHA-256. Returns `BOX_BAD_MAGIC` / `BOX_UNSUPPORTED` /
    /// `BOX_CORRUPT` on the relevant failure — never reaches decryption.
    pub fn parse(data: &[u8]) -> Result<Self, Outcome> {
        const FIXED_PREFIX: usize = 8 + 2 + KID_LEN + 8 + SENDER_ID_LEN; // through sender_id
        if data.len() < 8 || &data[0..8] != SEALED_MAGIC.as_slice() {
            return Err(Outcome::BoxBadMagic);
        }
        if data.len() < FIXED_PREFIX + 2 {
            return Err(Outcome::BoxCorrupt);
        }
        let format = u16::from_le_bytes([data[8], data[9]]);
        if format != SEALED_FORMAT {
            return Err(Outcome::BoxUnsupported);
        }
        let mut kid = [0u8; KID_LEN];
        kid.copy_from_slice(&data[10..10 + KID_LEN]);
        let gen_start = 10 + KID_LEN;
        let generation = u64::from_le_bytes(data[gen_start..gen_start + 8].try_into().unwrap());
        let created_start = gen_start + 8;
        let created_at = i64::from_le_bytes(data[created_start..created_start + 8].try_into().unwrap());
        let sender_id_start = created_start + 8;
        let mut sender_id = [0u8; SENDER_ID_LEN];
        sender_id.copy_from_slice(&data[sender_id_start..sender_id_start + SENDER_ID_LEN]);

        let name_len_start = sender_id_start + SENDER_ID_LEN;
        if data.len() < name_len_start + 2 {
            return Err(Outcome::BoxCorrupt);
        }
        let name_len = u16::from_le_bytes([data[name_len_start], data[name_len_start + 1]]) as usize;
        if name_len > SENDER_NAME_MAX_LEN {
            return Err(Outcome::BoxCorrupt);
        }
        let name_start = name_len_start + 2;
        if data.len() < name_start + name_len {
            return Err(Outcome::BoxCorrupt);
        }
        let sender_name = std::str::from_utf8(&data[name_start..name_start + name_len])
            .map_err(|_| Outcome::BoxCorrupt)?
            .to_string();

        let alg_pos = name_start + name_len;
        if data.len() < alg_pos + 1 {
            return Err(Outcome::BoxCorrupt);
        }
        let alg = SealAlg::from_byte(data[alg_pos]).ok_or(Outcome::BoxCorrupt)?;
        let nonce_len = alg.nonce_len();
        let nonce_start = alg_pos + 1;
        if data.len() < nonce_start + nonce_len + 4 {
            return Err(Outcome::BoxCorrupt);
        }
        let nonce = data[nonce_start..nonce_start + nonce_len].to_vec();

        let ct_len_pos = nonce_start + nonce_len;
        let ciphertext_len =
            u32::from_le_bytes(data[ct_len_pos..ct_len_pos + 4].try_into().unwrap()) as usize;
        let ct_start = ct_len_pos + 4;
        let tag_start = ct_start.checked_add(ciphertext_len).ok_or(Outcome::BoxCorrupt)?;
        let hash_start = tag_start.checked_add(TAG_LEN).ok_or(Outcome::BoxCorrupt)?;
        let end = hash_start.checked_add(SHA256_LEN).ok_or(Outcome::BoxCorrupt)?;
        // Declared lengths must exactly consume the buffer — no trailing
        // slack, which would let an attacker append garbage a naive parser
        // ignores (contracts §3 check 3).
        if data.len() != end {
            return Err(Outcome::BoxCorrupt);
        }

        let ciphertext = data[ct_start..tag_start].to_vec();
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&data[tag_start..tag_start + TAG_LEN]);

        use sha2::{Digest, Sha256};
        let computed = Sha256::digest(&data[..hash_start]);
        if computed.as_slice() != &data[hash_start..end] {
            return Err(Outcome::BoxCorrupt);
        }

        Ok(SealedVaultFile {
            format,
            kid,
            generation,
            created_at,
            sender_id,
            sender_name,
            alg,
            nonce,
            ciphertext,
            tag,
        })
    }

    /// Step 7 of `verify_and_import`: AEAD-open this container's ciphertext
    /// under `key`. Must only be called after `parse` succeeded and the
    /// `kid` has already been matched against a held key (step 5) — never
    /// call this against a key whose `kid` doesn't match.
    pub fn open(&self, key: &SealKey) -> Result<Vec<u8>, Outcome> {
        let aad = Self::aad(&self.kid, self.generation, self.format);
        open_generic(key, &aad, &self.nonce, &self.ciphertext, &self.tag)
            .map_err(|()| Outcome::BoxCorrupt)
    }
}

fn current_unix_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Format discrimination (contracts §2): the sealed magic first, then the
/// legacy magic, then refuse. The two cannot collide — `OMNV` is 4 bytes and
/// the legacy byte at offset 4 is a version number, never `L` (the 5th byte
/// of `SSHCLTX1`).
pub enum DiscriminatedFormat {
    Sealed,
    Legacy,
    Unknown,
}

pub fn discriminate_format(data: &[u8]) -> DiscriminatedFormat {
    if data.len() >= 8 && &data[0..8] == SEALED_MAGIC.as_slice() {
        DiscriminatedFormat::Sealed
    } else if is_legacy_blob(data) {
        DiscriminatedFormat::Legacy
    } else {
        DiscriminatedFormat::Unknown
    }
}

/// Derive the 16-byte key identifier from a vault key (data-model.md §2.2).
/// `SHA-256(DEK)[0..16)`. Public: appears in every sealed file; its only job
/// is answering "could this device possibly open this file?" before any
/// decryption is attempted.
pub fn derive_kid(dek: &[u8; 32]) -> [u8; KID_LEN] {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(dek);
    let mut kid = [0u8; KID_LEN];
    kid.copy_from_slice(&hash[..KID_LEN]);
    kid
}

/// Generate a fresh random per-device sender identifier (FR-011). MUST NOT
/// be derived from a hardware serial or anything else that would survive a
/// reinstall — see `sync_device_node_id` in lib.rs for the existing analogous
/// idiom this mirrors (a random id in a device-local sidecar file, outside
/// the vault so it never travels with it).
pub fn generate_sender_id() -> [u8; SENDER_ID_LEN] {
    let mut id = [0u8; SENDER_ID_LEN];
    rand::thread_rng().fill(&mut id[..]);
    id
}

// ---------------------------------------------------------------------------
// Diagnostics (T107-T109, data-model.md §2.11, FR-067/068/069/070)
// ---------------------------------------------------------------------------

/// A local-only diagnostic record. Deliberately has no field CAPABLE of
/// holding a hostname, file path, user-chosen filename, username,
/// credential, recovery-phrase word, or vault content (FR-068) — the
/// exclusion list is enforced by this type's shape, not by a runtime
/// filter that a future field could quietly bypass.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DiagnosticEntry {
    pub outcome_code: String,
    pub timestamp: i64,
    pub local_revision: Option<u64>,
    pub incoming_revision: Option<u64>,
    /// Short hex prefix (4 bytes) of a `kid` — never the full identifier,
    /// and never the key itself (FR-002).
    pub kid_prefix: Option<String>,
    /// Short hex prefix (4 bytes) of the involved file's content hash.
    pub hash_prefix: Option<String>,
}

impl DiagnosticEntry {
    pub fn new(outcome_code: &str) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        Self {
            outcome_code: outcome_code.to_string(),
            timestamp,
            local_revision: None,
            incoming_revision: None,
            kid_prefix: None,
            hash_prefix: None,
        }
    }

    #[must_use]
    pub fn with_revisions(mut self, local: Option<u64>, incoming: Option<u64>) -> Self {
        self.local_revision = local;
        self.incoming_revision = incoming;
        self
    }

    #[must_use]
    pub fn with_kid(mut self, kid: &[u8]) -> Self {
        self.kid_prefix = Some(hex::encode(&kid[..kid.len().min(4)]));
        self
    }

    #[must_use]
    pub fn with_hash(mut self, hash: &[u8]) -> Self {
        self.hash_prefix = Some(hex::encode(&hash[..hash.len().min(4)]));
        self
    }
}

/// Every `Outcome` this module can produce — the closed "outcome
/// vocabulary" FR-067 means. Used to recognize a propagated `"[CODE] ..."`
/// error string as one of THESE (never a `[STATE]`/`[FILE]`/`[CRYPTO]`/
/// `[VALIDATION]` internal error, which are plumbing details, not
/// documented outcomes) before it's worth logging at all.
const ALL_OUTCOMES: &[Outcome] = &[
    Outcome::BoxBadMagic, Outcome::BoxUnsupported, Outcome::BoxCorrupt, Outcome::BoxUnknownKey,
    Outcome::BoxOlder, Outcome::BoxConflict, Outcome::BoxAuth,
    Outcome::VaultLocked, Outcome::VaultAuth, Outcome::VaultCorrupt, Outcome::VaultUnknownKid,
    Outcome::VaultRollback, Outcome::VaultNoKeystore, Outcome::VaultKeystoreDenied, Outcome::VaultKdf,
    Outcome::VaultBusy, Outcome::KitMalformed, Outcome::KitWrongPassphrase, Outcome::KitKidMismatch,
];

/// Extracts the leading `[CODE]` from an error string produced by
/// `Outcome::to_string()` elsewhere in this crate, but only if `CODE` is
/// actually one of `Outcome`'s own codes — an internal `[STATE]`/`[FILE]`/
/// `[CRYPTO]`/`[VALIDATION]` error (plumbing, not a documented outcome)
/// yields `None`, so callers never log those.
pub fn outcome_code_from_error(err: &str) -> Option<&'static str> {
    let rest = err.strip_prefix('[')?;
    let candidate = rest.split(']').next()?;
    ALL_OUTCOMES.iter().find(|o| o.code() == candidate).map(|o| o.code())
}

/// Best-effort append of one diagnostic line to a device-wide, append-only
/// JSONL sidecar (never per-profile — a diagnostic about a failed unlock
/// or import has nothing to do with which profile, if any, ends up open).
/// A logging failure here must never surface as a user-facing error or
/// block whatever operation triggered it (FR-069: local only, and this is
/// diagnostics about failures, not itself allowed to cause one).
pub fn record_diagnostic(app: &tauri::AppHandle, entry: &DiagnosticEntry) {
    use tauri::Manager as _;
    let Ok(dir) = app.path().app_data_dir() else { return };
    let _ = std::fs::create_dir_all(&dir);
    let Ok(line) = serde_json::to_string(entry) else { return };
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("vault_diagnostics.jsonl"))
    {
        use std::io::Write;
        let _ = writeln!(f, "{}", line);
    }
}

/// Records a diagnostic for `result` if it's an `Err` carrying a
/// recognized outcome code, then returns `result` unchanged — lets a
/// caller wrap a fallible expression in place (`record_outcome(app,
/// some_call())?`) without restructuring its own error handling.
pub fn record_outcome<T>(app: &tauri::AppHandle, result: Result<T, String>) -> Result<T, String> {
    if let Err(err) = &result {
        if let Some(code) = outcome_code_from_error(err) {
            record_diagnostic(app, &DiagnosticEntry::new(code));
        }
    }
    result
}

/// Load — or generate once — this device's stable sender id. Stored in a
/// device-local sidecar file, deliberately outside any vault (mirrors
/// `sync_device_node_id`'s rationale in lib.rs exactly).
pub fn load_or_create_sender_id(app: &tauri::AppHandle) -> [u8; SENDER_ID_LEN] {
    use tauri::Manager as _;
    let fresh = generate_sender_id;
    let Ok(dir) = app.path().app_data_dir() else {
        return fresh();
    };
    let path = dir.join("vault_sender_id.json");
    if let Ok(bytes) = std::fs::read(&path) {
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
            if let Some(hex_str) = v.get("sender_id").and_then(|x| x.as_str()) {
                if let Ok(decoded) = hex::decode(hex_str) {
                    if decoded.len() == SENDER_ID_LEN {
                        let mut id = [0u8; SENDER_ID_LEN];
                        id.copy_from_slice(&decoded);
                        return id;
                    }
                }
            }
        }
    }
    let id = fresh();
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::write(
        &path,
        serde_json::json!({ "sender_id": hex::encode(id) }).to_string(),
    );
    id
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;

    /// T109/SC-025: a battery of realistic entries, serialized exactly as
    /// `record_diagnostic` would write them, must never contain a
    /// hostname, path, filename, username, credential, or phrase word —
    /// even when the source outcome carries a `message()` that mentions
    /// paths in its own static text (the entry never stores `message()`,
    /// only `outcome_code()`).
    #[test]
    fn serialized_entries_never_leak_forbidden_content() {
        let forbidden = [
            "example.com", "/home/", "/Users/", "C:\\", "alice", "bob",
            "password", "correct horse battery staple", ".ssh", "id_rsa",
        ];
        let samples = [
            DiagnosticEntry::new(Outcome::VaultAuth.code()),
            DiagnosticEntry::new(Outcome::BoxUnknownKey.code())
                .with_kid(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x11]),
            DiagnosticEntry::new(Outcome::BoxOlder.code())
                .with_revisions(Some(5), Some(3))
                .with_hash(&[0x12, 0x34, 0x56, 0x78]),
            DiagnosticEntry::new(Outcome::KitWrongPassphrase.code()),
            DiagnosticEntry::new(Outcome::VaultRollback.code())
                .with_revisions(Some(9), None),
        ];
        for entry in &samples {
            let json = serde_json::to_string(entry).expect("entry serializes");
            for needle in forbidden {
                assert!(
                    !json.to_lowercase().contains(&needle.to_lowercase()),
                    "diagnostic entry leaked forbidden content {:?}: {}", needle, json
                );
            }
        }
    }

    /// FR-068's real risk isn't the entry's own fields (which structurally
    /// can't hold this) — it's a caller accidentally feeding a `[FILE]`/
    /// `[STATE]`/`[CRYPTO]` internal error (which routinely DOES embed a
    /// real path) into the diagnostic log. `outcome_code_from_error` is
    /// the guard: it must recognize only this module's own outcome codes
    /// and reject everything else, no matter what that "everything else"
    /// contains.
    #[test]
    fn internal_errors_with_real_paths_are_never_recognized_as_outcomes() {
        let leaky_internal_errors = [
            "[FILE] KEYWRAP_READ_FAILED: /Users/alice/Library/Application Support/sshclientx/profiles/work.keywrap",
            "[STATE] LOCK_FAILED_PROFILE",
            "[CRYPTO] KDF_JOIN: task panicked",
            "[VALIDATION] UNKNOWN_STAGING_ID",
        ];
        for err in leaky_internal_errors {
            assert_eq!(
                outcome_code_from_error(err), None,
                "internal error should never be recognized as a diagnosable outcome: {}", err
            );
        }
    }

    #[test]
    fn genuine_outcome_errors_are_recognized_by_their_code() {
        for outcome in ALL_OUTCOMES {
            let err_string = outcome.to_string();
            assert_eq!(outcome_code_from_error(&err_string), Some(outcome.code()));
        }
    }
}

#[cfg(test)]
mod container_tests {
    use super::*;

    fn test_key(alg: SealAlg) -> ([u8; 32], SealKey<'static>) {
        // Leaked on purpose: tests are short-lived processes, and SealKey
        // borrows its key material — this sidesteps lifetime plumbing in
        // test helper functions without affecting production code, which
        // always borrows from a real caller-owned buffer.
        let key: &'static [u8; 32] = Box::leak(Box::new([0x42u8; 32]));
        (*key, SealKey { alg, key })
    }

    #[test]
    fn round_trip_xchacha20poly1305() {
        let (_owned, key) = test_key(SealAlg::XChaCha20Poly1305);
        let kid = [7u8; KID_LEN];
        let sender_id = [9u8; SENDER_ID_LEN];
        let plaintext = b"hello vault payload, this stands in for zstd(sqlite)";

        let sealed = SealedVaultFile::seal(&key, kid, 1, sender_id, "test-device", plaintext)
            .expect("seal");
        let bytes = sealed.to_bytes();

        let parsed = SealedVaultFile::parse(&bytes).expect("parse");
        assert_eq!(parsed.kid, kid);
        assert_eq!(parsed.generation, 1);
        assert_eq!(parsed.sender_name, "test-device");
        assert_eq!(parsed.alg, SealAlg::XChaCha20Poly1305);

        let opened = parsed.open(&key).expect("open");
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn round_trip_aes256gcm() {
        let (_owned, key) = test_key(SealAlg::Aes256Gcm);
        let kid = [3u8; KID_LEN];
        let sender_id = [5u8; SENDER_ID_LEN];
        let plaintext = b"aes fallback payload";

        let sealed = SealedVaultFile::seal(&key, kid, 42, sender_id, "", plaintext).expect("seal");
        let bytes = sealed.to_bytes();
        let parsed = SealedVaultFile::parse(&bytes).expect("parse");
        let opened = parsed.open(&key).expect("open");
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn single_byte_flip_anywhere_yields_box_corrupt() {
        let (_owned, key) = test_key(SealAlg::XChaCha20Poly1305);
        let sealed = SealedVaultFile::seal(
            &key, [1u8; KID_LEN], 1, [2u8; SENDER_ID_LEN], "d", b"payload data here",
        )
        .expect("seal");
        let bytes = sealed.to_bytes();

        // Flip one byte at a handful of positions spanning header, sender
        // name, ciphertext, and the trailing hash — every position must be
        // caught, either by parse() (structural fields) or by open()
        // (ciphertext/AAD-bound fields), never silently accepted.
        for &pos in &[0usize, 9, 20, bytes.len() / 2, bytes.len() - 1] {
            let mut corrupted = bytes.clone();
            corrupted[pos] ^= 0x01;
            match SealedVaultFile::parse(&corrupted) {
                Err(Outcome::BoxCorrupt) | Err(Outcome::BoxBadMagic) | Err(Outcome::BoxUnsupported) => {
                    // parse() itself caught it — acceptable, still not silently accepted.
                }
                Ok(parsed) => {
                    // Structurally valid but content corrupted — open() must catch it.
                    let result = parsed.open(&key);
                    assert!(
                        matches!(result, Err(Outcome::BoxCorrupt)),
                        "byte flip at {} was not caught by open()",
                        pos
                    );
                }
                Err(other) => panic!("unexpected outcome at byte {}: {:?}", pos, other),
            }
        }
    }

    #[test]
    fn truncation_yields_box_corrupt() {
        let (_owned, key) = test_key(SealAlg::XChaCha20Poly1305);
        let sealed = SealedVaultFile::seal(
            &key, [1u8; KID_LEN], 1, [2u8; SENDER_ID_LEN], "d", b"some payload",
        )
        .expect("seal");
        let bytes = sealed.to_bytes();
        for cut in [1, bytes.len() / 2, bytes.len() - 1] {
            let truncated = &bytes[..cut];
            let result = SealedVaultFile::parse(truncated);
            assert!(
                matches!(result, Err(Outcome::BoxCorrupt) | Err(Outcome::BoxBadMagic)),
                "truncation to {} bytes was not rejected",
                cut
            );
        }
    }

    #[test]
    fn altering_kid_or_generation_breaks_the_aead_via_aad_binding() {
        let (_owned, key) = test_key(SealAlg::XChaCha20Poly1305);
        let sealed = SealedVaultFile::seal(
            &key, [1u8; KID_LEN], 5, [2u8; SENDER_ID_LEN], "d", b"payload",
        )
        .expect("seal");

        let mut altered_kid = sealed.clone();
        altered_kid.kid = [9u8; KID_LEN];
        assert!(matches!(altered_kid.open(&key), Err(Outcome::BoxCorrupt)));

        let mut altered_gen = sealed.clone();
        altered_gen.generation = 999;
        assert!(matches!(altered_gen.open(&key), Err(Outcome::BoxCorrupt)));

        // Sanity: the untouched original still opens fine.
        assert!(sealed.open(&key).is_ok());
    }

    #[test]
    fn no_trailing_slack_is_accepted() {
        let (_owned, key) = test_key(SealAlg::XChaCha20Poly1305);
        let sealed = SealedVaultFile::seal(
            &key, [1u8; KID_LEN], 1, [2u8; SENDER_ID_LEN], "d", b"payload",
        )
        .expect("seal");
        let mut bytes = sealed.to_bytes();
        bytes.extend_from_slice(b"trailing garbage an attacker appended");
        assert!(matches!(SealedVaultFile::parse(&bytes), Err(Outcome::BoxCorrupt)));
    }

    #[test]
    fn oversized_sender_name_is_rejected_at_seal_time() {
        let (_owned, key) = test_key(SealAlg::XChaCha20Poly1305);
        let too_long = "x".repeat(SENDER_NAME_MAX_LEN + 1);
        let result = SealedVaultFile::seal(
            &key, [1u8; KID_LEN], 1, [2u8; SENDER_ID_LEN], &too_long, b"payload",
        );
        assert!(result.is_err());
    }

    #[test]
    fn format_discrimination_distinguishes_sealed_legacy_and_unknown() {
        let (_owned, key) = test_key(SealAlg::XChaCha20Poly1305);
        let sealed_bytes = SealedVaultFile::seal(
            &key, [1u8; KID_LEN], 1, [2u8; SENDER_ID_LEN], "d", b"payload",
        )
        .unwrap()
        .to_bytes();
        assert!(matches!(discriminate_format(&sealed_bytes), DiscriminatedFormat::Sealed));

        let mut legacy_bytes = LEGACY_MAGIC.to_vec();
        legacy_bytes.push(LEGACY_VERSION);
        legacy_bytes.extend_from_slice(&[0u8; 40]);
        assert!(matches!(discriminate_format(&legacy_bytes), DiscriminatedFormat::Legacy));

        assert!(matches!(discriminate_format(b"not a vault file at all"), DiscriminatedFormat::Unknown));
        assert!(matches!(discriminate_format(b""), DiscriminatedFormat::Unknown));
    }

    #[test]
    fn legacy_blob_still_round_trips_through_the_legacy_path() {
        let password = "correct horse battery staple";
        let mut salt = [0u8; LEGACY_SALT_LEN];
        rand::thread_rng().fill(&mut salt[..]);
        let key = legacy_derive_key(password, &salt).expect("derive");
        let plaintext = b"legacy sqlite serialization stand-in";
        let compressed = vault_compress(plaintext).expect("compress");
        let (ciphertext, nonce) = legacy_encrypt(&compressed, &key).expect("encrypt");
        let blob = legacy_write_blob(&salt, &nonce, &ciphertext);

        assert!(is_legacy_blob(&blob));
        let (parsed_salt, parsed_nonce, parsed_ct) = legacy_parse_blob(&blob).expect("parse");
        assert_eq!(parsed_salt, salt.to_vec());
        let rederived = legacy_derive_key(password, &parsed_salt).expect("re-derive");
        let decrypted = legacy_decrypt(&parsed_ct, &parsed_nonce, &rederived).expect("decrypt");
        let decompressed = vault_decompress(&decrypted).expect("decompress");
        assert_eq!(decompressed, plaintext);
    }

    #[test]
    fn kid_is_stable_and_distinguishes_different_keys() {
        let key_a = [1u8; 32];
        let key_b = [2u8; 32];
        assert_eq!(derive_kid(&key_a), derive_kid(&key_a));
        assert_ne!(derive_kid(&key_a), derive_kid(&key_b));
    }

    #[test]
    fn sender_id_is_random_per_call() {
        let a = generate_sender_id();
        let b = generate_sender_id();
        assert_ne!(a, b, "two generated sender ids collided — CSPRNG failure or reused buffer");
    }
}

// ---------------------------------------------------------------------------
// verify_and_import: the one verification pipeline (FR-029).
//
// Every route into the app — the import file picker, the recovery-kit
// restore, and later QR/cloud transports — calls this on bytes already
// copied into the app's own storage. Checks run in the order
// contracts/sealed-container.md §3 specifies, and the first failure
// returns; later checks never run on data an earlier check rejected.
// ---------------------------------------------------------------------------

/// What the caller's key registry reports for a given `kid`. Kept as a
/// small enum the caller constructs from its own state (profile table +
/// unclaimed-key store, T024+) rather than this module reaching into a
/// database directly — `vault.rs` owns the format and the pipeline, not
/// profile storage.
#[derive(Clone)]
pub enum KeyLookup {
    /// No profile or unclaimed key on this device matches this `kid`.
    Unknown,
    /// This `kid` is unclaimed — it came from a consumed recovery kit and
    /// owns no profile yet (FR-031a). Importing a file for it creates a new
    /// profile that then owns it (FR-032).
    Unclaimed { key: [u8; 32] },
    /// This `kid` is owned by an existing profile. `current_revision` and
    /// `current_content_hash` (SHA-256 of the *decrypted* local payload, not
    /// of the local sealed bytes — two seals of identical content get
    /// different ciphertext from a fresh nonce every time) drive the
    /// revision policy in step 8.
    Owned {
        profile: String,
        key: [u8; 32],
        current_revision: u64,
        current_content_hash: [u8; 32],
    },
}

/// What importing this file would do, decided by step 5 (key match) and
/// step 8 (revision policy) of the pipeline (contracts §3.1, §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposition {
    /// `kid` matched an unclaimed key — offer to create a new profile that
    /// owns it (FR-032).
    CreateProfile,
    /// `kid` matched a key an existing profile owns — offer only to
    /// restore over that profile, naming it (FR-032a).
    RestoreOver { profile: String },
    /// Same revision, identical content — a no-op re-import, not a
    /// conflict (spec Edge Cases: "same file imported twice"). Carries the
    /// matched profile's name purely for the caller's own message.
    NoOp { profile: String },
}

/// Which confirmation, if any, a caller must obtain before committing this
/// import (FR-033). Kept distinct rather than one boolean because the two
/// cases require *different* explicit choices from the user
/// (`confirm_older` vs `resolve_conflict` in the command contract) — a
/// single flag would lose that distinction exactly where it matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmationNeeded {
    /// Nothing further needed — safe to commit as-is.
    None,
    /// Incoming revision is lower than local. Committing without explicit
    /// confirmation must be refused (`BOX_OLDER`), and the newer local
    /// state must be preserved as a recoverable revision, not clobbered.
    Older,
    /// Same revision, different content. Committing without a separate
    /// explicit choice must be refused (`BOX_CONFLICT`) — never overwrite
    /// silently.
    Conflict,
}

/// Result of a successful `verify_and_import` call: the file was
/// cryptographically valid and its `kid` matched a key this device holds.
/// This succeeds even for an older or conflicting revision — those are not
/// pipeline failures, they are decisions the caller (the staging step, then
/// the commit step) must still get explicit sign-off on before writing
/// anything, per `confirmation_needed`.
pub struct ImportDecision {
    pub disposition: Disposition,
    pub confirmation_needed: ConfirmationNeeded,
    pub sealed: SealedVaultFile,
}

/// The single verification pipeline (FR-029). `registry` answers "what key,
/// if any, matches this incoming file's `kid`" from the caller's own state.
/// `identity_confirmed` must reflect a *already-completed* identity
/// confirmation (platform authentication or password, FR-055) — step 6 in
/// the pipeline checks this flag, it does not perform confirmation itself,
/// since prompting the user is an orchestration concern that lives above
/// this module.
///
/// Legacy (`OMNV`) bytes are explicitly out of scope here — this pipeline is
/// for the sealed container only. A legacy blob is routed to the migration
/// path (T033+), never through this function.
pub fn verify_and_import(
    bytes: &[u8],
    registry: &dyn Fn(&[u8; KID_LEN]) -> KeyLookup,
    identity_confirmed: bool,
) -> Result<ImportDecision, Outcome> {
    // Steps 1-4: magic, format, length self-consistency, hash. All folded
    // into SealedVaultFile::parse, which never reaches decryption on any of
    // these failures.
    let sealed = SealedVaultFile::parse(bytes)?;

    // Step 5: kid match against every key the device holds, owned or
    // unclaimed — never against "the" local profile's key alone (FR-031).
    let lookup = registry(&sealed.kid);
    let (key, disposition_hint) = match lookup {
        KeyLookup::Unknown => return Err(Outcome::BoxUnknownKey),
        KeyLookup::Unclaimed { key } => (key, None),
        KeyLookup::Owned { profile, key, current_revision, current_content_hash } => {
            (key, Some((profile, current_revision, current_content_hash)))
        }
    };

    // Step 6: identity confirmation, checked here — performed by the
    // caller before this call.
    if !identity_confirmed {
        return Err(Outcome::BoxAuth);
    }

    // Step 7: AEAD open. Never reached above for an unknown kid or an
    // unconfirmed caller — a file for a key this device does not hold, or
    // one nobody has authorised, is never decrypted.
    let plaintext = sealed.open(&SealKey { alg: sealed.alg, key: &key })?;

    // Step 8: revision policy — only meaningful when there is a local
    // vault to compare against (the Owned case). An unclaimed key has no
    // local revision, so importing it is unconditionally a fresh profile.
    // Note: an older or conflicting revision is still `Ok` here — it is a
    // decision for the caller to get sign-off on, not a pipeline failure.
    // `BOX_OLDER`/`BOX_CONFLICT` are what the *commit* step returns if that
    // sign-off wasn't supplied (contracts/tauri-command-contract.md §2).
    let (disposition, confirmation_needed) = match disposition_hint {
        None => (Disposition::CreateProfile, ConfirmationNeeded::None),
        Some((profile, current_revision, current_content_hash)) => {
            use std::cmp::Ordering;
            match sealed.generation.cmp(&current_revision) {
                Ordering::Greater => {
                    (Disposition::RestoreOver { profile }, ConfirmationNeeded::None)
                }
                Ordering::Equal => {
                    use sha2::{Digest, Sha256};
                    let incoming_hash: [u8; 32] = Sha256::digest(&plaintext).into();
                    if incoming_hash == current_content_hash {
                        (Disposition::NoOp { profile }, ConfirmationNeeded::None)
                    } else {
                        (Disposition::RestoreOver { profile }, ConfirmationNeeded::Conflict)
                    }
                }
                Ordering::Less => {
                    (Disposition::RestoreOver { profile }, ConfirmationNeeded::Older)
                }
            }
        }
    };

    Ok(ImportDecision {
        disposition,
        confirmation_needed,
        sealed,
    })
}

#[cfg(test)]
mod verify_and_import_tests {
    use super::*;

    fn leaked_key(alg: SealAlg) -> ([u8; 32], SealKey<'static>) {
        leaked_key_bytes(alg, 0x11)
    }

    /// Like `leaked_key`, but with a caller-chosen byte pattern — needed
    /// whenever a test genuinely requires two or more *distinct* keys
    /// (and therefore distinct `kid`s) in the same test, since `leaked_key`
    /// always returns the same constant bytes.
    fn leaked_key_bytes(alg: SealAlg, byte: u8) -> ([u8; 32], SealKey<'static>) {
        let key: &'static [u8; 32] = Box::leak(Box::new([byte; 32]));
        (*key, SealKey { alg, key })
    }

    fn seal_bytes(key: &SealKey, kid: [u8; KID_LEN], generation: u64, plaintext: &[u8]) -> Vec<u8> {
        SealedVaultFile::seal(key, kid, generation, [1u8; SENDER_ID_LEN], "d", plaintext)
            .unwrap()
            .to_bytes()
    }

    fn content_hash(plaintext: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(plaintext).into()
    }

    #[test]
    fn unknown_kid_is_never_decrypted() {
        let (_owned, key) = leaked_key(SealAlg::XChaCha20Poly1305);
        let bytes = seal_bytes(&key, [1u8; KID_LEN], 1, b"secret payload");
        let result = verify_and_import(&bytes, &|_kid| KeyLookup::Unknown, true);
        assert!(matches!(result, Err(Outcome::BoxUnknownKey)));
    }

    #[test]
    fn unconfirmed_identity_is_refused_before_decryption() {
        let (owned, key) = leaked_key(SealAlg::XChaCha20Poly1305);
        let kid = [1u8; KID_LEN];
        let bytes = seal_bytes(&key, kid, 1, b"secret payload");
        let result = verify_and_import(
            &bytes,
            &move |_kid| KeyLookup::Unclaimed { key: owned },
            false, // identity NOT confirmed
        );
        assert!(matches!(result, Err(Outcome::BoxAuth)));
    }

    #[test]
    fn unclaimed_key_match_yields_create_profile() {
        let (owned, key) = leaked_key(SealAlg::XChaCha20Poly1305);
        let kid = [2u8; KID_LEN];
        let bytes = seal_bytes(&key, kid, 1, b"payload for a brand new profile");
        let result = verify_and_import(&bytes, &move |_| KeyLookup::Unclaimed { key: owned }, true)
            .expect("should succeed");
        assert_eq!(result.disposition, Disposition::CreateProfile);
        assert_eq!(result.confirmation_needed, ConfirmationNeeded::None);
    }

    #[test]
    fn owned_key_newer_revision_yields_restore_over_no_confirmation() {
        let (owned, key) = leaked_key(SealAlg::XChaCha20Poly1305);
        let kid = [3u8; KID_LEN];
        let bytes = seal_bytes(&key, kid, 10, b"newer content");
        let result = verify_and_import(
            &bytes,
            &move |_| KeyLookup::Owned {
                profile: "alice".into(),
                key: owned,
                current_revision: 5,
                current_content_hash: content_hash(b"older content"),
            },
            true,
        )
        .expect("should succeed");
        assert_eq!(result.disposition, Disposition::RestoreOver { profile: "alice".into() });
        assert_eq!(result.confirmation_needed, ConfirmationNeeded::None);
    }

    #[test]
    fn owned_key_older_revision_needs_explicit_confirmation() {
        let (owned, key) = leaked_key(SealAlg::XChaCha20Poly1305);
        let kid = [4u8; KID_LEN];
        let bytes = seal_bytes(&key, kid, 3, b"stale content");
        let result = verify_and_import(
            &bytes,
            &move |_| KeyLookup::Owned {
                profile: "bob".into(),
                key: owned,
                current_revision: 9,
                current_content_hash: content_hash(b"fresh content"),
            },
            true,
        )
        .expect("should still succeed — confirmation is the caller's job, not a pipeline error");
        assert_eq!(result.disposition, Disposition::RestoreOver { profile: "bob".into() });
        assert_eq!(result.confirmation_needed, ConfirmationNeeded::Older);
    }

    #[test]
    fn same_revision_identical_content_is_a_no_op() {
        let (owned, key) = leaked_key(SealAlg::XChaCha20Poly1305);
        let kid = [5u8; KID_LEN];
        let plaintext = b"identical payload, imported twice";
        let bytes = seal_bytes(&key, kid, 7, plaintext);
        let result = verify_and_import(
            &bytes,
            &move |_| KeyLookup::Owned {
                profile: "carol".into(),
                key: owned,
                current_revision: 7,
                current_content_hash: content_hash(plaintext),
            },
            true,
        )
        .expect("should succeed");
        assert_eq!(result.disposition, Disposition::NoOp { profile: "carol".into() });
        assert_eq!(result.confirmation_needed, ConfirmationNeeded::None);
    }

    #[test]
    fn same_revision_different_content_is_flagged_as_conflict() {
        let (owned, key) = leaked_key(SealAlg::XChaCha20Poly1305);
        let kid = [6u8; KID_LEN];
        let bytes = seal_bytes(&key, kid, 7, b"incoming version");
        let result = verify_and_import(
            &bytes,
            &move |_| KeyLookup::Owned {
                profile: "dave".into(),
                key: owned,
                current_revision: 7,
                current_content_hash: content_hash(b"different local version"),
            },
            true,
        )
        .expect("should still succeed — conflict is a confirmation requirement, not an error");
        assert_eq!(result.disposition, Disposition::RestoreOver { profile: "dave".into() });
        assert_eq!(result.confirmation_needed, ConfirmationNeeded::Conflict);
    }

    #[test]
    fn corrupt_file_never_reaches_the_registry_lookup() {
        let (_owned, key) = leaked_key(SealAlg::XChaCha20Poly1305);
        let mut bytes = seal_bytes(&key, [7u8; KID_LEN], 1, b"payload");
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF; // corrupt the trailing hash
        let called = std::cell::Cell::new(false);
        let result = verify_and_import(
            &bytes,
            &|_kid| {
                called.set(true);
                KeyLookup::Unknown
            },
            true,
        );
        assert!(matches!(result, Err(Outcome::BoxCorrupt)));
        assert!(!called.get(), "registry must not be consulted for a structurally invalid file");
    }

    #[test]
    fn wrong_key_for_a_matched_kid_yields_box_corrupt_not_a_panic() {
        // Pathological but must be handled gracefully: the registry claims a
        // key for this kid, but that key doesn't actually open the file
        // (e.g. a bug elsewhere in key bookkeeping). Must fail closed.
        let (_sealing_owned, sealing_key) = leaked_key(SealAlg::XChaCha20Poly1305);
        let wrong_key: &'static [u8; 32] = Box::leak(Box::new([0x99u8; 32]));
        let kid = [8u8; KID_LEN];
        let bytes = seal_bytes(&sealing_key, kid, 1, b"payload");
        let result = verify_and_import(
            &bytes,
            &move |_| KeyLookup::Unclaimed { key: *wrong_key },
            true,
        );
        assert!(matches!(result, Err(Outcome::BoxCorrupt)));
    }

    /// T104: the remaining two of the seven import failure outcomes,
    /// completing coverage alongside `unknown_kid_is_never_decrypted`
    /// (BOX_UNKNOWN_KEY), `unconfirmed_identity_is_refused_before_decryption`
    /// (BOX_AUTH), `corrupt_file_never_reaches_the_registry_lookup` and
    /// `wrong_key_for_a_matched_kid_yields_box_corrupt_not_a_panic`
    /// (BOX_CORRUPT). BOX_OLDER/BOX_CONFLICT are the `ConfirmationNeeded`
    /// cases already covered above — those are surfaced as actual errors
    /// at the commit layer (`import_vault_commit` in lib.rs), which needs
    /// a running Tauri app to unit test; this pipeline's own contribution
    /// to them is exactly `ConfirmationNeeded::Older`/`Conflict`, tested by
    /// `owned_key_older_revision_needs_explicit_confirmation` and
    /// `same_revision_different_content_is_flagged_as_conflict`.
    #[test]
    fn not_a_vault_file_at_all_yields_box_bad_magic() {
        let result = verify_and_import(b"definitely not a vault file", &|_| KeyLookup::Unknown, true);
        assert!(matches!(result, Err(Outcome::BoxBadMagic)));
    }

    #[test]
    fn unsupported_format_version_yields_box_unsupported() {
        let (_owned, key) = leaked_key(SealAlg::XChaCha20Poly1305);
        let mut bytes = seal_bytes(&key, [1u8; KID_LEN], 1, b"payload");
        // format is a little-endian u16 at offset 8-9 (contracts §1).
        bytes[8] = 0xFF;
        bytes[9] = 0xFF;
        // The trailing hash no longer matches after this edit, so this
        // exercises whichever check catches it first — either is a
        // legitimate rejection of the same malformed input, but the
        // pipeline is specifically ordered to check `format` (step 2)
        // before the hash (step 4), so BOX_UNSUPPORTED is what must win.
        let result = SealedVaultFile::parse(&bytes);
        assert!(matches!(result, Err(Outcome::BoxUnsupported)), "format check must run before the hash check");
    }

    /// T105: on a device holding several profiles, a file never produces a
    /// second profile sharing an existing one's key — proven here with a
    /// registry backed by more than one simulated profile, so "route to
    /// the right one, never invent a duplicate" is checked against a
    /// multi-profile registry shape, not just a single mock mapping.
    #[test]
    fn multiple_profiles_never_share_a_key_via_create_profile() {
        let (owned_a, key_a) = leaked_key_bytes(SealAlg::XChaCha20Poly1305, 0xA1);
        let kid_a = derive_kid(&owned_a);
        let (owned_b, _key_b) = leaked_key_bytes(SealAlg::XChaCha20Poly1305, 0xB2);
        let kid_b = derive_kid(&owned_b);

        // Simulates a device with two existing profiles ("alice" owns
        // kid_a, "bob" owns kid_b) plus one unclaimed key (kid_c). Three
        // genuinely distinct keys — `leaked_key_bytes` with different
        // byte patterns, not the shared single-pattern `leaked_key` —
        // otherwise this test would trivially "pass" while actually
        // exercising one key three times, catching nothing.
        let (owned_c, key_c) = leaked_key_bytes(SealAlg::XChaCha20Poly1305, 0xC3);
        let kid_c = derive_kid(&owned_c);

        let registry = move |k: &[u8; KID_LEN]| -> KeyLookup {
            if *k == kid_a {
                KeyLookup::Owned { profile: "alice".into(), key: owned_a, current_revision: 3, current_content_hash: [0u8; 32] }
            } else if *k == kid_b {
                KeyLookup::Owned { profile: "bob".into(), key: owned_b, current_revision: 5, current_content_hash: [0u8; 32] }
            } else if *k == kid_c {
                KeyLookup::Unclaimed { key: owned_c }
            } else {
                KeyLookup::Unknown
            }
        };

        // A file for alice's key must restore over alice, never create a
        // second profile, and must never touch bob's or the unclaimed key.
        let file_for_a = seal_bytes(&key_a, kid_a, 10, b"newer content for alice");
        let result_a = verify_and_import(&file_for_a, &registry, true).expect("must succeed");
        assert_eq!(result_a.disposition, Disposition::RestoreOver { profile: "alice".into() });

        // A file for the unclaimed key must create a new profile — and
        // ONLY because it matched the unclaimed slot, not alice's or bob's.
        let file_for_c = seal_bytes(&key_c, kid_c, 1, b"brand new profile content");
        let result_c = verify_and_import(&file_for_c, &registry, true).expect("must succeed");
        assert_eq!(result_c.disposition, Disposition::CreateProfile);
    }
}

// ---------------------------------------------------------------------------
// Key model: DEK generation, the two-of-two wrap, and the on-disk key-wrap
// sidecar (T024, T025). research.md Decision 3.
//
//   KEK        = Argon2id(password, salt)     // salt lives in the key-wrap file
//   K_device   = 32 random bytes              // OS secure store (keystore.rs)
//   K_combined = SHA-256(K_device || KEK)
//   dek.wrap   = AEAD(K_combined, DEK)        // key-wrap file, app private storage
//
// Neither `K_device` alone nor the password alone yields `K_combined`, so
// FR-007a and SC-011 hold in both directions. The DEK itself is never
// written anywhere except inside this wrap.
// ---------------------------------------------------------------------------

use std::path::{Path, PathBuf};
use std::fs;
use zeroize::Zeroizing;

/// Salt length for the KEK's Argon2id derivation. Reuses the legacy salt
/// length for no reason beyond "no reason to pick a different number" —
/// this salt and the legacy vault's salt are otherwise unrelated.
pub const KEYWRAP_SALT_LEN: usize = LEGACY_SALT_LEN;

/// Generate a fresh 256-bit DEK. CSPRNG, never derived from the password
/// (FR-001, FR-007).
pub fn generate_dek() -> Zeroizing<[u8; 32]> {
    let mut dek = [0u8; 32];
    rand::thread_rng().fill(&mut dek);
    Zeroizing::new(dek)
}

/// Generate a fresh 256-bit device factor — the secret actually held in the
/// OS secure store. Never derived from, or combined in a reversible way
/// with, the DEK it protects.
pub fn generate_device_factor() -> [u8; 32] {
    let mut factor = [0u8; 32];
    rand::thread_rng().fill(&mut factor);
    factor
}

/// KEK = Argon2id(password, salt). Deliberately reuses `legacy_derive_key`
/// rather than a second implementation: the constitution states Argon2id
/// parameters MUST NOT change without a versioned re-key migration, and that
/// requirement is not scoped to the legacy format only — one derivation
/// function is what makes "the same parameters" a fact about the code
/// rather than a fact someone has to keep two copies in sync about.
fn derive_kek(password: &str, salt: &[u8; KEYWRAP_SALT_LEN]) -> Result<[u8; 32], String> {
    legacy_derive_key(password, salt)
}

/// K_combined = SHA-256(K_device || KEK). A plain hash is the right
/// primitive here (not a second password-hardened KDF): both inputs are
/// already uniformly random 32-byte secrets — the password has already
/// been through Argon2id to produce `kek`.
fn combine_keys(device_factor: &[u8; 32], kek: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(device_factor);
    hasher.update(kek);
    hasher.finalize().into()
}

const KEYWRAP_MAGIC: &[u8; 4] = b"DWR1";

/// The on-disk key-wrap sidecar: the DEK, sealed under the two-of-two
/// combination, plus the salt needed to re-derive the KEK half on next
/// unlock. Lives in app private storage next to (not inside) the profile's
/// vault file — safe to sit there because it holds the DEK in *wrapped*
/// form, not raw (FR-002 forbids the raw key next to the vault file, not a
/// wrapped one).
pub struct KeyWrapFile {
    pub salt: [u8; KEYWRAP_SALT_LEN],
    pub alg: SealAlg,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub tag: [u8; TAG_LEN],
}

impl KeyWrapFile {
    /// Seal `dek` under a fresh combination of `device_factor` and
    /// `password`. `salt` MUST be freshly generated by the caller — never
    /// reused across two different wraps, including a password change
    /// (FR-007b, once that flow exists).
    pub fn create(
        device_factor: &[u8; 32],
        password: &str,
        salt: [u8; KEYWRAP_SALT_LEN],
        dek: &[u8; 32],
    ) -> Result<Self, String> {
        let kek = derive_kek(password, &salt)?;
        let combined = combine_keys(device_factor, &kek);
        let seal_key = SealKey { alg: SealAlg::XChaCha20Poly1305, key: &combined };
        let (nonce, ciphertext, tag) = seal_generic(&seal_key, &[], dek)?;
        Ok(KeyWrapFile { salt, alg: SealAlg::XChaCha20Poly1305, nonce, ciphertext, tag })
    }

    /// Unwrap the DEK. Requires BOTH `device_factor` (from the keystore,
    /// this device only) and `password` — reproduces Decision 3's
    /// two-of-two exactly: neither alone can compute `combined`, so neither
    /// alone can reach the DEK (FR-007a, SC-011).
    ///
    /// A failure here cannot distinguish "wrong password" from "wrong
    /// device factor" — both look identical to the AEAD (an authentication
    /// failure), and that is correct: from the caller's side both mean "you
    /// don't have what this vault needs," which is exactly `VaultAuth`.
    pub fn unwrap_dek(&self, device_factor: &[u8; 32], password: &str) -> Result<Zeroizing<[u8; 32]>, Outcome> {
        let kek = derive_kek(password, &self.salt).map_err(|_| Outcome::VaultKdf)?;
        let combined = combine_keys(device_factor, &kek);
        let seal_key = SealKey { alg: self.alg, key: &combined };
        let plaintext = open_generic(&seal_key, &[], &self.nonce, &self.ciphertext, &self.tag)
            .map_err(|()| Outcome::VaultAuth)?;
        if plaintext.len() != 32 {
            return Err(Outcome::VaultCorrupt);
        }
        let mut dek = [0u8; 32];
        dek.copy_from_slice(&plaintext);
        Ok(Zeroizing::new(dek))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(KEYWRAP_MAGIC);
        out.extend_from_slice(&self.salt);
        out.push(self.alg.as_byte());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&(self.ciphertext.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&self.tag);
        out
    }

    pub fn parse(data: &[u8]) -> Result<Self, Outcome> {
        if data.len() < 4 || &data[..4] != KEYWRAP_MAGIC {
            return Err(Outcome::VaultCorrupt);
        }
        let salt_start = 4;
        if data.len() < salt_start + KEYWRAP_SALT_LEN + 1 {
            return Err(Outcome::VaultCorrupt);
        }
        let mut salt = [0u8; KEYWRAP_SALT_LEN];
        salt.copy_from_slice(&data[salt_start..salt_start + KEYWRAP_SALT_LEN]);
        let alg_pos = salt_start + KEYWRAP_SALT_LEN;
        let alg = SealAlg::from_byte(data[alg_pos]).ok_or(Outcome::VaultCorrupt)?;
        let nonce_len = alg.nonce_len();
        let nonce_start = alg_pos + 1;
        if data.len() < nonce_start + nonce_len + 4 {
            return Err(Outcome::VaultCorrupt);
        }
        let nonce = data[nonce_start..nonce_start + nonce_len].to_vec();
        let ct_len_pos = nonce_start + nonce_len;
        let ct_len = u32::from_le_bytes(data[ct_len_pos..ct_len_pos + 4].try_into().unwrap()) as usize;
        let ct_start = ct_len_pos + 4;
        let tag_start = ct_start.checked_add(ct_len).ok_or(Outcome::VaultCorrupt)?;
        let end = tag_start.checked_add(TAG_LEN).ok_or(Outcome::VaultCorrupt)?;
        if data.len() != end {
            return Err(Outcome::VaultCorrupt);
        }
        let ciphertext = data[ct_start..tag_start].to_vec();
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&data[tag_start..end]);
        Ok(KeyWrapFile { salt, alg, nonce, ciphertext, tag })
    }
}

/// Path of the key-wrap sidecar for a given vault file path — same
/// directory, `.keywrap` appended to the full file name (so
/// `alice.sshclientx` gets `alice.sshclientx.keywrap`, never colliding with
/// the vault file, the `.tmp` write target, or a legacy `.submarine` file).
pub fn keywrap_path(vault_path: &Path) -> PathBuf {
    let mut name = vault_path.file_name().unwrap_or_default().to_os_string();
    name.push(".keywrap");
    vault_path.with_file_name(name)
}

// ---------------------------------------------------------------------------
// Sealing and revision history (T026, T027).
// ---------------------------------------------------------------------------

/// Directory holding a profile's local revision history — five most recent
/// prior sealed states (FR-006), used when the current file fails
/// verification or a restore is unwanted.
pub fn revisions_dir(vault_path: &Path) -> PathBuf {
    let mut name = vault_path.file_name().unwrap_or_default().to_os_string();
    name.push(".revisions");
    vault_path.with_file_name(name)
}

const REVISION_HISTORY_DEPTH: usize = 5;

/// Before overwriting `vault_path`, copy its current contents into the
/// revisions directory, named by that file's own `generation` (peeked from
/// the header — no decryption needed), then prune down to the five most
/// recent. Called BEFORE the atomic tmp-write of the new content, so a
/// crash between rotation and rename leaves either the old current file or
/// the new one intact — never neither, and the rotated-out copy is safe
/// either way since it's a copy, not a move.
pub(crate) fn rotate_into_history(vault_path: &Path) -> Result<(), String> {
    if !vault_path.exists() {
        return Ok(());
    }
    let dir = revisions_dir(vault_path);
    fs::create_dir_all(&dir).map_err(|e| format!("[FILE] REVISIONS_MKDIR_FAILED: {}", e))?;
    let bytes = fs::read(vault_path).map_err(|e| format!("[FILE] REVISION_READ_FAILED: {}", e))?;
    // Structural parse only (magic/format/length/hash) — no decryption, no
    // key needed, just enough to learn the generation to name the copy by.
    let sealed = SealedVaultFile::parse(&bytes)
        .map_err(|e| format!("[VAULT] REVISION_PARSE_FAILED: {}", e))?;
    let dest = dir.join(format!("g{}.sshclientx", sealed.generation));
    fs::copy(vault_path, &dest).map_err(|e| format!("[FILE] REVISION_COPY_FAILED: {}", e))?;
    prune_history(&dir, REVISION_HISTORY_DEPTH)
}

fn prune_history(dir: &Path, keep: usize) -> Result<(), String> {
    let mut entries: Vec<(u64, PathBuf)> = fs::read_dir(dir)
        .map_err(|e| format!("[FILE] REVISIONS_READ_DIR_FAILED: {}", e))?
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            name.strip_prefix('g')
                .and_then(|s| s.strip_suffix(".sshclientx"))
                .and_then(|n| n.parse::<u64>().ok())
                .map(|gen| (gen, e.path()))
        })
        .collect();
    entries.sort_by_key(|(gen, _)| std::cmp::Reverse(*gen));
    for (_, path) in entries.into_iter().skip(keep) {
        let _ = fs::remove_file(path);
    }
    Ok(())
}

/// Seal `plaintext` (the uncompressed SQLite serialisation) under `dek`,
/// advance to `new_generation`, atomically replace `vault_path`, and rotate
/// the five-deep revision history (FR-005, FR-006, FR-026 atomicity carried
/// over unchanged from the legacy save path).
///
/// `profile_name` identifies the high-water keystore entry to advance
/// (T041, FR-062) — done here, in the one place every save (ordinary save,
/// migration, fresh creation) funnels through, rather than trusted to each
/// caller separately. A failure to update it is deliberately best-effort:
/// the vault write itself already succeeded by the time this runs, and
/// refusing a successful save over a bookkeeping update would be a worse
/// failure mode than a high-water mark that's merely one save stale.
pub fn seal_and_save(
    dek: &[u8; 32],
    kid: [u8; KID_LEN],
    sender_id: [u8; SENDER_ID_LEN],
    sender_name: &str,
    new_generation: u64,
    plaintext: &[u8],
    vault_path: &Path,
    profile_name: &str,
) -> Result<(), String> {
    let compressed = Zeroizing::new(vault_compress(plaintext)?);
    let seal_key = SealKey { alg: SealAlg::XChaCha20Poly1305, key: dek };
    let sealed = SealedVaultFile::seal(&seal_key, kid, new_generation, sender_id, sender_name, &compressed)?;
    let blob = sealed.to_bytes();

    rotate_into_history(vault_path)?;

    let tmp_path = vault_path.with_extension("sshclientx.tmp");
    {
        use std::io::Write as _;
        let mut f = fs::File::create(&tmp_path)
            .map_err(|e| format!("[FILE] VAULT_TMP_CREATE_FAILED at {:?}: {}", tmp_path, e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("[FILE] VAULT_TMP_CHMOD_FAILED at {:?}: {}", tmp_path, e))?;
        }
        f.write_all(&blob)
            .map_err(|e| format!("[FILE] VAULT_TMP_WRITE_FAILED at {:?}: {}", tmp_path, e))?;
        f.sync_all()
            .map_err(|e| format!("[FILE] VAULT_TMP_SYNC_FAILED at {:?}: {}", tmp_path, e))?;
    }
    fs::rename(&tmp_path, vault_path)
        .map_err(|e| format!("[FILE] VAULT_RENAME_FAILED {:?} -> {:?}: {}", tmp_path, vault_path, e))?;

    let _ = crate::keystore::store_high_water(profile_name, new_generation);
    Ok(())
}

// ---------------------------------------------------------------------------
// Rollback detection (T041, T042). data-model.md §2.6.
// ---------------------------------------------------------------------------

/// Compare a file's own revision against the recorded high-water mark for
/// `profile_name` (FR-064). Needs no key material — `file_generation` comes
/// straight from the sealed container's structural header
/// (`SealedVaultFile::parse`), so this check can run before any password
/// is asked for, catching a restored-from-backup file as early as possible.
///
/// A missing high-water entry (profile never saved under this scheme yet)
/// is not a rollback — there is nothing yet to have gone backwards from.
pub fn check_rollback(profile_name: &str, file_generation: u64) -> Result<(), Outcome> {
    let high_water = crate::keystore::load_high_water(profile_name)?;
    if file_generation < high_water {
        return Err(Outcome::VaultRollback);
    }
    Ok(())
}

/// FR-065: the user has deliberately accepted an older file as current.
/// Resets the high-water mark to its revision so the rollback warning does
/// not recur on every subsequent open of this now-accepted file.
pub fn accept_rollback(profile_name: &str, file_generation: u64) -> Result<(), Outcome> {
    crate::keystore::store_high_water(profile_name, file_generation)
}

// ---------------------------------------------------------------------------
// Single writer (T045-T048). research.md Decision 11.
// ---------------------------------------------------------------------------

/// Proof that this process holds exclusive write access to a profile
/// (FR-058, FR-059, FR-060, FR-061). Backed by `std::fs::File::try_lock`
/// on a `<name>.sshclientx.lock` sidecar — never the vault file itself,
/// since atomic-rename-on-save replaces the vault file's inode on every
/// write, which would silently orphan a lock held on it.
///
/// The OS releases the underlying lock automatically when the last handle
/// to this open file closes — including on process crash or `SIGKILL` —
/// which is exactly FR-060's "a claim left by a crashed instance must not
/// block the profile" with no PID file, heartbeat, or stale-claim cleanup
/// code required. Empirically verified (not just read from docs): two
/// independent `File` handles to the same path, even within one process,
/// correctly conflict via `try_lock`, and dropping the first frees the
/// second to succeed.
pub struct WriterClaim {
    // Held only to keep the OS-level lock alive for as long as this value
    // lives; never read from or written to directly.
    _file: fs::File,
}

/// Path of the writer-claim sidecar for a given vault path — same
/// directory, `.lock` appended to the full file name (so
/// `alice.sshclientx` gets `alice.sshclientx.lock`, distinct from the
/// vault file, its `.tmp` write target, and the `.keywrap` sidecar).
pub fn writer_claim_path(vault_path: &Path) -> PathBuf {
    let mut name = vault_path.file_name().unwrap_or_default().to_os_string();
    name.push(".lock");
    vault_path.with_file_name(name)
}

impl WriterClaim {
    /// Attempt to acquire the claim for `vault_path`. `VaultBusy` if
    /// another live instance already holds it (FR-058) — the caller names
    /// the profile in its own error message, since this function only
    /// knows the path.
    pub fn acquire(vault_path: &Path) -> Result<Self, Outcome> {
        let path = writer_claim_path(vault_path);
        let file = fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|_| Outcome::VaultCorrupt)?;
        match file.try_lock() {
            Ok(()) => Ok(WriterClaim { _file: file }),
            Err(std::fs::TryLockError::WouldBlock) => Err(Outcome::VaultBusy),
            Err(std::fs::TryLockError::Error(_)) => Err(Outcome::VaultCorrupt),
        }
    }
}

#[cfg(test)]
mod key_model_tests {
    use super::*;

    #[test]
    fn device_factor_alone_does_not_unwrap_the_dek() {
        let dek = generate_dek();
        let device_factor = generate_device_factor();
        let salt = {
            let mut s = [0u8; KEYWRAP_SALT_LEN];
            rand::thread_rng().fill(&mut s[..]);
            s
        };
        let wrap = KeyWrapFile::create(&device_factor, "correct horse battery staple", salt, &dek)
            .expect("create");

        // Right device factor, WRONG password.
        let result = wrap.unwrap_dek(&device_factor, "wrong password entirely");
        assert!(matches!(result, Err(Outcome::VaultAuth)));
    }

    #[test]
    fn password_alone_does_not_unwrap_the_dek() {
        let dek = generate_dek();
        let device_factor = generate_device_factor();
        let password = "correct horse battery staple";
        let salt = {
            let mut s = [0u8; KEYWRAP_SALT_LEN];
            rand::thread_rng().fill(&mut s[..]);
            s
        };
        let wrap = KeyWrapFile::create(&device_factor, password, salt, &dek).expect("create");

        // Right password, WRONG device factor (simulating a stolen vault
        // file + keywrap opened on a machine that never held this device's
        // keystore entry — SC-011).
        let wrong_factor = generate_device_factor();
        let result = wrap.unwrap_dek(&wrong_factor, password);
        assert!(matches!(result, Err(Outcome::VaultAuth)));
    }

    #[test]
    fn both_factors_together_unwrap_correctly() {
        let dek = generate_dek();
        let device_factor = generate_device_factor();
        let password = "correct horse battery staple";
        let salt = {
            let mut s = [0u8; KEYWRAP_SALT_LEN];
            rand::thread_rng().fill(&mut s[..]);
            s
        };
        let wrap = KeyWrapFile::create(&device_factor, password, salt, &dek).expect("create");
        let unwrapped = wrap.unwrap_dek(&device_factor, password).expect("unwrap");
        assert_eq!(*unwrapped, *dek);
    }

    #[test]
    fn keywrap_file_round_trips_through_bytes() {
        let dek = generate_dek();
        let device_factor = generate_device_factor();
        let password = "hunter2";
        let salt = [7u8; KEYWRAP_SALT_LEN];
        let wrap = KeyWrapFile::create(&device_factor, password, salt, &dek).expect("create");
        let bytes = wrap.to_bytes();
        let parsed = KeyWrapFile::parse(&bytes).expect("parse");
        let unwrapped = parsed.unwrap_dek(&device_factor, password).expect("unwrap");
        assert_eq!(*unwrapped, *dek);
    }

    #[test]
    fn corrupted_keywrap_bytes_fail_closed_not_panic() {
        let dek = generate_dek();
        let device_factor = generate_device_factor();
        let wrap = KeyWrapFile::create(&device_factor, "pw", [1u8; KEYWRAP_SALT_LEN], &dek)
            .expect("create");
        let mut bytes = wrap.to_bytes();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        let parsed = KeyWrapFile::parse(&bytes).expect("still structurally parseable");
        let result = parsed.unwrap_dek(&device_factor, "pw");
        assert!(result.is_err());
    }

    #[test]
    fn seal_and_save_advances_generation_and_keeps_five_revisions() {
        let dir = std::env::temp_dir().join(format!("vault-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let vault_path = dir.join("test.sshclientx");
        // Uniquely named per test run so it can never collide with a real
        // profile's keystore entries, and cleaned up at the end of this
        // test (below) so no keychain entry outlives the test.
        let test_profile = format!("test-seal-and-save-{}", std::process::id());

        let dek = generate_dek();
        let kid = derive_kid(&dek);
        let sender_id = generate_sender_id();

        // Save 8 times, generations 1..=8, to exercise pruning past 5.
        for gen in 1u64..=8 {
            let plaintext = format!("payload at generation {gen}");
            seal_and_save(&dek, kid, sender_id, "test-device", gen, plaintext.as_bytes(), &vault_path, &test_profile)
                .expect("seal_and_save");
        }

        // Current file must be at generation 8 with the matching content.
        let current_bytes = fs::read(&vault_path).unwrap();
        let current = SealedVaultFile::parse(&current_bytes).unwrap();
        assert_eq!(current.generation, 8);
        let opened = current.open(&SealKey { alg: SealAlg::XChaCha20Poly1305, key: &dek }).unwrap();
        let decompressed = vault_decompress(&opened).unwrap();
        assert_eq!(decompressed, b"payload at generation 8");

        // Revision history: exactly 5 files, generations 3..=7 (8 was never
        // rotated in — it's the current file; 1 and 2 were pruned).
        let rev_dir = revisions_dir(&vault_path);
        let mut gens: Vec<u64> = fs::read_dir(&rev_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                e.file_name()
                    .to_string_lossy()
                    .strip_prefix('g')
                    .and_then(|s| s.strip_suffix(".sshclientx"))
                    .and_then(|n| n.parse::<u64>().ok())
            })
            .collect();
        gens.sort_unstable();
        assert_eq!(gens, vec![3, 4, 5, 6, 7], "expected exactly the 5 most recent prior revisions");

        // `seal_and_save` writes a best-effort high-water entry to the real
        // OS keystore under `test_profile` (T041) — clean it up so the
        // test leaves nothing behind, matching how the temp directory
        // below is also removed.
        let _ = crate::keystore::delete_high_water(&test_profile);
        let _ = fs::remove_dir_all(&dir);
    }
}

// ---------------------------------------------------------------------------
// Migration from the legacy format (T033-T036).
// ---------------------------------------------------------------------------

/// What the caller keeps in memory for the rest of this profile session
/// after a successful migration.
pub struct MigratedVault {
    pub dek: Zeroizing<[u8; 32]>,
    pub kid: [u8; KID_LEN],
}

/// Re-seal an already-decrypted legacy vault into the new sealed format at
/// `new_vault_path`, generation 1.
///
/// MUST only be called after `password` has already decrypted the legacy
/// vault successfully (FR-014) — this function does not re-verify the
/// legacy password itself; `plaintext` having been produced at all is the
/// caller's proof of that. It never reads or writes `legacy_path` in any
/// way — the pre-migration file is left completely untouched here. Per
/// FR-015/FR-015a, deleting it is a *separate*, later step the caller takes
/// only after the user acknowledges the one-time migration notice; this
/// function's job ends at "a verified, working sealed vault now exists."
///
/// Crash safety (T035, FR-015/spec Edge Cases "migration interrupted"):
/// every write here goes through the same tmp-write-then-fsync-then-rename
/// discipline as an ordinary save, and the legacy file is never touched, so
/// at any interruption point either the legacy file (untouched) or the new
/// sealed file (complete, verified) is intact — never neither, and the
/// legacy file remains a fallback until the caller positively confirms the
/// new one works.
pub fn migrate_to_sealed(
    plaintext: &[u8],
    password: &str,
    new_vault_path: &Path,
    sender_id: [u8; SENDER_ID_LEN],
    device_factor: [u8; 32],
    profile_name: &str,
) -> Result<MigratedVault, Outcome> {
    // `device_factor` is generated AND stored in the OS keystore by the
    // caller BEFORE this function is called — never generated here. That
    // ordering is load-bearing: if the keystore write failed after this
    // function had already written a sealed file, `resolve_profile_path`
    // would start preferring that now-unopenable sealed file over the
    // still-good legacy one on every future unlock attempt, and migration
    // could never retry. Requiring the factor as an input makes "keystore
    // committed first" a fact the caller must establish, not an ordering
    // this function could get wrong.
    let dek = generate_dek();
    let kid = derive_kid(&dek);

    let mut salt = [0u8; KEYWRAP_SALT_LEN];
    rand::thread_rng().fill(&mut salt[..]);
    let keywrap = KeyWrapFile::create(&device_factor, password, salt, &dek)
        .map_err(|_| Outcome::VaultKdf)?;

    // Generation 1: migration establishes a new vault-key identity. The
    // legacy format had no revision counter to carry forward.
    seal_and_save(&dek, kid, sender_id, "", 1, plaintext, new_vault_path, profile_name)
        .map_err(|_| Outcome::VaultCorrupt)?;

    // T034: verify the re-sealed vault actually opens, byte-for-byte
    // matching what was migrated, before this function reports success.
    let written = fs::read(new_vault_path).map_err(|_| Outcome::VaultCorrupt)?;
    let sealed = SealedVaultFile::parse(&written)?;
    let reopened = sealed.open(&SealKey { alg: SealAlg::XChaCha20Poly1305, key: &dek })?;
    let decompressed = vault_decompress(&reopened).map_err(|_| Outcome::VaultCorrupt)?;
    if decompressed != plaintext {
        return Err(Outcome::VaultCorrupt);
    }

    // The key-wrap sidecar is written only after the vault itself is
    // verified — a failure above must never leave a keywrap file pointing
    // at a vault that doesn't actually work.
    let keywrap_dest = keywrap_path(new_vault_path);
    let keywrap_tmp = keywrap_dest.with_extension("keywrap.tmp");
    fs::write(&keywrap_tmp, keywrap.to_bytes())
        .map_err(|_| Outcome::VaultCorrupt)?;
    fs::rename(&keywrap_tmp, &keywrap_dest)
        .map_err(|_| Outcome::VaultCorrupt)?;

    Ok(MigratedVault { dek, kid })
}

#[cfg(test)]
mod migration_tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("vault-migration-test-{}-{}", std::process::id(), tag));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Build a legacy `OMNV` vault on disk exactly as the pre-migration
    /// code path would have, so migration tests exercise the real legacy
    /// reader, not a shortcut.
    fn write_legacy_vault(path: &Path, password: &str, plaintext: &[u8]) {
        let mut salt = [0u8; LEGACY_SALT_LEN];
        rand::thread_rng().fill(&mut salt[..]);
        let key = legacy_derive_key(password, &salt).unwrap();
        let compressed = vault_compress(plaintext).unwrap();
        let (ciphertext, nonce) = legacy_encrypt(&compressed, &key).unwrap();
        let blob = legacy_write_blob(&salt, &nonce, &ciphertext);
        fs::write(path, blob).unwrap();
    }

    #[test]
    fn migrated_vault_content_matches_the_legacy_vault_exactly() {
        let dir = temp_dir("content-match");
        let legacy_path = dir.join("alice.submarine");
        let password = "correct horse battery staple";
        let plaintext = b"this stands in for a real sqlite serialization";
        write_legacy_vault(&legacy_path, password, plaintext);

        // Simulate the caller's already-succeeded legacy read (this is what
        // setup_master_db_inner does today, unchanged by this function).
        let legacy_bytes = fs::read(&legacy_path).unwrap();
        let (salt, nonce, ciphertext) = legacy_parse_blob(&legacy_bytes).unwrap();
        let mut salt_fixed = [0u8; LEGACY_SALT_LEN];
        salt_fixed.copy_from_slice(&salt);
        let key = legacy_derive_key(password, &salt_fixed).unwrap();
        let raw = legacy_decrypt(&ciphertext, &nonce, &key).unwrap();
        let decompressed = vault_decompress(&raw).unwrap();
        assert_eq!(decompressed, plaintext, "sanity: legacy read must reproduce the original");

        let new_path = dir.join("alice.sshclientx"); // T036: .submarine -> .sshclientx
        let sender_id = generate_sender_id();
        let test_profile = format!("test-migrate-content-match-{}", std::process::id());
        let migrated = migrate_to_sealed(&decompressed, password, &new_path, sender_id, generate_device_factor(), &test_profile)
            .expect("migration should succeed");

        // The legacy file must be completely untouched.
        assert!(legacy_path.exists(), "legacy file must not be deleted by migration itself");
        let legacy_after = fs::read(&legacy_path).unwrap();
        assert_eq!(legacy_after, legacy_bytes, "legacy file must not be modified by migration");

        // The new sealed vault must open with the migrated DEK and match content exactly.
        let sealed_bytes = fs::read(&new_path).unwrap();
        let sealed = SealedVaultFile::parse(&sealed_bytes).unwrap();
        assert_eq!(sealed.generation, 1);
        assert_eq!(sealed.kid, migrated.kid);
        let opened = sealed
            .open(&SealKey { alg: SealAlg::XChaCha20Poly1305, key: &migrated.dek })
            .unwrap();
        let final_plaintext = vault_decompress(&opened).unwrap();
        assert_eq!(final_plaintext, plaintext);

        // migrate_to_sealed's internal seal_and_save writes a best-effort
        // high-water entry to the real OS keystore (T041) — clean it up.
        let _ = crate::keystore::delete_high_water(&test_profile);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_password_never_reaches_migration_and_leaves_legacy_untouched() {
        let dir = temp_dir("wrong-password");
        let legacy_path = dir.join("bob.submarine");
        let real_password = "the real password";
        let plaintext = b"secret content";
        write_legacy_vault(&legacy_path, real_password, plaintext);
        let legacy_bytes_before = fs::read(&legacy_path).unwrap();

        // Attempt to read with the WRONG password — mirrors exactly what
        // setup_master_db_inner does: this must fail before migration is
        // ever attempted, because migrate_to_sealed is never called without
        // a successfully-decrypted plaintext in hand.
        let (salt, nonce, ciphertext) = legacy_parse_blob(&legacy_bytes_before).unwrap();
        let mut salt_fixed = [0u8; LEGACY_SALT_LEN];
        salt_fixed.copy_from_slice(&salt);
        let wrong_key = legacy_derive_key("totally wrong password", &salt_fixed).unwrap();
        let decrypt_result = legacy_decrypt(&ciphertext, &nonce, &wrong_key);
        assert!(decrypt_result.is_err(), "wrong password must fail to decrypt the legacy vault");

        // No new sealed file, no keywrap, and the legacy file untouched.
        let new_path = dir.join("bob.sshclientx");
        assert!(!new_path.exists());
        assert!(!keywrap_path(&new_path).exists());
        let legacy_bytes_after = fs::read(&legacy_path).unwrap();
        assert_eq!(legacy_bytes_after, legacy_bytes_before);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn migration_from_submarine_extension_targets_sshclientx() {
        let dir = temp_dir("extension-rename");
        let legacy_path = dir.join("carol.submarine");
        let password = "pw";
        write_legacy_vault(&legacy_path, password, b"content");
        let legacy_bytes = fs::read(&legacy_path).unwrap();
        let (salt, nonce, ciphertext) = legacy_parse_blob(&legacy_bytes).unwrap();
        let mut salt_fixed = [0u8; LEGACY_SALT_LEN];
        salt_fixed.copy_from_slice(&salt);
        let key = legacy_derive_key(password, &salt_fixed).unwrap();
        let raw = legacy_decrypt(&ciphertext, &nonce, &key).unwrap();
        let decompressed = vault_decompress(&raw).unwrap();

        // The caller (lib.rs's `migrate_vault_path`) is responsible for
        // mapping .submarine -> .sshclientx; this test confirms
        // migrate_to_sealed writes wherever it's told, so that mapping is
        // sufficient on its own (T036).
        let new_path = dir.join("carol.sshclientx");
        let test_profile = format!("test-migrate-extension-rename-{}", std::process::id());
        migrate_to_sealed(&decompressed, password, &new_path, generate_sender_id(), generate_device_factor(), &test_profile).unwrap();
        assert!(new_path.exists());
        assert!(new_path.to_string_lossy().ends_with(".sshclientx"));

        let _ = crate::keystore::delete_high_water(&test_profile);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn keywrap_sidecar_is_never_left_behind_pointing_at_a_missing_vault() {
        // If seal_and_save fails (simulated here by pointing at an
        // unwritable directory), no keywrap file should exist afterward.
        let dir = temp_dir("failure-atomicity");
        let unwritable_path = dir.join("does-not-exist-parent").join("dave.sshclientx");
        let test_profile = format!("test-migrate-failure-atomicity-{}", std::process::id());
        let result = migrate_to_sealed(b"content", "pw", &unwritable_path, generate_sender_id(), generate_device_factor(), &test_profile);
        assert!(result.is_err());
        assert!(!keywrap_path(&unwritable_path).exists());
        let _ = fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod rollback_tests {
    use super::*;

    /// Each test uses a uniquely-named profile so it can never collide
    /// with a real one, and cleans up its keystore entry at the end —
    /// these tests exercise the real OS keystore (high-water is stored
    /// there, T041), so leaving nothing behind matters here the same way
    /// it does for the seal_and_save/migration tests above.
    fn test_profile(tag: &str) -> String {
        format!("test-rollback-{}-{}", tag, std::process::id())
    }

    #[test]
    fn no_recorded_high_water_is_not_a_rollback() {
        let profile = test_profile("no-history");
        // Never saved before — nothing to have gone backwards from.
        assert!(check_rollback(&profile, 1).is_ok());
        let _ = crate::keystore::delete_high_water(&profile);
    }

    #[test]
    fn lower_generation_than_high_water_is_a_rollback() {
        let profile = test_profile("lower-gen");
        crate::keystore::store_high_water(&profile, 10).unwrap();

        let result = check_rollback(&profile, 5);
        assert!(matches!(result, Err(Outcome::VaultRollback)));

        let _ = crate::keystore::delete_high_water(&profile);
    }

    #[test]
    fn equal_or_higher_generation_is_not_a_rollback() {
        let profile = test_profile("equal-or-higher");
        crate::keystore::store_high_water(&profile, 10).unwrap();

        assert!(check_rollback(&profile, 10).is_ok());
        assert!(check_rollback(&profile, 11).is_ok());

        let _ = crate::keystore::delete_high_water(&profile);
    }

    /// The core distinction the spec insisted on: a rollback (the file
    /// underneath the app went backwards, e.g. restored from a backup) is
    /// not the same outcome as an import that's merely older (`BOX_OLDER`,
    /// a deliberate user choice during import) or a damaged file
    /// (`VAULT_CORRUPT`, tampering/truncation). Distinct codes, distinct
    /// messages, so a tester or user can tell them apart from the message
    /// alone.
    #[test]
    fn vault_rollback_is_a_distinct_outcome_from_box_older_and_vault_corrupt() {
        assert_ne!(Outcome::VaultRollback.code(), Outcome::BoxOlder.code());
        assert_ne!(Outcome::VaultRollback.code(), Outcome::VaultCorrupt.code());
        assert_ne!(Outcome::VaultRollback.message(), Outcome::BoxOlder.message());
        assert_ne!(Outcome::VaultRollback.message(), Outcome::VaultCorrupt.message());
    }

    /// FR-065: accepting an older file resets the high-water mark so the
    /// warning does not recur on the NEXT open of that same (now-accepted)
    /// revision.
    #[test]
    fn accepting_a_rollback_stops_the_warning_from_recurring() {
        let profile = test_profile("accept-stops-recurrence");
        crate::keystore::store_high_water(&profile, 10).unwrap();
        assert!(matches!(check_rollback(&profile, 5), Err(Outcome::VaultRollback)));

        accept_rollback(&profile, 5).expect("accept_rollback");

        // The SAME file, at the SAME revision, must no longer be flagged.
        assert!(check_rollback(&profile, 5).is_ok(), "warning must not recur after acceptance");

        // And a genuinely OLDER file than the newly-accepted baseline must
        // still be caught — acceptance resets the baseline, it doesn't
        // disable the check.
        assert!(matches!(check_rollback(&profile, 3), Err(Outcome::VaultRollback)));

        let _ = crate::keystore::delete_high_water(&profile);
    }
}

#[cfg(test)]
mod writer_claim_tests {
    use super::*;

    fn temp_vault_path(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("vault-claim-test-{}-{}", tag, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir.join("profile.sshclientx")
    }

    /// T049: a second acquisition fails while the first guard lives, and
    /// succeeds once it's dropped. Verified with two independent
    /// `WriterClaim`s within this one test process — empirically confirmed
    /// (research phase) that `try_lock` conflicts correctly even between
    /// two handles in the same process, so this is a faithful test of the
    /// cross-process property it stands in for, not a weaker approximation
    /// of it.
    #[test]
    fn second_acquisition_fails_while_first_lives_and_succeeds_after_drop() {
        let path = temp_vault_path("second-fails");

        let first = WriterClaim::acquire(&path).expect("first acquisition must succeed");
        let second = WriterClaim::acquire(&path);
        assert!(matches!(second, Err(Outcome::VaultBusy)), "second acquisition must be refused while the first is held");

        drop(first);
        let third = WriterClaim::acquire(&path);
        assert!(third.is_ok(), "acquisition must succeed once the prior claim is dropped");

        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn claim_locks_a_sidecar_not_the_vault_file_itself() {
        let path = temp_vault_path("sidecar-not-vault");
        let _claim = WriterClaim::acquire(&path).expect("acquire");

        // The vault file itself must remain completely untouched by
        // acquiring a claim — no file created at `path`, only at the
        // `.lock` sidecar path (research.md Decision 11: locking the vault
        // file itself would be orphaned by the atomic rename every save
        // performs).
        assert!(!path.exists(), "acquiring a claim must not create the vault file itself");
        assert!(writer_claim_path(&path).exists(), "the sidecar lock file must exist");

        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn two_different_profiles_claims_do_not_conflict() {
        let path_a = temp_vault_path("profile-a");
        let path_b = temp_vault_path("profile-b");
        let _claim_a = WriterClaim::acquire(&path_a).expect("acquire a");
        let claim_b = WriterClaim::acquire(&path_b);
        assert!(claim_b.is_ok(), "unrelated profiles must never contend for the same claim");

        let _ = fs::remove_dir_all(path_a.parent().unwrap());
        let _ = fs::remove_dir_all(path_b.parent().unwrap());
    }
}

#[cfg(test)]
mod concurrent_export_safety_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    /// T095: an export (a plain read of the current vault path) taken while
    /// a save is in flight must always see one complete revision, never a
    /// half-written one. This is not a code path this test exercises
    /// directly — it is a property of `seal_and_save`'s tmp-write-then-
    /// fsync-then-rename discipline, which never makes a partial write
    /// visible at the final path at all. Proven here by hammering real
    /// concurrent saves against one file from a background thread while
    /// repeatedly reading that same path from the foreground, and asserting
    /// every single read that returns bytes parses as a complete, valid
    /// `SealedVaultFile` — never truncated, never a corrupt fragment.
    #[test]
    fn concurrent_reads_never_observe_a_partial_write() {
        let dir = std::env::temp_dir()
            .join(format!("vault-concurrent-export-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let vault_path = dir.join("test.sshclientx");
        let test_profile = format!("test-concurrent-export-{}", std::process::id());

        let dek = generate_dek();
        let kid = derive_kid(&dek);
        let sender_id = generate_sender_id();

        // Seed an initial complete file so the reader never starts against
        // a nonexistent path.
        seal_and_save(&dek, kid, sender_id, "d", 1, b"seed", &vault_path, &test_profile).unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let writer_path = vault_path.clone();
        let writer_profile = test_profile.clone();
        let writer_stop = Arc::clone(&stop);
        let writer = std::thread::spawn(move || {
            for gen in 2u64..=60 {
                let plaintext = format!("payload at generation {gen}");
                seal_and_save(&dek, kid, sender_id, "d", gen, plaintext.as_bytes(), &writer_path, &writer_profile)
                    .expect("seal_and_save under concurrent read pressure");
            }
            writer_stop.store(true, Ordering::SeqCst);
        });

        let mut reads_checked = 0usize;
        while !stop.load(Ordering::SeqCst) {
            if let Ok(bytes) = fs::read(&vault_path) {
                // Every read that returns anything at all must be a
                // complete, structurally valid container — parse failure
                // here would mean the reader observed a half-written tmp
                // file at the final path, which must be impossible.
                match SealedVaultFile::parse(&bytes) {
                    Ok(_) => reads_checked += 1,
                    Err(e) => panic!("read observed an invalid/partial vault file: {:?}", e),
                }
            }
        }
        writer.join().unwrap();

        assert!(reads_checked > 0, "test didn't actually exercise any concurrent reads");
        let _ = crate::keystore::delete_high_water(&test_profile);
        let _ = fs::remove_dir_all(&dir);
    }
}
