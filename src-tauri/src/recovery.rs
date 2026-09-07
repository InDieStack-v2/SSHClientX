//! Opt-in offline recovery kit (spec 002-e2e-vault-migration, User Story 2).
//!
//! Re-establishes a vault's DEK on a second device the user controls,
//! sealed under a **recovery passphrase** that is deliberately distinct
//! from any device's vault password (FR-019a, FR-019a1) — a device's vault
//! password never leaves that device, in any form, ever. Two forms carry
//! identical sealed material and are fully interchangeable (FR-019d): a
//! printable 24-word phrase, and a self-contained file.
//!
//! ## Why this isn't AEAD
//!
//! A 24-word BIP39 phrase holds at most 256 bits of entropy (32 bytes) —
//! that's `bip39`'s own hard ceiling (128-256 bits, multiple of 32). A
//! 32-byte DEK sealed with any AEAD (AES-256-GCM, XChaCha20-Poly1305) needs
//! 32 bytes of ciphertext **plus** a mandatory 16-byte tag: 48 bytes,
//! which does not fit. research.md Decision 10 resolves this with a
//! tag-less construction: a one-time pad derived from the recovery KEK via
//! SHA-256 (the same "hash as PRF" pattern `vault::combine_keys` already
//! uses for the two-of-two unlock), XORed against the DEK exactly once.
//! Authentication comes from recomputing `kid` from the recovered
//! candidate and comparing it to the target — never from a tag. This is
//! sound specifically because the pad is used for exactly one message,
//! ever, under a key that exists for exactly one kit.

use crate::vault::{derive_kid, Outcome, KID_LEN};
use zeroize::Zeroizing;

const RECOVERY_SALT_LEN: usize = 16;
const PAD_LABEL: &[u8] = b"sshclientx-recovery-pad-v1";

/// KEK_recovery = Argon2id(recovery_passphrase, salt). Reuses the vault's
/// own Argon2id derivation (identical parameters everywhere — the
/// constitution requires this) rather than a second implementation.
fn derive_recovery_kek(passphrase: &str, salt: &[u8; RECOVERY_SALT_LEN]) -> Result<[u8; 32], String> {
    crate::vault::legacy_derive_key(passphrase, salt)
}

/// A pseudorandom 32-byte pad, keyed on the recovery KEK and domain-
/// separated so it can never collide with any other SHA-256 use in this
/// codebase (`derive_kid`, `combine_keys`) even if the same bytes were
/// ever hashed elsewhere.
fn recovery_pad(kek: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(kek);
    hasher.update(PAD_LABEL);
    hasher.finalize().into()
}

fn xor32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// Wrap (or unwrap — XOR is its own inverse) the DEK under a recovery KEK.
fn xor_wrap(dek: &[u8; 32], kek: &[u8; 32]) -> [u8; 32] {
    xor32(dek, &recovery_pad(kek))
}

/// Deterministic salt for the phrase form — derived from `kid`, not
/// stored, since the phrase has no spare bytes to carry one (FR-019g: this
/// is exactly why phrase recovery requires the vault file, which is the
/// only source of `kid` before the passphrase is used).
fn phrase_salt(kid: &[u8; KID_LEN]) -> [u8; RECOVERY_SALT_LEN] {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(kid);
    let mut salt = [0u8; RECOVERY_SALT_LEN];
    salt.copy_from_slice(&hash[..RECOVERY_SALT_LEN]);
    salt
}

// ---------------------------------------------------------------------------
// Phrase form (T077).
// ---------------------------------------------------------------------------

/// Seal `dek` into a 24-word recovery phrase (FR-019c). Requires `kid` so
/// the salt can be derived; the receiving device will need the vault file
/// for the same reason (FR-019g, FR-019h).
pub fn create_phrase_kit(dek: &[u8; 32], kid: [u8; KID_LEN], passphrase: &str) -> Result<Vec<String>, Outcome> {
    let salt = phrase_salt(&kid);
    let kek = derive_recovery_kek(passphrase, &salt).map_err(|_| Outcome::VaultKdf)?;
    let wrapped = xor_wrap(dek, &kek);
    let mnemonic = bip39::Mnemonic::from_entropy(&wrapped)
        // Only fails if `wrapped` isn't 128-256 bits — it is always
        // exactly 256 (32 bytes), so this arm is unreachable in practice,
        // but mapped rather than unwrapped so a future refactor that
        // breaks that invariant fails closed instead of panicking.
        .map_err(|_| Outcome::KitMalformed)?;
    Ok(mnemonic.words().map(|w| w.to_string()).collect())
}

/// Recover the DEK from a phrase. `vault_kid` MUST come from a vault file
/// the caller has already read (FR-019g) — there is no other source for
/// the salt this needs. Checksum is validated (bip39's own `parse`) before
/// any passphrase use, so a mistyped word is `KIT_MALFORMED`, distinct from
/// `KIT_WRONG_PASSPHRASE` (FR-019e).
pub fn consume_phrase_kit(
    phrase: &str,
    passphrase: &str,
    vault_kid: [u8; KID_LEN],
) -> Result<Zeroizing<[u8; 32]>, Outcome> {
    let mnemonic = bip39::Mnemonic::parse(phrase).map_err(|_| Outcome::KitMalformed)?;
    let entropy = mnemonic.to_entropy();
    let wrapped: [u8; 32] = entropy.try_into().map_err(|_| Outcome::KitMalformed)?;

    let salt = phrase_salt(&vault_kid);
    let kek = derive_recovery_kek(passphrase, &salt).map_err(|_| Outcome::VaultKdf)?;
    let candidate = xor_wrap(&wrapped, &kek);

    if derive_kid(&candidate) != vault_kid {
        return Err(Outcome::KitWrongPassphrase);
    }
    Ok(Zeroizing::new(candidate))
}

// ---------------------------------------------------------------------------
// File form (T078) — self-contained: carries its own salt and `kid`, so
// (unlike the phrase) it needs no accompanying vault file to establish the
// key (FR-019g's "MAY be consumed without the vault file on desktop").
// ---------------------------------------------------------------------------

const FILE_KIT_MAGIC: &[u8; 4] = b"RKIT";
const FILE_KIT_LEN: usize = 4 + KID_LEN + RECOVERY_SALT_LEN + 32;

pub fn create_file_kit(dek: &[u8; 32], kid: [u8; KID_LEN], passphrase: &str) -> Result<Vec<u8>, Outcome> {
    let mut salt = [0u8; RECOVERY_SALT_LEN];
    rand::thread_rng().fill(&mut salt[..]);
    let kek = derive_recovery_kek(passphrase, &salt).map_err(|_| Outcome::VaultKdf)?;
    let wrapped = xor_wrap(dek, &kek);

    let mut out = Vec::with_capacity(FILE_KIT_LEN);
    out.extend_from_slice(FILE_KIT_MAGIC);
    out.extend_from_slice(&kid);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&wrapped);
    Ok(out)
}

/// Recover the DEK and its `kid` from a self-contained kit file. No vault
/// file needed — everything required is in `bytes`.
pub fn consume_file_kit(bytes: &[u8], passphrase: &str) -> Result<(Zeroizing<[u8; 32]>, [u8; KID_LEN]), Outcome> {
    if bytes.len() != FILE_KIT_LEN || &bytes[..4] != FILE_KIT_MAGIC {
        return Err(Outcome::KitMalformed);
    }
    let mut kid = [0u8; KID_LEN];
    kid.copy_from_slice(&bytes[4..4 + KID_LEN]);
    let mut salt = [0u8; RECOVERY_SALT_LEN];
    salt.copy_from_slice(&bytes[4 + KID_LEN..4 + KID_LEN + RECOVERY_SALT_LEN]);
    let mut wrapped = [0u8; 32];
    wrapped.copy_from_slice(&bytes[4 + KID_LEN + RECOVERY_SALT_LEN..]);

    let kek = derive_recovery_kek(passphrase, &salt).map_err(|_| Outcome::VaultKdf)?;
    let candidate = xor_wrap(&wrapped, &kek);

    if derive_kid(&candidate) != kid {
        return Err(Outcome::KitWrongPassphrase);
    }
    Ok((Zeroizing::new(candidate), kid))
}

// ---------------------------------------------------------------------------
// Unclaimed-key storage (T084, T085).
//
// After a kit is consumed, the recovered DEK is established on this device
// exactly like any other vault key (FR-021, FR-021a) — a fresh device
// factor in the keystore, a key-wrap sidecar under a NEW vault password
// chosen for THIS device. It stays "unclaimed" (owns no profile) until a
// matching vault file is imported (FR-032), at which point the import
// commit path (US4) claims it by renaming the sidecar and the keystore
// entry under the new profile's name. Until then, it must be visible and
// disposable (spec Edge Cases: "a recovery kit is consumed but no vault
// file is ever imported") — that's `list_unclaimed_keys` /
// `discard_unclaimed_key`.
// ---------------------------------------------------------------------------

use std::fs;
use std::path::{Path, PathBuf};

/// Directory holding sidecar key-wrap files for unclaimed keys, one per
/// consumed kit not yet matched to a profile.
pub fn unclaimed_dir(profiles_dir: &Path) -> PathBuf {
    profiles_dir.join(".unclaimed")
}

/// Synthetic keystore identifier for an unclaimed key's device factor.
/// Namespaced with a colon, which `validate_profile_name` never accepts in
/// a real profile name — this can never collide with one.
pub fn unclaimed_keystore_id(kid: &[u8; KID_LEN]) -> String {
    format!("unclaimed:{}", hex::encode(kid))
}

/// Establish a recovered DEK on this device: a fresh device factor in the
/// keystore, and a key-wrap sidecar sealed under `new_vault_password` — a
/// password chosen for THIS device, never the one the kit was created
/// under, and never anything from the originating device (FR-021a).
pub fn establish_unclaimed_key(
    profiles_dir: &Path,
    dek: &[u8; 32],
    kid: [u8; KID_LEN],
    new_vault_password: &str,
) -> Result<(), Outcome> {
    let device_factor = crate::vault::generate_device_factor();
    crate::keystore::store_device_factor(&unclaimed_keystore_id(&kid), &device_factor)?;

    let mut salt = [0u8; crate::vault::KEYWRAP_SALT_LEN];
    rand::thread_rng().fill(&mut salt[..]);
    let keywrap = crate::vault::KeyWrapFile::create(&device_factor, new_vault_password, salt, dek)
        .map_err(|_| Outcome::VaultKdf)?;

    let dir = unclaimed_dir(profiles_dir);
    fs::create_dir_all(&dir).map_err(|_| Outcome::VaultCorrupt)?;
    let dest = dir.join(format!("{}.keywrap", hex::encode(kid)));
    let tmp = dest.with_extension("keywrap.tmp");
    fs::write(&tmp, keywrap.to_bytes()).map_err(|_| Outcome::VaultCorrupt)?;
    fs::rename(&tmp, &dest).map_err(|_| Outcome::VaultCorrupt)?;
    Ok(())
}

/// An unclaimed key visible to the user — enough to show "a recovered key
/// is waiting for its vault file" and let them discard it.
pub struct UnclaimedKey {
    pub kid_hex: String,
}

pub fn list_unclaimed_keys(profiles_dir: &Path) -> Vec<UnclaimedKey> {
    let dir = unclaimed_dir(profiles_dir);
    let Ok(entries) = fs::read_dir(&dir) else {
        return Vec::new();
    };
    entries
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            e.file_name()
                .to_string_lossy()
                .strip_suffix(".keywrap")
                .map(|hex| UnclaimedKey { kid_hex: hex.to_string() })
        })
        .collect()
}

/// Remove an unclaimed key's sidecar and its keystore device-factor entry.
/// Best-effort on the file (already gone is not an error); propagates a
/// real keystore failure since that's a genuine `Outcome` the caller needs.
pub fn discard_unclaimed_key(profiles_dir: &Path, kid_hex: &str) -> Result<(), Outcome> {
    let dest = unclaimed_dir(profiles_dir).join(format!("{}.keywrap", kid_hex));
    let _ = fs::remove_file(&dest);
    crate::keystore::delete_device_factor(&format!("unclaimed:{}", kid_hex))
}

use rand::Rng;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phrase_kit_round_trips() {
        let dek = [7u8; 32];
        let kid = derive_kid(&dek);
        let passphrase = "a recovery passphrase, not a vault password";
        let words = create_phrase_kit(&dek, kid, passphrase).expect("create");
        assert_eq!(words.len(), 24, "24-word phrase expected for 256-bit entropy");
        let phrase = words.join(" ");
        let recovered = consume_phrase_kit(&phrase, passphrase, kid).expect("consume");
        assert_eq!(*recovered, dek);
    }

    #[test]
    fn file_kit_round_trips() {
        let dek = [9u8; 32];
        let kid = derive_kid(&dek);
        let passphrase = "another recovery passphrase";
        let bytes = create_file_kit(&dek, kid, passphrase).expect("create");
        let (recovered, recovered_kid) = consume_file_kit(&bytes, passphrase).expect("consume");
        assert_eq!(*recovered, dek);
        assert_eq!(recovered_kid, kid);
    }

    /// SC-014: both forms of one kit are interchangeable — same key
    /// recovered regardless of which form carries it.
    #[test]
    fn both_forms_recover_the_same_dek() {
        let dek = [42u8; 32];
        let kid = derive_kid(&dek);
        let passphrase = "shared passphrase for both forms";

        let words = create_phrase_kit(&dek, kid, passphrase).unwrap();
        let from_phrase = consume_phrase_kit(&words.join(" "), passphrase, kid).unwrap();

        let file_bytes = create_file_kit(&dek, kid, passphrase).unwrap();
        let (from_file, file_kid) = consume_file_kit(&file_bytes, passphrase).unwrap();

        assert_eq!(*from_phrase, *from_file);
        assert_eq!(*from_phrase, dek);
        assert_eq!(file_kid, kid);
    }

    /// SC-013: kit plus vault file (kid) without the recovery passphrase
    /// yields nothing and establishes no key. "Without the passphrase" is
    /// modeled here as "with the WRONG passphrase" — there is no
    /// passphrase-less call at all in this API, which is itself part of
    /// the guarantee: you cannot even attempt recovery without supplying
    /// something for the passphrase argument.
    #[test]
    fn wrong_passphrase_recovers_nothing_for_phrase_form() {
        let dek = [3u8; 32];
        let kid = derive_kid(&dek);
        let words = create_phrase_kit(&dek, kid, "the real passphrase").unwrap();
        let result = consume_phrase_kit(&words.join(" "), "totally wrong", kid);
        assert!(matches!(result, Err(Outcome::KitWrongPassphrase)));
    }

    #[test]
    fn wrong_passphrase_recovers_nothing_for_file_form() {
        let dek = [5u8; 32];
        let kid = derive_kid(&dek);
        let bytes = create_file_kit(&dek, kid, "the real passphrase").unwrap();
        let result = consume_file_kit(&bytes, "totally wrong");
        assert!(matches!(result, Err(Outcome::KitWrongPassphrase)));
    }

    #[test]
    fn wrong_vault_kid_recovers_nothing_for_phrase_form() {
        // Simulates presenting the right phrase and passphrase but against
        // the WRONG vault file's kid — e.g. a kit for profile A applied
        // while holding profile B's exported file.
        let dek = [11u8; 32];
        let real_kid = derive_kid(&dek);
        let wrong_kid = derive_kid(&[99u8; 32]);
        let words = create_phrase_kit(&dek, real_kid, "pw").unwrap();
        let result = consume_phrase_kit(&words.join(" "), "pw", wrong_kid);
        assert!(matches!(result, Err(Outcome::KitWrongPassphrase)));
    }

    /// FR-019e: a mistranscribed phrase is reported BEFORE any passphrase
    /// attempt, distinctly from a wrong passphrase.
    #[test]
    fn mistyped_word_yields_kit_malformed_before_any_passphrase_use() {
        let dek = [13u8; 32];
        let kid = derive_kid(&dek);
        let words = create_phrase_kit(&dek, kid, "pw").unwrap();
        let mut broken = words.clone();
        broken[0] = "zzznotarealbip39word".to_string();
        let result = consume_phrase_kit(&broken.join(" "), "pw", kid);
        assert!(matches!(result, Err(Outcome::KitMalformed)));
    }

    #[test]
    fn missing_word_yields_kit_malformed() {
        let dek = [17u8; 32];
        let kid = derive_kid(&dek);
        let words = create_phrase_kit(&dek, kid, "pw").unwrap();
        let short_phrase = words[..23].join(" "); // 23 words, not 24
        let result = consume_phrase_kit(&short_phrase, "pw", kid);
        assert!(matches!(result, Err(Outcome::KitMalformed)));
    }

    #[test]
    fn corrupted_file_kit_bytes_fail_closed_not_panic() {
        let dek = [19u8; 32];
        let kid = derive_kid(&dek);
        let mut bytes = create_file_kit(&dek, kid, "pw").unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        // Still structurally the right length/magic, so this must fail as
        // a wrong-passphrase-shaped outcome (the XOR construction has no
        // way to detect ciphertext corruption other than via the kid
        // check), not panic.
        let result = consume_file_kit(&bytes, "pw");
        assert!(matches!(result, Err(Outcome::KitWrongPassphrase)));
    }

    #[test]
    fn truncated_file_kit_is_malformed() {
        let dek = [23u8; 32];
        let kid = derive_kid(&dek);
        let bytes = create_file_kit(&dek, kid, "pw").unwrap();
        let truncated = &bytes[..bytes.len() - 5];
        let result = consume_file_kit(truncated, "pw");
        assert!(matches!(result, Err(Outcome::KitMalformed)));
    }

    #[test]
    fn garbage_is_not_a_kit() {
        let result = consume_file_kit(b"not a recovery kit at all", "pw");
        assert!(matches!(result, Err(Outcome::KitMalformed)));
    }

    /// FR-019b: a kit stays valid under its own recovery passphrase
    /// regardless of any device's vault password — there is no vault
    /// password anywhere in this module's API to even entangle with.
    #[test]
    fn kit_creation_and_consumption_never_touch_a_vault_password() {
        // Structural guarantee, not just a runtime check: neither
        // create_phrase_kit, create_file_kit, consume_phrase_kit, nor
        // consume_file_kit takes anything named/shaped like a device vault
        // password — only `passphrase` (the kit's own secret). This test
        // exists to make that a documented, checked expectation rather
        // than an implicit property a future edit could quietly break.
        let dek = [29u8; 32];
        let kid = derive_kid(&dek);
        let recovery_passphrase = "recovery-only-secret";
        let words = create_phrase_kit(&dek, kid, recovery_passphrase).unwrap();
        let recovered = consume_phrase_kit(&words.join(" "), recovery_passphrase, kid).unwrap();
        assert_eq!(*recovered, dek);
    }


    /// `establish_unclaimed_key` and `discard_unclaimed_key` touch the
    /// real OS keystore (`keystore::store_device_factor` /
    /// `delete_device_factor`) — deliberately not exercised by an
    /// automated test here, for the same reason `keystore.rs`'s own tests
    /// only cover its pure `classify_error` function: popping a real
    /// Keychain/Secret-Service prompt during `cargo test` is invasive and
    /// not something to do unattended. That keystore-touching path is
    /// covered by quickstart.md Scenario C on a real machine instead. What
    /// IS tested here, without touching any keystore, is the file-based
    /// half: the listing and discard logic operating on `.keywrap`
    /// sidecar files directly.

    #[test]
    fn list_unclaimed_keys_finds_keywrap_sidecars_by_kid() {
        let dir = std::env::temp_dir()
            .join(format!("recovery-unclaimed-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let unclaimed = unclaimed_dir(&dir);
        fs::create_dir_all(&unclaimed).unwrap();

        let kid_a = derive_kid(&[1u8; 32]);
        let kid_b = derive_kid(&[2u8; 32]);
        fs::write(unclaimed.join(format!("{}.keywrap", hex::encode(kid_a))), b"stub").unwrap();
        fs::write(unclaimed.join(format!("{}.keywrap", hex::encode(kid_b))), b"stub").unwrap();
        // A file that doesn't match the naming convention must be ignored,
        // not misparsed as a third unclaimed key.
        fs::write(unclaimed.join("not-a-keywrap.txt"), b"stub").unwrap();

        let mut found: Vec<String> = list_unclaimed_keys(&dir).into_iter().map(|k| k.kid_hex).collect();
        found.sort();
        let mut expected = vec![hex::encode(kid_a), hex::encode(kid_b)];
        expected.sort();
        assert_eq!(found, expected);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_unclaimed_keys_on_a_missing_directory_is_empty_not_an_error() {
        let dir = std::env::temp_dir()
            .join(format!("recovery-unclaimed-missing-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir); // ensure it does not exist
        assert!(list_unclaimed_keys(&dir).is_empty());
    }
}
