//! OS secure-store wrapper for the end-to-end vault (spec 002).
//!
//! Owns every read/write against the platform secret store: the DEK itself,
//! the revision high-water mark kept beside it (rollback detection,
//! data-model.md §2.6), and — later — the platform-authentication-gated
//! quick-unlock entry (FR-054). Every function here is **synchronous and
//! blocking**: `keyring`'s calls can pop a GUI prompt (Keychain access
//! dialog, a Secret Service unlock prompt) and block the calling thread
//! until it's answered or dismissed. Callers on the async Tauri command
//! path MUST wrap every call here in `tokio::task::spawn_blocking` — this
//! module follows the same sync-primitive/async-wrapper split already used
//! for `save_vault_blocking`/`save_vault_async` in `lib.rs`.
//!
//! The one thing this module exists to get right is FR-003 vs FR-003a: a
//! machine with no secret store at all (`VAULT_NO_KEYSTORE`, terminal) must
//! never be confused with a secret store that merely declined one request
//! (`VAULT_KEYSTORE_DENIED`, retryable) — see `classify_error` below and
//! research.md Decision 5.
//!
//! T113/FR-038: nothing in this file is platform-specific — `keyring`'s
//! `Entry` API is identical on Android (backed by
//! `android-native-keyring-store`, enabled in Cargo.toml's Android target
//! block) to what macOS/Windows/Linux already use here. `classify_error`'s
//! generic `NoStorageAccess`/`PlatformFailure` arm already covers Android's
//! own error shape (it collapses into the same `keyring_core::Error`
//! variants) without needing an Android-specific downcast the way Linux's
//! ambiguous D-Bus failure modes did.

use crate::vault::Outcome;

/// Keyring "service" namespace for every artifact this module stores.
/// Distinct suffixes per artifact type, `username` = profile name, so two
/// profiles never collide and the three artifact kinds never collide with
/// each other.
const SERVICE_DEVICE_FACTOR: &str = "com.sshclientx.app.vault.devicefactor";
const SERVICE_HIGH_WATER: &str = "com.sshclientx.app.vault.highwater";
const SERVICE_QUICK_UNLOCK: &str = "com.sshclientx.app.vault.quickunlock";

#[cfg(target_os = "android")]
type PlatformEntry = keyring_core::Entry;
#[cfg(not(target_os = "android"))]
type PlatformEntry = keyring::Entry;

/// Register the Android Keystore-backed store as keyring's default.
///
/// `keyring` 4.2's `v1` feature (what `Entry::new` uses) explicitly refuses
/// to initialize on Android — its `set_credential_store` returns
/// `Invalid("platform")`, after which every `keyring::Entry::new` is a
/// permanent `NoDefaultStore`. T113 enabled `android-native-keyring-store`
/// and `ndk-context`, but never called `set_default_store`, so every vault
/// create/open on Android reported VAULT_NO_KEYSTORE. We set the store
/// ourselves via `keyring_core` after `android_bridge` has initialized
/// `ndk-context`. Failure is not cached: a too-early call (before the JNI
/// bridge) must be allowed to succeed on retry.
#[cfg(target_os = "android")]
pub fn ensure_android_store() -> Result<(), Outcome> {
    use std::sync::Mutex;
    static READY: Mutex<bool> = Mutex::new(false);
    let mut ready = READY.lock().map_err(|_| Outcome::VaultNoKeystore)?;
    if *ready {
        return Ok(());
    }
    let store = android_native_keyring_store::Store::new().map_err(|e| classify_error(&e))?;
    keyring_core::set_default_store(store);
    *ready = true;
    Ok(())
}

fn entry(service: &str, profile: &str) -> Result<PlatformEntry, Outcome> {
    #[cfg(target_os = "android")]
    {
        ensure_android_store()?;
        keyring_core::Entry::new(service, profile).map_err(|e| classify_error(&e))
    }
    #[cfg(not(target_os = "android"))]
    {
        keyring::Entry::new(service, profile).map_err(|e| classify_error(&e))
    }
}

/// Store the 32-byte device factor (`K_device`, research.md Decision 3)
/// for `profile`. This is NOT the DEK — it is one of the two-of-two unlock
/// factors combined with the password to unwrap the DEK from its key-wrap
/// sidecar (`vault::KeyWrapFile`). Overwrites any existing entry.
pub fn store_device_factor(profile: &str, factor: &[u8; 32]) -> Result<(), Outcome> {
    entry(SERVICE_DEVICE_FACTOR, profile)?
        .set_secret(factor)
        .map_err(|e| classify_error(&e))
}

/// Load the 32-byte device factor for `profile`. `VaultNoKeystore`/
/// `VaultKeystoreDenied` per `classify_error`. A missing entry is
/// `VaultUnknownKid` — the store is there, this device simply does not
/// hold this profile's factor (copied vault, or the keystore item was
/// deleted). Mapping that to `VaultNoKeystore` told users their machine
/// could not run the app when Keychain/Credential Manager/Secret Service
/// was sitting there working (FR-003 vs FR-003a; constitution: lost
/// keystore entry is permanent data loss, not "no store exists").
pub fn load_device_factor(profile: &str) -> Result<[u8; 32], Outcome> {
    let secret = match entry(SERVICE_DEVICE_FACTOR, profile)?.get_secret() {
        Ok(bytes) => bytes,
        Err(keyring::Error::NoEntry) => return Err(Outcome::VaultUnknownKid),
        Err(e) => return Err(classify_error(&e)),
    };
    if secret.len() != 32 {
        // A 32-byte DEK should never be anything else; treat as store
        // corruption rather than panicking on the array conversion below.
        return Err(Outcome::VaultCorrupt);
    }
    let mut factor = [0u8; 32];
    factor.copy_from_slice(&secret);
    Ok(factor)
}

/// Remove the stored device factor for `profile` (profile deletion).
pub fn delete_device_factor(profile: &str) -> Result<(), Outcome> {
    match entry(SERVICE_DEVICE_FACTOR, profile)?.delete_credential() {
        Ok(()) => Ok(()),
        // Deleting something already gone is not a failure for our caller.
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(classify_error(&e)),
    }
}

/// Store the revision high-water mark for `profile` (data-model.md §2.6).
/// Deliberately a *separate* keystore entry from the DEK, on the same
/// reasoning as its own storage rule: it must never be recoverable by
/// restoring an old vault *file*, only by restoring this device's keystore
/// state, which an old vault file cannot touch.
pub fn store_high_water(profile: &str, revision: u64) -> Result<(), Outcome> {
    entry(SERVICE_HIGH_WATER, profile)?
        .set_secret(&revision.to_le_bytes())
        .map_err(|e| classify_error(&e))
}

/// Load the revision high-water mark for `profile`. A missing entry means
/// no revision has ever been recorded for this profile (e.g. freshly
/// migrated, or freshly created) — that is normal, not an error, and reads
/// as `0` so the first save always looks like forward progress.
pub fn load_high_water(profile: &str) -> Result<u64, Outcome> {
    match entry(SERVICE_HIGH_WATER, profile)?.get_secret() {
        Ok(bytes) if bytes.len() == 8 => {
            Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
        }
        Ok(_) => Err(Outcome::VaultCorrupt),
        Err(keyring::Error::NoEntry) => Ok(0),
        Err(e) => Err(classify_error(&e)),
    }
}

/// Remove the high-water entry for `profile` (profile deletion).
pub fn delete_high_water(profile: &str) -> Result<(), Outcome> {
    match entry(SERVICE_HIGH_WATER, profile)?.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(classify_error(&e)),
    }
}

/// Store the platform-authentication-gated quick-unlock DEK copy (FR-043b).
/// Whatever gates *this* entry behind biometric/OS-credential confirmation is
/// a platform-store concern outside `keyring`'s portable API — the lock
/// module (T051) is responsible for only calling this after a fresh full
/// unlock, and for calling `delete_quick_unlock` on every hard lock.
pub fn store_quick_unlock(profile: &str, dek: &[u8; 32]) -> Result<(), Outcome> {
    entry(SERVICE_QUICK_UNLOCK, profile)?
        .set_secret(dek)
        .map_err(|e| classify_error(&e))
}

pub fn load_quick_unlock(profile: &str) -> Result<[u8; 32], Outcome> {
    let secret = match entry(SERVICE_QUICK_UNLOCK, profile)?.get_secret() {
        Ok(bytes) => bytes,
        // Soft-lock entry gone (hard lock, crash, or never written) — the
        // password path is the recovery, not "this machine has no store".
        Err(keyring::Error::NoEntry) => return Err(Outcome::VaultAuth),
        Err(e) => return Err(classify_error(&e)),
    };
    if secret.len() != 32 {
        return Err(Outcome::VaultCorrupt);
    }
    let mut dek = [0u8; 32];
    dek.copy_from_slice(&secret);
    Ok(dek)
}

/// MUST be called on every hard lock and on app exit (FR-043a) — releases
/// the quick-unlock reference so a `locked_hard` vault genuinely requires a
/// full unlock. Not finding one to delete is not an error.
pub fn delete_quick_unlock(profile: &str) -> Result<(), Outcome> {
    match entry(SERVICE_QUICK_UNLOCK, profile)?.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(classify_error(&e)),
    }
}

/// Cheap up-front check: is a secret store available on this machine at
/// all? Probes with a real `get_secret` rather than `Entry::store_status()`.
/// `store_status` caches a failure for the process lifetime (research.md
/// risk table) and on Android is permanently `NoDefaultStore` because `v1`
/// refuses that platform. `NoEntry` on the canary name means the store is
/// up — nothing stored under that name is the expected empty result.
///
/// Test-only: every production keystore call already surfaces this same
/// `classify_error` distinction on its own first real operation (e.g.
/// `store_device_factor` during profile creation), so a separate up-front
/// probe adds no production value — this exists solely to let the tests
/// below skip themselves on a CI box with no real secret store.
#[cfg(test)]
fn store_available() -> Result<(), Outcome> {
    match entry("com.sshclientx.app.vault.probe", "availability")?.get_secret() {
        Ok(_) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(classify_error(&e)),
    }
}

/// T018 — the classification the spec insisted on: distinguish "no secret
/// store exists at all" (`VaultNoKeystore`, terminal, FR-003) from "a store
/// exists but this request was denied or is unavailable right now"
/// (`VaultKeystoreDenied`, retryable, FR-003a). `keyring_core::Error` alone
/// collapses this on Linux — its `PlatformFailure`/`NoStorageAccess` wrap an
/// opaque boxed platform error, so telling the two apart needs a downcast to
/// the concrete `secret-service` error underneath. Two checks, not one (see
/// research.md Decision 5): `Unavailable` alone doesn't cover "D-Bus is
/// running but no keyring provider is installed", which shows up as a
/// `Zbus(MethodError(ServiceUnknown | NameHasNoOwner))` instead.
///
/// On Windows and macOS, `NoStorageAccess`/`PlatformFailure` need no
/// downcast — those platforms' own errors (`ERROR_NO_SUCH_LOGON_SESSION`,
/// `errSecNotAvailable`) already surface distinctly enough through the
/// message, and there's no secondary "service not installed" case to catch.
pub fn classify_error(e: &keyring::Error) -> Outcome {
    match e {
        keyring::Error::NoStorageAccess(source) | keyring::Error::PlatformFailure(source) => {
            #[cfg(all(unix, not(any(target_os = "macos", target_os = "android"))))]
            {
                if let Some(outcome) = classify_linux_source(source.as_ref()) {
                    return outcome;
                }
            }
            #[cfg(not(all(unix, not(any(target_os = "macos", target_os = "android")))))]
            {
                let _ = source;
            }
            // No platform-specific signal available (or the downcast
            // didn't match a known case) — the safer default is retryable,
            // not terminal: telling a user their machine can't run the app
            // over a transient/ambiguous failure is the worse mistake.
            Outcome::VaultKeystoreDenied
        }
        keyring::Error::Ambiguous(_) => {
            // T019: multiple Secret Service items matched this entry's
            // attributes — reachable if an earlier build wrote a different
            // attribute schema. Not a "no store" or "denied" situation; the
            // store works, our own data in it is inconsistent.
            Outcome::VaultCorrupt
        }
        keyring::Error::NoDefaultStore => Outcome::VaultNoKeystore,
        // NoEntry is handled by each call site (it's an expected, non-error
        // outcome for high-water/quick-unlock reads) — reaching here means
        // a caller didn't special-case it, which we still map safely rather
        // than panicking.
        keyring::Error::NoEntry => Outcome::VaultNoKeystore,
        // Anything else (BadEncoding, BadDataFormat, BadStoreFormat,
        // TooLong, Invalid, NotSupportedByStore, or a future
        // #[non_exhaustive] variant) is store-side data trouble, not an
        // availability question.
        _ => Outcome::VaultCorrupt,
    }
}

#[cfg(all(unix, not(any(target_os = "macos", target_os = "android"))))]
fn classify_linux_source(source: &(dyn std::error::Error + 'static)) -> Option<Outcome> {
    let ss_err = source.downcast_ref::<secret_service::Error>()?;
    match ss_err {
        // No D-Bus session address, or the socket is missing — headless
        // box, plain SSH session, no session bus at all.
        secret_service::Error::Unavailable => Some(Outcome::VaultNoKeystore),
        // Keyring locked, prompt dismissed, or the service died mid-prompt
        // — all recoverable by trying again.
        secret_service::Error::Locked
        | secret_service::Error::Prompt
        | secret_service::Error::PromptDisconnected => Some(Outcome::VaultKeystoreDenied),
        // D-Bus itself is up, but no keyring provider (gnome-keyring,
        // kwallet, ...) is registered to handle the Secret Service
        // interface. This is `Unavailable`-shaped but arrives as a
        // different error entirely, which is exactly why one check isn't
        // enough here.
        secret_service::Error::Zbus(zbus::Error::MethodError(name, _, _))
            if name.as_str() == "org.freedesktop.DBus.Error.ServiceUnknown"
                || name.as_str() == "org.freedesktop.DBus.Error.NameHasNoOwner" =>
        {
            Some(Outcome::VaultNoKeystore)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests exercise `classify_error` against constructed
    // `keyring::Error` values — they do not touch a real platform secret
    // store, so they run identically in CI on every OS. The Linux-specific
    // downcast arms (T018's actual point) can only be exercised on a Unix,
    // non-macOS target, since `secret_service` is a Linux-only dependency;
    // they still compile-check on Linux CI even though this file is
    // authored and unit-tested here on macOS.

    #[test]
    fn ambiguous_maps_to_corrupt_not_denied_or_no_keystore() {
        let e = keyring::Error::Ambiguous(vec![]);
        assert_eq!(classify_error(&e), Outcome::VaultCorrupt);
    }

    #[test]
    fn no_default_store_maps_to_no_keystore() {
        let e = keyring::Error::NoDefaultStore;
        assert_eq!(classify_error(&e), Outcome::VaultNoKeystore);
    }

    #[test]
    fn opaque_platform_failure_with_unrecognised_source_is_retryable_not_terminal() {
        #[derive(Debug)]
        struct Opaque;
        impl std::fmt::Display for Opaque {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "opaque")
            }
        }
        impl std::error::Error for Opaque {}
        let e = keyring::Error::PlatformFailure(Box::new(Opaque));
        // Safer default: an error we can't classify must not tell the user
        // their machine can't run the app at all.
        assert_eq!(classify_error(&e), Outcome::VaultKeystoreDenied);
    }

    #[test]
    fn no_entry_maps_to_no_keystore() {
        // Reaching classify_error with NoEntry means a call site didn't
        // special-case an expected missing entry (high-water/quick-unlock
        // reads do, and treat it as normal); this is the safe fallback.
        let e = keyring::Error::NoEntry;
        assert_eq!(classify_error(&e), Outcome::VaultNoKeystore);
    }

    #[test]
    fn missing_device_factor_is_unknown_kid_not_no_keystore() {
        let profile = format!("test-missing-df-{}", std::process::id());
        let _ = delete_device_factor(&profile);
        if store_available().is_err() {
            return;
        }
        assert_eq!(
            load_device_factor(&profile),
            Err(Outcome::VaultUnknownKid),
            "a working store with no item for this profile is the other-device case, not 'no store on this machine'"
        );
    }

    #[test]
    fn device_factor_roundtrip_when_store_available() {
        if store_available().is_err() {
            return;
        }
        let profile = format!("test-df-roundtrip-{}", std::process::id());
        let factor = [0x5Au8; 32];
        store_device_factor(&profile, &factor).expect("store");
        let loaded = load_device_factor(&profile).expect("load after store");
        assert_eq!(loaded, factor);
        delete_device_factor(&profile).expect("cleanup");
    }

    #[cfg(all(unix, not(any(target_os = "macos", target_os = "android"))))]
    #[test]
    fn linux_dbus_service_unknown_is_terminal_no_keystore() {
        // D-Bus itself is up, but no keyring provider is registered — this
        // is the case FR-003 vs FR-003a insisted on catching separately
        // from `Unavailable`, since the crate's own Unavailable variant
        // does not cover it.
        let zbus_err = zbus::Error::MethodError(
            "org.freedesktop.DBus.Error.ServiceUnknown".try_into().unwrap(),
            None,
            zbus::Message::method_call("/", "m").unwrap().build(&()).unwrap(),
        );
        let ss_err = secret_service::Error::Zbus(zbus_err);
        let e = keyring::Error::NoStorageAccess(Box::new(ss_err));
        assert_eq!(classify_error(&e), Outcome::VaultNoKeystore);
    }

    #[cfg(all(unix, not(any(target_os = "macos", target_os = "android"))))]
    #[test]
    fn linux_unavailable_is_terminal_no_keystore() {
        let ss_err = secret_service::Error::Unavailable;
        let e = keyring::Error::NoStorageAccess(Box::new(ss_err));
        assert_eq!(classify_error(&e), Outcome::VaultNoKeystore);
    }

    #[cfg(all(unix, not(any(target_os = "macos", target_os = "android"))))]
    #[test]
    fn linux_locked_or_prompt_dismissed_is_retryable() {
        for ss_err in [
            secret_service::Error::Locked,
            secret_service::Error::Prompt,
            secret_service::Error::PromptDisconnected,
        ] {
            let e = keyring::Error::PlatformFailure(Box::new(ss_err));
            assert_eq!(classify_error(&e), Outcome::VaultKeystoreDenied);
        }
    }
}
