//! Platform authentication (Touch ID / Windows Hello) for the vault lock
//! lifecycle's soft-lock quick re-unlock (FR-054) and for identity
//! confirmation (FR-055). macOS and Windows only — research.md Decision 6:
//! Linux has no portable, distribution-friendly mechanism (polkit needs a
//! root-installed `.policy` file and a running authentication agent, and
//! answers "is this action authorized", not "prove you are the logged-in
//! user"). `#[cfg]`'d out entirely there; callers always fall back to the
//! password on Linux (FR-056), which is why every function here compiles
//! and is callable on every platform but only ever prompts on macOS/Windows.

/// Why a platform-authentication attempt did not end in success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthOutcome {
    /// The user authenticated successfully.
    #[cfg_attr(not(any(target_os = "macos", target_os = "windows")), allow(dead_code))]
    Success,
    /// The user was shown a prompt and failed it (wrong fingerprint/PIN,
    /// cancelled, or fell back to a method the policy doesn't support).
    /// Counts toward the repeated-failure threshold that forces a password
    /// fallback (FR-057, T065).
    #[cfg_attr(not(any(target_os = "macos", target_os = "windows")), allow(dead_code))]
    Failed,
    /// No prompt could be shown at all — no biometrics enrolled, no device
    /// passcode set, the platform has no mechanism (Linux), or (macOS
    /// `LAError -1004`/Windows first-call-after-login) the request was
    /// transiently refused. Does NOT count as a failed attempt: callers
    /// should offer the password immediately rather than retry a prompt
    /// that was never shown (T064).
    Unavailable,
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
mod backend {
    use super::AuthOutcome;
    use robius_authentication::{
        AndroidText, BiometricStrength, Context, Error as AuthError, PolicyBuilder, Text,
        WindowsText,
    };

    /// Bridges `robius_authentication::Context::authenticate`'s callback API
    /// (T062) to async with a `tokio::sync::oneshot`. The callback is `Fn`,
    /// not `FnOnce` (the crate calls it exactly once per our own use, but
    /// the trait bound doesn't guarantee that), so the sender is taken out
    /// of a `Mutex<Option<_>>` on first (and only) invocation.
    pub async fn authenticate(reason: &str) -> AuthOutcome {
        // Both platforms accept "biometrics OR password" as one policy — on
        // Windows this is the ONLY policy `PolicyBuilder::build()` accepts
        // (it refuses ones that turn off either), and on macOS it maps to
        // `LAPolicy::DeviceOwnerAuthentication`, the standard "Touch ID or
        // device passcode" prompt. `companion` (Apple Watch) is harmless to
        // leave on and costs nothing on Windows.
        let Some(policy) = PolicyBuilder::new()
            .biometrics(Some(BiometricStrength::Strong))
            .password(true)
            .companion(true)
            .build()
        else {
            // Unreachable for this exact combination on macOS/Windows, but
            // the crate's own API returns `Option` — honor it rather than
            // `unwrap()` a crate invariant we don't own.
            return AuthOutcome::Unavailable;
        };

        let windows_text = WindowsText::new_truncated("SSHClientX", reason);
        let text = Text {
            android: AndroidText { title: "SSHClientX", subtitle: None, description: Some(reason) },
            apple: reason,
            windows: windows_text,
        };

        let (tx, rx) = tokio::sync::oneshot::channel();
        let tx = std::sync::Mutex::new(Some(tx));
        let started = Context::new(()).authenticate(text, &policy, move |result| {
            if let Some(tx) = tx.lock().unwrap_or_else(|e| e.into_inner()).take() {
                let _ = tx.send(result);
            }
        });

        if started.is_err() {
            return AuthOutcome::Unavailable;
        }

        match rx.await {
            Ok(Ok(())) => AuthOutcome::Success,
            Ok(Err(err)) => classify(err),
            // The sender was dropped without ever being called — treat as
            // unavailable rather than hanging or panicking.
            Err(_) => AuthOutcome::Unavailable,
        }
    }

    /// T064: `LAError.notInteractive` (raw code **-1004** in Apple's own
    /// enum — the crate's `Error::NotInteractive`) fires when the system
    /// refuses to show a prompt right now (app not frontmost, or the very
    /// first call right after login before the window server is ready).
    /// That's a transient refusal to even ask, not a failed answer, so it's
    /// bucketed with the other "couldn't attempt" cases rather than with a
    /// wrong fingerprint — it must never itself burn one of the FR-057
    /// retry-limit attempts.
    fn classify(err: AuthError) -> AuthOutcome {
        match err {
            AuthError::NotInteractive
            | AuthError::Unavailable
            | AuthError::NotEnrolled
            | AuthError::PasscodeNotSet
            | AuthError::BiometryDisconnected
            | AuthError::NotPaired
            | AuthError::CompanionNotAvailable
            | AuthError::NotConfigured
            | AuthError::DisabledByPolicy
            | AuthError::Busy
            | AuthError::InvalidText
            | AuthError::InvalidDimensions
            | AuthError::InvalidActionId
            | AuthError::UpdateRequired
            // A lockout means retrying biometrics is pointless right now —
            // treat like "couldn't attempt" so the caller offers the
            // password instead of counting it as one more failure that
            // could compound toward some retry ceiling (FR-057 forbids
            // exactly that: no attempt limit that can make the vault
            // permanently unopenable).
            | AuthError::Exhausted
            | AuthError::Unknown => AuthOutcome::Unavailable,
            AuthError::Authentication
            | AuthError::UserCanceled
            | AuthError::AppCanceled
            | AuthError::SystemCanceled
            | AuthError::UserFallback
            | AuthError::Timeout => AuthOutcome::Failed,
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
mod backend {
    use super::AuthOutcome;

    /// Linux (and any other target): no platform-authentication mechanism
    /// exists (research.md Decision 6). Always unavailable, never a
    /// "failed" attempt — there is nothing to retry.
    pub async fn authenticate(_reason: &str) -> AuthOutcome {
        AuthOutcome::Unavailable
    }
}

pub use backend::authenticate;

// ---------------------------------------------------------------------------
// Repeated-failure -> password fallback (T065)
// ---------------------------------------------------------------------------

/// FR-057: after this many consecutive *failed* (not merely unavailable)
/// platform-auth attempts, the caller must stop offering the prompt and
/// fall back to the password — but the password path itself never has an
/// attempt limit, so the vault can never become permanently unopenable.
/// Process-only counter, reset by any success or by a full password unlock.
pub const MAX_CONSECUTIVE_FAILURES: u32 = 3;

pub fn should_fall_back_to_password(consecutive_failures: u32) -> bool {
    consecutive_failures >= MAX_CONSECUTIVE_FAILURES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn falls_back_only_after_the_threshold() {
        assert!(!should_fall_back_to_password(0));
        assert!(!should_fall_back_to_password(MAX_CONSECUTIVE_FAILURES - 1));
        assert!(should_fall_back_to_password(MAX_CONSECUTIVE_FAILURES));
        assert!(should_fall_back_to_password(MAX_CONSECUTIVE_FAILURES + 1));
    }
}
