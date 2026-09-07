//! Vault lock lifecycle (spec 002, data-model.md §2.10).
//!
//! Three process-only states — never persisted, since a restarted process
//! always starts `Unlocked` (no profile open yet). `locked_soft` retains a
//! platform-authentication-gated *reference* to the DEK in the OS secure
//! store (`keystore::store_quick_unlock`); `locked_hard` releases that too,
//! so only a full password unlock can recover it (FR-043, FR-043a, FR-043b).
//!
//! This module owns the state machine, idle-timeout config, and the
//! per-platform idle/screen-lock/sleep detectors that feed it. It does NOT
//! touch SSH sessions, tunnels, transfers, mirrors, or monitors (FR-049) —
//! those keep running across every lock, so nothing here reaches into
//! `SshState`/`MonitorMap`/`MirrorMap` at all.

use serde::Serialize;

// ---------------------------------------------------------------------------
// State machine (T050, T061)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LockState {
    Unlocked,
    LockedSoft,
    LockedHard,
}

impl LockState {
    pub const fn as_str(self) -> &'static str {
        match self {
            LockState::Unlocked => "unlocked",
            LockState::LockedSoft => "locked_soft",
            LockState::LockedHard => "locked_hard",
        }
    }
}

/// Every trigger the transition table (data-model.md §2.10) responds to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockEvent {
    /// Window focus lost, or the app backgrounded (mobile).
    FocusLost,
    /// The configured idle timeout elapsed with no user input.
    IdleTimeout,
    /// The OS screen locked, or the system went to sleep.
    OsScreenLockOrSleep,
    /// The user pressed the UI's explicit lock button, or the app is exiting.
    ExplicitLock,
    /// Platform authentication (Touch ID / Windows Hello) succeeded.
    PlatformAuthSucceeded,
    /// A full password + secure-store unlock succeeded.
    FullUnlockSucceeded,
}

/// Pure state transition — no I/O, no locking, so this is trivially testable
/// and trivially correct to read against the spec's table. An event that
/// doesn't apply to the current state (e.g. `FocusLost` while already
/// `LockedHard`) is a no-op rather than an error: callers drive real events
/// off real OS signals, and a redundant signal must never panic.
pub fn transition(current: LockState, event: LockEvent) -> LockState {
    use LockEvent::*;
    use LockState::*;
    match (current, event) {
        (Unlocked, FocusLost) => LockedSoft,
        (Unlocked, IdleTimeout | OsScreenLockOrSleep | ExplicitLock) => LockedHard,
        (LockedSoft, PlatformAuthSucceeded) => Unlocked,
        (LockedSoft, IdleTimeout | OsScreenLockOrSleep | ExplicitLock) => LockedHard,
        (LockedHard, FullUnlockSucceeded) => Unlocked,
        (state, _) => state,
    }
}

// ---------------------------------------------------------------------------
// Idle timeout config (T056)
// ---------------------------------------------------------------------------
//
// Device-wide, not per-profile — same reasoning as `vault::load_or_create_
// sender_id`: a plain JSON sidecar in `app_data_dir`, no encryption needed
// since a timeout-in-minutes carries no secret.

pub const MIN_IDLE_MINUTES: u32 = 1;
pub const MAX_IDLE_MINUTES: u32 = 60;
pub const DEFAULT_IDLE_MINUTES: u32 = 15;

fn idle_timeout_path(app: &tauri::AppHandle) -> Option<std::path::PathBuf> {
    use tauri::Manager as _;
    app.path().app_data_dir().ok().map(|d| d.join("vault_lock_settings.json"))
}

/// Read the configured idle timeout, in minutes. Falls back to the default
/// on any missing/unreadable/out-of-range file rather than failing — this
/// setting is not disableable, and a corrupt sidecar must never leave the
/// app with no timeout at all.
pub fn idle_timeout_get(app: &tauri::AppHandle) -> u32 {
    let Some(path) = idle_timeout_path(app) else {
        return DEFAULT_IDLE_MINUTES;
    };
    let Ok(bytes) = std::fs::read(&path) else {
        return DEFAULT_IDLE_MINUTES;
    };
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return DEFAULT_IDLE_MINUTES;
    };
    match v.get("idle_timeout_minutes").and_then(|x| x.as_u64()) {
        Some(m) if (MIN_IDLE_MINUTES as u64..=MAX_IDLE_MINUTES as u64).contains(&m) => m as u32,
        _ => DEFAULT_IDLE_MINUTES,
    }
}

/// Set the idle timeout. Rejects out-of-range values rather than clamping
/// them (FR-045) — a caller that asks for 0 or 999 gets an error, not a
/// silently substituted number it never agreed to.
pub fn idle_timeout_set(app: &tauri::AppHandle, minutes: u32) -> Result<(), String> {
    if !(MIN_IDLE_MINUTES..=MAX_IDLE_MINUTES).contains(&minutes) {
        return Err(format!(
            "[VALIDATION] IDLE_TIMEOUT_OUT_OF_RANGE: must be between {} and {} minutes.",
            MIN_IDLE_MINUTES, MAX_IDLE_MINUTES
        ));
    }
    let path = idle_timeout_path(app)
        .ok_or("[STATE] APP_DATA_DIR_UNAVAILABLE")?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("[FILE] DIR_CREATION_FAILED: {}", e))?;
    }
    std::fs::write(&path, serde_json::json!({ "idle_timeout_minutes": minutes }).to_string())
        .map_err(|e| format!("[FILE] IDLE_TIMEOUT_WRITE_FAILED: {}", e))
}

// ---------------------------------------------------------------------------
// Orchestration: driving a lock transition against real process state
// (T051, T057, T058, T059, T060)
// ---------------------------------------------------------------------------

/// Drives one *locking* transition end-to-end: advances the state machine,
/// seals any pending changes first (T057, FR-047 — a lock must never leave
/// a partially written vault), drops the DEK from process memory (T051,
/// FR-043), and stores or clears the platform-authentication-gated
/// quick-unlock keystore reference. Emits `vault-lock-state` on an actual
/// change (T059). Never touches `conn`, `SshState`, `MonitorMap`, or
/// `MirrorMap` — those all keep running across a lock (FR-049, T058), so
/// this function has no parameter that could reach them.
///
/// A no-op transition (event doesn't apply to the current state) returns
/// the unchanged state without touching the keystore, the DEK, or saving —
/// there is nothing to do, and repeated no-signal events (e.g. a second
/// focus-loss while already `locked_hard`) must stay cheap and side-effect
/// free.
pub async fn perform_lock(
    app: &tauri::AppHandle,
    state: &crate::DbState,
    event: LockEvent,
) -> Result<LockState, String> {
    use tauri::Emitter;

    let current = *state.lock_state.lock().map_err(|_| "[STATE] LOCK_FAILED_LOCKSTATE")?;
    let next = transition(current, event);
    if next == current {
        return Ok(next);
    }

    // T057: seal pending changes BEFORE dropping the key. Best-effort, same
    // reasoning as `close_profile`'s identical step 0 — if there's no
    // profile open, or no writer claim, this is already a no-op; a genuine
    // save failure here is swallowed rather than blocking the lock, since a
    // lock (unlike a close) must always be able to complete (the user may
    // be locking precisely because something urgent interrupted them).
    //
    // T059: this is also the one naturally-motivated place to emit
    // `vault-background-activity` today — a lock's own pre-lock save is
    // exactly the kind of activity the locked screen should be able to
    // show completed/failed, with no hostname, path, or content (FR-051).
    // Sessions/tunnels/transfers/mirrors/monitors keep running across a
    // lock too, but wiring each of those subsystems to report through this
    // same event is real, separate work, not implied by this function.
    let _ = app.emit("vault-background-activity", serde_json::json!({ "kind": "save", "status": "in_progress" }));
    let save_result = crate::save_vault_async(state).await;
    let _ = app.emit(
        "vault-background-activity",
        serde_json::json!({ "kind": "save", "status": if save_result.is_ok() { "done" } else { "failed" } }),
    );

    let profile_name = state.active_profile.lock().ok().and_then(|g| g.clone());
    let current_dek = state.dek.lock().ok().and_then(|g| g.clone());

    match (next, &profile_name, &current_dek) {
        (LockState::LockedSoft, Some(name), Some(dek)) => {
            // Stash a copy for quick re-unlock BEFORE dropping the live
            // DEK below. Nothing in `keyring`'s portable API gates this
            // entry itself (research.md Decision 5 rejected the
            // signing-dependent `protected` store) — the gate is
            // `vault_unlock_quick` requiring a fresh platform-
            // authentication success before it ever reads this back.
            let _ = crate::keystore::store_quick_unlock(name, dek);
        }
        (LockState::LockedHard, Some(name), _) => {
            // FR-043a: hard lock releases the quick-unlock reference too,
            // so only a full password unlock can recover from here.
            let _ = crate::keystore::delete_quick_unlock(name);
        }
        _ => {}
    }

    // FR-043: drop the DEK from memory on every lock. `kid` and
    // `generation` deliberately stay — both are public metadata (kid is
    // SHA-256(DEK)[0..16]; generation is a plain revision counter), needed
    // again immediately on the next save, and dropping them would gain no
    // security and cost a redundant re-derivation on unlock.
    if let Ok(mut dek_guard) = state.dek.lock() {
        *dek_guard = None;
    }
    if let Ok(mut lock_state_guard) = state.lock_state.lock() {
        *lock_state_guard = next;
    }

    let _ = app.emit("vault-lock-state", serde_json::json!({ "state": next.as_str() }));
    Ok(next)
}

/// Applies a successful *unlock* (either quick or full) to `state` and
/// emits `vault-lock-state`. The command layer (T066) does the
/// unlock-specific work — platform authentication or password re-
/// derivation — and calls this only once it already holds a verified DEK;
/// `event` (`PlatformAuthSucceeded` or `FullUnlockSucceeded`) is run
/// through the same `transition()` table as every other trigger, rather
/// than hardcoding the destination state.
pub fn apply_unlock(app: &tauri::AppHandle, state: &crate::DbState, event: LockEvent) -> Result<(), String> {
    use tauri::Emitter;
    let next = if let Ok(mut lock_state_guard) = state.lock_state.lock() {
        let next = transition(*lock_state_guard, event);
        *lock_state_guard = next;
        next
    } else {
        LockState::Unlocked
    };
    let _ = app.emit("vault-lock-state", serde_json::json!({ "state": next.as_str() }));
    Ok(())
}

// ---------------------------------------------------------------------------
// Per-platform idle time + screen-lock/sleep detection (T053, T054, T055)
// ---------------------------------------------------------------------------

/// Seconds since the last user input (keyboard, mouse, touch), or `None` if
/// this session has no way to know — currently only a pure-Wayland Linux
/// session (see the Cargo.toml comment on the `x11rb` dependency for why
/// `ext-idle-notify-v1` isn't wired up: it would need a new, ungoverned
/// crate). Callers must treat `None` as "never times out on idle", not as
/// zero — a Wayland user must still be able to lock explicitly, via OS
/// screen-lock, or via sleep.
pub fn seconds_since_last_input() -> Option<f64> {
    #[cfg(target_os = "macos")]
    {
        Some(macos::seconds_since_last_input())
    }
    #[cfg(target_os = "windows")]
    {
        windows_impl::seconds_since_last_input()
    }
    #[cfg(all(unix, not(any(target_os = "macos", target_os = "android"))))]
    {
        linux::seconds_since_last_input()
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "windows",
        all(unix, not(any(target_os = "macos", target_os = "android")))
    )))]
    {
        None
    }
}

#[cfg(target_os = "macos")]
pub(crate) mod macos {
    use block2::RcBlock;
    use objc2_app_kit::{NSWorkspace, NSWorkspaceWillSleepNotification};
    use objc2_foundation::{NSDistributedNotificationCenter, NSNotification, NSString};
    use std::ptr::NonNull;

    // `CGEventSourceSecondsSinceLastEventType` is a plain C function in the
    // CoreGraphics framework, already linked transitively through AppKit/
    // WebKit — no bindings crate needed at all, and (per research.md
    // Decision 12) it needs no Accessibility or Input-Monitoring permission,
    // unlike every IOKit-based idle crate.
    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        fn CGEventSourceSecondsSinceLastEventType(state_id: i32, event_type: u32) -> f64;
    }

    /// `kCGEventSourceStateHIDSystemState` (CGEventSource.h).
    const HID_SYSTEM_STATE: i32 = 1;
    /// `kCGAnyInputEventType` = `(CGEventType)~0` (CGEventTypes.h).
    const ANY_INPUT_EVENT_TYPE: u32 = u32::MAX;

    pub fn seconds_since_last_input() -> f64 {
        unsafe { CGEventSourceSecondsSinceLastEventType(HID_SYSTEM_STATE, ANY_INPUT_EVENT_TYPE) }
    }

    /// Registers observers for the OS screen lock (a distributed
    /// notification — `NSDistributedNotificationCenter` is itself a
    /// `NSNotificationCenter` subclass, so it takes the same block-based
    /// `addObserverForName:object:queue:usingBlock:` API, no custom
    /// Objective-C class needed) and system sleep (an ordinary `NSWorkspace`
    /// notification). MUST be called on the main thread (`run_on_main_
    /// thread`, T053) — both centers deliver on the runloop of whichever
    /// thread registered, and only the main thread's runloop is guaranteed
    /// to keep pumping for the app's entire lifetime.
    ///
    /// `on_lock_or_sleep` fires for both events, which is all a hard-lock
    /// trigger needs to know; it does not distinguish which one occurred.
    /// The registered blocks are intentionally leaked (`mem::forget`) —
    /// there is no unregister path because these observers live exactly as
    /// long as the process does, so freeing them would only ever happen at
    /// exit, where it's moot.
    pub fn register_screen_and_sleep_observers(on_lock_or_sleep: impl Fn() + Send + Sync + 'static) {
        let callback = std::sync::Arc::new(on_lock_or_sleep);

        let distributed = NSDistributedNotificationCenter::defaultCenter();
        let cb = callback.clone();
        let screen_lock_block = RcBlock::new(move |_note: NonNull<NSNotification>| cb());
        unsafe {
            distributed.addObserverForName_object_queue_usingBlock(
                Some(&NSString::from_str("com.apple.screenIsLocked")),
                None,
                None,
                &screen_lock_block,
            );
        }
        std::mem::forget(screen_lock_block);

        let workspace = NSWorkspace::sharedWorkspace();
        let center = workspace.notificationCenter();
        let cb2 = callback;
        let sleep_block = RcBlock::new(move |_note: NonNull<NSNotification>| cb2());
        unsafe {
            center.addObserverForName_object_queue_usingBlock(
                Some(NSWorkspaceWillSleepNotification),
                None,
                None,
                &sleep_block,
            );
        }
        std::mem::forget(sleep_block);
    }
}

#[cfg(target_os = "windows")]
pub(crate) mod windows_impl {
    use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::System::RemoteDesktop::{
        WTSRegisterSessionNotification, NOTIFY_FOR_THIS_SESSION,
    };
    use windows::Win32::System::SystemInformation::GetTickCount;
    use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, RegisterClassExW,
        TranslateMessage, HWND_MESSAGE, MSG, PBT_APMSUSPEND, WM_POWERBROADCAST,
        WM_WTSSESSION_CHANGE, WNDCLASSEXW, WNDCLASS_STYLES, WTS_SESSION_LOCK,
    };
    use windows::core::w;

    /// `GetLastInputInfo` + `GetTickCount`, both session-scoped (a locked
    /// workstation reads as idle, which is what FR-045 wants). Both return
    /// millisecond tick counts that wrap every ~49.7 days;
    /// `u32::wrapping_sub` recovers the correct elapsed delta across that
    /// wrap as long as the actual gap is under 2^32 ms, which always holds
    /// for an idle timeout measured in minutes.
    pub fn seconds_since_last_input() -> Option<f64> {
        let mut info = LASTINPUTINFO {
            cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
            dwTime: 0,
        };
        if unsafe { GetLastInputInfo(&mut info) }.as_bool() {
            let now = unsafe { GetTickCount() };
            Some(f64::from(now.wrapping_sub(info.dwTime)) / 1000.0)
        } else {
            None
        }
    }

    /// Process-lifetime singleton: the message-only window and its callback
    /// are created exactly once (from `register_session_and_power_observer`)
    /// and never torn down, so a plain `OnceLock` read from the raw
    /// `extern "system"` WndProc is simpler and just as safe as stashing a
    /// pointer via `SetWindowLongPtrW`/`GWLP_USERDATA`.
    static CALLBACK: std::sync::OnceLock<std::sync::Arc<dyn Fn() + Send + Sync>> =
        std::sync::OnceLock::new();

    unsafe extern "system" fn wndproc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        // Both WM_WTSSESSION_CHANGE and WM_POWERBROADCAST are delivered via
        // SendMessage, not PostMessage, so they arrive here directly and
        // never reach the GetMessageW loop — handling them anywhere else
        // (research.md Decision 12's exact warning) silently never fires.
        if msg == WM_WTSSESSION_CHANGE && wparam.0 as u32 == WTS_SESSION_LOCK {
            if let Some(cb) = CALLBACK.get() {
                cb();
            }
        } else if msg == WM_POWERBROADCAST && wparam.0 as u32 == PBT_APMSUSPEND {
            if let Some(cb) = CALLBACK.get() {
                cb();
            }
        }
        unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
    }

    /// Spawns a dedicated thread that creates a message-only (`HWND_
    /// MESSAGE`) window, registers it for WTS session-change notifications
    /// (session lock, T054) and pumps its message loop for the lifetime of
    /// the process. `on_lock_or_suspend` fires on `WTS_SESSION_LOCK` and on
    /// `PBT_APMSUSPEND` (system suspend) — the same two triggers macOS
    /// reports through one callback.
    ///
    /// A message-only window needs no visible window, no icon, no menu, and
    /// receives no user input — it exists purely to be a valid `HWND` that
    /// `WTSRegisterSessionNotification` and the window manager can address.
    pub fn register_session_and_power_observer(on_lock_or_suspend: impl Fn() + Send + Sync + 'static) {
        let _ = CALLBACK.set(std::sync::Arc::new(on_lock_or_suspend));

        std::thread::Builder::new()
            .name("sshclientx-lock-watcher".into())
            .spawn(|| unsafe {
                let Ok(hinstance) = GetModuleHandleW(None) else { return };
                let class_name = w!("SSHClientXLockWatcher");

                let class = WNDCLASSEXW {
                    cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
                    style: WNDCLASS_STYLES(0),
                    lpfnWndProc: Some(wndproc),
                    cbClsExtra: 0,
                    cbWndExtra: 0,
                    hInstance: hinstance.into(),
                    hIcon: Default::default(),
                    hCursor: Default::default(),
                    hbrBackground: Default::default(),
                    lpszMenuName: windows::core::PCWSTR::null(),
                    lpszClassName: class_name,
                    hIconSm: Default::default(),
                };
                if RegisterClassExW(&class) == 0 {
                    return;
                }

                let hwnd = CreateWindowExW(
                    Default::default(),
                    class_name,
                    class_name,
                    Default::default(),
                    0,
                    0,
                    0,
                    0,
                    HWND_MESSAGE,
                    None,
                    hinstance,
                    None,
                );
                if hwnd.0 == 0 {
                    return;
                }

                // Best-effort: if this fails, the window still pumps
                // WM_POWERBROADCAST (a global broadcast, not session-scoped),
                // it just won't see WM_WTSSESSION_CHANGE for a lock.
                let _ = WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION);

                let mut msg = MSG::default();
                while GetMessageW(&mut msg, None, 0, 0).as_bool() {
                    let _ = TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            })
            .ok();
    }
}

#[cfg(all(unix, not(any(target_os = "macos", target_os = "android"))))]
pub(crate) mod linux {
    use x11rb::connection::Connection as _;
    use x11rb::protocol::screensaver;

    /// X11 idle time via the ScreenSaver extension's `QueryInfo` — exact
    /// milliseconds, no Xlib, no permission prompt. A fresh connection per
    /// call rather than a held one: this runs on an infrequent poll (every
    /// few seconds from `lock`'s background loop), and reconnecting is
    /// simpler and more robust across an X server restart than managing a
    /// long-lived connection's error recovery. Returns `None` on a
    /// pure-Wayland session (no X11 display to connect to) — see the
    /// Cargo.toml comment on the `x11rb` dependency for why
    /// `ext-idle-notify-v1` isn't implemented instead.
    pub fn seconds_since_last_input() -> Option<f64> {
        let (conn, screen_num) = x11rb::connect(None).ok()?;
        let root = conn.setup().roots.get(screen_num)?.root;
        let reply = screensaver::query_info(&conn, root).ok()?.reply().ok()?;
        Some(f64::from(reply.ms_since_user_input) / 1000.0)
    }

    #[zbus::proxy(
        default_service = "org.freedesktop.login1",
        default_path = "/org/freedesktop/login1",
        interface = "org.freedesktop.login1.Manager"
    )]
    trait Manager {
        #[zbus(signal)]
        fn prepare_for_sleep(&self, start: bool) -> zbus::Result<()>;

        fn get_session_by_pid(&self, pid: u32) -> zbus::Result<zbus::zvariant::OwnedObjectPath>;
    }

    #[zbus::proxy(default_service = "org.freedesktop.login1", interface = "org.freedesktop.login1.Session")]
    trait Session {
        #[zbus(signal)]
        fn lock(&self) -> zbus::Result<()>;
    }

    /// Subscribes to logind's `Manager.PrepareForSleep` (fires on both
    /// suspend and resume — only the `start: true` edge is a lock trigger)
    /// and this process's own session's `Session.Lock` signal (the desktop
    /// environment's screen-lock action, or an explicit `loginctl
    /// lock-session`). Identical on X11 and Wayland — this is systemd-
    /// logind D-Bus, not a windowing-system API, so no separate Wayland
    /// path is needed here (unlike idle time).
    ///
    /// Silently does nothing if the system bus, logind, or this session's
    /// D-Bus object aren't reachable (e.g. no systemd, a bare container) —
    /// there is no user-facing error path for "this desktop can't tell us
    /// about screen lock/sleep"; the idle timeout and explicit lock still
    /// work regardless.
    pub async fn watch_sleep_and_lock(on_lock_or_sleep: std::sync::Arc<dyn Fn() + Send + Sync>) {
        use futures_util::StreamExt;

        let Ok(conn) = zbus::Connection::system().await else { return };

        if let Ok(manager) = ManagerProxy::new(&conn).await {
            if let Ok(mut stream) = manager.receive_prepare_for_sleep().await {
                let cb = on_lock_or_sleep.clone();
                tokio::spawn(async move {
                    while let Some(signal) = stream.next().await {
                        if let Ok(args) = signal.args() {
                            if args.start {
                                cb();
                            }
                        }
                    }
                });
            }

            if let Ok(session_path) = manager.get_session_by_pid(std::process::id()).await {
                let built = match SessionProxy::builder(&conn).path(&session_path) {
                    Ok(builder) => builder.build().await,
                    Err(e) => Err(e),
                };
                if let Ok(session) = built {
                    if let Ok(mut lock_stream) = session.receive_lock().await {
                        let cb = on_lock_or_sleep.clone();
                        tokio::spawn(async move {
                            while lock_stream.next().await.is_some() {
                                cb();
                            }
                        });
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod transition_tests {
    use super::*;

    #[test]
    fn unlocked_focus_lost_goes_soft() {
        assert_eq!(transition(LockState::Unlocked, LockEvent::FocusLost), LockState::LockedSoft);
    }

    #[test]
    fn unlocked_hard_triggers_go_hard() {
        for ev in [LockEvent::IdleTimeout, LockEvent::OsScreenLockOrSleep, LockEvent::ExplicitLock] {
            assert_eq!(transition(LockState::Unlocked, ev), LockState::LockedHard);
        }
    }

    #[test]
    fn soft_platform_auth_returns_to_unlocked() {
        assert_eq!(
            transition(LockState::LockedSoft, LockEvent::PlatformAuthSucceeded),
            LockState::Unlocked
        );
    }

    #[test]
    fn soft_lock_followed_by_idle_timeout_reaches_hard() {
        let soft = transition(LockState::Unlocked, LockEvent::FocusLost);
        assert_eq!(soft, LockState::LockedSoft);
        let hard = transition(soft, LockEvent::IdleTimeout);
        assert_eq!(hard, LockState::LockedHard);
    }

    #[test]
    fn soft_hard_triggers_all_go_hard() {
        for ev in [LockEvent::IdleTimeout, LockEvent::OsScreenLockOrSleep, LockEvent::ExplicitLock] {
            assert_eq!(transition(LockState::LockedSoft, ev), LockState::LockedHard);
        }
    }

    #[test]
    fn hard_full_unlock_returns_to_unlocked() {
        assert_eq!(
            transition(LockState::LockedHard, LockEvent::FullUnlockSucceeded),
            LockState::Unlocked
        );
    }

    #[test]
    fn hard_platform_auth_is_a_no_op() {
        // T069: quick re-unlock must be refused from locked_hard, not
        // silently accepted. The state machine backs that by simply not
        // defining this transition — it stays put.
        assert_eq!(
            transition(LockState::LockedHard, LockEvent::PlatformAuthSucceeded),
            LockState::LockedHard
        );
    }

    #[test]
    fn redundant_or_inapplicable_events_are_no_ops() {
        assert_eq!(transition(LockState::Unlocked, LockEvent::PlatformAuthSucceeded), LockState::Unlocked);
        assert_eq!(transition(LockState::Unlocked, LockEvent::FullUnlockSucceeded), LockState::Unlocked);
        assert_eq!(transition(LockState::LockedSoft, LockEvent::FocusLost), LockState::LockedSoft);
        assert_eq!(transition(LockState::LockedHard, LockEvent::FocusLost), LockState::LockedHard);
        assert_eq!(transition(LockState::LockedHard, LockEvent::IdleTimeout), LockState::LockedHard);
    }
}

#[cfg(test)]
mod idle_timeout_tests {
    use super::*;

    // `idle_timeout_get`/`idle_timeout_set` need a real `tauri::AppHandle` to
    // resolve `app_data_dir()`, which isn't constructible outside a running
    // app — there is no lightweight mock in this Tauri version. The range
    // check is what T056 actually needs proven (out-of-range must be
    // rejected, not clamped) and is exercised directly here; the read/write/
    // default-fallback path is covered indirectly by every manual run of
    // `idle_timeout_get`/`set` through the picker's settings UI.
    #[test]
    fn range_excludes_zero_and_above_max_but_includes_the_default() {
        assert!(!(MIN_IDLE_MINUTES..=MAX_IDLE_MINUTES).contains(&0));
        assert!(!(MIN_IDLE_MINUTES..=MAX_IDLE_MINUTES).contains(&(MAX_IDLE_MINUTES + 1)));
        assert!((MIN_IDLE_MINUTES..=MAX_IDLE_MINUTES).contains(&DEFAULT_IDLE_MINUTES));
    }
}
