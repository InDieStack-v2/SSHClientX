//! T113/FR-038: initializes `ndk-context`'s global Android context, which
//! `android-native-keyring-store` (this app's Android keystore backend,
//! see `keystore.rs` and Cargo.toml's Android target block) reads on every
//! `keyring::Entry::new()` call and panics if it was never set.
//!
//! **Verified, not assumed**: `android-native-keyring-store`'s own README
//! claims "Tauri Mobile... already provide[s] this initialization for
//! you." That's checked against this exact dependency tree (Tauri 2.11 /
//! tao 0.35 / wry 0.55) by grepping every cached crate source for
//! `ndk_context::initialize_android_context` — the only call site found
//! anywhere is inside `android-native-keyring-store` itself, expecting a
//! caller to have already done the initializing. Nothing in Tauri, tao, or
//! wry does. This module is that missing initialization, done once from
//! `MainActivity.onCreate` (see the Kotlin side in
//! `gen/android/app/src/main/java/com/sshclientx/app/MainActivity.kt`),
//! which always runs before the WebView can load any JS capable of
//! invoking a Tauri command — so by the time anything could call
//! `keyring::Entry::new()`, this has already run.
//!
//! Uses `tao`'s own `android_fn!` macro (re-exported at `tauri::tao::
//! platform::android::prelude::android_fn`) to generate the JNI export —
//! the same, already-proven mechanism this app's own Tauri/wry dependency
//! chain uses internally for the WebView's JNI bridge — rather than
//! hand-rolling `#[no_mangle] extern "C"` JNI symbol names and risking a
//! mismatched mangled name that would surface as an
//! `UnsatisfiedLinkError` only at runtime, on a real device.

use jni::objects::{JClass, JObject, JValue};
use jni::{JNIEnv, JavaVM};
use std::sync::OnceLock;

static JAVA_VM: OnceLock<usize> = OnceLock::new();
static ACTIVITY_REF: OnceLock<usize> = OnceLock::new();

// Domain/package split follows tao_macros::android_fn's own documented
// convention (`Java_{domain}_{package}_{class}_{function}`, dot-separated
// Java package segments joined by underscores — see the worked example in
// tao_macros' own source): this app's identifier is `com.sshclientx.app`
// and `MainActivity` lives in that exact Kotlin package, so domain =
// `com_sshclientx` (every segment but the last) and package = `app` (the
// last segment) reproduce `Java_com_sshclientx_app_MainActivity_...`,
// matching the real fully-qualified class name byte-for-byte.
tauri::tao::platform::android::prelude::android_fn![
    com_sshclientx,
    app,
    MainActivity,
    initKeystoreContext,
    [JObject<'local>],
    __VOID__
];

#[allow(non_snake_case)]
unsafe fn initKeystoreContext<'local>(env: JNIEnv<'local>, _class: JClass<'local>, context: JObject<'local>) {
    let Ok(vm) = env.get_java_vm() else {
        eprintln!("[ANDROID_BRIDGE] failed to obtain the JavaVM handle; keystore access will fail later");
        return;
    };
    let vm_ptr = vm.get_java_vm_pointer();
    let Ok(global_ref) = env.new_global_ref(&context) else {
        eprintln!("[ANDROID_BRIDGE] failed to create a global ref to the Android activity; keystore access will fail later");
        return;
    };
    let context_ptr = global_ref.as_obj().as_raw();
    let _ = JAVA_VM.set(vm_ptr as usize);
    let _ = ACTIVITY_REF.set(context_ptr as usize);
    std::mem::forget(global_ref);
    unsafe {
        ndk_context::initialize_android_context(vm_ptr.cast(), context_ptr.cast());
    }
    if let Err(e) = crate::keystore::ensure_android_store() {
        eprintln!("[ANDROID_BRIDGE] failed to register the Android keystore backend: {e}");
    }
}

/// Toggle Android's OS-level screenshot and screen-recording protection for
/// the short-lived QR transfer screens. Desktop has no equivalent API.
pub fn set_qr_transfer_screen_secure(enabled: bool) -> Result<(), String> {
    let vm_ptr = *JAVA_VM.get().ok_or("[ANDROID_BRIDGE] JavaVM unavailable")? as *mut jni::sys::JavaVM;
    let activity_ptr = *ACTIVITY_REF.get().ok_or("[ANDROID_BRIDGE] Activity unavailable")? as *mut jni::sys::_jobject;
    let vm = unsafe { JavaVM::from_raw(vm_ptr).map_err(|_| "[ANDROID_BRIDGE] invalid JavaVM")? };
    let mut env = vm.attach_current_thread().map_err(|e| format!("[ANDROID_BRIDGE] attach failed: {e}"))?;
    let activity = unsafe { JObject::from_raw(activity_ptr) };
    env.call_method(&activity, "setQrTransferScreenSecure", "(Z)V", &[JValue::Bool(enabled as u8)])
        .map_err(|e| format!("[ANDROID_BRIDGE] secure-screen call failed: {e}"))?;
    std::mem::forget(activity);
    Ok(())
}
