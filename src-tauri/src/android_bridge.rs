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

use jni::objects::{JClass, JObject};
use jni::JNIEnv;

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
        // No sensible recovery: without this, every later keystore call
        // panics anyway. Logging (not panicking) here just makes THIS the
        // diagnosable failure point instead of a confusing panic deep
        // inside `android-native-keyring-store` on first vault use.
        eprintln!("[ANDROID_BRIDGE] failed to obtain the JavaVM handle; keystore access will fail later");
        return;
    };
    let vm_ptr = vm.get_java_vm_pointer();

    // MUST be a global reference, not the local `context` parameter — a
    // local ref is only valid for the duration of this JNI call and would
    // leave `ndk_context` holding a dangling pointer the instant this
    // function returns. `mem::forget` is deliberate: this reference must
    // outlive the entire process (matching what `ndk_context` expects),
    // so it is never released via `DeleteGlobalRef` at all.
    let Ok(global_ref) = env.new_global_ref(context) else {
        eprintln!("[ANDROID_BRIDGE] failed to create a global ref to the Android context; keystore access will fail later");
        return;
    };
    let context_ptr = global_ref.as_obj().as_raw();
    std::mem::forget(global_ref);

    unsafe {
        ndk_context::initialize_android_context(vm_ptr.cast(), context_ptr.cast());
    }

    // v1 never registers a default store on Android. Do it now that
    // ndk-context is set — Store::new reads it and panics if it isn't.
    if let Err(e) = crate::keystore::ensure_android_store() {
        eprintln!("[ANDROID_BRIDGE] failed to register the Android keystore backend: {e}");
    }
}
