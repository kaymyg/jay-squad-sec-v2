//! Zero-dependency JNI entry points for `com.jaysquadsec.bridge.NativeBridge`.
//!
//! Only six JNIEnv functions are used, addressed by their index in the JNI
//! function table. The indices are fixed by the JNI specification (the table
//! is append-only across JDK and Android releases) and were verified against
//! `jni.h`; a unit test pins them so an accidental edit is caught.
//!
//! Safety properties of this layer:
//! - Java arrays are **copied** into Rust with `GetByteArrayRegion` after a
//!   length check; nothing is pinned, so no Java memory is touched after the
//!   call returns and a hostile array length cannot cause an over-read.
//! - Every entry point catches panics. Unwinding into the JVM is undefined
//!   behaviour; instead the call returns an error code (or null/0).
//! - Handles are registry IDs (see the crate docs), so a Kotlin bug such as a
//!   double close or use-after-close returns `ERR_BAD_HANDLE` rather than
//!   corrupting memory.

#![allow(non_snake_case)] // JNI symbol names are fixed by the Java class.

use crate::{
    engine_free, engine_new, guarded, note_undelivered, submit, take_alerts, ABI_VERSION,
    ERR_INVALID, ERR_NULL, MAX_IDENTITY_LEN, MAX_KIND_LEN, MIN_ALERT_BUFFER,
};
use jay_squad_sec_protocol::MAX_DETAIL_LEN;
use std::ffi::c_void;

type JInt = i32;
type JLong = i64;
type JSize = i32;
type JBoolean = u8;
type JObject = *mut c_void;
type JByteArray = JObject;
type JClass = JObject;
/// `JNIEnv*`: a pointer to a pointer to the JNI function table.
type Env = *mut *const *const c_void;

/// JNI function-table indices (from `struct JNINativeInterface_`).
pub(crate) mod idx {
    pub const EXCEPTION_CLEAR: usize = 17;
    pub const GET_ARRAY_LENGTH: usize = 171;
    pub const NEW_BYTE_ARRAY: usize = 176;
    pub const GET_BYTE_ARRAY_REGION: usize = 200;
    pub const SET_BYTE_ARRAY_REGION: usize = 208;
    pub const EXCEPTION_CHECK: usize = 228;
}

/// Load a function pointer from the JNI function table.
///
/// # Safety
/// `env` must be the valid `JNIEnv*` passed to the current native call.
unsafe fn table_fn(env: Env, index: usize) -> *const c_void {
    // SAFETY: a JNIEnv* points at a pointer to the function table, which has
    // more than 228 entries on every supported JDK/Android version.
    unsafe { *(*env).add(index) }
}

type GetArrayLengthFn = unsafe extern "system" fn(Env, JObject) -> JSize;
type GetByteArrayRegionFn = unsafe extern "system" fn(Env, JByteArray, JSize, JSize, *mut i8);
type NewByteArrayFn = unsafe extern "system" fn(Env, JSize) -> JByteArray;
type SetByteArrayRegionFn = unsafe extern "system" fn(Env, JByteArray, JSize, JSize, *const i8);
type ExceptionCheckFn = unsafe extern "system" fn(Env) -> JBoolean;
type ExceptionClearFn = unsafe extern "system" fn(Env);

/// If a Java exception is pending, clear it and report failure. We never
/// leave an exception pending on return, and never call further JNI functions
/// with one pending.
///
/// # Safety
/// `env` must be valid for the current call.
unsafe fn exception_occurred(env: Env) -> bool {
    // SAFETY: indices are fixed by the JNI spec; env is valid.
    unsafe {
        let check: ExceptionCheckFn = std::mem::transmute(table_fn(env, idx::EXCEPTION_CHECK));
        if check(env) != 0 {
            let clear: ExceptionClearFn = std::mem::transmute(table_fn(env, idx::EXCEPTION_CLEAR));
            clear(env);
            return true;
        }
    }
    false
}

/// Copy a Java `byte[]` into a Rust Vec, enforcing `max` before allocating.
///
/// # Safety
/// `env` must be valid for the current call and `arr` a local or global
/// reference (or null).
unsafe fn read_byte_array(env: Env, arr: JByteArray, max: usize) -> Result<Vec<u8>, i32> {
    if arr.is_null() {
        return Err(ERR_NULL);
    }
    // SAFETY: indices fixed by the JNI spec; env valid; arr non-null.
    unsafe {
        let get_len: GetArrayLengthFn = std::mem::transmute(table_fn(env, idx::GET_ARRAY_LENGTH));
        let len = get_len(env, arr);
        if exception_occurred(env) || len < 0 || len as usize > max {
            return Err(ERR_INVALID);
        }
        let mut buf = vec![0u8; len as usize];
        if len > 0 {
            let get: GetByteArrayRegionFn =
                std::mem::transmute(table_fn(env, idx::GET_BYTE_ARRAY_REGION));
            get(env, arr, 0, len, buf.as_mut_ptr().cast());
            if exception_occurred(env) {
                return Err(ERR_INVALID);
            }
        }
        Ok(buf)
    }
}

/// Create a new Java `byte[]` holding `bytes`. Returns null on failure (and
/// clears any pending exception, e.g. OutOfMemoryError).
///
/// # Safety
/// `env` must be valid for the current call.
unsafe fn new_byte_array(env: Env, bytes: &[u8]) -> JByteArray {
    let Ok(len) = JSize::try_from(bytes.len()) else {
        return std::ptr::null_mut();
    };
    // SAFETY: indices fixed by the JNI spec; env valid; len checked.
    unsafe {
        let new: NewByteArrayFn = std::mem::transmute(table_fn(env, idx::NEW_BYTE_ARRAY));
        let arr = new(env, len);
        if arr.is_null() || exception_occurred(env) {
            return std::ptr::null_mut();
        }
        if len > 0 {
            let set: SetByteArrayRegionFn =
                std::mem::transmute(table_fn(env, idx::SET_BYTE_ARRAY_REGION));
            set(env, arr, 0, len, bytes.as_ptr().cast());
            if exception_occurred(env) {
                return std::ptr::null_mut();
            }
        }
        arr
    }
}

fn handle_from(h: JLong) -> u64 {
    h as u64 // bit-preserving; 0 and unknown IDs are rejected by the registry
}

/// `static native long nativeNew(long bootNonce)` — 0 on failure.
#[no_mangle]
pub extern "system" fn Java_com_jaysquadsec_bridge_NativeBridge_nativeNew(
    _env: Env,
    _cls: JClass,
    boot_nonce: JLong,
) -> JLong {
    engine_new(boot_nonce as u64) as JLong
}

/// `static native int nativeFree(long handle)`.
#[no_mangle]
pub extern "system" fn Java_com_jaysquadsec_bridge_NativeBridge_nativeFree(
    _env: Env,
    _cls: JClass,
    handle: JLong,
) -> JInt {
    engine_free(handle_from(handle))
}

/// `static native int nativeSubmit(long handle, int pid, long generation,
///     byte[] packageIdentity, byte[] kind, byte[] detail, long atMs)`.
///
/// # Safety
/// Called only by the JVM: `env` must be the `JNIEnv*` for this call and the
/// array arguments valid references or null. Both hold for any call from Java.
#[no_mangle]
#[allow(clippy::too_many_arguments)] // signature fixed by the Java declaration
pub unsafe extern "system" fn Java_com_jaysquadsec_bridge_NativeBridge_nativeSubmit(
    env: Env,
    _cls: JClass,
    handle: JLong,
    pid: JInt,
    generation: JLong,
    package_identity: JByteArray,
    kind: JByteArray,
    detail: JByteArray,
    at_ms: JLong,
) -> JInt {
    let result = guarded(|| {
        if pid <= 0 || generation <= 0 || at_ms < 0 {
            return Err(ERR_INVALID);
        }
        // SAFETY: env and array refs come straight from the JVM for this call.
        let (identity, kind, detail) = unsafe {
            (
                read_byte_array(env, package_identity, MAX_IDENTITY_LEN)?,
                read_byte_array(env, kind, MAX_KIND_LEN)?,
                read_byte_array(env, detail, MAX_DETAIL_LEN)?,
            )
        };
        Ok(submit(
            handle_from(handle),
            pid as u32,
            generation as u64,
            &identity,
            &kind,
            &detail,
            at_ms as u64,
        ))
    });
    match result {
        Ok(code) => code,
        Err(e) => e,
    }
}

/// `static native byte[] nativeTakeAlerts(long handle, int maxBytes)` —
/// newline-separated UTF-8, empty if none, null on error (bad handle or
/// poisoned engine). A `maxBytes` below `MIN_ALERT_BUFFER` is raised to it.
///
/// # Safety
/// Called only by the JVM: `env` must be the `JNIEnv*` for this call.
#[no_mangle]
pub unsafe extern "system" fn Java_com_jaysquadsec_bridge_NativeBridge_nativeTakeAlerts(
    env: Env,
    _cls: JClass,
    handle: JLong,
    max_bytes: JInt,
) -> JByteArray {
    let max = usize::try_from(max_bytes)
        .unwrap_or(0)
        .max(MIN_ALERT_BUFFER);
    let h = handle_from(handle);
    match guarded(|| take_alerts(h, max)) {
        Ok(bytes) => {
            // SAFETY: env is valid for this call.
            let arr = unsafe { new_byte_array(env, &bytes) };
            if arr.is_null() && !bytes.is_empty() {
                // Lines were already dequeued; count them as dropped rather
                // than losing them silently (e.g. OutOfMemoryError).
                let lines = bytes.iter().filter(|&&b| b == b'\n').count() as u64;
                note_undelivered(h, lines);
            }
            arr
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// `static native int nativeAbiVersion()`.
#[no_mangle]
pub extern "system" fn Java_com_jaysquadsec_bridge_NativeBridge_nativeAbiVersion(
    _env: Env,
    _cls: JClass,
) -> JInt {
    ABI_VERSION as JInt
}

#[cfg(test)]
mod tests {
    /// Pin the table indices to the values verified against jni.h, so an
    /// accidental edit (which would be a silent crash at runtime) fails CI.
    #[test]
    fn jni_table_indices_match_the_spec() {
        use super::idx::*;
        assert_eq!(EXCEPTION_CLEAR, 17);
        assert_eq!(GET_ARRAY_LENGTH, 171);
        assert_eq!(NEW_BYTE_ARRAY, 176);
        assert_eq!(GET_BYTE_ARRAY_REGION, 200);
        assert_eq!(SET_BYTE_ARRAY_REGION, 208);
        assert_eq!(EXCEPTION_CHECK, 228);
    }
}
