//! Narrow C ABI scaffold for Android's future JNI adapter.
//!
//! This is not yet a JNI implementation. It provides a small C ABI for a
//! Kotlin/JNI wrapper after ownership and error contracts are reviewed.
//! No raw pointer is retained beyond a call. Callers must serialize access
//! to each handle; this scaffold is not internally synchronized.

use jay_squad_sec::engine::Engine;
use jay_squad_sec::rtid::Rtid;
use jay_squad_sec_protocol::{validate, WireEvent, PROTOCOL_VERSION};
use std::collections::HashMap;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};

const OK: i32 = 0;
const ERR_NULL: i32 = 1;
const ERR_INVALID: i32 = 2;
const ERR_PANIC: i32 = 3;

pub struct JssEngine {
    engine: Engine,
    identities: HashMap<u32, Rtid>,
}

/// Create an alert-only engine. Returns null if construction fails.
#[no_mangle]
pub extern "C" fn jss_engine_new(boot_nonce: u64) -> *mut JssEngine {
    match catch_unwind(|| {
        let mut engine = Engine::new(boot_nonce);
        engine.set_alert_only(true);
        Box::into_raw(Box::new(JssEngine { engine, identities: HashMap::new() }))
    }) {
        Ok(p) => p,
        Err(_) => std::ptr::null_mut(),
    }
}

/// Destroy a handle returned by jss_engine_new. Null is accepted.
#[no_mangle]
pub unsafe extern "C" fn jss_engine_free(handle: *mut JssEngine) {
    if !handle.is_null() {
        // SAFETY: caller must pass a live handle exactly once.
        drop(unsafe { Box::from_raw(handle) });
    }
}

/// Submit a validated event. Return codes: 0 accepted; 1 null; 2 invalid; 3 panic.
/// Caller guarantees kind/detail are readable NUL-terminated UTF-8 strings.
/// PID reuse is not yet handled; this is a scaffold, not release-ready FFI.
#[no_mangle]
pub unsafe extern "C" fn jss_engine_submit_event(
    handle: *mut JssEngine,
    pid: u32,
    kind: *const c_char,
    detail: *const c_char,
    at_ms: u64,
) -> i32 {
    if handle.is_null() || kind.is_null() || detail.is_null() {
        return ERR_NULL;
    }
    match catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: caller guarantees valid NUL-terminated buffers for this call.
        let kind = unsafe { CStr::from_ptr(kind) }.to_str().map_err(|_| ERR_INVALID)?;
        let detail = unsafe { CStr::from_ptr(detail) }.to_str().map_err(|_| ERR_INVALID)?;
        let wire = WireEvent {
            schema_version: PROTOCOL_VERSION,
            pid,
            kind: kind.to_owned(),
            detail: detail.to_owned(),
            at_ms,
        };
        let validated = validate(&wire).map_err(|_| ERR_INVALID)?;
        let state = unsafe { &mut *handle };
        let rtid = if let Some(existing) = state.identities.get(&pid) {
            *existing
        } else {
            let created = state.engine.adopt("android-process", format!("pid:{pid}").as_bytes(), at_ms);
            state.identities.insert(pid, created);
            created
        };
        state.engine.bus.publish(validated.into_event(rtid));
        let _ = state.engine.tick(at_ms);
        Ok::<(), i32>(())
    })) {
        Ok(Ok(())) => OK,
        Ok(Err(code)) => code,
        Err(_) => ERR_PANIC,
    }
}

/// Current bridge ABI version. Kotlin must check this before other calls.
#[no_mangle]
pub extern "C" fn jss_bridge_abi_version() -> u32 {
    1
}
