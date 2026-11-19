//! Narrow, bounded C ABI boundary for Android's future JNI adapter.
//!
//! This is not yet a JNI implementation. The Kotlin wrapper must own each
//! opaque handle exactly once, serialize close against in-flight calls, and
//! pass valid readable buffers for the duration of each call. Per-handle
//! operations are internally serialized by a Mutex.

use jay_squad_sec::engine::Engine;
use jay_squad_sec::rtid::Rtid;
use jay_squad_sec::event::EventKind;
use jay_squad_sec_protocol::{validate, WireEvent, PROTOCOL_VERSION, MAX_DETAIL_LEN};
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;
use std::str;
use std::sync::Mutex;

const OK: i32 = 0;
const ERR_NULL: i32 = 1;
const ERR_INVALID: i32 = 2;
const ERR_PANIC: i32 = 3;
const ERR_POISONED: i32 = 4;
const MAX_KIND_LEN: usize = 64;
const MAX_IDENTITY_LEN: usize = 512;

struct EngineState {
    engine: Engine,
    // PID alone is not identity: Android may reuse it. A monotonically
    // increasing process generation supplied by the adapter disambiguates it.
    identities: HashMap<(u32, u64), Rtid>,
}

pub struct JssEngine {
    state: Mutex<EngineState>,
}

/// Convert a caller-owned byte buffer to UTF-8 without allocating.
/// The FFI caller must guarantee that a non-empty range is readable for the
/// duration of the call. Length is checked before creating the slice.
unsafe fn bounded_utf8<'a>(
    ptr: *const u8,
    len: usize,
    max: usize,
    allow_empty: bool,
) -> Result<&'a str, i32> {
    if len > max || (!allow_empty && len == 0) {
        return Err(ERR_INVALID);
    }
    if len == 0 {
        return Ok("");
    }
    if ptr.is_null() {
        return Err(ERR_NULL);
    }
    // SAFETY: caller contract requires ptr..ptr+len to be readable.
    let bytes = unsafe { slice::from_raw_parts(ptr, len) };
    str::from_utf8(bytes).map_err(|_| ERR_INVALID)
}

/// Create an alert-only engine. Returns null if construction fails.
#[no_mangle]
pub extern "C" fn jss_engine_new(boot_nonce: u64) -> *mut JssEngine {
    match catch_unwind(|| {
        let mut engine = Engine::new(boot_nonce);
        engine.set_alert_only(true);
        Box::into_raw(Box::new(JssEngine {
            state: Mutex::new(EngineState { engine, identities: HashMap::new() }),
        }))
    }) {
        Ok(p) => p,
        Err(_) => std::ptr::null_mut(),
    }
}

/// Destroy a handle returned by jss_engine_new. Null is accepted.
///
/// SAFETY CONTRACT: caller must pass a live handle returned by
/// jss_engine_new exactly once and must prevent concurrent/in-flight calls.
/// A raw-pointer ABI cannot make use-after-free or double-free safe for a
/// caller that violates this ownership contract.
#[no_mangle]
pub unsafe extern "C" fn jss_engine_free(handle: *mut JssEngine) {
    if !handle.is_null() {
        // SAFETY: upheld by the documented caller ownership contract.
        drop(unsafe { Box::from_raw(handle) });
    }
}

/// Submit one event using bounded byte buffers, not unbounded C strings.
///
/// process_generation must change whenever the OS reuses a PID.
/// package_identity should be a canonical package name plus signing
/// certificate digest supplied by the trusted Android adapter.
/// Return codes: 0 accepted; 1 null pointer; 2 invalid input; 3 panic;
/// 4 poisoned engine mutex.
///
/// SAFETY CONTRACT: handle must be live; every non-empty input buffer must be
/// readable for its supplied length until this function returns. The caller
/// must not free the handle concurrently with this call.
#[no_mangle]
pub unsafe extern "C" fn jss_engine_submit_event(
    handle: *mut JssEngine,
    pid: u32,
    process_generation: u64,
    package_identity: *const u8,
    package_identity_len: usize,
    kind: *const u8,
    kind_len: usize,
    detail: *const u8,
    detail_len: usize,
    at_ms: u64,
) -> i32 {
    if handle.is_null() {
        return ERR_NULL;
    }
    if pid == 0 || process_generation == 0 {
        return ERR_INVALID;
    }

    match catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: buffer validity is part of this function's FFI contract.
        let identity = unsafe { bounded_utf8(package_identity, package_identity_len, MAX_IDENTITY_LEN, false)? };
        let kind = unsafe { bounded_utf8(kind, kind_len, MAX_KIND_LEN, false)? };
        let detail = unsafe { bounded_utf8(detail, detail_len, MAX_DETAIL_LEN, true)? };

        let wire = WireEvent {
            schema_version: PROTOCOL_VERSION,
            pid,
            kind: kind.to_owned(),
            detail: detail.to_owned(),
            at_ms,
        };
        let validated = validate(&wire).map_err(|_| ERR_INVALID)?;

        // SAFETY: caller guarantees handle is live and does not race free.
        let state = unsafe { &*handle };
        let mut guard = state.state.lock().map_err(|_| ERR_POISONED)?;
        let key = (pid, process_generation);
        let rtid = if let Some(existing) = guard.identities.get(&key) {
            *existing
        } else {
            let created = guard.engine.adopt(identity, identity.as_bytes(), at_ms);
            guard.identities.insert(key, created);
            created
        };

        let is_exit = validated.kind == EventKind::ProcessExit;
        guard.engine.bus.publish(validated.into_event(rtid));
        let _ = guard.engine.tick(at_ms);
        if is_exit {
            guard.identities.remove(&key);
        }
        Ok::<(), i32>(())
    })) {
        Ok(Ok(())) => OK,
        Ok(Err(code)) => code,
        Err(_) => ERR_PANIC,
    }
}

/// Current bridge ABI version. Increment on any incompatible signature change.
#[no_mangle]
pub extern "C" fn jss_bridge_abi_version() -> u32 {
    2
}
