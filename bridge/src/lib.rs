//! Narrow, bounded boundary between the Android app and the security engine.
//!
//! Two front doors share one implementation:
//! - a C ABI (`jss_*`, ABI version 3) for native callers and tests;
//! - JNI entry points ([`jni`]) for the Kotlin wrapper on Android.
//!
//! # Ownership model (ABI v3)
//!
//! Handles are opaque `u64` IDs, not pointers. A global registry maps IDs to
//! reference-counted engine instances; IDs are never reused (0 is invalid).
//! Every call looks the ID up and takes its own reference for the duration of
//! the call, so:
//! - `jss_engine_free` on a handle that another thread is using is safe: the
//!   ID stops resolving immediately and the engine is dropped when the last
//!   in-flight call finishes;
//! - double-free and use-after-free return [`ERR_BAD_HANDLE`], never UB.
//!
//! The only remaining caller obligation is the usual one for raw buffers in
//! the C ABI (pointer + length must be readable for the call). The JNI path
//! copies Java arrays itself and has no such obligation.
//!
//! # Bounds
//!
//! Everything a caller can grow is capped: engines ([`MAX_ENGINES`]), live
//! process identities per engine ([`MAX_IDENTITIES`]), queued alerts
//! ([`MAX_ALERTS`], oldest dropped and reported), alert line length, and all
//! input lengths. The engine's own audit ledger is a bounded ring in `core`.

pub mod jni;

use jay_squad_sec::engine::Engine;
use jay_squad_sec::event::EventKind;
use jay_squad_sec::rtid::Rtid;
use jay_squad_sec_protocol::{validate, WireEvent, MAX_DETAIL_LEN, PROTOCOL_VERSION};
use std::collections::{BTreeMap, VecDeque};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex, MutexGuard};

/// Opaque engine handle. 0 is never a valid handle.
pub type JssHandle = u64;

pub const OK: i32 = 0;
/// A required pointer or array was null.
pub const ERR_NULL: i32 = 1;
/// Input failed validation (length, UTF-8, control characters, schema...).
pub const ERR_INVALID: i32 = 2;
/// A panic was caught inside the bridge; nothing unwound across the boundary.
pub const ERR_PANIC: i32 = 3;
/// The engine's lock was poisoned by an earlier panic; the handle is unusable.
pub const ERR_POISONED: i32 = 4;
/// A capacity limit was reached (engines or live identities).
pub const ERR_CAPACITY: i32 = 5;
/// A live (pid, generation) was submitted with a different package identity.
pub const ERR_IDENTITY_MISMATCH: i32 = 6;
/// The handle is 0, already freed, or never existed.
pub const ERR_BAD_HANDLE: i32 = 7;
/// The output buffer is smaller than [`MIN_ALERT_BUFFER`].
pub const ERR_BUFFER_TOO_SMALL: i32 = 8;

/// Maximum simultaneously live engines per process.
pub const MAX_ENGINES: usize = 8;
/// Maximum live process identities tracked per engine.
pub const MAX_IDENTITIES: usize = 4096;
/// Maximum queued alert lines per engine before the oldest are dropped.
pub const MAX_ALERTS: usize = 256;
/// Alert lines longer than this many bytes are truncated (at a char boundary).
pub const MAX_ALERT_LINE: usize = 1024;
/// Smallest output buffer `take_alerts` accepts: one maximal line + newline.
pub const MIN_ALERT_BUFFER: usize = MAX_ALERT_LINE + 1;
pub const MAX_KIND_LEN: usize = 64;
pub const MAX_IDENTITY_LEN: usize = 512;
/// Current ABI version. Bump on any incompatible change.
pub const ABI_VERSION: u32 = 3;

struct Identity {
    rtid: Rtid,
    package: String,
}

struct EngineState {
    engine: Engine,
    // PID alone is not identity: Android reuses PIDs. The adapter supplies a
    // generation that changes whenever a PID is reused.
    identities: BTreeMap<(u32, u64), Identity>,
    alerts: VecDeque<String>,
    alerts_dropped: u64,
}

struct Instance {
    state: Mutex<EngineState>,
}

struct Registry {
    next: u64,
    live: BTreeMap<u64, Arc<Instance>>,
}

static REGISTRY: Mutex<Registry> = Mutex::new(Registry {
    next: 1,
    live: BTreeMap::new(),
});

/// The registry only does inserts/removes/lookups, which leave it consistent
/// even if a panic happened while it was held, so recovering from poison is
/// sound here (unlike an engine lock).
fn registry() -> MutexGuard<'static, Registry> {
    REGISTRY.lock().unwrap_or_else(|p| p.into_inner())
}

fn lookup(handle: JssHandle) -> Result<Arc<Instance>, i32> {
    registry().live.get(&handle).cloned().ok_or(ERR_BAD_HANDLE)
}

fn guarded<T>(f: impl FnOnce() -> Result<T, i32>) -> Result<T, i32> {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(Err(ERR_PANIC))
}

/// Validate a caller-supplied byte string as UTF-8 within bounds, rejecting
/// control characters (these strings end up in alert text).
fn checked_text(bytes: &[u8], max: usize, allow_empty: bool) -> Result<String, i32> {
    if bytes.len() > max || (!allow_empty && bytes.is_empty()) {
        return Err(ERR_INVALID);
    }
    let s = std::str::from_utf8(bytes).map_err(|_| ERR_INVALID)?;
    if s.chars().any(char::is_control) {
        return Err(ERR_INVALID);
    }
    Ok(s.to_owned())
}

fn truncate_line(mut line: String) -> String {
    if line.len() > MAX_ALERT_LINE {
        let mut cut = MAX_ALERT_LINE;
        while !line.is_char_boundary(cut) {
            cut -= 1;
        }
        line.truncate(cut);
    }
    // Lines are newline-delimited on output; never let one contain a newline.
    line.replace(['\n', '\r'], " ")
}

// ---------------------------------------------------------------------------
// Safe core API shared by the C ABI and JNI.
// ---------------------------------------------------------------------------

/// Create an alert-only engine. Returns 0 on failure (capacity or panic).
pub fn engine_new(boot_nonce: u64) -> JssHandle {
    guarded(|| {
        let mut reg = registry();
        if reg.live.len() >= MAX_ENGINES {
            return Err(ERR_CAPACITY);
        }
        let id = reg.next;
        reg.next = id.checked_add(1).ok_or(ERR_CAPACITY)?;
        let mut engine = Engine::new(boot_nonce);
        engine.set_alert_only(true);
        let inst = Instance {
            state: Mutex::new(EngineState {
                engine,
                identities: BTreeMap::new(),
                alerts: VecDeque::new(),
                alerts_dropped: 0,
            }),
        };
        reg.live.insert(id, Arc::new(inst));
        Ok(id)
    })
    .unwrap_or(0)
}

/// Release a handle. Safe to call while other threads use it, and safe to
/// call twice (the second call returns [`ERR_BAD_HANDLE`]).
pub fn engine_free(handle: JssHandle) -> i32 {
    match guarded(|| {
        registry()
            .live
            .remove(&handle)
            .map(|_| ())
            .ok_or(ERR_BAD_HANDLE)
    }) {
        Ok(()) => OK,
        Err(e) => e,
    }
}

/// Submit one event. See [`jss_engine_submit_event`] for the parameters.
pub fn submit(
    handle: JssHandle,
    pid: u32,
    process_generation: u64,
    package_identity: &[u8],
    kind: &[u8],
    detail: &[u8],
    at_ms: u64,
) -> i32 {
    let result = guarded(|| {
        if pid == 0 || process_generation == 0 {
            return Err(ERR_INVALID);
        }
        let identity = checked_text(package_identity, MAX_IDENTITY_LEN, false)?;
        let kind = checked_text(kind, MAX_KIND_LEN, false)?;
        // detail: length + UTF-8 here; control/bidi/zero-width rules in validate().
        if detail.len() > MAX_DETAIL_LEN {
            return Err(ERR_INVALID);
        }
        let detail = std::str::from_utf8(detail)
            .map_err(|_| ERR_INVALID)?
            .to_owned();
        let validated = validate(&WireEvent {
            schema_version: PROTOCOL_VERSION,
            pid,
            kind,
            detail,
            at_ms,
        })
        .map_err(|_| ERR_INVALID)?;

        let inst = lookup(handle)?;
        let mut st = inst.state.lock().map_err(|_| ERR_POISONED)?;
        let key = (pid, process_generation);
        let rtid = match st.identities.get(&key) {
            Some(existing) if existing.package != identity => {
                return Err(ERR_IDENTITY_MISMATCH);
            }
            Some(existing) => existing.rtid,
            None => {
                if st.identities.len() >= MAX_IDENTITIES {
                    return Err(ERR_CAPACITY);
                }
                let rtid = st.engine.adopt(&identity, identity.as_bytes(), at_ms);
                st.identities.insert(
                    key,
                    Identity {
                        rtid,
                        package: identity,
                    },
                );
                rtid
            }
        };

        let is_exit = validated.kind == EventKind::ProcessExit;
        st.engine.bus.publish(validated.into_event(rtid));
        let lines = st.engine.tick(at_ms);
        for line in lines {
            if st.alerts.len() >= MAX_ALERTS {
                st.alerts.pop_front();
                st.alerts_dropped += 1;
            }
            st.alerts.push_back(truncate_line(line));
        }
        if is_exit {
            // Retire the identity so a reused PID can never inherit its risk,
            // and drop the engine's state for it (bounded memory).
            st.identities.remove(&key);
            st.engine.prune_exited();
        }
        Ok(())
    });
    match result {
        Ok(()) => OK,
        Err(e) => e,
    }
}

/// Take queued alert lines, newline-separated, oldest first, using at most
/// `max_bytes` (must be >= [`MIN_ALERT_BUFFER`]). Lines that do not fit stay
/// queued for the next call; a line is never split. If alerts were dropped
/// because the queue was full, the first line reports how many.
pub fn take_alerts(handle: JssHandle, max_bytes: usize) -> Result<Vec<u8>, i32> {
    guarded(|| {
        if max_bytes < MIN_ALERT_BUFFER {
            return Err(ERR_BUFFER_TOO_SMALL);
        }
        let inst = lookup(handle)?;
        let mut st = inst.state.lock().map_err(|_| ERR_POISONED)?;
        let mut out = Vec::new();
        if st.alerts_dropped > 0 {
            let note = format!(
                "[bridge] {} alerts dropped (queue full)\n",
                st.alerts_dropped
            );
            out.extend_from_slice(note.as_bytes());
            st.alerts_dropped = 0;
        }
        while let Some(front) = st.alerts.front() {
            if out.len() + front.len() + 1 > max_bytes {
                break;
            }
            let line = st.alerts.pop_front().unwrap_or_default();
            out.extend_from_slice(line.as_bytes());
            out.push(b'\n');
        }
        Ok(out)
    })
}

// ---------------------------------------------------------------------------
// C ABI
// ---------------------------------------------------------------------------

/// Create an alert-only engine. Returns 0 on failure.
#[no_mangle]
pub extern "C" fn jss_engine_new(boot_nonce: u64) -> JssHandle {
    engine_new(boot_nonce)
}

/// Release a handle. Returns [`OK`] or [`ERR_BAD_HANDLE`]. Safe to call while
/// other threads are using the handle and safe to call more than once.
#[no_mangle]
pub extern "C" fn jss_engine_free(handle: JssHandle) -> i32 {
    engine_free(handle)
}

/// Build a byte slice from a caller buffer. A zero length never touches the
/// pointer (null is fine); a non-zero length with a null pointer is an error.
///
/// # Safety
/// For `len > 0`, `ptr..ptr+len` must be readable for the duration of the call.
unsafe fn caller_bytes<'a>(ptr: *const u8, len: usize, max: usize) -> Result<&'a [u8], i32> {
    if len > max {
        return Err(ERR_INVALID);
    }
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(ERR_NULL);
    }
    // SAFETY: length bounded above; readability is the caller's contract.
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// Submit one event using bounded byte buffers.
///
/// - `process_generation` must change whenever the OS reuses a PID.
/// - `package_identity` should be the canonical package name plus signing
///   certificate digest, supplied by the trusted Android adapter. A live
///   `(pid, generation)` can never change identity ([`ERR_IDENTITY_MISMATCH`]).
/// - A `process_exit` event retires the identity.
///
/// Returns [`OK`] or one of the `ERR_*` codes.
///
/// # Safety
/// Every buffer with a non-zero length must be readable for that length until
/// this function returns. The handle itself needs no care: invalid, freed or
/// concurrently-freed handles are detected.
#[no_mangle]
pub unsafe extern "C" fn jss_engine_submit_event(
    handle: JssHandle,
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
    // SAFETY: buffer readability is this function's documented contract.
    let bufs = unsafe {
        (
            caller_bytes(package_identity, package_identity_len, MAX_IDENTITY_LEN),
            caller_bytes(kind, kind_len, MAX_KIND_LEN),
            caller_bytes(detail, detail_len, MAX_DETAIL_LEN),
        )
    };
    match bufs {
        (Ok(i), Ok(k), Ok(d)) => submit(handle, pid, process_generation, i, k, d, at_ms),
        (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => e,
    }
}

/// Copy queued alerts into `out` (newline-separated UTF-8, never split
/// mid-line) and store the byte count in `*out_len`. `out_cap` must be at
/// least [`MIN_ALERT_BUFFER`]. Returns [`OK`] or an `ERR_*` code; on error
/// nothing is consumed and `*out_len` is set to 0 when writable.
///
/// # Safety
/// `out` must be writable for `out_cap` bytes and `out_len` writable, for the
/// duration of the call.
#[no_mangle]
pub unsafe extern "C" fn jss_engine_take_alerts(
    handle: JssHandle,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if out_len.is_null() {
        return ERR_NULL;
    }
    // SAFETY: out_len is non-null and writable per contract.
    unsafe { *out_len = 0 };
    if out.is_null() {
        return ERR_NULL;
    }
    match take_alerts(handle, out_cap) {
        Ok(bytes) => {
            // SAFETY: bytes.len() <= out_cap by construction; out is writable.
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
                *out_len = bytes.len();
            }
            OK
        }
        Err(e) => e,
    }
}

/// Current bridge ABI version.
#[no_mangle]
pub extern "C" fn jss_bridge_abi_version() -> u32 {
    ABI_VERSION
}
