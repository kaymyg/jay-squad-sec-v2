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
//! # Trusted time
//!
//! Each engine runs on its own monotonic clock (milliseconds since the engine
//! was created). A caller's `at_ms` is validated and kept as information only;
//! it never drives risk decay. Trusting it let a single far-future timestamp
//! decay every process's risk to zero (found in review).
//!
//! # Process lifecycle
//!
//! One PID is one live process. When a PID arrives with a new generation, the
//! old generation is retired first (Android often kills processes without any
//! exit event). Retired generations are remembered per PID, so a retired
//! `(pid, generation)` can never be revived with a clean score or a new
//! identity. If identity capacity is still exhausted, the lowest-risk, least
//! recently active identity is evicted (with an alert) rather than rejecting
//! new processes, so a full table can never switch detection off.
//!
//! # Bounds
//!
//! Everything a caller can grow is capped: engines ([`MAX_ENGINES`]), live
//! process identities per engine ([`MAX_IDENTITIES`]), remembered retired PIDs
//! ([`MAX_RETIRED_PIDS`]), queued alerts ([`MAX_ALERTS`], oldest dropped and
//! reported), alert line length, and all input lengths. The engine's own audit
//! ledger is a bounded ring in `core`.

pub mod jni;

use jay_squad_sec::engine::Engine;
use jay_squad_sec::event::{Event, EventKind};
use jay_squad_sec::rtid::Rtid;
use jay_squad_sec_apply::{UpdateStore, MAX_PATCH_FILE_BYTES};
use jay_squad_sec_protocol::{validate, WireEvent, MAX_DETAIL_LEN, PROTOCOL_VERSION};
use std::collections::{BTreeMap, VecDeque};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

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
/// A capacity limit was reached (engine count). Identity capacity never
/// rejects: it evicts the lowest-risk idle identity instead.
pub const ERR_CAPACITY: i32 = 5;
/// A live (pid, generation) was submitted with a different package identity.
pub const ERR_IDENTITY_MISMATCH: i32 = 6;
/// The handle is 0, already freed, or never existed.
pub const ERR_BAD_HANDLE: i32 = 7;
/// The output buffer is smaller than [`MIN_ALERT_BUFFER`].
pub const ERR_BUFFER_TOO_SMALL: i32 = 8;
/// The generation is not newer than one already retired for this PID.
pub const ERR_STALE_GENERATION: i32 = 9;
/// No builder public key was embedded in this product build.
pub const ERR_UPDATE_NOT_CONFIGURED: i32 = 10;
/// A signed rules patch failed verification, policy validation or installation.
pub const ERR_UPDATE_REJECTED: i32 = 11;

/// Maximum simultaneously live engines per process.
pub const MAX_ENGINES: usize = 8;
/// Maximum live process identities tracked per engine.
pub const MAX_IDENTITIES: usize = 4096;
/// Maximum PIDs whose highest retired generation is remembered per engine
/// (oldest forgotten first). Bounds memory against a huge PID space.
pub const MAX_RETIRED_PIDS: usize = 65_536;
/// Maximum queued alert lines per engine before the oldest are dropped.
pub const MAX_ALERTS: usize = 256;
/// Alert lines longer than this many bytes are truncated (at a char boundary).
pub const MAX_ALERT_LINE: usize = 1024;
/// Smallest output buffer `take_alerts` accepts: one maximal line + newline.
pub const MIN_ALERT_BUFFER: usize = MAX_ALERT_LINE + 1;
pub const MAX_KIND_LEN: usize = 64;
pub const MAX_IDENTITY_LEN: usize = 512;
/// Current ABI version. Bump on any incompatible change.
/// v4: signed rules load/apply entry points and codes 10/11.
pub const ABI_VERSION: u32 = 4;

struct Identity {
    rtid: Rtid,
    package: String,
    last_seen_ms: u64,
}

struct EngineState {
    engine: Engine,
    /// Trusted monotonic time origin for this engine.
    started: Instant,
    // PID alone is not identity: Android reuses PIDs. The adapter supplies a
    // generation that changes whenever a PID is reused. One live entry per pid.
    identities: BTreeMap<(u32, u64), Identity>,
    /// Highest retired generation per PID; generations at or below it are stale.
    retired: BTreeMap<u32, u64>,
    /// Insertion order of `retired`, for bounded FIFO forgetting.
    retired_order: VecDeque<u32>,
    alerts: VecDeque<String>,
    alerts_dropped: u64,
    /// Version of the rules active in this engine (0 = compiled-in defaults).
    /// Activation never goes below it, so a stale directory cannot downgrade
    /// a running engine.
    rules_version: u64,
    /// Storage directory this engine's rules are bound to. The first update
    /// call fixes it; any other directory is refused, so anti-rollback cannot
    /// be reset by pointing the engine at a fresh directory.
    rules_dir: Option<PathBuf>,
}

impl EngineState {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn push_alert(&mut self, line: String) {
        if self.alerts.len() >= MAX_ALERTS {
            self.alerts.pop_front();
            self.alerts_dropped += 1;
        }
        self.alerts.push_back(truncate_line(line));
    }

    fn remember_retired(&mut self, pid: u32, generation: u64) {
        let entry = self.retired.entry(pid).or_insert(0);
        let fresh = *entry == 0;
        if generation > *entry {
            *entry = generation;
        }
        if fresh {
            self.retired_order.push_back(pid);
            while self.retired_order.len() > MAX_RETIRED_PIDS {
                if let Some(old) = self.retired_order.pop_front() {
                    self.retired.remove(&old);
                }
            }
        }
    }

    /// Retire a live identity: tell the engine the process is gone (its state
    /// is pruned after the next tick) and remember the generation as retired.
    fn retire(&mut self, key: (u32, u64), now_ms: u64) {
        if let Some(id) = self.identities.remove(&key) {
            self.engine.bus.publish(Event {
                rtid: id.rtid,
                kind: EventKind::ProcessExit,
                at_ms: now_ms,
                detail: String::new(),
            });
        }
        self.remember_retired(key.0, key.1);
    }

    /// Pick the identity to evict when full: lowest current risk, then least
    /// recently active, so a flood of new processes cannot push a suspicious
    /// one out of the table.
    fn eviction_victim(&self) -> Option<(u32, u64)> {
        self.identities
            .iter()
            .min_by(|(_, a), (_, b)| {
                let ra = self
                    .engine
                    .process(a.rtid)
                    .map(|p| p.risk.score)
                    .unwrap_or(0.0);
                let rb = self
                    .engine
                    .process(b.rtid)
                    .map(|p| p.risk.score)
                    .unwrap_or(0.0);
                ra.total_cmp(&rb).then(a.last_seen_ms.cmp(&b.last_seen_ms))
            })
            .map(|(k, _)| *k)
    }
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
                started: Instant::now(),
                identities: BTreeMap::new(),
                retired: BTreeMap::new(),
                retired_order: VecDeque::new(),
                alerts: VecDeque::new(),
                alerts_dropped: 0,
                rules_version: 0,
                rules_dir: None,
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
        // Take the instance out under the registry lock, but drop it (which
        // may tear down thousands of processes) only after releasing the lock.
        let removed = registry().live.remove(&handle);
        removed.map(drop).ok_or(ERR_BAD_HANDLE)
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
        let now = st.now_ms();
        let key = (pid, process_generation);

        // A generation at or below one already retired for this pid is stale:
        // reviving it would reset its score and allow an identity change.
        if st
            .retired
            .get(&pid)
            .is_some_and(|&r| process_generation <= r)
        {
            st.push_alert(format!(
                "[bridge] stale generation rejected pid={pid} gen={process_generation}"
            ));
            return Err(ERR_STALE_GENERATION);
        }

        let rtid = match st.identities.get(&key) {
            Some(existing) if existing.package != identity => {
                // A live process changing identity is itself a security signal.
                st.push_alert(format!(
                    "[bridge] identity mismatch rejected pid={pid} gen={process_generation}"
                ));
                return Err(ERR_IDENTITY_MISMATCH);
            }
            Some(existing) => existing.rtid,
            None => {
                // One pid is one live process: retire any older generation
                // that never sent an exit (common on Android).
                let stale: Vec<(u32, u64)> = st
                    .identities
                    .range((pid, 0)..=(pid, u64::MAX))
                    .map(|(k, _)| *k)
                    .collect();
                for old in stale {
                    st.retire(old, now);
                }
                if st.identities.len() >= MAX_IDENTITIES {
                    if let Some(victim) = st.eviction_victim() {
                        st.retire(victim, now);
                        st.push_alert(format!(
                            "[bridge] identity table full; evicted lowest-risk idle pid={} gen={}",
                            victim.0, victim.1
                        ));
                    }
                }
                let rtid = st.engine.adopt(&identity, identity.as_bytes(), now);
                st.identities.insert(
                    key,
                    Identity {
                        rtid,
                        package: identity,
                        last_seen_ms: now,
                    },
                );
                rtid
            }
        };
        if let Some(id) = st.identities.get_mut(&key) {
            id.last_seen_ms = now;
        }

        let is_exit = validated.kind == EventKind::ProcessExit;
        // The caller's at_ms stays on the event as information; the engine
        // advances only on its own trusted clock.
        st.engine.bus.publish(validated.into_event(rtid));
        for line in st.engine.tick(now) {
            st.push_alert(line);
        }
        if is_exit {
            st.retire(key, now);
            for line in st.engine.tick(now) {
                st.push_alert(line);
            }
        }
        // Drop state for every exited/retired process (bounded memory).
        st.engine.prune_exited();
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

/// Report that `lines` alerts already taken from the queue could not be
/// delivered (e.g. the JVM could not allocate the result array), so the next
/// take reports them as dropped instead of losing them silently.
pub fn note_undelivered(handle: JssHandle, lines: u64) {
    let _ = guarded(|| {
        let inst = lookup(handle)?;
        let mut st = inst.state.lock().map_err(|_| ERR_POISONED)?;
        st.alerts_dropped = st.alerts_dropped.saturating_add(lines);
        Ok(())
    });
}

// ---------------------------------------------------------------------------
// Signed rules updates (data only; no dynamic code loading).
// ---------------------------------------------------------------------------

/// Android has a distinct product identity: desktop-agent patches cannot be
/// replayed into the consumer app. Set the matching product ID when signing.
pub const ANDROID_PRODUCT_ID: &str = "jay-squad-sec-android";
/// Maximum app-private storage path length accepted for rules state.
pub const MAX_STORAGE_PATH_LEN: usize = 4096;

/// The builder public key is a **build-time** input, never supplied by Kotlin
/// or JNI, so a compromised caller cannot substitute its own key.
///
/// - `JSS_ANDROID_BUILDER_PUBLIC_KEY_HEX`: exactly 64 hex characters.
/// - `JSS_ANDROID_MIN_RULES_VERSION`: required whenever a key is embedded
///   (set it deliberately, even to 0); raise it each release.
///
/// Cargo tracks both variables (`env-dep`), so changing either rebuilds the
/// library; a stale key cannot survive into a later build. Any missing or
/// malformed setting makes every update operation fail closed.
fn android_update_store(dir: &str) -> Result<UpdateStore, i32> {
    let encoded =
        option_env!("JSS_ANDROID_BUILDER_PUBLIC_KEY_HEX").ok_or(ERR_UPDATE_NOT_CONFIGURED)?;
    let public_key = decode_public_key(encoded).ok_or(ERR_UPDATE_NOT_CONFIGURED)?;
    let min_version = option_env!("JSS_ANDROID_MIN_RULES_VERSION")
        .ok_or(ERR_UPDATE_NOT_CONFIGURED)?
        .parse::<u64>()
        .map_err(|_| ERR_UPDATE_NOT_CONFIGURED)?;
    // State must live at a fixed, absolute app-private location; a relative
    // path would silently depend on the process working directory.
    if !std::path::Path::new(dir).is_absolute() {
        return Err(ERR_INVALID);
    }
    Ok(
        UpdateStore::new(PathBuf::from(dir), public_key, ANDROID_PRODUCT_ID)
            .with_min_version(min_version),
    )
}

fn decode_public_key(encoded: &str) -> Option<[u8; 32]> {
    let bytes = encoded.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut key = [0u8; 32];
    for (i, out) in key.iter_mut().enumerate() {
        let hi = (bytes[i * 2] as char).to_digit(16)? as u8;
        let lo = (bytes[i * 2 + 1] as char).to_digit(16)? as u8;
        *out = (hi << 4) | lo;
    }
    Some(key)
}

/// Bind the engine to one storage directory: the first call fixes it, and a
/// different directory afterwards is refused with [`ERR_INVALID`].
fn bind_rules_dir(state: &mut EngineState, dir: &str) -> Result<(), i32> {
    let dir = PathBuf::from(dir);
    match &state.rules_dir {
        Some(bound) if *bound != dir => {
            state.push_alert(
                "[update] refused: rules storage directory differs from the one this engine is bound to"
                    .to_string(),
            );
            Err(ERR_INVALID)
        }
        Some(_) => Ok(()),
        None => {
            state.rules_dir = Some(dir);
            Ok(())
        }
    }
}

/// Load the highest verified Android rules patch from app-private storage.
/// The embedded builder key and product ID are fixed by this native build.
pub fn load_signed_rules(handle: JssHandle, storage_dir: &[u8]) -> Result<u64, i32> {
    guarded(|| {
        let dir = checked_text(storage_dir, MAX_STORAGE_PATH_LEN, false)?;
        let store = android_update_store(&dir)?;
        let inst = lookup(handle)?;
        let mut state = inst.state.lock().map_err(|_| ERR_POISONED)?;
        bind_rules_dir(&mut state, &dir)?;
        let installed = store.load();
        if installed.source == jay_squad_sec_apply::StateSource::Default
            && store.state_files_present()
        {
            state.push_alert(
                "[update] stored rules failed verification (tampered, corrupt or below minimum); \
                 not using them"
                    .to_string(),
            );
        }
        let active = state.rules_version;
        if installed.version < active {
            state.push_alert(format!(
                "[update] refused to downgrade active rules v{active} to stored v{}",
                installed.version
            ));
            return Err(ERR_UPDATE_REJECTED);
        }
        state
            .engine
            .set_rules(installed.rules)
            .map_err(|_| ERR_UPDATE_REJECTED)?;
        state.rules_version = installed.version;
        if installed.source != jay_squad_sec_apply::StateSource::Current && installed.version > 0 {
            state.push_alert(format!(
                "[update] Android rules recovered from previous verified state, version {}",
                installed.version
            ));
        }
        Ok(installed.version)
    })
}

/// Verify, validate and atomically install a signed data-only rules patch,
/// then activate those rules in this engine. Caller supplies only bytes and
/// app-private storage path; the builder public key is not caller-selectable.
pub fn apply_signed_rules(
    handle: JssHandle,
    storage_dir: &[u8],
    patch_bytes: &[u8],
) -> Result<u64, i32> {
    guarded(|| {
        if patch_bytes.len() > MAX_PATCH_FILE_BYTES as usize {
            return Err(ERR_INVALID);
        }
        let dir = checked_text(storage_dir, MAX_STORAGE_PATH_LEN, false)?;
        let store = android_update_store(&dir)?;
        let inst = lookup(handle)?;
        let mut state = inst.state.lock().map_err(|_| ERR_POISONED)?;
        bind_rules_dir(&mut state, &dir)?;
        let installed = match store.apply_patch_bytes(patch_bytes) {
            Ok(value) => value,
            Err(e) => {
                // The reason (bad signature, rollback, invalid rules...) helps
                // the user and leaks nothing secret.
                state.push_alert(format!(
                    "[update] Android rules patch rejected ({e}); active rules unchanged"
                ));
                return Err(ERR_UPDATE_REJECTED);
            }
        };
        // apply_patch_bytes has already decoded and validated the exact RulesConfig,
        // so this cannot fail today; if it ever did, the disk holds the new
        // version while the engine keeps its old rules, and we say so.
        if state.engine.set_rules(installed.rules).is_err() {
            state.push_alert(format!(
                "[update] rules v{} installed but could not be activated; restart to retry",
                installed.version
            ));
            return Err(ERR_UPDATE_REJECTED);
        }
        state.rules_version = installed.version;
        state.push_alert(format!(
            "[update] Android rules v{} verified, installed and activated",
            installed.version
        ));
        Ok(installed.version)
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
/// - `process_generation` must increase whenever the OS reuses a PID. A new
///   generation retires the previous one; a retired one is rejected with
///   [`ERR_STALE_GENERATION`].
/// - `at_ms` is informational only; the engine uses its own monotonic clock.
/// - `package_identity` should be the canonical package name plus signing
///   certificate digest, supplied by the trusted Android adapter. A live
///   `(pid, generation)` can never change identity ([`ERR_IDENTITY_MISMATCH`]).
/// - A `process_exit` event retires the identity.
///
/// Returns [`OK`] or one of the `ERR_*` codes.
///
/// # Safety
/// Every buffer with a non-zero length must be readable for that length until
/// this function returns, and must not be written by another thread during the
/// call. The handle itself needs no care: invalid, freed or concurrently-freed
/// handles are detected.
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
/// `out` must be writable for `out_cap` bytes and `out_len` must be a valid,
/// aligned, writable pointer, for the duration of the call. Neither may be
/// accessed by another thread during the call.
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
