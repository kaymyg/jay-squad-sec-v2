//! C-ABI boundary tests for bridge ABI v3.
//!
//! All tests share one process-wide engine registry (capped at MAX_ENGINES),
//! so every test takes TEST_LOCK to keep the capacity test deterministic.

use jay_squad_sec_bridge::*;
use std::sync::{Arc, Barrier, Mutex};

static TEST_LOCK: Mutex<()> = Mutex::new(());

fn lock() -> std::sync::MutexGuard<'static, ()> {
    TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

/// Submit through the C ABI with Rust-owned slices.
fn c_submit(
    h: JssHandle,
    pid: u32,
    gen: u64,
    ident: &[u8],
    kind: &[u8],
    detail: &[u8],
    at: u64,
) -> i32 {
    // SAFETY: the slices outlive the call and are readable for their lengths.
    unsafe {
        jss_engine_submit_event(
            h,
            pid,
            gen,
            ident.as_ptr(),
            ident.len(),
            kind.as_ptr(),
            kind.len(),
            detail.as_ptr(),
            detail.len(),
            at,
        )
    }
}

fn c_take(h: JssHandle, cap: usize) -> (i32, String) {
    let mut buf = vec![0u8; cap];
    let mut len = 0usize;
    // SAFETY: buf is writable for cap bytes; len is writable.
    let code = unsafe { jss_engine_take_alerts(h, buf.as_mut_ptr(), cap, &mut len) };
    buf.truncate(len);
    (code, String::from_utf8(buf).expect("alerts are UTF-8"))
}

const APP: &[u8] = b"com.example.app:sha256:ab12";

#[test]
fn reports_abi_v5_and_creates_a_handle() {
    let _g = lock();
    assert_eq!(jss_bridge_abi_version(), 5);
    let h = jss_engine_new(7);
    assert_ne!(h, 0);
    assert_eq!(jss_engine_free(h), OK);
}

#[test]
fn double_free_and_use_after_free_are_errors_not_ub() {
    let _g = lock();
    let h = jss_engine_new(7);
    assert_eq!(jss_engine_free(h), OK);
    assert_eq!(jss_engine_free(h), ERR_BAD_HANDLE, "double free");
    assert_eq!(
        c_submit(h, 10, 1, APP, b"file_write", b"x", 100),
        ERR_BAD_HANDLE,
        "use after free"
    );
    assert_eq!(c_take(h, MIN_ALERT_BUFFER).0, ERR_BAD_HANDLE);
    assert_eq!(jss_engine_free(0), ERR_BAD_HANDLE, "0 is never valid");
    assert_eq!(
        c_submit(u64::MAX, 10, 1, APP, b"file_write", b"x", 100),
        ERR_BAD_HANDLE
    );
}

#[test]
fn handles_are_never_reused() {
    let _g = lock();
    let a = jss_engine_new(1);
    jss_engine_free(a);
    let b = jss_engine_new(1);
    assert_ne!(a, b, "a stale handle must never alias a new engine");
    jss_engine_free(b);
}

#[test]
fn rejects_invalid_inputs() {
    let _g = lock();
    let h = jss_engine_new(7);
    assert_eq!(
        c_submit(h, 0, 1, APP, b"file_write", b"", 1),
        ERR_INVALID,
        "pid 0"
    );
    assert_eq!(
        c_submit(h, 10, 0, APP, b"file_write", b"", 1),
        ERR_INVALID,
        "generation 0"
    );
    assert_eq!(
        c_submit(h, 10, 1, b"", b"file_write", b"", 1),
        ERR_INVALID,
        "empty identity"
    );
    assert_eq!(
        c_submit(h, 10, 1, APP, b"not_a_kind", b"", 1),
        ERR_INVALID,
        "unknown kind"
    );
    assert_eq!(
        c_submit(h, 10, 1, &[0xFF, 0xFE], b"file_write", b"", 1),
        ERR_INVALID,
        "bad UTF-8"
    );
    assert_eq!(
        c_submit(h, 10, 1, b"evil\napp", b"file_write", b"", 1),
        ERR_INVALID,
        "control char"
    );
    assert_eq!(
        c_submit(h, 10, 1, APP, b"file_write", "a\u{202E}b".as_bytes(), 1),
        ERR_INVALID,
        "bidi"
    );
    let long = vec![b'a'; MAX_IDENTITY_LEN + 1];
    assert_eq!(
        c_submit(h, 10, 1, &long, b"file_write", b"", 1),
        ERR_INVALID,
        "identity too long"
    );
    // Null pointer with non-zero length.
    // SAFETY: null with len>0 is rejected before any dereference.
    let code = unsafe {
        jss_engine_submit_event(
            h,
            10,
            1,
            std::ptr::null(),
            5,
            b"k".as_ptr(),
            1,
            std::ptr::null(),
            0,
            1,
        )
    };
    assert_eq!(code, ERR_NULL);
    // Null pointer with zero length is fine for the optional detail.
    // SAFETY: zero-length buffers are never dereferenced.
    let code = unsafe {
        jss_engine_submit_event(
            h,
            10,
            1,
            APP.as_ptr(),
            APP.len(),
            b"file_write".as_ptr(),
            10,
            std::ptr::null(),
            0,
            1,
        )
    };
    assert_eq!(code, OK);
    jss_engine_free(h);
}

#[test]
fn a_live_process_cannot_change_identity() {
    let _g = lock();
    let h = jss_engine_new(7);
    assert_eq!(c_submit(h, 42, 1, APP, b"file_write", b"", 1), OK);
    assert_eq!(
        c_submit(h, 42, 1, b"com.attacker:sha256:ff", b"file_write", b"", 2),
        ERR_IDENTITY_MISMATCH
    );
    let alerts = c_take(h, 64 * 1024).1;
    assert!(
        alerts.contains("identity mismatch rejected pid=42"),
        "must be recorded: {alerts}"
    );
    jss_engine_free(h);
}

#[test]
fn exit_retires_identity_so_a_reused_pid_starts_clean() {
    let _g = lock();
    let h = jss_engine_new(7);
    for k in [
        "unsigned_module_load",
        "rwx_alloc",
        "remote_thread_injection",
    ] {
        assert_eq!(c_submit(h, 42, 1, APP, k.as_bytes(), b"", 1), OK);
    }
    assert_eq!(c_submit(h, 42, 1, APP, b"process_exit", b"", 1), OK);
    let _ = c_take(h, 64 * 1024);
    // The OS reuses pid 42 for a different app with a NEW generation.
    let other = b"com.other.app:sha256:cd34";
    assert_eq!(c_submit(h, 42, 2, other, b"file_write", b"", 1), OK);
    let (_, alerts) = c_take(h, 64 * 1024);
    assert!(
        !alerts.contains("ALERT"),
        "reused pid inherited risk: {alerts}"
    );
    jss_engine_free(h);
}

#[test]
fn a_retired_generation_cannot_be_revived() {
    // Review finding: after exit, the same (pid, gen) came back with zero risk
    // and a different identity.
    let _g = lock();
    let h = jss_engine_new(7);
    assert_eq!(
        c_submit(h, 20, 7, APP, b"remote_thread_injection", b"", 1),
        OK
    );
    assert_eq!(c_submit(h, 20, 7, APP, b"process_exit", b"", 1), OK);
    let _ = c_take(h, 64 * 1024);
    let attacker = b"com.attacker:sha256:ff";
    assert_eq!(
        c_submit(h, 20, 7, attacker, b"file_write", b"", 1),
        ERR_STALE_GENERATION
    );
    assert_eq!(
        c_submit(h, 20, 6, attacker, b"file_write", b"", 1),
        ERR_STALE_GENERATION
    );
    let (_, alerts) = c_take(h, 64 * 1024);
    assert!(
        alerts.contains("stale generation rejected pid=20"),
        "must be recorded: {alerts}"
    );
    jss_engine_free(h);
}

#[test]
fn a_far_future_timestamp_cannot_wipe_risk() {
    // Review finding: one event with at_ms = i64::MAX decayed every process's
    // risk to zero. The engine now ignores caller time for decay.
    let _g = lock();
    let h = jss_engine_new(7);
    for k in ["unsigned_module_load", "rwx_alloc", "privilege_escalation"] {
        assert_eq!(c_submit(h, 10, 1, APP, k.as_bytes(), b"", 1), OK);
    }
    let before = c_take(h, 64 * 1024).1;
    assert!(
        before.contains("Restrict") || before.contains("RESTRICT") || before.contains("would"),
        "{before}"
    );
    // Another process sends a far-future timestamp.
    assert_eq!(
        c_submit(
            h,
            11,
            1,
            b"com.noise:sha256:00",
            b"file_write",
            b"",
            i64::MAX as u64
        ),
        OK
    );
    let after = c_take(h, 64 * 1024).1;
    assert!(
        !after.contains("de-escalated"),
        "risk was wiped by a timestamp: {after}"
    );
    jss_engine_free(h);
}

#[test]
fn a_new_generation_retires_the_old_one_without_an_exit() {
    // Review finding: processes killed without an exit event leaked identity
    // capacity until every new process was rejected (fail open).
    let _g = lock();
    let h = jss_engine_new(7);
    for gen in 1..=(MAX_IDENTITIES as u64 + 50) {
        assert_eq!(
            c_submit(h, 77, gen, APP, b"file_write", b"", 1),
            OK,
            "gen {gen}"
        );
    }
    // Detection still works for a brand-new process.
    assert_eq!(c_submit(h, 78, 1, APP, b"privilege_escalation", b"", 1), OK);
    jss_engine_free(h);
}

#[test]
fn alerts_flow_out_and_are_never_split() {
    let _g = lock();
    let h = jss_engine_new(7);
    for (i, k) in [
        "unsigned_module_load",
        "rwx_alloc",
        "privilege_escalation",
        "remote_thread_injection",
        "credential_access",
    ]
    .iter()
    .enumerate()
    {
        assert_eq!(
            c_submit(h, 7, 1, APP, k.as_bytes(), b"", 1_000 + 100 * i as u64),
            OK
        );
    }
    assert_eq!(
        c_take(h, 10).0,
        ERR_BUFFER_TOO_SMALL,
        "tiny buffer rejected"
    );
    // Drain with the minimum buffer, repeatedly; every chunk must end on a
    // line boundary and together they must contain the escalation.
    let mut all = String::new();
    loop {
        let (code, chunk) = c_take(h, MIN_ALERT_BUFFER);
        assert_eq!(code, OK);
        if chunk.is_empty() {
            break;
        }
        assert!(chunk.ends_with('\n'), "chunk split mid-line: {chunk:?}");
        all.push_str(&chunk);
    }
    assert!(
        all.contains("BLOCKED"),
        "expected a block alert, got:\n{all}"
    );
    assert!(
        all.contains("alert-only"),
        "bridge engines must be alert-only:\n{all}"
    );
    jss_engine_free(h);
}

#[test]
fn alert_queue_is_bounded_and_reports_drops() {
    let _g = lock();
    let h = jss_engine_new(7);
    // Many short-lived processes, each climbing to Block, generate far more
    // than MAX_ALERTS lines without anyone draining.
    for p in 0..200u32 {
        for (i, k) in ["remote_thread_injection", "credential_access", "rwx_alloc"]
            .iter()
            .enumerate()
        {
            c_submit(h, 1000 + p, 1, APP, k.as_bytes(), b"", 1 + i as u64);
        }
        c_submit(h, 1000 + p, 1, APP, b"process_exit", b"", 5);
    }
    let (code, first) = c_take(h, 1 << 20);
    assert_eq!(code, OK);
    assert!(
        first.starts_with("[bridge] "),
        "drop count must be reported first:\n{}",
        &first[..200.min(first.len())]
    );
    assert!(
        first.lines().count() <= MAX_ALERTS + 1,
        "queue must be bounded"
    );
    jss_engine_free(h);
}

#[test]
fn a_full_identity_table_evicts_low_risk_and_never_rejects() {
    let _g = lock();
    let h = jss_engine_new(7);
    // One suspicious process first.
    for k in ["remote_thread_injection", "credential_access"] {
        assert_eq!(c_submit(h, 1, 1, APP, k.as_bytes(), b"", 1), OK);
    }
    // Fill the table with benign processes, then keep going past capacity.
    for p in 2..=(MAX_IDENTITIES as u32 + 20) {
        assert_eq!(
            c_submit(h, p, 1, APP, b"file_write", b"", 1),
            OK,
            "pid {p} rejected"
        );
    }
    let alerts = c_take(h, 1 << 20).1;
    assert!(
        alerts.contains("identity table full; evicted"),
        "eviction must be reported"
    );
    assert!(
        !alerts.contains("evicted lowest-risk idle pid=1 "),
        "the suspicious process must not be evicted"
    );
    // The suspicious process is still tracked: its identity still can't change.
    assert_eq!(
        c_submit(h, 1, 1, b"com.attacker:sha256:ff", b"file_write", b"", 1),
        ERR_IDENTITY_MISMATCH
    );
    jss_engine_free(h);
}

#[test]
fn engine_capacity_is_enforced() {
    let _g = lock();
    let hs: Vec<_> = (0..MAX_ENGINES).map(|i| jss_engine_new(i as u64)).collect();
    assert!(hs.iter().all(|&h| h != 0));
    assert_eq!(jss_engine_new(99), 0, "over capacity must fail, not grow");
    for h in hs {
        jss_engine_free(h);
    }
    let h = jss_engine_new(1);
    assert_ne!(h, 0, "capacity frees up after release");
    jss_engine_free(h);
}

#[test]
fn free_while_other_threads_submit_is_safe() {
    let _g = lock();
    for _round in 0..20 {
        let h = jss_engine_new(7);
        let start = Arc::new(Barrier::new(9));
        let workers: Vec<_> = (0..8u32)
            .map(|t| {
                let start = Arc::clone(&start);
                std::thread::spawn(move || {
                    start.wait();
                    for i in 0..200u64 {
                        let code = c_submit(
                            h,
                            100 + t,
                            1,
                            APP,
                            b"network_connect",
                            b"example.org:443",
                            i,
                        );
                        assert!(code == OK || code == ERR_BAD_HANDLE, "unexpected {code}");
                        let (tc, _) = c_take(h, MIN_ALERT_BUFFER);
                        assert!(tc == OK || tc == ERR_BAD_HANDLE, "unexpected take {tc}");
                    }
                })
            })
            .collect();
        start.wait();
        std::thread::yield_now();
        assert_eq!(jss_engine_free(h), OK, "free while busy");
        for w in workers {
            w.join().expect("worker panicked");
        }
        assert_eq!(
            c_submit(h, 1, 1, APP, b"file_write", b"", 1),
            ERR_BAD_HANDLE
        );
    }
}
