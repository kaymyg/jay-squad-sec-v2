use jay_squad_sec_bridge::{
    jss_bridge_abi_version, jss_engine_free, jss_engine_new, jss_engine_submit_event,
};

unsafe fn submit(
    handle: *mut jay_squad_sec_bridge::JssEngine,
    pid: u32,
    generation: u64,
    identity: &[u8],
    kind: &[u8],
    detail: &[u8],
) -> i32 {
    // SAFETY: slices remain alive and readable for the duration of the call.
    unsafe {
        jss_engine_submit_event(
            handle,
            pid,
            generation,
            identity.as_ptr(),
            identity.len(),
            kind.as_ptr(),
            kind.len(),
            detail.as_ptr(),
            detail.len(),
            100,
        )
    }
}

#[test]
fn reports_abi_v2_and_creates_an_alert_only_handle() {
    assert_eq!(jss_bridge_abi_version(), 2);
    let handle = jss_engine_new(7);
    assert!(!handle.is_null());
    // SAFETY: handle was returned by new and is freed exactly once.
    unsafe { jss_engine_free(handle) };
}

#[test]
fn rejects_null_handle_and_invalid_required_fields() {
    let kind = b"process_start";
    let detail = b"";
    // SAFETY: null handle is rejected before any pointer is dereferenced.
    let code = unsafe {
        jss_engine_submit_event(
            std::ptr::null_mut(),
            10,
            1,
            b"com.example.app".as_ptr(),
            15,
            kind.as_ptr(),
            kind.len(),
            detail.as_ptr(),
            detail.len(),
            100,
        )
    };
    assert_eq!(code, 1);

    let handle = jss_engine_new(7);
    assert!(!handle.is_null());
    // SAFETY: valid handle; required empty kind is rejected before use.
    let code = unsafe { submit(handle, 10, 1, b"com.example.app", b"", b"") };
    assert_eq!(code, 2);
    // SAFETY: valid handle freed once after synchronous call.
    unsafe { jss_engine_free(handle) };
}

#[test]
fn rejects_oversized_buffers_before_reading_them() {
    let handle = jss_engine_new(7);
    assert!(!handle.is_null());
    // A null pointer with an oversized length must be rejected on length
    // before any attempt to construct/dereference a slice.
    // SAFETY: handle is live; null+oversized buffers are intentionally invalid.
    let code = unsafe {
        jss_engine_submit_event(
            handle,
            10,
            1,
            std::ptr::null(),
            513,
            b"process_start".as_ptr(),
            12,
            std::ptr::null(),
            0,
            100,
        )
    };
    assert_eq!(code, 2);
    // SAFETY: valid handle freed once.
    unsafe { jss_engine_free(handle) };
}

#[test]
fn pid_reuse_uses_distinct_process_generations() {
    let handle = jss_engine_new(7);
    assert!(!handle.is_null());
    // SAFETY: all byte slices are valid for each synchronous call.
    unsafe {
        assert_eq!(
            submit(handle, 42, 1, b"com.example.one", b"process_start", b""),
            0
        );
        assert_eq!(
            submit(
                handle,
                42,
                1,
                b"com.example.one",
                b"network_connect",
                b"one.test:443"
            ),
            0
        );
        assert_eq!(
            submit(handle, 42, 1, b"com.example.one", b"process_exit", b""),
            0
        );
        assert_eq!(
            submit(handle, 42, 2, b"com.example.two", b"process_start", b""),
            0
        );
        jss_engine_free(handle);
    }
}

#[test]
fn concurrent_submissions_are_serialized_by_the_handle_mutex() {
    let handle = jss_engine_new(7);
    assert!(!handle.is_null());
    let address = handle as usize;
    let mut threads = Vec::new();
    for i in 0..8u32 {
        threads.push(std::thread::spawn(move || {
            let handle = address as *mut jay_squad_sec_bridge::JssEngine;
            let detail = format!("host-{i}.example:443");
            // SAFETY: the main test retains the handle until all worker threads
            // join; each thread passes its own live input buffers.
            unsafe {
                submit(
                    handle,
                    100 + i,
                    1,
                    b"com.example.concurrent",
                    b"network_connect",
                    detail.as_bytes(),
                )
            }
        }));
    }
    for thread in threads {
        assert_eq!(thread.join().expect("worker thread panicked"), 0);
    }
    // SAFETY: all calls have joined; free exactly once.
    unsafe { jss_engine_free(handle) };
}
