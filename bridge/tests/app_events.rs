//! App-level observations (installed apps, no process) through the bridge.
use jay_squad_sec_bridge::*;
use std::sync::Mutex;

// Engines are capped per process; run these one at a time.
static LOCK: Mutex<()> = Mutex::new(());
const APP: &[u8] = b"com.example.bank:sha256:aa";

fn with_engine(f: impl FnOnce(JssHandle)) {
    let _g = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let h = engine_new(11);
    assert_ne!(h, 0);
    f(h);
    assert_eq!(engine_free(h), OK);
}

#[test]
fn unknown_app_is_allowed_with_zero_score() {
    with_engine(|h| assert_eq!(app_assessment(h, APP), Ok((0, 0.0))));
}

#[test]
fn a_swapped_app_is_restricted_and_extra_access_suspends_it() {
    with_engine(|h| {
        assert_eq!(submit_app_event(h, APP, b"app_signer_changed", b""), OK);
        let (action, score) = app_assessment(h, APP).unwrap();
        assert_eq!((action, score), (2, 60.0)); // Restrict
        assert_eq!(
            submit_app_event(h, APP, b"sensitive_permission_granted", b"READ_SMS"),
            OK
        );
        assert_eq!(app_assessment(h, APP).unwrap().0, 3); // Suspend
                                                          // Another app is unaffected.
        assert_eq!(app_assessment(h, b"com.other:sha256:bb"), Ok((0, 0.0)));
        let alerts = String::from_utf8(take_alerts(h, 1 << 16).unwrap()).unwrap();
        assert!(
            alerts.contains("com.example.bank"),
            "engine alerts name the app"
        );
    });
}

#[test]
fn app_and_process_kinds_cannot_be_mixed_up() {
    with_engine(|h| {
        assert_eq!(
            submit_app_event(h, APP, b"credential_access", b""),
            ERR_INVALID
        );
        assert_eq!(submit_app_event(h, APP, b"no_such_kind", b""), ERR_INVALID);
        assert_eq!(
            submit(h, 100, 1, APP, b"app_signer_changed", b"", 0),
            ERR_INVALID,
            "process submit must refuse app-level kinds"
        );
        assert_eq!(
            app_assessment(h, APP),
            Ok((0, 0.0)),
            "refused events change nothing"
        );
    });
}

#[test]
fn hostile_input_is_rejected() {
    with_engine(|h| {
        assert_eq!(
            submit_app_event(h, b"", b"app_signer_changed", b""),
            ERR_INVALID
        );
        assert_eq!(
            submit_app_event(h, &[0xff, 0xfe], b"app_signer_changed", b""),
            ERR_INVALID
        );
        let long = vec![b'a'; MAX_IDENTITY_LEN + 1];
        assert_eq!(
            submit_app_event(h, &long, b"app_signer_changed", b""),
            ERR_INVALID
        );
        assert_eq!(
            submit_app_event(h, APP, b"app_signer_changed", b"line\nbreak"),
            ERR_INVALID
        );
        assert_eq!(app_assessment(h, b""), Err(ERR_INVALID));
    });
    assert_eq!(
        submit_app_event(0, APP, b"app_signer_changed", b""),
        ERR_BAD_HANDLE
    );
    assert_eq!(app_assessment(0, APP), Err(ERR_BAD_HANDLE));
}

#[test]
fn app_subjects_are_capped() {
    with_engine(|h| {
        for i in 0..MAX_APP_SUBJECTS {
            let id = format!("com.app{i}:sha256:00");
            assert_eq!(
                submit_app_event(h, id.as_bytes(), b"new_app_with_sensitive_access", b""),
                OK
            );
        }
        assert_eq!(
            submit_app_event(
                h,
                b"com.one.more:sha256:00",
                b"new_app_with_sensitive_access",
                b""
            ),
            ERR_CAPACITY
        );
        // Existing subjects still accept events at capacity.
        assert_eq!(
            submit_app_event(h, b"com.app0:sha256:00", b"app_signer_changed", b""),
            OK
        );
    });
}

#[test]
fn c_abi_assessment_checks_pointers_and_reports_thousandths() {
    with_engine(|h| {
        assert_eq!(submit_app_event(h, APP, b"app_signer_changed", b""), OK);
        let (mut action, mut milli) = (99u32, 0u32);
        let rc = unsafe {
            jss_engine_app_assessment(h, APP.as_ptr(), APP.len(), &mut action, &mut milli)
        };
        assert_eq!((rc, action, milli), (OK, 2, 60_000));
        let rc = unsafe {
            jss_engine_app_assessment(h, APP.as_ptr(), APP.len(), std::ptr::null_mut(), &mut milli)
        };
        assert_eq!(rc, ERR_NULL);
        let rc = unsafe {
            jss_engine_submit_app_event(
                h,
                std::ptr::null(),
                5,
                b"x".as_ptr(),
                1,
                std::ptr::null(),
                0,
            )
        };
        assert_eq!(rc, ERR_NULL);
    });
    assert_eq!(score_milli(f32::NAN), u32::MAX);
    assert_eq!(score_milli(-3.0), 0);
    assert_eq!(score_milli(1e30), u32::MAX);
}

#[test]
fn verdicts_are_deterministic_at_exact_thresholds() {
    with_engine(|h| {
        assert_eq!(submit_app_event(h, APP, b"app_signer_changed", b""), OK);
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert_eq!(
            submit_app_event(h, APP, b"sensitive_permission_granted", b""),
            OK
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
        // 60 + 15 = 75 is exactly Suspend; time passing must not change it.
        assert_eq!(app_assessment(h, APP), Ok((3, 75.0)));
        let alerts = String::from_utf8(take_alerts(h, 1 << 16).unwrap()).unwrap();
        assert!(
            alerts.contains("Restrict -> Suspend"),
            "escalation alerted: {alerts}"
        );
        assert!(
            !alerts.contains("pid"),
            "app alerts never talk about processes"
        );
    });
}

#[test]
fn observations_per_app_are_capped() {
    with_engine(|h| {
        for _ in 0..MAX_APP_EVENTS {
            assert_eq!(
                submit_app_event(h, APP, b"sensitive_permission_granted", b""),
                OK
            );
        }
        assert_eq!(
            submit_app_event(h, APP, b"sensitive_permission_granted", b""),
            ERR_CAPACITY
        );
    });
}
