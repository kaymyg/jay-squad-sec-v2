//! What the engine decides for Android app-level observations under the
//! default rules. These fix the intended calibration: a swapped app alone is
//! serious, a single new permission is not, and signals on the same app add up.
use jay_squad_sec::engine::Engine;
use jay_squad_sec::event::{Event, EventKind, EventKind::*};
use jay_squad_sec::risk::{action_for, PolicyAction};

fn assess(kinds: &[EventKind]) -> (f32, PolicyAction) {
    let mut e = Engine::new(7);
    e.set_alert_only(true);
    let id = e.adopt("com.example.app", b"com.example.app:sha256:00", 0);
    e.tick(0);
    for (i, k) in kinds.iter().enumerate() {
        e.bus.publish(Event {
            rtid: id,
            kind: *k,
            at_ms: 10 + i as u64,
            detail: String::new(),
        });
    }
    e.tick(10 + kinds.len() as u64);
    let score = e.process(id).unwrap().risk.score;
    (score, action_for(score))
}

#[test]
fn a_single_new_permission_is_noted_not_escalated() {
    assert_eq!(assess(&[SensitivePermissionGranted]).1, PolicyAction::Allow);
}

#[test]
fn several_sensitive_permissions_on_one_app_escalate() {
    let two = assess(&[SensitivePermissionGranted; 2]).1;
    let four = assess(&[SensitivePermissionGranted; 4]).1;
    assert_eq!(two, PolicyAction::Monitor);
    assert_eq!(four, PolicyAction::Restrict);
}

#[test]
fn a_swapped_app_alone_is_restricted() {
    assert_eq!(assess(&[AppSignerChanged]).1, PolicyAction::Restrict);
}

#[test]
fn a_swapped_app_that_also_gains_access_is_suspended() {
    assert_eq!(
        assess(&[AppSignerChanged, SensitivePermissionGranted]).1,
        PolicyAction::Suspend
    );
}

#[test]
fn a_new_app_with_sms_and_microphone_is_monitored() {
    let (score, action) = assess(&[
        NewAppWithSensitiveAccess,
        SensitivePermissionGranted,
        SensitivePermissionGranted,
    ]);
    assert_eq!(score, 40.0);
    assert_eq!(action, PolicyAction::Monitor);
}
