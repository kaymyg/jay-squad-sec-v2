//! What the rules decide for Android app-level observations under the
//! defaults. These fix the calibration (a swapped app alone is serious, a
//! single new permission is not, signals on one app add up) and pin the exact
//! threshold sums, which are deterministic because app verdicts never decay.
use jay_squad_sec::event::{EventKind, EventKind::*};
use jay_squad_sec::risk::PolicyAction;
use jay_squad_sec::rules::{kind_index, RulesConfig, RulesError, DEFAULT_RULES};

fn assess(kinds: &[EventKind]) -> (f32, PolicyAction) {
    DEFAULT_RULES.assess_app(kinds)
}

#[test]
fn a_single_new_permission_is_noted_not_escalated() {
    assert_eq!(assess(&[SensitivePermissionGranted]), (15.0, PolicyAction::Allow));
}

#[test]
fn several_sensitive_permissions_on_one_app_escalate() {
    assert_eq!(assess(&[SensitivePermissionGranted; 2]).1, PolicyAction::Monitor);
    assert_eq!(assess(&[SensitivePermissionGranted; 4]).1, PolicyAction::Restrict);
}

#[test]
fn a_swapped_app_alone_is_restricted() {
    assert_eq!(assess(&[AppSignerChanged]), (60.0, PolicyAction::Restrict));
}

#[test]
fn exact_threshold_sums_are_stable() {
    // 60 + 15 = 75 is exactly Suspend; 10 + 15 = 25 exactly Monitor; a new app
    // with six sensitive permissions is exactly 100, Block.
    assert_eq!(assess(&[AppSignerChanged, SensitivePermissionGranted]), (75.0, PolicyAction::Suspend));
    assert_eq!(assess(&[NewAppWithSensitiveAccess, SensitivePermissionGranted]), (25.0, PolicyAction::Monitor));
    let mut six = vec![NewAppWithSensitiveAccess];
    six.extend([SensitivePermissionGranted; 6]);
    assert_eq!(assess(&six), (100.0, PolicyAction::Block));
    // Same input, same answer, every time.
    for _ in 0..1000 {
        assert_eq!(assess(&[AppSignerChanged, SensitivePermissionGranted]).1, PolicyAction::Suspend);
    }
}

#[test]
fn process_kinds_do_not_count_for_apps() {
    assert_eq!(assess(&[CredentialAccess, RemoteThreadInjection]), (0.0, PolicyAction::Allow));
}

#[test]
fn a_patch_cannot_make_a_swapped_app_look_harmless() {
    let mut r: RulesConfig = DEFAULT_RULES;
    r.weights[kind_index(AppSignerChanged)] = 1.0;
    assert_eq!(r.validate(), Err(RulesError::AppSignerTooWeak));
    r.weights[kind_index(AppSignerChanged)] = r.restrict_at;
    assert_eq!(r.validate(), Ok(()));
}

#[test]
fn version_1_rules_payloads_are_rejected() {
    let mut bytes = DEFAULT_RULES.encode();
    assert_eq!(&bytes[4..6], &2u16.to_le_bytes());
    bytes[4..6].copy_from_slice(&1u16.to_le_bytes());
    assert_eq!(RulesConfig::decode(&bytes), Err(RulesError::Malformed));
    // A genuine v1-sized payload (15 weights) is rejected too.
    let v1_len = 4 + 2 + 4 + 4 * 15 + 4 * 4;
    let mut v1 = vec![0u8; v1_len];
    v1[0..4].copy_from_slice(b"JSSR");
    v1[4..6].copy_from_slice(&1u16.to_le_bytes());
    assert_eq!(RulesConfig::decode(&v1), Err(RulesError::Malformed));
}
