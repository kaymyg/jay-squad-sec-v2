use jay_squad_sec::risk::{action_for, PolicyAction};

#[test]
fn every_policy_threshold_is_inclusive_and_adjacent_values_are_stable() {
    let cases = [
        (24.999, PolicyAction::Allow),
        (25.0, PolicyAction::Monitor),
        (49.999, PolicyAction::Monitor),
        (50.0, PolicyAction::Restrict),
        (74.999, PolicyAction::Restrict),
        (75.0, PolicyAction::Suspend),
        (99.999, PolicyAction::Suspend),
        (100.0, PolicyAction::Block),
    ];
    for (score, expected) in cases {
        assert_eq!(action_for(score), expected, "score {score}");
    }
}

#[test]
fn negative_and_zero_scores_allow_but_non_finite_scores_block() {
    assert_eq!(action_for(0.0), PolicyAction::Allow);
    assert_eq!(action_for(-1.0), PolicyAction::Allow);
    assert_eq!(action_for(f32::NAN), PolicyAction::Block);
    assert_eq!(action_for(f32::INFINITY), PolicyAction::Block);
    assert_eq!(action_for(f32::NEG_INFINITY), PolicyAction::Block);
}
