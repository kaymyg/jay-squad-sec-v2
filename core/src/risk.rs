//! Risk & Policy Engine.
//!
//! Every event contributes weighted evidence. Scores decay unless reinforced.
//! Thresholds map deterministically to policy actions — no ML in the loop.
//!
//! The weights, thresholds and half-life live in [`RulesConfig`] so a verified
//! data-only update can retune them. The free functions and the plain
//! `RiskState` methods use [`DEFAULT_RULES`] and behave exactly as before; the
//! engine uses the `*_with` variants with its currently installed rules.

use crate::event::EventKind;
use crate::rules::{RulesConfig, DEFAULT_RULES};

/// Weighted evidence per event under the default rules (architecture doc).
pub fn base_score(kind: EventKind) -> f32 {
    DEFAULT_RULES.weight(kind)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PolicyAction {
    Allow,    //   0-24
    Monitor,  //  25-49
    Restrict, //  50-74
    Suspend,  //  75-99
    Block,    // >=100
}

/// Map a score to a policy action under the default rules. Fails closed: any
/// non-finite score (NaN, +inf, -inf) is unevaluable and maps to Block.
pub fn action_for(score: f32) -> PolicyAction {
    DEFAULT_RULES.action_for(score)
}

#[derive(Clone, Copy, Debug)]
pub struct RiskState {
    pub score: f32,
    last_ms: u64,
}

impl RiskState {
    pub fn new(now_ms: u64) -> Self {
        Self { score: 0.0, last_ms: now_ms }
    }

    /// Decay to `now` under the default rules, floor at zero.
    pub fn decay_to(&mut self, now_ms: u64) {
        self.decay_to_with(now_ms, &DEFAULT_RULES);
    }

    /// Decay to `now` using the given rules' half-life, floor at zero.
    pub fn decay_to_with(&mut self, now_ms: u64, rules: &RulesConfig) {
        if now_ms > self.last_ms {
            let dt = (now_ms - self.last_ms) as f32;
            self.score *= 0.5f32.powf(dt / rules.half_life_ms);
            self.last_ms = now_ms;
        }
        // Floor negatives only. A NaN is deliberately NOT scrubbed to 0: left as
        // NaN it maps to Block (fail closed); scrubbing it would fail open.
        if self.score < 0.0 {
            self.score = 0.0;
        }
    }

    /// Decay, then absorb one piece of evidence (default rules).
    pub fn absorb(&mut self, kind: EventKind, now_ms: u64) {
        self.absorb_with(kind, now_ms, &DEFAULT_RULES);
    }

    /// Decay, then absorb one piece of evidence using the given rules.
    pub fn absorb_with(&mut self, kind: EventKind, now_ms: u64, rules: &RulesConfig) {
        self.decay_to_with(now_ms, rules);
        self.score = (self.score + rules.weight(kind)).max(0.0);
    }

    /// Current action under the default rules.
    pub fn action(&self) -> PolicyAction {
        action_for(self.score)
    }

    /// Current action under the given rules.
    pub fn action_with(&self, rules: &RulesConfig) -> PolicyAction {
        rules.action_for(self.score)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_decays_by_half_after_half_life() {
        let mut r = RiskState::new(0);
        r.absorb(EventKind::CredentialAccess, 0); // +40
        r.decay_to(30_000);
        assert!((r.score - 20.0).abs() < 0.5);
    }

    #[test]
    fn good_evidence_cannot_push_below_zero() {
        let mut r = RiskState::new(0);
        r.absorb(EventKind::SignedBinary, 0);
        r.absorb(EventKind::StableTick, 0);
        assert_eq!(r.score, 0.0);
    }

    #[test]
    fn thresholds_map_to_actions() {
        assert_eq!(action_for(10.0), PolicyAction::Allow);
        assert_eq!(action_for(25.0), PolicyAction::Monitor);
        assert_eq!(action_for(50.0), PolicyAction::Restrict);
        assert_eq!(action_for(75.0), PolicyAction::Suspend);
        assert_eq!(action_for(100.0), PolicyAction::Block);
    }

    #[test]
    fn actions_are_ordered() {
        assert!(PolicyAction::Block > PolicyAction::Suspend);
        assert!(PolicyAction::Restrict > PolicyAction::Monitor);
    }

    #[test]
    fn nan_fails_closed_instead_of_open() {
        // an unevaluable score is the one case where Allow is the worst answer
        assert_eq!(action_for(f32::NAN), PolicyAction::Block);
    }

    #[test]
    fn infinities_fail_closed() {
        // Both infinities are unevaluable, so both must Block, never Allow.
        assert_eq!(action_for(f32::INFINITY), PolicyAction::Block);
        assert_eq!(action_for(f32::NEG_INFINITY), PolicyAction::Block);
    }}
