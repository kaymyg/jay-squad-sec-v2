//! Risk & Policy Engine.
//!
//! Every event contributes weighted evidence. Scores decay unless reinforced.
//! Thresholds map deterministically to policy actions — no ML in the loop.

use crate::event::EventKind;

/// Risk half-life (simulated ms): unreinforced suspicion fades.
const HALF_LIFE_MS: f32 = 30_000.0;

/// Weighted evidence per event (straight from the architecture doc).
pub fn base_score(kind: EventKind) -> f32 {
    use EventKind::*;
    match kind {
        UnsignedBinary => 15.0,
        RwxAlloc => 25.0,
        RemoteThreadInjection => 35.0,
        CredentialAccess => 40.0,
        UnsignedModuleLoad => 20.0,
        PersistenceWrite => 15.0,
        PrivilegeEscalation => 20.0,
        NetworkConnect => 2.0,
        FileWrite => 1.0,
        SignedBinary => -10.0,
        StableTick => -5.0,
        TempExecution => 20.0,
        DeletedExecutable => 30.0,
        ProcessStart | ProcessExit => 0.0,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PolicyAction {
    Allow,    //   0-24
    Monitor,  //  25-49
    Restrict, //  50-74
    Suspend,  //  75-99
    Block,    // >=100
}

pub fn action_for(score: f32) -> PolicyAction {
    // NaN compares false against every threshold below, so it used to fall
    // through to Allow. A risk engine that cannot evaluate a score must fail
    // closed, not open.
    if score.is_nan() {
        return PolicyAction::Block;
    }
    match score {
        s if s >= 100.0 => PolicyAction::Block,
        s if s >= 75.0 => PolicyAction::Suspend,
        s if s >= 50.0 => PolicyAction::Restrict,
        s if s >= 25.0 => PolicyAction::Monitor,
        _ => PolicyAction::Allow,
    }
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

    /// Decay to `now`, floor at zero.
    pub fn decay_to(&mut self, now_ms: u64) {
        if now_ms > self.last_ms {
            let dt = (now_ms - self.last_ms) as f32;
            self.score *= 0.5f32.powf(dt / HALF_LIFE_MS);
            self.last_ms = now_ms;
        }
        if self.score < 0.0 {
            self.score = 0.0;
        }
    }

    /// Decay, then absorb one piece of evidence.
    pub fn absorb(&mut self, kind: EventKind, now_ms: u64) {
        self.decay_to(now_ms);
        self.score = (self.score + base_score(kind)).max(0.0);
    }

    pub fn action(&self) -> PolicyAction {
        action_for(self.score)
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
    fn infinities_land_on_the_extremes() {
        assert_eq!(action_for(f32::INFINITY), PolicyAction::Block);
        assert_eq!(action_for(f32::NEG_INFINITY), PolicyAction::Allow);
    }}
