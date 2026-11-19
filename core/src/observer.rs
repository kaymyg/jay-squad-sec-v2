//! Adaptive Observation Engine.
//!
//! Observation depth follows behaviour, not reputation. Levels rise fast and
//! fall with hysteresis (dropping requires a lower score than rising did),
//! so a process can't flap between telemetry depths.
//!
//! Level boundaries follow the installed rules, so a patched policy and the
//! observation depth never disagree: L2/L3/L4 start at monitor/restrict/
//! suspend, and L1 at two fifths of monitor (richer metadata before any policy
//! action). With DEFAULT_RULES this is exactly the original 10/25/50/75.

use crate::rules::{RulesConfig, DEFAULT_RULES};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ObservationLevel {
    L0MinimalMetadata,
    L1BehaviourMetadata,
    L2BehaviourMonitoring,
    L3DeepCorrelation,
    L4Containment,
}

impl ObservationLevel {
    pub fn label(self) -> &'static str {
        match self {
            ObservationLevel::L0MinimalMetadata => "L0 minimal",
            ObservationLevel::L1BehaviourMetadata => "L1 metadata",
            ObservationLevel::L2BehaviourMonitoring => "L2 monitoring",
            ObservationLevel::L3DeepCorrelation => "L3 deep-correlation",
            ObservationLevel::L4Containment => "L4 containment",
        }
    }
}

#[allow(clippy::neg_cmp_op_on_partial_ord)] // deliberate: `!(x < t)` is true for NaN, so NaN escalates (fail closed)
fn raw_level(score: f32, rules: &RulesConfig) -> ObservationLevel {
    // Fail closed: a non-finite score (or a NaN threshold in an unvalidated
    // config) observes at maximum depth rather than falling through to L0.
    // Comparisons are `!(score < t)` so NaN escalates.
    let l1_at = rules.monitor_at * 2.0 / 5.0;
    if !score.is_finite() || !(score < rules.suspend_at) {
        ObservationLevel::L4Containment
    } else if !(score < rules.restrict_at) {
        ObservationLevel::L3DeepCorrelation
    } else if !(score < rules.monitor_at) {
        ObservationLevel::L2BehaviourMonitoring
    } else if !(score < l1_at) {
        ObservationLevel::L1BehaviourMetadata
    } else {
        ObservationLevel::L0MinimalMetadata
    }
}

/// Hysteresis margin: to drop a level, score must fall this far below the
/// raw threshold for the current level.
const DROP_MARGIN: f32 = 5.0;

#[derive(Clone, Copy, Debug)]
pub struct AdaptiveObserver {
    pub level: ObservationLevel,
}

impl AdaptiveObserver {
    pub fn new() -> Self {
        Self { level: ObservationLevel::L0MinimalMetadata }
    }

    /// Returns Some((old, new)) on transition. Uses the default rules.
    pub fn update(&mut self, score: f32) -> Option<(ObservationLevel, ObservationLevel)> {
        self.update_with(score, &DEFAULT_RULES)
    }

    /// Returns Some((old, new)) on transition, with level boundaries taken
    /// from the given (installed) rules.
    pub fn update_with(
        &mut self,
        score: f32,
        rules: &RulesConfig,
    ) -> Option<(ObservationLevel, ObservationLevel)> {
        let target = raw_level(score, rules);
        // Escalate immediately; de-escalate only once clearly below the
        // boundary (hysteresis), so the level does not flap around a threshold.
        let escalate = target > self.level;
        let deescalate = target < self.level && raw_level(score + DROP_MARGIN, rules) < self.level;
        let new = if escalate || deescalate { target } else { self.level };
        if new != self.level {
            let old = self.level;
            self.level = new;
            Some((old, new))
        } else {
            None
        }
    }
}

impl Default for AdaptiveObserver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escalates_immediately() {
        let mut o = AdaptiveObserver::new();
        let t = o.update(80.0).unwrap();
        assert_eq!(t.1, ObservationLevel::L4Containment);
    }

    #[test]
    fn hysteresis_prevents_flapping_at_boundary() {
        let mut o = AdaptiveObserver::new();
        o.update(30.0); // -> L2
        assert!(o.update(24.0).is_none()); // just under threshold: stays L2
        assert!(o.update(15.0).is_some()); // clearly below: drops
        assert_eq!(o.level, ObservationLevel::L1BehaviourMetadata);
    }
}
