//! Adaptive Observation Engine.
//!
//! Observation depth follows behaviour, not reputation. Levels rise fast and
//! fall with hysteresis (dropping requires a lower score than rising did),
//! so a process can't flap between telemetry depths.

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

fn raw_level(score: f32) -> ObservationLevel {
    // A non-finite score is unevaluable; observe at maximum depth rather than
    // falling through to L0, mirroring the risk engine's fail-closed stance.
    if !score.is_finite() {
        return ObservationLevel::L4Containment;
    }
    match score {
        s if s >= 75.0 => ObservationLevel::L4Containment,
        s if s >= 50.0 => ObservationLevel::L3DeepCorrelation,
        s if s >= 25.0 => ObservationLevel::L2BehaviourMonitoring,
        s if s >= 10.0 => ObservationLevel::L1BehaviourMetadata,
        _ => ObservationLevel::L0MinimalMetadata,
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

    /// Returns Some((old, new)) on transition.
    pub fn update(&mut self, score: f32) -> Option<(ObservationLevel, ObservationLevel)> {
        let target = raw_level(score);
        // Escalate immediately; de-escalate only once clearly below the
        // boundary (hysteresis), so the level does not flap around a threshold.
        let escalate = target > self.level;
        let deescalate = target < self.level && raw_level(score + DROP_MARGIN) < self.level;
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
