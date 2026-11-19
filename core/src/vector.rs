//! Behaviour Vector Engine.
//!
//! Raw events are folded into a compact per-process vector that decays over
//! time. Raw events themselves are short-lived; the vector is what persists.

use crate::event::EventKind;

/// Half-life of behavioural memory (simulated ms).
const HALF_LIFE_MS: f32 = 60_000.0;

#[derive(Clone, Copy, Debug, Default)]
pub struct BehaviorVector {
    pub network: f32,
    pub filesystem: f32,
    pub memory: f32,
    pub privilege: f32,
    pub injection: f32,
    pub persistence: f32,
}

impl BehaviorVector {
    /// Exponential decay toward zero.
    pub fn decay(&mut self, dt_ms: u64) {
        let f = 0.5f32.powf(dt_ms as f32 / HALF_LIFE_MS);
        self.network *= f;
        self.filesystem *= f;
        self.memory *= f;
        self.privilege *= f;
        self.injection *= f;
        self.persistence *= f;
    }

    /// Fold one event into the vector.
    pub fn apply(&mut self, kind: EventKind) {
        use EventKind::*;
        match kind {
            NetworkConnect => self.network += 1.0,
            FileWrite => self.filesystem += 1.0,
            RwxAlloc => self.memory += 3.0,
            UnsignedModuleLoad => self.memory += 2.0,
            PrivilegeEscalation => self.privilege += 3.0,
            CredentialAccess => self.privilege += 4.0,
            RemoteThreadInjection => self.injection += 4.0,
            PersistenceWrite => self.persistence += 3.0,
            TempExecution => self.filesystem += 2.0,
            DeletedExecutable => self.memory += 2.0,
            _ => {}
        }
    }

    /// Rough single-number summary (used only for display).
    pub fn magnitude(&self) -> f32 {
        (self.network.powi(2)
            + self.filesystem.powi(2)
            + self.memory.powi(2)
            + self.privilege.powi(2)
            + self.injection.powi(2)
            + self.persistence.powi(2))
        .sqrt()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decay_halves_after_half_life() {
        let mut v = BehaviorVector::default();
        v.apply(EventKind::NetworkConnect);
        v.apply(EventKind::NetworkConnect);
        assert!((v.network - 2.0).abs() < 1e-6);
        v.decay(60_000);
        assert!((v.network - 1.0).abs() < 1e-3);
    }

    #[test]
    fn injection_weighs_more_than_file_io() {
        let mut a = BehaviorVector::default();
        let mut b = BehaviorVector::default();
        a.apply(EventKind::RemoteThreadInjection);
        b.apply(EventKind::FileWrite);
        assert!(a.magnitude() > b.magnitude());
    }
}
