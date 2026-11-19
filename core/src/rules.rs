//! Patchable detection rules: the risk weights, thresholds and decay half-life.
//!
//! This is the ONLY thing a signed update can change. Engine code is immutable;
//! updates carry data, never code, so an update has no code-injection surface.
//!
//! Every config is validated before it can be installed, and validation is
//! deliberately opinionated: an update may *retune* detection but may not
//! *disable* it. Concretely:
//! - threat indicators (injection, credential access, …) must keep a positive
//!   weight, so a patch cannot zero out a detection;
//! - high-volume neutral events (file writes, network connects, process
//!   start/exit) must not be negative, or a process could launder its own risk
//!   score down by spamming them;
//! - good-evidence events (signed binary, stable tick) must not be positive;
//! - thresholds must be finite and strictly increasing.
//!
//! [`DEFAULT_RULES`] reproduces the original hard-coded engine values exactly,
//! so behaviour is unchanged until a verified patch says otherwise.

use crate::event::EventKind;
use crate::risk::PolicyAction;

/// Number of event kinds. Must match [`KINDS`]; enforced by a test.
pub const KIND_COUNT: usize = 15;

/// Canonical kind order used for the weights array and the wire encoding.
/// Never reorder: append only, and bump [`RULES_FORMAT_VERSION`].
pub const KINDS: [EventKind; KIND_COUNT] = [
    EventKind::ProcessStart,
    EventKind::ProcessExit,
    EventKind::SignedBinary,
    EventKind::UnsignedBinary,
    EventKind::NetworkConnect,
    EventKind::FileWrite,
    EventKind::UnsignedModuleLoad,
    EventKind::RwxAlloc,
    EventKind::RemoteThreadInjection,
    EventKind::CredentialAccess,
    EventKind::PersistenceWrite,
    EventKind::PrivilegeEscalation,
    EventKind::StableTick,
    EventKind::TempExecution,
    EventKind::DeletedExecutable,
];

/// Index of a kind in [`KINDS`]. Exhaustive match: adding an EventKind is a
/// compile error here until it is given a slot.
pub fn kind_index(k: EventKind) -> usize {
    use EventKind::*;
    match k {
        ProcessStart => 0,
        ProcessExit => 1,
        SignedBinary => 2,
        UnsignedBinary => 3,
        NetworkConnect => 4,
        FileWrite => 5,
        UnsignedModuleLoad => 6,
        RwxAlloc => 7,
        RemoteThreadInjection => 8,
        CredentialAccess => 9,
        PersistenceWrite => 10,
        PrivilegeEscalation => 11,
        StableTick => 12,
        TempExecution => 13,
        DeletedExecutable => 14,
    }
}

/// How a kind's weight is constrained by validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WeightClass {
    /// Evidence of malicious behaviour: weight must be > 0.
    Indicator,
    /// High-volume, attacker-producible activity: weight must be >= 0.
    Neutral,
    /// Evidence of benign behaviour: weight must be <= 0.
    GoodEvidence,
}

fn class(k: EventKind) -> WeightClass {
    use EventKind::*;
    match k {
        UnsignedBinary | UnsignedModuleLoad | RwxAlloc | RemoteThreadInjection
        | CredentialAccess | PersistenceWrite | PrivilegeEscalation | TempExecution
        | DeletedExecutable => WeightClass::Indicator,
        ProcessStart | ProcessExit | NetworkConnect | FileWrite => WeightClass::Neutral,
        SignedBinary | StableTick => WeightClass::GoodEvidence,
    }
}

/// Bounds enforced by [`RulesConfig::validate`].
pub const MIN_HALF_LIFE_MS: f32 = 1_000.0; // 1 second
pub const MAX_HALF_LIFE_MS: f32 = 86_400_000.0; // 1 day
pub const MAX_ABS_WEIGHT: f32 = 100.0;
pub const MAX_THRESHOLD: f32 = 10_000.0;

/// The tunable parameters of the risk engine.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RulesConfig {
    /// Risk half-life in ms: unreinforced suspicion halves over this period.
    pub half_life_ms: f32,
    /// Evidence weight per event kind, in [`KINDS`] order.
    pub weights: [f32; KIND_COUNT],
    pub monitor_at: f32,
    pub restrict_at: f32,
    pub suspend_at: f32,
    pub block_at: f32,
}

/// The original engine values (architecture doc). Behaviour-identical default.
pub const DEFAULT_RULES: RulesConfig = RulesConfig {
    half_life_ms: 30_000.0,
    weights: [
        0.0,   // ProcessStart
        0.0,   // ProcessExit
        -10.0, // SignedBinary
        15.0,  // UnsignedBinary
        2.0,   // NetworkConnect
        1.0,   // FileWrite
        20.0,  // UnsignedModuleLoad
        25.0,  // RwxAlloc
        35.0,  // RemoteThreadInjection
        40.0,  // CredentialAccess
        15.0,  // PersistenceWrite
        20.0,  // PrivilegeEscalation
        -5.0,  // StableTick
        20.0,  // TempExecution
        30.0,  // DeletedExecutable
    ],
    monitor_at: 25.0,
    restrict_at: 50.0,
    suspend_at: 75.0,
    block_at: 100.0,
};

impl Default for RulesConfig {
    fn default() -> Self {
        DEFAULT_RULES
    }
}

/// Why a rules config was rejected. A rejected config is never installed.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RulesError {
    /// Encoded rules had the wrong length, magic or format version.
    Malformed,
    /// A value was NaN or infinite.
    NonFinite,
    HalfLifeOutOfRange,
    WeightOutOfRange(EventKind),
    /// A threat indicator was given a weight <= 0 (would disable detection).
    IndicatorNotPositive(EventKind),
    /// A neutral high-volume event was given a negative weight (risk laundering).
    NeutralNegative(EventKind),
    /// A good-evidence event was given a positive weight.
    GoodEvidencePositive(EventKind),
    /// Thresholds were not 0 < monitor < restrict < suspend < block <= max.
    ThresholdsInvalid,
}

impl core::fmt::Display for RulesError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RulesError::Malformed => write!(f, "rules data is malformed"),
            RulesError::NonFinite => write!(f, "rules contain a NaN or infinite value"),
            RulesError::HalfLifeOutOfRange => write!(
                f,
                "half-life must be within {MIN_HALF_LIFE_MS}..={MAX_HALF_LIFE_MS} ms"
            ),
            RulesError::WeightOutOfRange(k) => {
                write!(f, "weight for {k:?} exceeds ±{MAX_ABS_WEIGHT}")
            }
            RulesError::IndicatorNotPositive(k) => {
                write!(f, "threat indicator {k:?} must keep a positive weight")
            }
            RulesError::NeutralNegative(k) => {
                write!(f, "neutral event {k:?} must not have a negative weight")
            }
            RulesError::GoodEvidencePositive(k) => {
                write!(f, "good-evidence event {k:?} must not have a positive weight")
            }
            RulesError::ThresholdsInvalid => write!(
                f,
                "thresholds must satisfy 0 < monitor < restrict < suspend < block <= {MAX_THRESHOLD}"
            ),
        }
    }
}

impl std::error::Error for RulesError {}

/// Magic bytes for encoded rules.
pub const RULES_MAGIC: &[u8; 4] = b"JSSR";
/// Rules wire-format version.
pub const RULES_FORMAT_VERSION: u16 = 1;
/// Exact encoded size: magic(4) + version(2) + half_life(4) + weights(60) + thresholds(16).
pub const RULES_ENCODED_LEN: usize = 4 + 2 + 4 + 4 * KIND_COUNT + 4 * 4;

impl RulesConfig {
    /// Evidence weight for an event kind.
    pub fn weight(&self, k: EventKind) -> f32 {
        self.weights[kind_index(k)]
    }

    /// Map a score to a policy action. Fails closed: any non-finite score
    /// is unevaluable and maps to Block.
    pub fn action_for(&self, score: f32) -> PolicyAction {
        if !score.is_finite() {
            return PolicyAction::Block;
        }
        if score >= self.block_at {
            PolicyAction::Block
        } else if score >= self.suspend_at {
            PolicyAction::Suspend
        } else if score >= self.restrict_at {
            PolicyAction::Restrict
        } else if score >= self.monitor_at {
            PolicyAction::Monitor
        } else {
            PolicyAction::Allow
        }
    }

    /// Check every invariant. See the module docs for the rationale.
    pub fn validate(&self) -> Result<(), RulesError> {
        let t = [self.monitor_at, self.restrict_at, self.suspend_at, self.block_at];
        if !self.half_life_ms.is_finite()
            || self.weights.iter().any(|w| !w.is_finite())
            || t.iter().any(|x| !x.is_finite())
        {
            return Err(RulesError::NonFinite);
        }
        if !(MIN_HALF_LIFE_MS..=MAX_HALF_LIFE_MS).contains(&self.half_life_ms) {
            return Err(RulesError::HalfLifeOutOfRange);
        }
        for k in KINDS {
            let w = self.weight(k);
            if w.abs() > MAX_ABS_WEIGHT {
                return Err(RulesError::WeightOutOfRange(k));
            }
            match class(k) {
                WeightClass::Indicator if w <= 0.0 => return Err(RulesError::IndicatorNotPositive(k)),
                WeightClass::Neutral if w < 0.0 => return Err(RulesError::NeutralNegative(k)),
                WeightClass::GoodEvidence if w > 0.0 => {
                    return Err(RulesError::GoodEvidencePositive(k))
                }
                _ => {}
            }
        }
        let ordered = 0.0 < t[0] && t[0] < t[1] && t[1] < t[2] && t[2] < t[3] && t[3] <= MAX_THRESHOLD;
        if !ordered {
            return Err(RulesError::ThresholdsInvalid);
        }
        Ok(())
    }

    /// Fixed-size little-endian encoding (zero dependencies).
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(RULES_ENCODED_LEN);
        b.extend_from_slice(RULES_MAGIC);
        b.extend_from_slice(&RULES_FORMAT_VERSION.to_le_bytes());
        b.extend_from_slice(&self.half_life_ms.to_le_bytes());
        for w in self.weights {
            b.extend_from_slice(&w.to_le_bytes());
        }
        for x in [self.monitor_at, self.restrict_at, self.suspend_at, self.block_at] {
            b.extend_from_slice(&x.to_le_bytes());
        }
        b
    }

    /// Decode AND validate. Never panics; anything that is not exactly a
    /// well-formed, valid config is rejected.
    pub fn decode(bytes: &[u8]) -> Result<Self, RulesError> {
        if bytes.len() != RULES_ENCODED_LEN || &bytes[0..4] != RULES_MAGIC {
            return Err(RulesError::Malformed);
        }
        if u16::from_le_bytes([bytes[4], bytes[5]]) != RULES_FORMAT_VERSION {
            return Err(RulesError::Malformed);
        }
        let f = |i: usize| f32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
        let half_life_ms = f(6);
        let mut weights = [0.0f32; KIND_COUNT];
        for (n, w) in weights.iter_mut().enumerate() {
            *w = f(10 + 4 * n);
        }
        let base = 10 + 4 * KIND_COUNT;
        let cfg = RulesConfig {
            half_life_ms,
            weights,
            monitor_at: f(base),
            restrict_at: f(base + 4),
            suspend_at: f(base + 8),
            block_at: f(base + 12),
        };
        cfg.validate()?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_table_is_complete_and_consistent() {
        for (i, k) in KINDS.iter().enumerate() {
            assert_eq!(kind_index(*k), i, "{k:?} index mismatch");
        }
        assert_eq!(RULES_ENCODED_LEN, DEFAULT_RULES.encode().len());
    }

    #[test]
    fn defaults_are_valid_and_match_original_engine() {
        assert_eq!(DEFAULT_RULES.validate(), Ok(()));
        assert_eq!(DEFAULT_RULES.weight(EventKind::CredentialAccess), 40.0);
        assert_eq!(DEFAULT_RULES.weight(EventKind::SignedBinary), -10.0);
        assert_eq!(DEFAULT_RULES.action_for(24.9), PolicyAction::Allow);
        assert_eq!(DEFAULT_RULES.action_for(25.0), PolicyAction::Monitor);
        assert_eq!(DEFAULT_RULES.action_for(100.0), PolicyAction::Block);
        assert_eq!(DEFAULT_RULES.action_for(f32::NAN), PolicyAction::Block);
    }

    #[test]
    fn encode_decode_round_trips() {
        let mut r = DEFAULT_RULES;
        r.weights[kind_index(EventKind::RwxAlloc)] = 30.0;
        r.block_at = 120.0;
        assert_eq!(RulesConfig::decode(&r.encode()), Ok(r));
    }

    #[test]
    fn decode_rejects_bad_framing() {
        let good = DEFAULT_RULES.encode();
        assert_eq!(RulesConfig::decode(&good[..good.len() - 1]), Err(RulesError::Malformed));
        let mut magic = good.clone();
        magic[0] = b'X';
        assert_eq!(RulesConfig::decode(&magic), Err(RulesError::Malformed));
        let mut ver = good.clone();
        ver[4] = 9;
        assert_eq!(RulesConfig::decode(&ver), Err(RulesError::Malformed));
        let mut nan = good.clone();
        nan[6..10].copy_from_slice(&f32::NAN.to_le_bytes());
        assert_eq!(RulesConfig::decode(&nan), Err(RulesError::NonFinite));
    }

    #[test]
    fn a_patch_cannot_disable_a_threat_indicator() {
        let mut r = DEFAULT_RULES;
        r.weights[kind_index(EventKind::CredentialAccess)] = 0.0;
        assert_eq!(
            r.validate(),
            Err(RulesError::IndicatorNotPositive(EventKind::CredentialAccess))
        );
    }

    #[test]
    fn a_patch_cannot_enable_risk_laundering() {
        let mut r = DEFAULT_RULES;
        r.weights[kind_index(EventKind::FileWrite)] = -1.0;
        assert_eq!(r.validate(), Err(RulesError::NeutralNegative(EventKind::FileWrite)));
    }

    #[test]
    fn good_evidence_cannot_become_suspicious() {
        let mut r = DEFAULT_RULES;
        r.weights[kind_index(EventKind::StableTick)] = 5.0;
        assert_eq!(r.validate(), Err(RulesError::GoodEvidencePositive(EventKind::StableTick)));
    }

    #[test]
    fn thresholds_must_be_strictly_increasing_and_bounded() {
        let mut r = DEFAULT_RULES;
        r.restrict_at = r.monitor_at;
        assert_eq!(r.validate(), Err(RulesError::ThresholdsInvalid));
        let mut r = DEFAULT_RULES;
        r.monitor_at = 0.0;
        assert_eq!(r.validate(), Err(RulesError::ThresholdsInvalid));
        let mut r = DEFAULT_RULES;
        r.block_at = MAX_THRESHOLD + 1.0;
        assert_eq!(r.validate(), Err(RulesError::ThresholdsInvalid));
    }

    #[test]
    fn out_of_range_values_are_rejected() {
        let mut r = DEFAULT_RULES;
        r.half_life_ms = 10.0;
        assert_eq!(r.validate(), Err(RulesError::HalfLifeOutOfRange));
        let mut r = DEFAULT_RULES;
        r.weights[kind_index(EventKind::RwxAlloc)] = 1_000.0;
        assert_eq!(r.validate(), Err(RulesError::WeightOutOfRange(EventKind::RwxAlloc)));
    }

    /// Deterministic fuzz-style pass: decode must never panic on any
    /// correctly-sized or wrongly-sized garbage.
    #[test]
    fn decode_never_panics_on_garbage() {
        for len in [0usize, 1, 4, 6, RULES_ENCODED_LEN - 1, RULES_ENCODED_LEN, RULES_ENCODED_LEN + 1] {
            for fill in [0x00u8, 0xFF, 0x7F, 0x80, 0xAB] {
                let mut buf = vec![fill; len];
                if len >= 6 {
                    buf[0..4].copy_from_slice(RULES_MAGIC);
                    buf[4..6].copy_from_slice(&RULES_FORMAT_VERSION.to_le_bytes());
                }
                let _ = RulesConfig::decode(&buf);
            }
        }
    }
}
