//! Patchable detection rules: the risk weights, thresholds and decay half-life.
//!
//! This is the ONLY thing a signed update can change. Engine code is immutable;
//! updates carry data, never code, so an update has no code-injection surface.
//!
//! Every config is validated before it can be installed, and validation is
//! deliberately opinionated: an update may *retune* detection but may not
//! *disable* it, and may not turn ordinary activity into mass false positives.
//! Bounds are semantic, not just sign checks (a review showed legal-but-absurd
//! values such as `1e-45` weights or a block threshold of 10000 could make a
//! full attack chain score Allow):
//! - threat indicators: weight in [1, 100], so no indicator can be silenced;
//! - neutral high-volume events (file writes, network connects, process
//!   start/exit): weight in [0, 5]: never negative (that would let a process
//!   launder its own risk by spamming them), never large (mass false positives);
//! - good evidence (signed binary, stable tick): weight in [-20, 0], so being
//!   signed cannot cancel out an injection + credential-theft chain;
//! - half-life in [10 s, 1 h]: suspicion can neither evaporate between steps
//!   of an attack nor linger forever;
//! - thresholds: monitor_at >= 5, block_at <= 400, each step >= 5 apart;
//! - reachability: the five strongest indicators together must reach
//!   block_at, so Block can never be made unreachable.
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
pub const MIN_HALF_LIFE_MS: f32 = 10_000.0; // 10 seconds
pub const MAX_HALF_LIFE_MS: f32 = 3_600_000.0; // 1 hour
/// Threat-indicator weight range.
pub const INDICATOR_WEIGHT: (f32, f32) = (1.0, 100.0);
/// Neutral high-volume event weight range.
pub const NEUTRAL_WEIGHT: (f32, f32) = (0.0, 5.0);
/// Good-evidence weight range.
pub const GOOD_EVIDENCE_WEIGHT: (f32, f32) = (-20.0, 0.0);
/// Lowest allowed monitor threshold.
pub const MIN_THRESHOLD: f32 = 5.0;
/// Highest allowed block threshold.
pub const MAX_THRESHOLD: f32 = 400.0;
/// Minimum gap between consecutive thresholds.
pub const MIN_THRESHOLD_GAP: f32 = 5.0;
/// How many of the strongest indicators must together reach block_at.
pub const REACHABILITY_INDICATORS: usize = 5;

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
    /// A threat indicator's weight was outside [1, 100] (could silence it).
    IndicatorOutOfRange(EventKind),
    /// A neutral event's weight was outside [0, 5] (risk laundering if
    /// negative, mass false positives if large).
    NeutralOutOfRange(EventKind),
    /// A good-evidence event's weight was outside [-20, 0].
    GoodEvidenceOutOfRange(EventKind),
    /// Thresholds were out of range, out of order, or too close together.
    ThresholdsInvalid,
    /// The strongest indicators combined cannot reach block_at.
    BlockUnreachable,
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
            RulesError::IndicatorOutOfRange(k) => write!(
                f,
                "threat indicator {k:?} must keep a weight in [{}, {}] (it cannot be silenced)",
                INDICATOR_WEIGHT.0, INDICATOR_WEIGHT.1
            ),
            RulesError::NeutralOutOfRange(k) => write!(
                f,
                "neutral event {k:?} must have a weight in [{}, {}]",
                NEUTRAL_WEIGHT.0, NEUTRAL_WEIGHT.1
            ),
            RulesError::GoodEvidenceOutOfRange(k) => write!(
                f,
                "good-evidence event {k:?} must have a weight in [{}, {}]",
                GOOD_EVIDENCE_WEIGHT.0, GOOD_EVIDENCE_WEIGHT.1
            ),
            RulesError::ThresholdsInvalid => write!(
                f,
                "thresholds must satisfy {MIN_THRESHOLD} <= monitor < restrict < suspend < block <= {MAX_THRESHOLD}, each at least {MIN_THRESHOLD_GAP} apart"
            ),
            RulesError::BlockUnreachable => write!(
                f,
                "block_at is unreachable: the {REACHABILITY_INDICATORS} strongest indicators must sum to at least block_at"
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

    /// Map a score to a policy action. Fails closed in every unevaluable
    /// case: a non-finite score maps to Block, and comparisons are written as
    /// `!(score < threshold)` so a NaN threshold (only possible in an
    /// unvalidated config) escalates instead of falling through to Allow.
    #[allow(clippy::neg_cmp_op_on_partial_ord)] // deliberate: `!(x < t)` is true for NaN, so NaN escalates (fail closed)
    pub fn action_for(&self, score: f32) -> PolicyAction {
        if !score.is_finite() || !(score < self.block_at) {
            PolicyAction::Block
        } else if !(score < self.suspend_at) {
            PolicyAction::Suspend
        } else if !(score < self.restrict_at) {
            PolicyAction::Restrict
        } else if !(score < self.monitor_at) {
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
        let within = |w: f32, (lo, hi): (f32, f32)| (lo..=hi).contains(&w);
        let mut indicators = Vec::with_capacity(KIND_COUNT);
        for k in KINDS {
            let w = self.weight(k);
            match class(k) {
                WeightClass::Indicator => {
                    if !within(w, INDICATOR_WEIGHT) {
                        return Err(RulesError::IndicatorOutOfRange(k));
                    }
                    indicators.push(w);
                }
                WeightClass::Neutral if !within(w, NEUTRAL_WEIGHT) => {
                    return Err(RulesError::NeutralOutOfRange(k))
                }
                WeightClass::GoodEvidence if !within(w, GOOD_EVIDENCE_WEIGHT) => {
                    return Err(RulesError::GoodEvidenceOutOfRange(k))
                }
                _ => {}
            }
        }
        let gap_ok = |a: f32, b: f32| b - a >= MIN_THRESHOLD_GAP;
        let ordered = t[0] >= MIN_THRESHOLD
            && gap_ok(t[0], t[1])
            && gap_ok(t[1], t[2])
            && gap_ok(t[2], t[3])
            && t[3] <= MAX_THRESHOLD;
        if !ordered {
            return Err(RulesError::ThresholdsInvalid);
        }
        // All values are finite here, so this sort cannot see a NaN.
        indicators.sort_by(|a, b| b.partial_cmp(a).unwrap_or(core::cmp::Ordering::Equal));
        let strongest: f32 = indicators.iter().take(REACHABILITY_INDICATORS).sum();
        if strongest < self.block_at {
            return Err(RulesError::BlockUnreachable);
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
            Err(RulesError::IndicatorOutOfRange(EventKind::CredentialAccess))
        );
    }

    #[test]
    fn a_patch_cannot_enable_risk_laundering() {
        let mut r = DEFAULT_RULES;
        r.weights[kind_index(EventKind::FileWrite)] = -1.0;
        assert_eq!(r.validate(), Err(RulesError::NeutralOutOfRange(EventKind::FileWrite)));
    }

    #[test]
    fn good_evidence_cannot_become_suspicious() {
        let mut r = DEFAULT_RULES;
        r.weights[kind_index(EventKind::StableTick)] = 5.0;
        assert_eq!(r.validate(), Err(RulesError::GoodEvidenceOutOfRange(EventKind::StableTick)));
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
        assert_eq!(r.validate(), Err(RulesError::IndicatorOutOfRange(EventKind::RwxAlloc)));
    }

    /// Each of these was a *legal* config before semantic bounds were added,
    /// and each let a full attack chain score Allow (found in review).
    #[test]
    fn review_attack_configs_are_all_rejected() {
        let mut r = DEFAULT_RULES; // Block pushed out of reach
        r.monitor_at = 9997.0; r.restrict_at = 9998.0; r.suspend_at = 9999.0; r.block_at = 10_000.0;
        assert_eq!(r.validate(), Err(RulesError::ThresholdsInvalid));

        let mut r = DEFAULT_RULES; // subnormal indicator weights
        for k in KINDS { if class(k) == WeightClass::Indicator { r.weights[kind_index(k)] = 1e-45; } }
        assert!(matches!(r.validate(), Err(RulesError::IndicatorOutOfRange(_))));

        let mut r = DEFAULT_RULES; // being signed cancels an injection chain
        r.weights[kind_index(EventKind::SignedBinary)] = -100.0;
        assert_eq!(r.validate(), Err(RulesError::GoodEvidenceOutOfRange(EventKind::SignedBinary)));

        let mut r = DEFAULT_RULES; // suspicion evaporates between attack steps
        r.half_life_ms = 1_000.0;
        assert_eq!(r.validate(), Err(RulesError::HalfLifeOutOfRange));

        let mut r = DEFAULT_RULES; // every networked app blocked
        r.weights[kind_index(EventKind::NetworkConnect)] = 100.0;
        assert_eq!(r.validate(), Err(RulesError::NeutralOutOfRange(EventKind::NetworkConnect)));

        let mut r = DEFAULT_RULES; // everything monitored
        r.monitor_at = 1e-45;
        assert_eq!(r.validate(), Err(RulesError::ThresholdsInvalid));
    }

    #[test]
    fn block_must_stay_reachable() {
        let mut r = DEFAULT_RULES; // defaults: five strongest sum to 150
        r.block_at = 150.0;
        assert_eq!(r.validate(), Ok(()));
        r.block_at = 160.0;
        assert_eq!(r.validate(), Err(RulesError::BlockUnreachable));
    }

    #[test]
    fn thresholds_too_close_together_are_rejected() {
        let mut r = DEFAULT_RULES;
        r.restrict_at = r.monitor_at + 1.0;
        assert_eq!(r.validate(), Err(RulesError::ThresholdsInvalid));
    }

    #[test]
    fn unvalidated_nan_thresholds_still_fail_closed() {
        let mut r = DEFAULT_RULES;
        r.block_at = f32::NAN; r.suspend_at = f32::NAN; r.restrict_at = f32::NAN; r.monitor_at = f32::NAN;
        assert_eq!(r.action_for(1.0), PolicyAction::Block);
        assert_eq!(r.action_for(1_000_000.0), PolicyAction::Block);
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
