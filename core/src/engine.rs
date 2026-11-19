//! Security engine: wires bus -> observer -> vector -> risk -> policy -> capabilities.
//!
//! The full workflow from the doc:
//!   Kernel event -> Normalize -> Adaptive Observer -> Behaviour Vector
//!   -> Risk Calculation -> Policy Evaluation -> Capability Decision -> Enforcement
//!
//! "Enforcement" here prints/records what the kernel command interface would be
//! told to do; a real build sends these to WFP / eBPF maps.

use crate::capability::{CapabilityManager, Permission};
use crate::event::{Event, EventBus, EventKind};
use crate::observer::AdaptiveObserver;
use crate::risk::{PolicyAction, RiskState};
use crate::rtid::{exe_hash, Rtid};
use crate::vector::BehaviorVector;
use std::collections::HashMap;

/// Audit ledger entry — only meaningful security decisions, never raw telemetry.
#[derive(Clone, Debug)]
pub struct AuditEntry {
    pub at_ms: u64,
    pub rtid: Rtid,
    pub what: String,
}

pub struct ProcessState {
    pub name: String,
    pub rtid: Rtid,
    pub vector: BehaviorVector,
    pub risk: RiskState,
    pub observer: AdaptiveObserver,
    pub action: PolicyAction,
    pub alive: bool,
    last_vector_decay_ms: u64,
}

pub struct Engine {
    pub bus: EventBus,
    pub caps: CapabilityManager,
    pub audit: Vec<AuditEntry>,
    procs: HashMap<Rtid, ProcessState>,
    boot_nonce: u64,
    nonce_counter: u64,
    /// Alert-only: record and report decisions but never change process
    /// state or revoke leases. The safe default for a freshly deployed agent.
    alert_only: bool,
}

impl Engine {
    pub fn new(boot_nonce: u64) -> Self {
        Self {
            bus: EventBus::new(),
            caps: CapabilityManager::new(boot_nonce ^ 0xC0FFEE),
            audit: Vec::new(),
            procs: HashMap::new(),
            boot_nonce,
            nonce_counter: 0,
            alert_only: false,
        }
    }

    pub fn set_alert_only(&mut self, on: bool) {
        self.alert_only = on;
    }

    /// Adopt an already-running external process observed by a real sensor.
    /// Unlike `spawn`, publishes no signature evidence — sensors supply
    /// evidence separately as they learn things.
    pub fn adopt(&mut self, name: &str, ident: &[u8], now_ms: u64) -> Rtid {
        self.nonce_counter += 1;
        let rtid = Rtid::derive(
            exe_hash(ident),
            None,
            self.boot_nonce,
            now_ms,
            self.nonce_counter,
        );
        self.procs.insert(
            rtid,
            ProcessState {
                name: name.to_string(),
                rtid,
                vector: BehaviorVector::default(),
                risk: RiskState::new(now_ms),
                observer: AdaptiveObserver::new(),
                action: PolicyAction::Allow,
                alive: true,
                last_vector_decay_ms: now_ms,
            },
        );
        self.bus.publish(Event {
            rtid,
            kind: EventKind::ProcessStart,
            at_ms: now_ms,
            detail: name.to_string(),
        });
        rtid
    }

    /// Drop state for exited processes (RTIDs expire with the process).
    /// Audit ledger entries are kept — they're the long-term record.
    pub fn prune_exited(&mut self) {
        self.procs.retain(|_, p| p.alive);
    }

    fn record(&mut self, at_ms: u64, rtid: Rtid, what: impl Into<String>) {
        self.audit.push(AuditEntry { at_ms, rtid, what: what.into() });
    }

    /// Register a new process: derive RTID, publish start + signature evidence.
    pub fn spawn(
        &mut self,
        name: &str,
        exe_bytes: &[u8],
        signed: bool,
        parent: Option<Rtid>,
        now_ms: u64,
    ) -> Rtid {
        self.nonce_counter += 1;
        let rtid = Rtid::derive(
            exe_hash(exe_bytes),
            parent,
            self.boot_nonce,
            now_ms,
            self.nonce_counter,
        );
        self.procs.insert(
            rtid,
            ProcessState {
                name: name.to_string(),
                rtid,
                vector: BehaviorVector::default(),
                risk: RiskState::new(now_ms),
                observer: AdaptiveObserver::new(),
                action: PolicyAction::Allow,
                alive: true,
                last_vector_decay_ms: now_ms,
            },
        );
        self.bus.publish(Event {
            rtid,
            kind: EventKind::ProcessStart,
            at_ms: now_ms,
            detail: name.to_string(),
        });
        self.bus.publish(Event {
            rtid,
            kind: if signed { EventKind::SignedBinary } else { EventKind::UnsignedBinary },
            at_ms: now_ms,
            detail: String::new(),
        });
        rtid
    }

    /// A process asks for a capability. Policy gate: only Allow/Monitor may
    /// receive new leases; Restrict and above are denied.
    pub fn request_capability(
        &mut self,
        rtid: Rtid,
        perm: Permission,
        scope: &str,
        ttl_ms: u64,
        now_ms: u64,
    ) -> Option<crate::capability::Capability> {
        let action = self.procs.get(&rtid).map(|p| p.action)?;
        if action > PolicyAction::Monitor {
            self.record(now_ms, rtid, format!("DENY lease {:?} {} (action {:?})", perm, scope, action));
            return None;
        }
        let cap = self.caps.grant(rtid, perm, scope, ttl_ms, now_ms);
        self.record(
            now_ms,
            rtid,
            format!("GRANT lease #{} {:?} {} ttl {}s", cap.id, perm, scope, ttl_ms / 1000),
        );
        Some(cap)
    }

    /// One engine cycle. Returns human-readable log lines for anything notable.
    pub fn tick(&mut self, now_ms: u64) -> Vec<String> {
        let mut log = Vec::new();

        // 1. Deliver a batch of normalized events.
        for ev in self.bus.drain_batch(256) {
            let Some(p) = self.procs.get_mut(&ev.rtid) else { continue };
            if !p.alive {
                continue;
            }
            // Behaviour vector update (decay first, then fold event in).
            let dt = now_ms.saturating_sub(p.last_vector_decay_ms);
            p.vector.decay(dt);
            p.last_vector_decay_ms = now_ms;
            p.vector.apply(ev.kind);
            // Risk update.
            p.risk.absorb(ev.kind, now_ms);
            if ev.kind == EventKind::ProcessExit {
                p.alive = false; // RTID expires with the process
            }
        }

        // 2. Decay risk for everyone, re-evaluate observation level + policy.
        let rtids: Vec<Rtid> = self.procs.keys().copied().collect();
        for rtid in rtids {
            let (name, score, transition, old_action, new_action) = {
                let p = self.procs.get_mut(&rtid).unwrap();
                if !p.alive {
                    continue;
                }
                p.risk.decay_to(now_ms);
                let transition = p.observer.update(p.risk.score);
                let old_action = p.action;
                let new_action = p.risk.action();
                p.action = new_action;
                (p.name.clone(), p.risk.score, transition, old_action, new_action)
            };

            if let Some((from, to)) = transition {
                log.push(format!(
                    "[obs] {} ({}) {} -> {} (risk {:.1})",
                    name, rtid.short(), from.label(), to.label(), score
                ));
            }

            if new_action != old_action {
                log.push(format!(
                    "[policy] {} ({}) {:?} -> {:?} (risk {:.1})",
                    name, rtid.short(), old_action, new_action, score
                ));
                self.record(now_ms, rtid, format!("POLICY {:?} -> {:?} risk {:.1}", old_action, new_action, score));
                self.enforce(rtid, &name, old_action, new_action, now_ms, &mut log);
            }
        }

        // 3. Housekeeping: expired leases vanish.
        self.caps.sweep(now_ms);
        log
    }

    /// Capability decision -> kernel command interface (simulated).
    fn enforce(
        &mut self,
        rtid: Rtid,
        name: &str,
        old: PolicyAction,
        new: PolicyAction,
        now_ms: u64,
        log: &mut Vec<String>,
    ) {
        use PolicyAction::*;
        if self.alert_only {
            // Report what enforcement WOULD do, change nothing.
            if new >= Restrict && old < Restrict {
                log.push(format!("[ALERT] {} would lose network access (alert-only mode)", name));
            }
            if new >= Suspend && old < Suspend {
                log.push(format!("[ALERT] {} would be SUSPENDED (alert-only mode) — inspect pid now", name));
            }
            if new == Block && old < Block {
                log.push(format!("[ALERT] {} would be BLOCKED (alert-only mode) — treat as hostile", name));
            }
            if new < Restrict && old >= Restrict {
                log.push(format!("[ALERT] {} de-escalated to {:?} (risk decayed)", name, new));
            }
            let _ = now_ms;
            return;
        }
        if new >= Restrict && old < Restrict {
            let n = self.caps.revoke(rtid, Some(Permission::Network));
            if n > 0 {
                self.record(now_ms, rtid, format!("REVOKE {} network lease(s)", n));
                log.push(format!("[enforce] {} network leases revoked -> kernel: drop flows for {}", name, rtid.short()));
            }
        }
        if new >= Suspend && old < Suspend {
            let n = self.caps.revoke(rtid, None);
            self.record(now_ms, rtid, format!("SUSPEND process, revoked {} remaining lease(s), awaiting user approval", n));
            log.push(format!("[enforce] {} SUSPENDED -> kernel: freeze threads of {}", name, rtid.short()));
        }
        if new == Block && old < Block {
            self.record(now_ms, rtid, "BLOCK + ISOLATE process".to_string());
            log.push(format!("[enforce] {} BLOCKED -> kernel: kill + network isolate {}", name, rtid.short()));
            if let Some(p) = self.procs.get_mut(&rtid) {
                p.alive = false;
            }
        }
        // De-escalation path: risk decayed back down.
        if new < Restrict && old >= Restrict {
            self.record(now_ms, rtid, format!("DE-ESCALATE to {:?} (risk decayed)", new));
            log.push(format!("[enforce] {} de-escalated to {:?}", name, new));
        }
    }

    pub fn process(&self, rtid: Rtid) -> Option<&ProcessState> {
        self.procs.get(&rtid)
    }

    pub fn processes(&self) -> impl Iterator<Item = &ProcessState> {
        self.procs.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Full pipeline: benign process keeps its lease, attacker escalates
    /// through Monitor -> Restrict -> Suspend -> Block and loses everything.
    #[test]
    fn escalating_process_is_contained_and_benign_one_is_not() {
        let mut e = Engine::new(42);
        let good = e.spawn("chrome", b"chrome-image", true, None, 0);
        let bad = e.spawn("helper_update.exe", b"updater-image", false, None, 0);
        e.tick(0);

        let cap = e.request_capability(good, Permission::Network, "https://github.com", 900_000, 0);
        assert!(cap.is_some());

        // Attack chain, compressed in time so decay doesn't mask it.
        for (t, kind) in [
            (1_000, EventKind::UnsignedModuleLoad),
            (2_000, EventKind::RwxAlloc),
            (3_000, EventKind::PrivilegeEscalation),
            (4_000, EventKind::RemoteThreadInjection),
            (5_000, EventKind::CredentialAccess),
        ] {
            e.bus.publish(Event { rtid: bad, kind, at_ms: t, detail: String::new() });
            e.tick(t);
        }

        let bad_state = e.process(bad).unwrap();
        assert_eq!(bad_state.action, PolicyAction::Block);
        assert!(!bad_state.alive);
        assert!(!e.caps.check(bad, Permission::Network, 6_000));

        // Benign process untouched.
        let good_state = e.process(good).unwrap();
        assert_eq!(good_state.action, PolicyAction::Allow);
        assert!(e.caps.check(good, Permission::Network, 6_000));

        // Ledger holds decisions, not telemetry.
        assert!(e.audit.iter().any(|a| a.what.contains("BLOCK")));
        assert!(e.audit.iter().any(|a| a.what.contains("SUSPEND")));
    }

    #[test]
    fn restricted_process_is_denied_new_leases() {
        let mut e = Engine::new(1);
        let p = e.spawn("sketchy", b"sketchy-image", false, None, 0);
        e.tick(0);
        e.bus.publish(Event { rtid: p, kind: EventKind::RwxAlloc, at_ms: 100, detail: String::new() });
        e.bus.publish(Event { rtid: p, kind: EventKind::UnsignedModuleLoad, at_ms: 100, detail: String::new() });
        e.tick(100); // 15 + 25 + 20 = 60 -> Restrict
        assert_eq!(e.process(p).unwrap().action, PolicyAction::Restrict);
        assert!(e.request_capability(p, Permission::Network, "*", 60_000, 200).is_none());
    }

    #[test]
    fn risk_decay_de_escalates() {
        let mut e = Engine::new(1);
        let p = e.spawn("one_off", b"tool-image", false, None, 0);
        e.tick(0);
        e.bus.publish(Event { rtid: p, kind: EventKind::UnsignedModuleLoad, at_ms: 0, detail: String::new() });
        e.tick(0); // 15 + 20 = 35 -> Monitor
        assert_eq!(e.process(p).unwrap().action, PolicyAction::Monitor);
        e.tick(120_000); // two half-lives later
        assert_eq!(e.process(p).unwrap().action, PolicyAction::Allow);
    }
}
