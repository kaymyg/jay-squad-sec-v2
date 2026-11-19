//! Normalized events + in-memory event bus.
//!
//! In production these arrive from kernel adapters (eBPF / ETW / WFP / fanotify)
//! already reduced to this normalized form. The bus is deliberately not a
//! message broker: normalize, prioritize, batch, deliver. No persistence.

use crate::rtid::Rtid;
use std::collections::VecDeque;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EventKind {
    ProcessStart,
    ProcessExit,
    SignedBinary,          // evidence: trusted signature verified
    UnsignedBinary,        // evidence: no/invalid signature
    NetworkConnect,
    FileWrite,
    UnsignedModuleLoad,    // e.g. unsigned DLL / .so loaded
    RwxAlloc,              // writable+executable memory
    RemoteThreadInjection,
    CredentialAccess,      // lsass / keyring / browser vault
    PersistenceWrite,      // run keys, systemd units, cron
    PrivilegeEscalation,
    StableTick,            // periodic "nothing suspicious happened"
    TempExecution,         // executable running from temp/download dirs
    DeletedExecutable,     // process whose on-disk binary was deleted (anti-forensics)
}

impl EventKind {
    /// Delivery priority: higher = drained first.
    pub fn severity(self) -> u8 {
        use EventKind::*;
        match self {
            CredentialAccess | RemoteThreadInjection => 3,
            RwxAlloc | PrivilegeEscalation | UnsignedModuleLoad | PersistenceWrite
            | DeletedExecutable => 2,
            UnsignedBinary | ProcessStart | ProcessExit | TempExecution => 1,
            NetworkConnect | FileWrite | SignedBinary | StableTick => 0,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Event {
    pub rtid: Rtid,
    pub kind: EventKind,
    pub at_ms: u64,
    pub detail: String,
}

/// Hard cap on queued events. Bounds memory on a device under an event flood
/// and keeps the per-drain sort cost bounded. Tunable per deployment.
pub const MAX_QUEUE: usize = 4096;

/// Lightweight in-memory bus. Single-threaded in the prototype;
/// production version wraps an mpsc/broadcast channel.
///
/// The queue is bounded: once full, a new event is admitted only if it is more
/// severe than the least-severe event already queued (which it then evicts).
/// This means a high-frequency flood of low-severity events cannot grow memory
/// without bound, and cannot push critical evidence out of the queue. Every
/// lost event is counted in `dropped` for telemetry.
#[derive(Default)]
pub struct EventBus {
    queue: VecDeque<Event>,
    dropped: u64,
}

impl EventBus {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn publish(&mut self, ev: Event) {
        if self.queue.len() < MAX_QUEUE {
            self.queue.push_back(ev);
            return;
        }
        // Full. The lowest severity tier is 0; a tier-0 event cannot beat the
        // minimum, so drop it immediately without scanning (the common flood
        // case, kept O(1)).
        let incoming_sev = ev.kind.severity();
        if incoming_sev == 0 {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        // Elevated event: evict the least-severe queued event if the newcomer
        // outranks it; otherwise drop the newcomer. Either way exactly one
        // event is lost. O(n), but only for the rare elevated-under-flood path.
        if let Some((idx, min_sev)) = self
            .queue
            .iter()
            .enumerate()
            .map(|(i, e)| (i, e.kind.severity()))
            .min_by_key(|&(_, s)| s)
        {
            if incoming_sev > min_sev {
                self.queue.remove(idx);
                self.queue.push_back(ev);
            }
        }
        self.dropped = self.dropped.saturating_add(1);
    }

    /// Total events dropped because the queue was full. Exposed so the agent
    /// can surface sensor overload rather than hiding it.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Drain up to `max` events, highest severity first (stable within a tier).
    pub fn drain_batch(&mut self, max: usize) -> Vec<Event> {
        let mut batch: Vec<Event> = self.queue.drain(..).collect();
        batch.sort_by_key(|e| std::cmp::Reverse(e.kind.severity()));
        if batch.len() > max {
            let rest = batch.split_off(max);
            for ev in rest {
                self.queue.push_back(ev); // requeue overflow
            }
        }
        batch
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtid::Rtid;

    fn ev(kind: EventKind) -> Event {
        Event { rtid: Rtid(1), kind, at_ms: 0, detail: String::new() }
    }

    #[test]
    fn critical_events_are_delivered_first() {
        let mut bus = EventBus::new();
        bus.publish(ev(EventKind::FileWrite));
        bus.publish(ev(EventKind::CredentialAccess));
        bus.publish(ev(EventKind::NetworkConnect));
        let batch = bus.drain_batch(10);
        assert_eq!(batch[0].kind, EventKind::CredentialAccess);
    }

    #[test]
    fn overflow_is_requeued_not_dropped() {
        let mut bus = EventBus::new();
        for _ in 0..5 {
            bus.publish(ev(EventKind::FileWrite));
        }
        let batch = bus.drain_batch(3);
        assert_eq!(batch.len(), 3);
        assert_eq!(bus.len(), 2);
    }

    #[test]
    fn flood_is_bounded_and_preserves_critical_evidence() {
        let mut bus = EventBus::new();
        // One piece of critical evidence arrives first.
        bus.publish(ev(EventKind::CredentialAccess));
        // Then a low-severity flood far beyond the cap.
        for _ in 0..(MAX_QUEUE as u64 + 1_000) {
            bus.publish(ev(EventKind::FileWrite));
        }
        assert!(bus.len() <= MAX_QUEUE, "queue must stay bounded under flood");
        assert!(bus.dropped() >= 1_000, "overflow must be counted, not hidden");
        // The critical event must survive the flood.
        let batch = bus.drain_batch(MAX_QUEUE);
        assert!(
            batch.iter().any(|e| e.kind == EventKind::CredentialAccess),
            "critical evidence must not be evicted by a low-severity flood"
        );
    }

    #[test]
    fn a_more_severe_event_evicts_a_less_severe_one_when_full() {
        let mut bus = EventBus::new();
        for _ in 0..MAX_QUEUE {
            bus.publish(ev(EventKind::FileWrite)); // tier 0, fills the queue
        }
        assert_eq!(bus.len(), MAX_QUEUE);
        bus.publish(ev(EventKind::CredentialAccess)); // tier 3, must get in
        assert_eq!(bus.len(), MAX_QUEUE, "stays bounded");
        let batch = bus.drain_batch(1); // highest severity first
        assert_eq!(batch[0].kind, EventKind::CredentialAccess);
    }
}
