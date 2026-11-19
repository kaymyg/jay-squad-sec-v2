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

/// Lightweight in-memory bus. Single-threaded in the prototype;
/// production version wraps an mpsc/broadcast channel.
#[derive(Default)]
pub struct EventBus {
    queue: VecDeque<Event>,
}

impl EventBus {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn publish(&mut self, ev: Event) {
        self.queue.push_back(ev);
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
}
