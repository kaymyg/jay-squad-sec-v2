//! Mock sensor: a scripted stand-in for the kernel adapters.
//!
//! Real builds replace this with eBPF ringbuffer readers (Linux) or
//! ETW/WFP consumers (Windows) that emit the same normalized `Event`s.

use crate::event::{Event, EventKind};
use crate::rtid::Rtid;

pub struct ScriptedSensor {
    script: Vec<(u64, Rtid, EventKind, String)>,
    cursor: usize,
}

impl ScriptedSensor {
    pub fn new(mut script: Vec<(u64, Rtid, EventKind, String)>) -> Self {
        script.sort_by_key(|s| s.0);
        Self { script, cursor: 0 }
    }

    /// Emit every scripted event whose time has arrived.
    pub fn poll(&mut self, now_ms: u64) -> Vec<Event> {
        let mut out = Vec::new();
        while self.cursor < self.script.len() && self.script[self.cursor].0 <= now_ms {
            let (at_ms, rtid, kind, detail) = self.script[self.cursor].clone();
            out.push(Event { rtid, kind, at_ms, detail });
            self.cursor += 1;
        }
        out
    }

    pub fn exhausted(&self) -> bool {
        self.cursor >= self.script.len()
    }
}
