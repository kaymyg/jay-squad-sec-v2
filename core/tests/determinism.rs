//! Regression test: the engine must be fully deterministic. The same scenario
//! run on two independent engines must yield byte-identical decision logs and
//! the same process listing in the same (Rtid) order.
//!
//! This failed before procs moved from HashMap (randomly seeded per instance)
//! to BTreeMap. Eight processes make an accidental match of two random
//! orderings vanishingly unlikely, so a regression is caught reliably.

use jay_squad_sec::engine::Engine;
use jay_squad_sec::event::EventKind::{self, *};
use jay_squad_sec::sensor::ScriptedSensor;

fn run_scenario() -> (Vec<String>, Vec<String>) {
    let mut engine = Engine::new(0xD37E_2026);
    let names = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel"];
    let mut ids = Vec::new();
    for (i, n) in names.iter().enumerate() {
        let image = format!("{n}-image");
        ids.push(engine.spawn(n, image.as_bytes(), i % 2 == 0, None, 0));
    }

    // Every process gets the same escalating sequence at staggered times, so
    // several cross policy thresholds within the same tick.
    let chain: [EventKind; 5] = [UnsignedModuleLoad, RwxAlloc, PrivilegeEscalation, RemoteThreadInjection, CredentialAccess];
    let mut script = Vec::new();
    for (i, id) in ids.iter().enumerate() {
        for (j, k) in chain.iter().enumerate() {
            let t = 1_000 * (j as u64 + 1) + (i as u64 % 3) * 1_000;
            script.push((t, *id, *k, format!("step {j}")));
        }
    }
    let mut sensor = ScriptedSensor::new(script);

    let mut log = Vec::new();
    for now in (0..=20_000).step_by(1_000) {
        for ev in sensor.poll(now) {
            engine.bus.publish(ev);
        }
        log.extend(engine.tick(now));
    }
    let listing = engine
        .processes()
        .map(|p| format!("{} {:?} {:08x} {:?}", p.name, p.rtid, p.risk.score.to_bits(), p.action))
        .collect();
    (log, listing)
}

#[test]
fn same_scenario_same_output_every_time() {
    let (log_a, list_a) = run_scenario();
    let (log_b, list_b) = run_scenario();
    assert!(!log_a.is_empty(), "scenario should produce decisions");
    assert_eq!(log_a, log_b, "decision log must be deterministic");
    assert_eq!(list_a, list_b, "process listing must be deterministic");
}

#[test]
fn process_listing_is_ordered_by_rtid() {
    let mut engine = Engine::new(1);
    for n in ["a", "b", "c", "d", "e", "f"] {
        engine.spawn(n, n.as_bytes(), true, None, 0);
    }
    let rtids: Vec<_> = engine.processes().map(|p| p.rtid).collect();
    let mut sorted = rtids.clone();
    sorted.sort();
    assert_eq!(rtids, sorted);
}
