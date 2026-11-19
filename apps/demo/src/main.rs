//! Demo: 60 simulated seconds, two processes.
//!
//! chrome           — signed, browses normally, holds a network lease.
//! helper_update.exe — unsigned, slowly escalates into an injection +
//!                     credential-theft chain. Watch it climb the policy
//!                     ladder and get contained.
//!
//! Run: cargo run

use jay_squad_sec::capability::Permission;
use jay_squad_sec::event::EventKind::*;
use jay_squad_sec::engine::Engine;
use jay_squad_sec::sensor::ScriptedSensor;

fn main() {
    let mut engine = Engine::new(0xB007_0503);

    println!("=== Jay Squad Sec — userspace core prototype ===\n");

    let chrome = engine.spawn("chrome", b"chrome-image-v126", true, None, 0);
    let updater = engine.spawn("helper_update.exe", b"helper-update-image", false, None, 0);
    engine.tick(0);

    // Chrome gets a 15-minute network lease, as in the doc's example.
    engine.request_capability(chrome, Permission::Network, "https://github.com", 15 * 60_000, 0);
    // The updater also asks for one — it's still Allow at this point, so it
    // gets it. Zero trust means we'll take it back the moment behaviour turns.
    engine.request_capability(updater, Permission::Network, "https://update.helper.example", 15 * 60_000, 0);

    // Scripted "kernel" telemetry.
    let mut sensor = ScriptedSensor::new(vec![
        // chrome: boring, healthy browsing.
        (2_000, chrome, NetworkConnect, "github.com:443".into()),
        (10_000, chrome, StableTick, "".into()),
        (12_000, chrome, NetworkConnect, "github.com:443".into()),
        (20_000, chrome, StableTick, "".into()),
        (30_000, chrome, StableTick, "".into()),
        (40_000, chrome, StableTick, "".into()),
        (50_000, chrome, StableTick, "".into()),
        // updater: the slow burn.
        (5_000, updater, FileWrite, "C:\\ProgramData\\helper\\cache.bin".into()),
        (15_000, updater, UnsignedModuleLoad, "inject_helper.dll".into()),
        (25_000, updater, RwxAlloc, "0x7ff6a2b40000 (64 KiB RWX)".into()),
        (30_000, updater, PrivilegeEscalation, "SeDebugPrivilege enabled".into()),
        (35_000, updater, RemoteThreadInjection, "target: chrome".into()),
        (45_000, updater, CredentialAccess, "lsass.exe memory read".into()),
        (50_000, updater, PersistenceWrite, "HKCU\\...\\Run\\helper".into()),
    ]);

    for now in (0..=60_000).step_by(1_000) {
        for ev in sensor.poll(now) {
            let who = if ev.rtid == chrome { "chrome" } else { "helper_update.exe" };
            println!("t={:>2}s  [kernel] {:<18} {:?} {}", now / 1000, who, ev.kind, ev.detail);
            engine.bus.publish(ev);
        }
        for line in engine.tick(now) {
            println!("t={:>2}s  {}", now / 1000, line);
        }
    }

    println!("\n=== Final process states ===");
    for p in engine.processes() {
        let v = p.vector;
        println!(
            "{:<18} rtid={} risk={:>6.1} action={:?} obs={} alive={}",
            p.name, p.rtid.short(), p.risk.score, p.action, p.observer.level.label(), p.alive
        );
        println!(
            "                   vector: net={:.1} fs={:.1} mem={:.1} priv={:.1} inj={:.1} persist={:.1}",
            v.network, v.filesystem, v.memory, v.privilege, v.injection, v.persistence
        );
    }

    println!("\n=== Capability check at t=60s ===");
    println!(
        "chrome network allowed:  {}",
        engine.caps.check(chrome, Permission::Network, 60_000)
    );
    println!(
        "updater network allowed: {}",
        engine.caps.check(updater, Permission::Network, 60_000)
    );

    println!("\n=== Audit ledger (decisions only — raw telemetry was discarded) ===");
    for a in &engine.audit {
        println!("t={:>2}s  {}  {}", a.at_ms / 1000, a.rtid.short(), a.what);
    }
}
