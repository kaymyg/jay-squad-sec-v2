//! Jay Squad Sec agent — real telemetry, ALERT-ONLY.
//!
//! Watches live processes, network peers, signatures and autoruns; feeds the
//! risk engine; alerts to console + log file. Never kills, suspends or
//! blocks anything. Designed to be forgotten: self-throttles if a poll ever
//! runs long, and idles at a fraction of a percent of CPU.
//!
//!   jaysec-agent                      run forever, 2s polls
//!   jaysec-agent --interval-ms 5000   gentler polling
//!   jaysec-agent --duration-secs 60   timed run (for testing)
//!   jaysec-agent --log FILE           alert log location (default jaysec_alerts.log)

use jay_squad_sec::engine::Engine;
use jay_squad_sec::event::{Event, EventKind};
use jay_squad_sec::risk::PolicyAction;
use jay_squad_sec::rtid::Rtid;
use jay_squad_sec::telemetry::{platform_sensor, suspicious_path};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_SIG_CHECKS_PER_POLL: usize = 8;
const AUTORUN_EVERY_N_POLLS: u64 = 15;
const STABLE_TICK_AFTER_MS: u64 = 60_000;
const MAX_INTERVAL_MS: u64 = 10_000;

struct Tracked {
    rtid: Rtid,
    exe: String,
    baseline: bool, // already running when agent started
    last_event_ms: u64,
}

fn main() {
    let mut interval_ms: u64 = 2_000;
    let mut duration_secs: u64 = 0;
    let mut log_path = "jaysec_alerts.log".to_string();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--interval-ms" => interval_ms = args.next().and_then(|v| v.parse().ok()).unwrap_or(2_000),
            "--duration-secs" => duration_secs = args.next().and_then(|v| v.parse().ok()).unwrap_or(0),
            "--log" => log_path = args.next().unwrap_or(log_path),
            "--help" | "-h" => {
                println!("jaysec-agent [--interval-ms N] [--duration-secs N] [--log FILE]");
                return;
            }
            _ => {}
        }
    }
    let base_interval = interval_ms.max(500);
    interval_ms = base_interval;

    let mut log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .expect("cannot open alert log");
    let boot_nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
    let mut engine = Engine::new(boot_nonce);
    engine.set_alert_only(true);
    let mut sensor = platform_sensor();
    let start = Instant::now();
    let own_pid = std::process::id();

    banner(&mut log, &log_path, base_interval);

    // --- Baseline: adopt everything already running, quietly. ---
    let mut tracked: HashMap<u32, Tracked> = HashMap::new();
    for p in sensor.processes() {
        if p.pid == own_pid {
            continue;
        }
        let rtid = engine.adopt(&p.name, format!("{}:{}", p.pid, p.exe).as_bytes(), 0);
        tracked.insert(
            p.pid,
            Tracked { rtid, exe: p.exe, baseline: true, last_event_ms: 0 },
        );
    }
    engine.tick(0);
    println!("[agent] baseline: {} processes enrolled at L0 (quiet)", tracked.len());

    let mut autorun_baseline: HashSet<String> = sensor.autoruns().into_iter().collect();
    let mut seen_conns: HashSet<(u32, String)> = HashSet::new();
    let mut sig_pending: Vec<(u32, String)> = Vec::new();
    let mut sig_done: HashSet<String> = HashSet::new();
    let mut audit_printed = engine.audit.len();
    let mut polls: u64 = 0;
    let mut last_heartbeat = Instant::now();

    loop {
        let poll_start = Instant::now();
        let now_ms = start.elapsed().as_millis() as u64;
        polls += 1;

        // 1. Process arrivals / departures.
        let procs = sensor.processes();
        let current: HashSet<u32> = procs.iter().map(|p| p.pid).collect();

        let new_pids: Vec<u32> = procs
            .iter()
            .filter(|p| p.pid != own_pid && !is_own_tooling(&p.name) && !tracked.contains_key(&p.pid))
            .map(|p| p.pid)
            .collect();
        let paths = sensor.exe_paths(&new_pids);

        for p in procs.iter().filter(|p| new_pids.contains(&p.pid)) {
            let exe = paths.get(&p.pid).cloned().unwrap_or_else(|| p.exe.clone());
            let rtid = engine.adopt(&p.name, format!("{}:{}:{}", p.pid, exe, now_ms).as_bytes(), now_ms);
            println!("[agent] t+{}s new process: {} (pid {}) {}", now_ms / 1000, p.name, p.pid, exe);

            // Evidence a userspace sensor can gather immediately:
            if let Some(reason) = suspicious_path(&exe) {
                publish(&mut engine, rtid, EventKind::TempExecution, reason, now_ms);
            }
            if exe.ends_with(" (deleted)") {
                publish(&mut engine, rtid, EventKind::DeletedExecutable, "binary deleted on disk", now_ms);
            }
            if !exe.is_empty() && !sig_done.contains(&exe) {
                sig_pending.push((p.pid, exe.clone()));
            }
            tracked.insert(
                p.pid,
                Tracked { rtid, exe, baseline: false, last_event_ms: now_ms },
            );
        }

        let gone: Vec<u32> = tracked.keys().filter(|pid| !current.contains(pid)).copied().collect();
        for pid in gone {
            if let Some(t) = tracked.remove(&pid) {
                publish(&mut engine, t.rtid, EventKind::ProcessExit, "", now_ms);
            }
        }

        // 2. Signature checks (Windows), rate-limited, cached by path.
        let batch: Vec<(u32, String)> = sig_pending
            .drain(..sig_pending.len().min(MAX_SIG_CHECKS_PER_POLL))
            .collect();
        if !batch.is_empty() {
            let path_list: Vec<String> = batch.iter().map(|(_, e)| e.clone()).collect();
            let results: HashMap<String, bool> =
                sensor.check_unsigned(&path_list).into_iter().collect();
            for (pid, exe) in &batch {
                sig_done.insert(exe.clone());
                if let (Some(&unsigned), Some(t)) = (results.get(exe), tracked.get(pid)) {
                    let kind = if unsigned { EventKind::UnsignedBinary } else { EventKind::SignedBinary };
                    publish(&mut engine, t.rtid, kind, exe, now_ms);
                }
            }
        }

        // 3. Network: deep-look only at non-baseline (new) processes.
        let watch_pids: Vec<u32> =
            tracked.iter().filter(|(_, t)| !t.baseline).map(|(pid, _)| *pid).collect();
        for (pid, remote) in sensor.connections(&watch_pids) {
            if seen_conns.insert((pid, remote.clone())) {
                if let Some(t) = tracked.get_mut(&pid) {
                    t.last_event_ms = now_ms;
                    publish(&mut engine, t.rtid, EventKind::NetworkConnect, &remote, now_ms);
                }
            }
        }

        // 4. Autorun/persistence diff, every Nth poll.
        if polls % AUTORUN_EVERY_N_POLLS == 0 {
            for entry in sensor.autoruns() {
                if autorun_baseline.insert(entry.clone()) {
                    // New persistence entry. Attribute to a tracked process if
                    // its executable appears in the entry, else free-standing.
                    let owner_rtid = tracked
                        .values()
                        .find(|t| !t.baseline && !t.exe.is_empty() && entry.contains(&t.exe))
                        .map(|t| t.rtid);
                    match owner_rtid {
                        Some(rtid) => publish(&mut engine, rtid, EventKind::PersistenceWrite, &entry, now_ms),
                        None => alert(&mut log, now_ms, &format!("new persistence entry (unattributed): {entry}")),
                    }
                }
            }
        }

        // 5. Good behaviour is evidence too.
        let mut stable: Vec<Rtid> = Vec::new();
        for t in tracked.values_mut() {
            if !t.baseline && now_ms.saturating_sub(t.last_event_ms) >= STABLE_TICK_AFTER_MS {
                stable.push(t.rtid);
                t.last_event_ms = now_ms;
            }
        }
        for rtid in stable {
            if engine.process(rtid).map(|p| p.risk.score > 0.0).unwrap_or(false) {
                publish(&mut engine, rtid, EventKind::StableTick, "", now_ms);
            }
        }

        // 6. Engine cycle; surface decisions.
        for line in engine.tick(now_ms) {
            println!("t+{}s {}", now_ms / 1000, line);
            if line.contains("[ALERT]") || line.contains("[policy]") {
                alert(&mut log, now_ms, &line);
            }
        }
        while audit_printed < engine.audit.len() {
            let a = engine.audit[audit_printed].clone();
            alert(&mut log, a.at_ms, &format!("ledger: {} {}", a.rtid.short(), a.what));
            audit_printed += 1;
        }
        engine.prune_exited();

        // 7. Heartbeat + self-throttle (never hog the machine).
        let spent = poll_start.elapsed().as_millis() as u64;
        if spent * 5 > interval_ms && interval_ms < MAX_INTERVAL_MS {
            interval_ms = (interval_ms * 3 / 2).min(MAX_INTERVAL_MS);
            println!("[agent] poll took {spent}ms — backing off to {interval_ms}ms interval");
        } else if spent * 20 < interval_ms && interval_ms > base_interval {
            interval_ms = (interval_ms * 2 / 3).max(base_interval);
        }
        if last_heartbeat.elapsed() >= Duration::from_secs(60) {
            let watched: Vec<String> = engine
                .processes()
                .filter(|p| p.action > PolicyAction::Allow)
                .map(|p| format!("{}({:.0})", p.name, p.risk.score))
                .collect();
            println!(
                "[agent] heartbeat: {} procs, poll {}ms/{}ms, elevated: {}",
                tracked.len(),
                spent,
                interval_ms,
                if watched.is_empty() { "none".to_string() } else { watched.join(", ") }
            );
            last_heartbeat = Instant::now();
        }

        if duration_secs > 0 && start.elapsed().as_secs() >= duration_secs {
            println!("[agent] duration reached, exiting. Alerts: {log_path}");
            break;
        }
        std::thread::sleep(Duration::from_millis(interval_ms.saturating_sub(spent)));
    }
}

/// The Windows sensor spawns these read-only query tools every poll; tracking
/// them would be the agent alerting on itself. Trade-off, stated honestly:
/// attacker recon via these same tools is also hidden — they're query-only
/// utilities, and parent-based attribution (kernel phase) is the real fix.
fn is_own_tooling(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "tasklist.exe" | "netstat.exe" | "reg.exe" | "conhost.exe"
    )
}

fn publish(engine: &mut Engine, rtid: Rtid, kind: EventKind, detail: &str, now_ms: u64) {
    engine.bus.publish(Event { rtid, kind, at_ms: now_ms, detail: detail.to_string() });
}

fn alert(log: &mut std::fs::File, now_ms: u64, msg: &str) {
    let epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let _ = writeln!(log, "{epoch} t+{}s {msg}", now_ms / 1000);
}

fn banner(log: &mut std::fs::File, log_path: &str, interval: u64) {
    println!("=== Jay Squad Sec agent v0.1 — ALERT-ONLY mode ===");
    println!("No process will be killed, suspended or blocked by this agent.");
    println!("Poll interval {interval}ms (self-throttling). Alerts -> {log_path}");
    println!("This complements, not replaces, your OS antivirus.\n");
    let epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let _ = writeln!(log, "{epoch} === agent started (alert-only) ===");
}
