# Jay Squad Sec — Userspace Core + Alert-Only Agent (v0.1)

[![CI](https://github.com/kaymyg/jay-squad-sec/actions/workflows/ci.yml/badge.svg)](https://github.com/kaymyg/jay-squad-sec/actions/workflows/ci.yml)
[![CodeQL](https://github.com/kaymyg/jay-squad-sec/actions/workflows/codeql.yml/badge.svg)](https://github.com/kaymyg/jay-squad-sec/actions/workflows/codeql.yml)

Rust implementation of the userspace core from the v2.0 architecture, plus a
**deployable alert-only agent** with real userspace sensors (see `DEPLOY.md`).
The core engine runs on a simulated millisecond clock, so risk decay and
lease expiry are deterministic and unit-testable.

## Run it

```
cargo run                          # 60-second simulation: chrome vs escalating updater
cargo test                         # 24 unit + integration tests
cargo run --release --bin agent    # REAL monitoring, alert-only (see DEPLOY.md)
```

Requires only stable Rust (1.75+). Zero dependencies.

## What maps to what

| Architecture component      | File             | Prototype simplification                          |
| --------------------------- | ---------------- | ------------------------------------------------- |
| Runtime Identity (RTID)     | `src/rtid.rs`    | std SipHash instead of BLAKE3                     |
| Event Bus                   | `src/event.rs`   | single-threaded VecDeque, severity-ordered drain  |
| Behaviour Vector Engine     | `src/vector.rs`  | 6-axis f32 vector, 60 s half-life decay           |
| Adaptive Observation Engine | `src/observer.rs`| L0–L4 from risk score, with drop hysteresis       |
| Risk & Policy Engine        | `src/risk.rs`    | doc's exact weights/thresholds, 30 s half-life    |
| Capability Manager          | `src/capability.rs` | keyed-hash MAC instead of ed25519              |
| Kernel adapters             | `src/sensor.rs`  | scripted event timeline (demo)                    |
| Userspace sensors (real)    | `src/telemetry.rs` | /proc (Linux); tasklist/netstat/reg/Authenticode (Windows) |
| Agent (deployable)          | `src/bin/agent.rs` | alert-only loop, self-throttling               |
| Security workflow wiring    | `src/engine.rs`  | tick loop + audit ledger (decisions only)         |

## What the demo shows

`helper_update.exe` (unsigned) climbs the ladder exactly as the doc describes:

```
t=15s  UnsignedModuleLoad   -> Monitor   (obs L2)
t=30s  PrivilegeEscalation  -> Restrict  -> network lease REVOKED
t=35s  RemoteThreadInjection-> Suspend   -> all leases revoked, threads frozen
t=45s  CredentialAccess     -> Block     -> kill + isolate
```

Meanwhile `chrome` (signed, stable behaviour) stays at Allow/L0 and keeps its
15-minute network lease the whole time. Risk decays (30 s half-life), so a
one-off anomaly de-escalates instead of poisoning a process forever —
`engine::tests::risk_decay_de_escalates` proves it.

## Deliberate simplifications (production swap list)

1. **Hashing/signing** — std SipHash is keyed but not collision-resistant for
   adversarial input. Swap: `blake3` for RTID, `ed25519-dalek` for leases.
2. **Clock** — simulated `u64` ms. Swap: `Instant` + monotonic boot time.
3. **Bus** — single-threaded. Swap: `tokio::sync::mpsc` or crossbeam, with
   backpressure instead of naive requeue.
4. **Sensor** — scripted. Next real step on Linux: an eBPF program (aya crate)
   feeding a ringbuffer that emits the same normalized `Event` type.
5. **Enforcement** — printed. Real Linux path: eBPF LSM verdict maps /
   cgroup net filters; Windows: WFP filters + process suspension.

## Suggested learning path from here

1. Play with the weights in `risk.rs` and the scenario in `main.rs`; watch how
   half-life vs event spacing changes outcomes (an attacker who goes *slow
   enough* never crosses Monitor — that's the classic low-and-slow evasion,
   and why the doc's behaviour vectors matter, since they decay slower).
2. Replace the keyed hash with real crypto (`blake3`, `ed25519-dalek`).
3. Make the engine event-driven with `tokio` and a real mpsc bus.
4. First real sensor (Linux, needs root): watch process exec events with
   `aya` (eBPF tracepoint `sched_process_exec`) and feed them into the bus —
   suddenly `cargo run` monitors your actual machine at L0.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to get set up and run the checks,
and [SECURITY.md](SECURITY.md) for reporting vulnerabilities privately.
