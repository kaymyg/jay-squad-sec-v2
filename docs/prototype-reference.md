# Prototype Recovery Reference

**Repository:** `kaymyg/jay-squad-sec-v2`  
**Baseline line:** imported `main` branch  
**Purpose:** preserve an implementation-level description of the inherited prototype before production refactoring.

This document records what the current prototype contains. It is not a statement that the prototype already provides Android protection or production-grade enforcement.

## 1. Scope and runtime

The inherited project is a Rust userspace security core accompanied by a deployable, alert-only agent. The core's demonstration scenario uses a simulated millisecond clock so risk decay and lease expiry can be tested deterministically. The README identifies stable Rust 1.75+ and describes the prototype as having zero third-party dependencies.

The current agent is documented for Linux and Windows. It is not an Android application and does not currently provide Android telemetry, Android permission management, or Android network protection.

## 2. Module map

| Component | Current source | Inherited behaviour and known simplification |
|---|---|---|
| Runtime Identity (RTID) | `src/rtid.rs` | Process/runtime identity; standard-library SipHash is used instead of a production cryptographic identity construction. |
| Event Bus | `src/event.rs` | Single-threaded `VecDeque` with severity-ordered draining. |
| Behaviour Vector Engine | `src/vector.rs` | Six-axis `f32` behaviour vector with 60-second half-life decay. |
| Adaptive Observation Engine | `src/observer.rs` | L0–L4 observation levels derived from risk score, with drop hysteresis. |
| Risk and Policy Engine | `src/risk.rs` | Risk weights and thresholds from the prototype design, with 30-second half-life decay. |
| Capability Manager | `src/capability.rs` | Capability/lease handling using a keyed-hash MAC; this is a prototype simplification, not the planned production signature design. |
| Demo sensor adapter | `src/sensor.rs` | Scripted event timeline for deterministic demonstration. |
| Userspace telemetry | `src/telemetry.rs` | Linux `/proc` observations and Windows task-list, network, registry and Authenticode-related observations. Coverage is platform- and privilege-dependent. |
| Deployable agent | `src/bin/agent.rs` | Alert-only monitoring loop with self-throttling, as described in `DEPLOY.md`. |
| Engine wiring | `src/engine.rs` | Tick loop and audit ledger recording policy decisions. |

## 3. Demonstration behaviour

The README's scripted `helper_update.exe` scenario describes a progression through the policy tiers:

- Unsigned module-load signal: Monitor.
- Privilege-escalation signal: Restrict, with a network lease shown as revoked in the simulated workflow.
- Remote-thread-injection signal: Suspend, with leases shown as revoked and threads frozen in the simulated workflow.
- Credential-access signal: Block, with kill/isolation represented in the demonstration.

A stable signed `chrome` example remains at Allow/L0. The scenario also demonstrates risk decay so an isolated anomaly can de-escalate over time.

**Important boundary:** these scenario outcomes demonstrate policy-engine decisions and workflow wiring. The README explicitly lists enforcement as printed rather than implemented. Do not interpret the simulated suspend, kill, isolation, or network-lease actions as actual operating-system enforcement by the deployable agent.

## 4. Deployable agent boundary

The agent is described as alert-only. It observes selected userspace signals and writes alerts to `jaysec_alerts.log`; it does not kill, suspend, or block processes or network connections. Its observations are constrained by platform APIs, polling cadence, permissions and the visibility of the operating system.

The existing deployment notes identify blind spots including short-lived processes between polls, credential-store access, remote-thread injection, writable/executable memory patterns, file-encryption bursts and kernel-level threats. Kernel-backed sensors and enforcement are future work, not current capabilities.

## 5. Explicit prototype substitutions

The inherited README identifies these production gaps:

1. **Identity and cryptography:** standard-library SipHash and keyed-hash MAC are prototype choices. They must not be treated as collision-resistant adversarial identity or as a production capability-signing scheme.
2. **Time:** simulated `u64` milliseconds are used for deterministic tests; production timing needs a monotonic clock strategy.
3. **Concurrency and event delivery:** the single-threaded queue has no production-grade asynchronous backpressure model.
4. **Sensors:** the demo sensor is scripted. Real userspace telemetry exists for Linux and Windows, but kernel telemetry is not present.
5. **Enforcement:** actions are represented or printed in the core workflow; the deployable agent remains alert-only.

The README proposes possible future Linux eBPF/LSM and Windows WFP work. Those proposals are roadmap items, not implemented guarantees.

## 6. Preservation and migration rules

Before changing this prototype:

- Keep the imported baseline commit and its history recoverable.
- Preserve the existing module behaviour in tests or explicit compatibility fixtures before replacing modules.
- Separate Android-specific observations and response capabilities from Linux/Windows assumptions.
- Do not silently translate simulated enforcement into claims of real Android enforcement.
- Record behavioural changes, removed features, and newly introduced security assumptions in reviewable commits.
- Keep the original `kaymyg/jay-squad-sec` repository untouched; all development belongs in `kaymyg/jay-squad-sec-v2`.

## 7. Source of truth

This reference is derived from the inherited repository's `README.md` and `DEPLOY.md`. If either file is updated, revise this reference in the same reviewed change so it remains a faithful recovery record.
