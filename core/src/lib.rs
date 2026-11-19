//! Jay Squad Sec — prototype userspace core.
//!
//! Maps to the v2.0 architecture:
//!   Sensors -> Event Bus -> Adaptive Observer -> Behaviour Vector Engine
//!   -> Risk & Policy Engine -> Capability Manager -> (Kernel Command Interface)
//!
//! Everything here runs on a simulated millisecond clock so behaviour
//! (risk decay, lease expiry) is deterministic and unit-testable.

pub mod capability;
pub mod engine;
pub mod event;
pub mod observer;
pub mod risk;
pub mod rtid;
pub mod sensor;
pub mod telemetry;
pub mod vector;
