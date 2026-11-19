//! Runtime Identity (RTID).
//!
//! RTID = H(exe_hash || parent_rtid || boot_nonce || start_ts || runtime_nonce)
//!
//! Prototype uses std's SipHash (DefaultHasher) twice for a 128-bit id.
//! Production: replace with BLAKE3 for a real 256-bit collision-resistant id.

use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::{Hash, Hasher};

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Rtid(pub u128);

impl Rtid {
    pub fn derive(
        exe_hash: u64,
        parent: Option<Rtid>,
        boot_nonce: u64,
        start_ts_ms: u64,
        runtime_nonce: u64,
    ) -> Self {
        let mut h1 = DefaultHasher::new();
        exe_hash.hash(&mut h1);
        parent.map(|p| p.0).unwrap_or(0).hash(&mut h1);
        boot_nonce.hash(&mut h1);
        start_ts_ms.hash(&mut h1);
        runtime_nonce.hash(&mut h1);
        let a = h1.finish();

        let mut h2 = DefaultHasher::new();
        a.hash(&mut h2);
        runtime_nonce.rotate_left(17).hash(&mut h2);
        exe_hash.rotate_left(31).hash(&mut h2);
        let b = h2.finish();

        Rtid(((a as u128) << 64) | b as u128)
    }

    /// Short human-readable form for logs.
    pub fn short(&self) -> String {
        format!("{:08x}", (self.0 >> 96) as u32)
    }
}

impl fmt::Display for Rtid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:032x}", self.0)
    }
}

impl fmt::Debug for Rtid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Rtid({})", self.short())
    }
}

/// Hash executable bytes (stand-in for hashing the file on disk).
pub fn exe_hash(bytes: &[u8]) -> u64 {
    let mut h = DefaultHasher::new();
    bytes.hash(&mut h);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_exe_different_runs_get_different_rtids() {
        let eh = exe_hash(b"chrome.exe contents");
        let a = Rtid::derive(eh, None, 42, 1000, 7);
        let b = Rtid::derive(eh, None, 42, 1000, 8); // different runtime nonce
        let c = Rtid::derive(eh, None, 42, 2000, 7); // different start time
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn parent_changes_identity() {
        let eh = exe_hash(b"cmd.exe");
        let p1 = Rtid::derive(exe_hash(b"explorer"), None, 1, 1, 1);
        let a = Rtid::derive(eh, Some(p1), 1, 5, 9);
        let b = Rtid::derive(eh, None, 1, 5, 9);
        assert_ne!(a, b);
    }
}
