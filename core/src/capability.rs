//! Capability Manager: signed, process-bound, time-bound leases.
//!
//! Prototype signs with a keyed hash (secret || fields) — a MAC, not a real
//! signature. Production: ed25519, key held by the service, verified by the
//! kernel command interface before enforcement changes.

use crate::rtid::Rtid;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Permission {
    Network,
    FileRead,
    FileWrite,
    ProcessSpawn,
}

#[derive(Clone, Debug)]
pub struct Capability {
    pub id: u64,
    pub rtid: Rtid,
    pub perm: Permission,
    pub scope: String, // e.g. "https://github.com", "/home/user/docs"
    pub expires_ms: u64,
    sig: u64,
}

pub struct CapabilityManager {
    secret: u64,
    next_id: u64,
    leases: HashMap<Rtid, Vec<Capability>>,
}

impl CapabilityManager {
    pub fn new(secret: u64) -> Self {
        Self { secret, next_id: 1, leases: HashMap::new() }
    }

    fn tag(&self, id: u64, rtid: Rtid, perm: Permission, scope: &str, expires_ms: u64) -> u64 {
        let mut h = DefaultHasher::new();
        self.secret.hash(&mut h);
        id.hash(&mut h);
        rtid.0.hash(&mut h);
        perm.hash(&mut h);
        scope.hash(&mut h);
        expires_ms.hash(&mut h);
        h.finish()
    }

    pub fn grant(
        &mut self,
        rtid: Rtid,
        perm: Permission,
        scope: &str,
        ttl_ms: u64,
        now_ms: u64,
    ) -> Capability {
        let id = self.next_id;
        self.next_id += 1;
        let expires_ms = now_ms + ttl_ms;
        let sig = self.tag(id, rtid, perm, scope, expires_ms);
        let cap = Capability { id, rtid, perm, scope: scope.to_string(), expires_ms, sig };
        self.leases.entry(rtid).or_default().push(cap.clone());
        cap
    }

    /// Integrity + binding check (does NOT check expiry — see `check`).
    pub fn verify(&self, cap: &Capability) -> bool {
        cap.sig == self.tag(cap.id, cap.rtid, cap.perm, &cap.scope, cap.expires_ms)
    }

    /// Would the kernel allow this action right now?
    pub fn check(&self, rtid: Rtid, perm: Permission, now_ms: u64) -> bool {
        self.leases
            .get(&rtid)
            .map(|v| {
                v.iter()
                    .any(|c| c.perm == perm && c.expires_ms > now_ms && self.verify(c))
            })
            .unwrap_or(false)
    }

    /// Revoke every lease matching `perm` (or all if None). Returns count.
    pub fn revoke(&mut self, rtid: Rtid, perm: Option<Permission>) -> usize {
        match self.leases.get_mut(&rtid) {
            None => 0,
            Some(v) => {
                let before = v.len();
                match perm {
                    Some(p) => v.retain(|c| c.perm != p),
                    None => v.clear(),
                }
                before - v.len()
            }
        }
    }

    /// Drop expired leases (periodic housekeeping).
    pub fn sweep(&mut self, now_ms: u64) {
        for v in self.leases.values_mut() {
            v.retain(|c| c.expires_ms > now_ms);
        }
    }

    pub fn active(&self, rtid: Rtid, now_ms: u64) -> Vec<&Capability> {
        self.leases
            .get(&rtid)
            .map(|v| v.iter().filter(|c| c.expires_ms > now_ms).collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk() -> (CapabilityManager, Rtid) {
        (CapabilityManager::new(0xDEADBEEF), Rtid(77))
    }

    #[test]
    fn grant_then_check_passes() {
        let (mut m, r) = mk();
        m.grant(r, Permission::Network, "https://github.com", 15 * 60_000, 0);
        assert!(m.check(r, Permission::Network, 1000));
    }

    #[test]
    fn tampered_lease_fails_verification() {
        let (mut m, r) = mk();
        let mut cap = m.grant(r, Permission::Network, "https://github.com", 60_000, 0);
        cap.scope = "https://evil.example".to_string(); // tamper
        assert!(!m.verify(&cap));
    }

    #[test]
    fn lease_expires() {
        let (mut m, r) = mk();
        m.grant(r, Permission::Network, "*", 10_000, 0);
        assert!(m.check(r, Permission::Network, 9_999));
        assert!(!m.check(r, Permission::Network, 10_000));
    }

    #[test]
    fn revocation_is_immediate_and_scoped() {
        let (mut m, r) = mk();
        m.grant(r, Permission::Network, "*", 60_000, 0);
        m.grant(r, Permission::FileWrite, "/tmp", 60_000, 0);
        assert_eq!(m.revoke(r, Some(Permission::Network)), 1);
        assert!(!m.check(r, Permission::Network, 1));
        assert!(m.check(r, Permission::FileWrite, 1)); // untouched
        assert_eq!(m.revoke(r, None), 1); // revoke-all clears the rest
    }
}
