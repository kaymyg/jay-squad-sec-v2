//! Safe application of verified detection-rule updates.
//!
//! Flow for every update: decode the signed patch, verify it against the
//! builder's public key and the installed version (anti-rollback), decode and
//! validate the rules payload, then install atomically. Any failure leaves the
//! installed rules exactly as they were.
//!
//! **Self-authenticating state.** What is persisted is the signed patch itself,
//! not a bare rules file, and its signature is re-verified on every load. So
//! someone who can write the app's storage still cannot install rules without
//! the builder's private key: a tampered state file fails verification and the
//! store falls back to the previous signed state, then to the compiled-in
//! defaults. Updates carry data only (see `jay_squad_sec::rules`), never code.
//!
//! **Crash safety.** New state is written to a temp file, fsynced, then moved
//! into place with an atomic rename, so the state file is always either the
//! complete old version or the complete new one. The previous good state is
//! kept as a fallback, and is always re-encoded from a *verified* state, never
//! blindly copied, so a corrupt file can never displace a good fallback.
//!
//! **Concurrency.** Callers must serialize `apply_*` calls (the engine bridge
//! holds a single store behind its lock). `load` is safe to call any time.
//!
//! **Residual risk (documented, not hidden).** If an attacker can *delete* the
//! state files, the store reverts to the compiled-in defaults at version 0,
//! after which an older, genuinely builder-signed patch could be re-applied.
//! That can only ever install rules the builder actually signed, and all of
//! them pass validation, but it is a downgrade. Platform storage protection
//! (Android app-private storage) is the control for that case.

use jay_squad_sec::rules::{RulesConfig, RulesError, DEFAULT_RULES};
use jay_squad_sec_update::{SignedPatch, UpdateError, Verifier};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Current installed state: the signed patch that produced the active rules.
pub const STATE_FILE: &str = "rules.jssp";
/// Previous verified state, kept as a crash/corruption fallback.
pub const PREV_FILE: &str = "rules.prev.jssp";
/// Rule patches are tiny (~100 bytes of payload); refuse anything larger
/// before reading it into memory.
pub const MAX_PATCH_FILE_BYTES: u64 = 64 * 1024;

/// Where the active rules came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateSource {
    /// No installed update: compiled-in defaults.
    Default,
    /// The current state file verified successfully.
    Current,
    /// The current state file was missing/corrupt/tampered; the previous
    /// verified state was used instead.
    RecoveredFromPrevious,
}

/// The active rules and their provenance.
#[derive(Clone, Debug, PartialEq)]
pub struct InstalledRules {
    /// Patch version of the active rules (0 = compiled-in defaults).
    pub version: u64,
    pub rules: RulesConfig,
    pub source: StateSource,
}

/// Why an update was not applied. On any error, nothing changed.
#[derive(Clone, Debug, PartialEq)]
pub enum ApplyError {
    /// Filesystem error while reading the patch or installing state.
    Io(std::io::ErrorKind),
    /// Patch file exceeded [`MAX_PATCH_FILE_BYTES`].
    PatchTooLarge,
    /// Patch failed decoding or signature/product/rollback verification.
    Update(UpdateError),
    /// Patch was authentic but its payload is not a valid rules config.
    Rules(RulesError),
}

impl core::fmt::Display for ApplyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ApplyError::Io(k) => write!(f, "filesystem error: {k:?}"),
            ApplyError::PatchTooLarge => {
                write!(f, "patch file exceeds {MAX_PATCH_FILE_BYTES} bytes")
            }
            ApplyError::Update(e) => write!(f, "patch rejected: {e}"),
            ApplyError::Rules(e) => write!(f, "patch payload rejected: {e}"),
        }
    }
}

impl std::error::Error for ApplyError {}

impl From<std::io::Error> for ApplyError {
    fn from(e: std::io::Error) -> Self {
        ApplyError::Io(e.kind())
    }
}
impl From<UpdateError> for ApplyError {
    fn from(e: UpdateError) -> Self {
        ApplyError::Update(e)
    }
}
impl From<RulesError> for ApplyError {
    fn from(e: RulesError) -> Self {
        ApplyError::Rules(e)
    }
}

/// Persistent store of the installed rules for one product and one builder key.
pub struct UpdateStore {
    dir: PathBuf,
    public_key: [u8; 32],
    product_id: String,
}

impl UpdateStore {
    pub fn new(dir: impl Into<PathBuf>, public_key: [u8; 32], product_id: impl Into<String>) -> Self {
        Self { dir: dir.into(), public_key, product_id: product_id.into() }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// Read and fully re-verify a stored signed patch. Returns `None` for a
    /// missing, oversized, undecodable, unauthentic or invalid file.
    fn read_verified(&self, name: &str) -> Option<(SignedPatch, RulesConfig)> {
        let bytes = read_capped(&self.path(name)).ok()?;
        let patch = SignedPatch::decode(&bytes).ok()?;
        // current_version 0: on load we re-check authenticity, product and
        // payload; anti-rollback against the device's own state is not
        // meaningful here (versions are always >= 1 for real patches).
        let verified = Verifier::new(self.public_key, self.product_id.clone(), 0)
            .verify(&patch)
            .ok()?;
        let rules = RulesConfig::decode(&verified.payload).ok()?;
        Some((patch, rules))
    }

    fn load_with_patch(&self) -> (InstalledRules, Option<SignedPatch>) {
        if let Some((p, rules)) = self.read_verified(STATE_FILE) {
            let version = p.manifest.patch_version;
            return (InstalledRules { version, rules, source: StateSource::Current }, Some(p));
        }
        if let Some((p, rules)) = self.read_verified(PREV_FILE) {
            let version = p.manifest.patch_version;
            return (
                InstalledRules { version, rules, source: StateSource::RecoveredFromPrevious },
                Some(p),
            );
        }
        (
            InstalledRules { version: 0, rules: DEFAULT_RULES, source: StateSource::Default },
            None,
        )
    }

    /// The active rules. Never fails: falls back current -> previous ->
    /// compiled-in defaults, re-verifying signatures at each step.
    pub fn load(&self) -> InstalledRules {
        self.load_with_patch().0
    }

    /// Verify and install a patch given as bytes. On success returns the newly
    /// active rules; on any error the installed state is unchanged.
    pub fn apply_patch_bytes(&self, bytes: &[u8]) -> Result<InstalledRules, ApplyError> {
        if bytes.len() as u64 > MAX_PATCH_FILE_BYTES {
            return Err(ApplyError::PatchTooLarge);
        }
        let (current, current_patch) = self.load_with_patch();

        let patch = SignedPatch::decode(bytes)?;
        let verified = Verifier::new(self.public_key, self.product_id.clone(), current.version)
            .verify(&patch)?;
        let rules = RulesConfig::decode(&verified.payload)?;

        // Everything checked. Install atomically.
        fs::create_dir_all(&self.dir)?;
        if let Some(prev) = current_patch {
            // Re-encode the VERIFIED current state as the fallback, so a corrupt
            // on-disk file can never displace a good previous state.
            atomic_write(&self.dir, &self.path(PREV_FILE), &prev.encode())?;
        }
        atomic_write(&self.dir, &self.path(STATE_FILE), &patch.encode())?;

        Ok(InstalledRules {
            version: verified.patch_version,
            rules,
            source: StateSource::Current,
        })
    }

    /// Verify and install a patch from a file. The file size is checked before
    /// it is read, and the read itself is capped.
    pub fn apply_patch_file(&self, path: &Path) -> Result<InstalledRules, ApplyError> {
        let bytes = read_capped(path)?;
        self.apply_patch_bytes(&bytes)
    }
}

/// Read a file, refusing anything over [`MAX_PATCH_FILE_BYTES`] (checked via
/// metadata first, then enforced on the read in case the file grows).
fn read_capped(path: &Path) -> Result<Vec<u8>, ApplyError> {
    let f = File::open(path)?;
    if f.metadata()?.len() > MAX_PATCH_FILE_BYTES {
        return Err(ApplyError::PatchTooLarge);
    }
    let mut buf = Vec::new();
    f.take(MAX_PATCH_FILE_BYTES + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_PATCH_FILE_BYTES {
        return Err(ApplyError::PatchTooLarge);
    }
    Ok(buf)
}

/// Write `data` to `dest` atomically: temp file in the same directory, fsync,
/// rename over the destination, then fsync the directory (Unix) so the rename
/// itself is durable.
fn atomic_write(dir: &Path, dest: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut tmp_name = dest.as_os_str().to_owned();
    tmp_name.push(".tmp");
    let tmp = PathBuf::from(tmp_name);
    {
        let mut f = OpenOptions::new().write(true).create(true).truncate(true).open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, dest)?;
    sync_dir(dir)
}

#[cfg(unix)]
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jay_squad_sec::event::EventKind;
    use jay_squad_sec::rules::kind_index;
    use jay_squad_sec_update::{generate_keypair, sign_patch};
    use std::sync::atomic::{AtomicU64, Ordering};

    const PRODUCT: &str = "jay-squad-sec-android";

    /// Unique scratch directory per test, removed on drop.
    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let p = std::env::temp_dir().join(format!(
                "jss-apply-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&p);
            Scratch(p)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn rules_with_block_at(block_at: f32) -> RulesConfig {
        let mut r = DEFAULT_RULES;
        r.block_at = block_at;
        r
    }

    fn signed(sk: &[u8; 64], version: u64, rules: &RulesConfig) -> Vec<u8> {
        sign_patch(sk, PRODUCT, version, rules.encode()).unwrap().encode()
    }

    #[test]
    fn fresh_store_uses_compiled_in_defaults() {
        let s = Scratch::new();
        let (pk, _) = generate_keypair();
        let st = UpdateStore::new(&s.0, pk, PRODUCT);
        let got = st.load();
        assert_eq!(got.version, 0);
        assert_eq!(got.rules, DEFAULT_RULES);
        assert_eq!(got.source, StateSource::Default);
    }

    #[test]
    fn a_verified_patch_is_installed_and_survives_reload() {
        let s = Scratch::new();
        let (pk, sk) = generate_keypair();
        let st = UpdateStore::new(&s.0, pk, PRODUCT);
        let r = rules_with_block_at(120.0);
        let out = st.apply_patch_bytes(&signed(&sk, 1, &r)).unwrap();
        assert_eq!((out.version, out.rules, out.source), (1, r, StateSource::Current));
        // A brand-new store instance (simulating an app restart) sees it.
        let reloaded = UpdateStore::new(&s.0, pk, PRODUCT).load();
        assert_eq!((reloaded.version, reloaded.rules), (1, r));
        assert_eq!(reloaded.source, StateSource::Current);
    }

    #[test]
    fn replay_and_downgrade_are_rejected_and_state_is_kept() {
        let s = Scratch::new();
        let (pk, sk) = generate_keypair();
        let st = UpdateStore::new(&s.0, pk, PRODUCT);
        let v1 = signed(&sk, 1, &rules_with_block_at(110.0));
        let v2 = signed(&sk, 2, &rules_with_block_at(120.0));
        st.apply_patch_bytes(&v1).unwrap();
        st.apply_patch_bytes(&v2).unwrap();
        assert!(matches!(
            st.apply_patch_bytes(&v2),
            Err(ApplyError::Update(UpdateError::Rollback { got: 2, current: 2 }))
        ));
        assert!(matches!(
            st.apply_patch_bytes(&v1),
            Err(ApplyError::Update(UpdateError::Rollback { got: 1, current: 2 }))
        ));
        assert_eq!(st.load().version, 2);
    }

    #[test]
    fn tampered_patch_is_rejected_and_nothing_changes() {
        let s = Scratch::new();
        let (pk, sk) = generate_keypair();
        let st = UpdateStore::new(&s.0, pk, PRODUCT);
        let mut bytes = signed(&sk, 1, &rules_with_block_at(120.0));
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01; // flip a bit inside the rules payload
        assert!(matches!(
            st.apply_patch_bytes(&bytes),
            Err(ApplyError::Update(UpdateError::BadSignature))
        ));
        assert_eq!(st.load().source, StateSource::Default);
        assert!(!s.0.join(STATE_FILE).exists(), "nothing may be written on rejection");
    }

    #[test]
    fn authentic_patch_with_detection_disabling_rules_is_rejected() {
        let s = Scratch::new();
        let (pk, sk) = generate_keypair();
        let st = UpdateStore::new(&s.0, pk, PRODUCT);
        let mut bad = DEFAULT_RULES;
        bad.weights[kind_index(EventKind::RemoteThreadInjection)] = 0.0;
        // Validly SIGNED, but the payload would switch a detection off.
        assert!(matches!(
            st.apply_patch_bytes(&signed(&sk, 1, &bad)),
            Err(ApplyError::Rules(RulesError::IndicatorNotPositive(
                EventKind::RemoteThreadInjection
            )))
        ));
        assert_eq!(st.load().source, StateSource::Default);
    }

    #[test]
    fn authentic_patch_with_non_rules_payload_is_rejected() {
        let s = Scratch::new();
        let (pk, sk) = generate_keypair();
        let st = UpdateStore::new(&s.0, pk, PRODUCT);
        let bytes = sign_patch(&sk, PRODUCT, 1, b"not a rules blob".to_vec()).unwrap().encode();
        assert!(matches!(
            st.apply_patch_bytes(&bytes),
            Err(ApplyError::Rules(RulesError::Malformed))
        ));
    }

    #[test]
    fn wrong_product_and_wrong_key_are_rejected() {
        let s = Scratch::new();
        let (pk, sk) = generate_keypair();
        let (_, attacker_sk) = generate_keypair();
        let st = UpdateStore::new(&s.0, pk, PRODUCT);
        let other = sign_patch(&sk, "other-app", 1, DEFAULT_RULES.encode()).unwrap().encode();
        assert!(matches!(
            st.apply_patch_bytes(&other),
            Err(ApplyError::Update(UpdateError::WrongProduct))
        ));
        let forged = signed(&attacker_sk, 1, &rules_with_block_at(10_000.0));
        assert!(matches!(
            st.apply_patch_bytes(&forged),
            Err(ApplyError::Update(UpdateError::BadSignature))
        ));
    }

    #[test]
    fn on_disk_tampering_falls_back_to_previous_then_defaults() {
        let s = Scratch::new();
        let (pk, sk) = generate_keypair();
        let st = UpdateStore::new(&s.0, pk, PRODUCT);
        let r1 = rules_with_block_at(110.0);
        let r2 = rules_with_block_at(120.0);
        st.apply_patch_bytes(&signed(&sk, 1, &r1)).unwrap();
        st.apply_patch_bytes(&signed(&sk, 2, &r2)).unwrap();

        // Attacker edits the installed state to weaken enforcement.
        let state = s.0.join(STATE_FILE);
        let mut b = fs::read(&state).unwrap();
        let n = b.len();
        b[n - 4..].copy_from_slice(&10_000.0f32.to_le_bytes()); // block_at -> max
        fs::write(&state, &b).unwrap();

        let got = st.load();
        assert_eq!(got.source, StateSource::RecoveredFromPrevious);
        assert_eq!((got.version, got.rules), (1, r1), "tampered state must not take effect");

        // Corrupt the fallback too: compiled-in defaults, never the forged rules.
        fs::write(s.0.join(PREV_FILE), b"garbage").unwrap();
        let got = st.load();
        assert_eq!((got.version, got.rules, got.source), (0, DEFAULT_RULES, StateSource::Default));
    }

    #[test]
    fn a_state_file_signed_by_another_key_is_ignored() {
        let s = Scratch::new();
        let (pk, _) = generate_keypair();
        let (_, attacker_sk) = generate_keypair();
        fs::create_dir_all(&s.0).unwrap();
        // Attacker drops a self-signed "installed state" straight onto disk.
        fs::write(s.0.join(STATE_FILE), signed(&attacker_sk, 99, &rules_with_block_at(10_000.0)))
            .unwrap();
        let got = UpdateStore::new(&s.0, pk, PRODUCT).load();
        assert_eq!((got.version, got.source), (0, StateSource::Default));
    }

    #[test]
    fn oversized_patch_file_is_refused_before_reading() {
        let s = Scratch::new();
        let (pk, _) = generate_keypair();
        fs::create_dir_all(&s.0).unwrap();
        let big = s.0.join("big.jssp");
        fs::write(&big, vec![0u8; (MAX_PATCH_FILE_BYTES + 1) as usize]).unwrap();
        let st = UpdateStore::new(&s.0, pk, PRODUCT);
        assert_eq!(st.apply_patch_file(&big), Err(ApplyError::PatchTooLarge));
    }

    #[test]
    fn installed_rules_drive_the_engine() {
        use jay_squad_sec::engine::Engine;
        let s = Scratch::new();
        let (pk, sk) = generate_keypair();
        let st = UpdateStore::new(&s.0, pk, PRODUCT);
        let r = rules_with_block_at(150.0);
        st.apply_patch_bytes(&signed(&sk, 1, &r)).unwrap();
        let mut engine = Engine::new(7);
        engine.set_rules(st.load().rules).unwrap();
        assert_eq!(engine.rules().block_at, 150.0);
    }
}
