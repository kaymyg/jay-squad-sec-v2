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
//! the builder's private key: a tampered state file fails verification and is
//! ignored. Updates carry data only (see `jay_squad_sec::rules`), never code.
//!
//! **Highest verified version wins.** Both the current and the previous state
//! file are verified on load and the higher version is used, so swapping an
//! older genuine patch into the current slot does not downgrade the rules.
//!
//! **Hostile directory.** State paths must be regular files: symlinks, FIFOs
//! and directories are refused without being opened (no reading through a
//! planted symlink, no hang on a FIFO). Temp files get unique names and are
//! created exclusively (`create_new`, i.e. O_EXCL), which never follows or
//! overwrites an existing symlink, so a planted link cannot redirect writes.
//!
//! **Crash safety.** New state is written to a temp file, fsynced, then moved
//! into place with an atomic rename, so the state file is always either the
//! complete old version or the complete new one. The previous good state is
//! kept as a fallback, re-encoded from a *verified* state, never blindly copied.
//!
//! **Concurrency.** `apply_*` calls are serialized within a process by a global
//! lock. Running two processes against one state directory is unsupported.
//!
//! **Residual risk (documented, not hidden).** Someone who can *delete* files
//! in the state directory can remove the current state (one-step downgrade to
//! the previous verified patch) or both (revert to compiled-in defaults at
//! version 0, after which an older builder-signed patch could be re-applied).
//! Every such outcome is rules the builder actually signed, all passing
//! validation. Mitigations: [`UpdateStore::with_min_version`] (set it to the
//! latest shipped patch version in each release so older patches can never
//! come back), `RecoveredFromPrevious` is surfaced as a tamper warning, and
//! platform storage protection (Android app-private storage). A hardware-backed
//! high-water mark (Android Keystore) is planned with the Android integration.

use jay_squad_sec::rules::{RulesConfig, RulesError, DEFAULT_RULES};
use jay_squad_sec_update::{SignedPatch, UpdateError, Verifier};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// Current installed state: the signed patch that produced the active rules.
pub const STATE_FILE: &str = "rules.jssp";
/// Previous verified state, kept as a crash/corruption fallback.
pub const PREV_FILE: &str = "rules.prev.jssp";
/// Rule patches are tiny (~100 bytes of payload); refuse anything larger
/// before reading it into memory.
pub const MAX_PATCH_FILE_BYTES: u64 = 64 * 1024;

/// Serializes all applies in this process (load -> verify -> write).
static APPLY_LOCK: Mutex<()> = Mutex::new(());

/// Where the active rules came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateSource {
    /// No installed update: compiled-in defaults.
    Default,
    /// The current state file verified and holds the highest version.
    Current,
    /// The previous state file was used: the current one was missing, invalid,
    /// tampered, or older. Treat as a possible tampering signal.
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
    /// A path that must be a regular file is a symlink, FIFO, directory, etc.
    NotARegularFile,
    /// Patch version is below this build's minimum accepted rules version.
    BelowMinimumVersion { got: u64, min: u64 },
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
            ApplyError::NotARegularFile => write!(f, "path is not a regular file"),
            ApplyError::BelowMinimumVersion { got, min } => {
                write!(f, "patch version {got} is below this build's minimum {min}")
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
    min_version: u64,
}

impl UpdateStore {
    pub fn new(dir: impl Into<PathBuf>, public_key: [u8; 32], product_id: impl Into<String>) -> Self {
        Self { dir: dir.into(), public_key, product_id: product_id.into(), min_version: 0 }
    }

    /// Refuse, and ignore on disk, any rules patch older than `min`. Set this
    /// to the latest shipped patch version in each release, so that even if
    /// the state directory is wiped an older patch can never be re-applied.
    pub fn with_min_version(mut self, min: u64) -> Self {
        self.min_version = min;
        self
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// Read and fully re-verify a stored signed patch. Returns `None` for a
    /// missing, non-regular, oversized, undecodable, unauthentic, invalid or
    /// below-minimum file.
    fn read_verified(&self, name: &str) -> Option<(SignedPatch, RulesConfig)> {
        let bytes = read_capped(&self.path(name), false).ok()?;
        let patch = SignedPatch::decode(&bytes).ok()?;
        // current_version 0: on load we re-check authenticity, product and
        // payload; ordering between slots is decided by the caller.
        let verified = Verifier::new(self.public_key, self.product_id.clone(), 0)
            .verify(&patch)
            .ok()?;
        if verified.patch_version < self.min_version {
            return None;
        }
        let rules = RulesConfig::decode(&verified.payload).ok()?;
        Some((patch, rules))
    }

    fn load_with_patch(&self) -> (InstalledRules, Option<SignedPatch>) {
        let cur = self.read_verified(STATE_FILE);
        let prev = self.read_verified(PREV_FILE);
        let pick = match (cur, prev) {
            (Some(c), Some(p)) if p.0.manifest.patch_version > c.0.manifest.patch_version => {
                Some((p, StateSource::RecoveredFromPrevious))
            }
            (Some(c), _) => Some((c, StateSource::Current)),
            (None, Some(p)) => Some((p, StateSource::RecoveredFromPrevious)),
            (None, None) => None,
        };
        match pick {
            Some(((patch, rules), source)) => {
                let version = patch.manifest.patch_version;
                (InstalledRules { version, rules, source }, Some(patch))
            }
            None => (
                InstalledRules { version: 0, rules: DEFAULT_RULES, source: StateSource::Default },
                None,
            ),
        }
    }

    /// The active rules. Never fails: uses the highest verified version among
    /// the current and previous state, else the compiled-in defaults.
    /// True if either state file exists on disk (as anything at all). When
    /// [`load`](Self::load) nonetheless reports [`StateSource::Default`], the
    /// stored state was tampered with, corrupted or is below the minimum
    /// version, and callers should raise an alert rather than treat it as a
    /// fresh install.
    pub fn state_files_present(&self) -> bool {
        [STATE_FILE, PREV_FILE]
            .iter()
            .any(|name| fs::symlink_metadata(self.path(name)).is_ok())
    }

    pub fn load(&self) -> InstalledRules {
        self.load_with_patch().0
    }

    /// Verify and install a patch given as bytes. On success returns the newly
    /// active rules; on any error the installed state is unchanged.
    pub fn apply_patch_bytes(&self, bytes: &[u8]) -> Result<InstalledRules, ApplyError> {
        let _guard = APPLY_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if bytes.len() as u64 > MAX_PATCH_FILE_BYTES {
            return Err(ApplyError::PatchTooLarge);
        }
        let (current, current_patch) = self.load_with_patch();

        let patch = SignedPatch::decode(bytes)?;
        let verified = Verifier::new(self.public_key, self.product_id.clone(), current.version)
            .verify(&patch)?;
        if verified.patch_version < self.min_version {
            return Err(ApplyError::BelowMinimumVersion {
                got: verified.patch_version,
                min: self.min_version,
            });
        }
        let rules = RulesConfig::decode(&verified.payload)?;

        // Everything checked. Install atomically.
        fs::create_dir_all(&self.dir)?;
        if let Some(prev) = current_patch {
            // Re-encode the VERIFIED active state as the fallback, so a corrupt
            // on-disk file can never displace a good previous state.
            atomic_write(&self.dir, &self.path(PREV_FILE), &prev.encode())?;
        }
        atomic_write(&self.dir, &self.path(STATE_FILE), &patch.encode())?;
        cleanup_stale_temps(&self.dir);

        Ok(InstalledRules {
            version: verified.patch_version,
            rules,
            source: StateSource::Current,
        })
    }

    /// Verify and install a patch from an operator-supplied file. The path may
    /// be a symlink, but its target must be a regular file; size is checked
    /// before reading and the read itself is capped.
    pub fn apply_patch_file(&self, path: &Path) -> Result<InstalledRules, ApplyError> {
        let bytes = read_capped(path, true)?;
        self.apply_patch_bytes(&bytes)
    }
}

/// Read a regular file, refusing anything over [`MAX_PATCH_FILE_BYTES`].
/// With `follow_symlinks = false` (state files) a symlink is refused outright;
/// either way a FIFO/device/directory is refused BEFORE opening, so a planted
/// FIFO cannot hang the reader. The open handle is re-checked (fstat) and the
/// read is capped in case the file grows.
fn read_capped(path: &Path, follow_symlinks: bool) -> Result<Vec<u8>, ApplyError> {
    let meta = if follow_symlinks { fs::metadata(path)? } else { fs::symlink_metadata(path)? };
    if !meta.file_type().is_file() {
        return Err(ApplyError::NotARegularFile);
    }
    if meta.len() > MAX_PATCH_FILE_BYTES {
        return Err(ApplyError::PatchTooLarge);
    }
    let f = File::open(path)?;
    let fmeta = f.metadata()?;
    if !fmeta.file_type().is_file() {
        return Err(ApplyError::NotARegularFile);
    }
    if fmeta.len() > MAX_PATCH_FILE_BYTES {
        return Err(ApplyError::PatchTooLarge);
    }
    let mut buf = Vec::new();
    f.take(MAX_PATCH_FILE_BYTES + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_PATCH_FILE_BYTES {
        return Err(ApplyError::PatchTooLarge);
    }
    Ok(buf)
}

/// Suffix marking our temp files, used by cleanup.
const TMP_SUFFIX: &str = ".tmp";

/// Write `data` to `dest` atomically. The temp file has a unique name in the
/// same directory and is created exclusively (O_EXCL via `create_new`), which
/// never follows or reuses an existing path, so a planted symlink cannot
/// redirect the write. Then fsync, rename over the destination (rename
/// replaces a symlink itself rather than following it), and fsync the
/// directory (Unix) so the rename is durable.
fn atomic_write(dir: &Path, dest: &Path, data: &[u8]) -> std::io::Result<()> {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut last_err = None;
    for _ in 0..8 {
        let mut name = dest.as_os_str().to_owned();
        name.push(format!(
            ".{}.{}.{}{}",
            std::process::id(),
            nanos,
            SEQ.fetch_add(1, Ordering::Relaxed),
            TMP_SUFFIX
        ));
        let tmp = PathBuf::from(name);
        let mut f = match OpenOptions::new().write(true).create_new(true).open(&tmp) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                last_err = Some(e);
                continue;
            }
            Err(e) => return Err(e),
        };
        let result = f
            .write_all(data)
            .and_then(|_| f.sync_all())
            .and_then(|_| fs::rename(&tmp, dest))
            .and_then(|_| sync_dir(dir));
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        return result;
    }
    Err(last_err.unwrap_or_else(|| std::io::Error::from(std::io::ErrorKind::AlreadyExists)))
}

/// Best-effort removal of temp files left by a crashed install. Only touches
/// names that start with a state-file name and end in `.tmp`; `remove_file`
/// on a symlink removes the link itself, never its target.
fn cleanup_stale_temps(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let ours = name.starts_with(STATE_FILE) || name.starts_with(PREV_FILE);
        if ours && name.ends_with(TMP_SUFFIX) {
            let _ = fs::remove_file(entry.path());
        }
    }
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
            Err(ApplyError::Rules(RulesError::IndicatorOutOfRange(
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

    #[test]
    fn swapping_an_older_patch_into_the_current_slot_does_not_downgrade() {
        let s = Scratch::new();
        let (pk, sk) = generate_keypair();
        let st = UpdateStore::new(&s.0, pk, PRODUCT);
        let r1 = rules_with_block_at(110.0);
        let r3 = rules_with_block_at(130.0);
        fs::create_dir_all(&s.0).unwrap();
        // Attacker puts genuine-but-old v1 in the current slot, v3 in prev.
        fs::write(s.0.join(STATE_FILE), signed(&sk, 1, &r1)).unwrap();
        fs::write(s.0.join(PREV_FILE), signed(&sk, 3, &r3)).unwrap();
        let got = st.load();
        assert_eq!((got.version, got.rules), (3, r3), "highest verified version must win");
        assert_eq!(got.source, StateSource::RecoveredFromPrevious, "surfaced as a tamper signal");
    }

    #[test]
    fn min_version_blocks_old_patches_on_disk_and_in_transit() {
        let s = Scratch::new();
        let (pk, sk) = generate_keypair();
        let v2 = signed(&sk, 2, &rules_with_block_at(110.0));
        UpdateStore::new(&s.0, pk, PRODUCT).apply_patch_bytes(&v2).unwrap();
        let st = UpdateStore::new(&s.0, pk, PRODUCT).with_min_version(3);
        assert_eq!(st.load().source, StateSource::Default, "stored v2 is below the floor");
        assert_eq!(
            st.apply_patch_bytes(&v2),
            Err(ApplyError::BelowMinimumVersion { got: 2, min: 3 })
        );
        let v3 = signed(&sk, 3, &rules_with_block_at(120.0));
        assert_eq!(st.apply_patch_bytes(&v3).unwrap().version, 3);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_state_file_is_not_followed() {
        let s = Scratch::new();
        let (pk, sk) = generate_keypair();
        fs::create_dir_all(&s.0).unwrap();
        let elsewhere = s.0.join("elsewhere.jssp");
        fs::write(&elsewhere, signed(&sk, 5, &rules_with_block_at(130.0))).unwrap();
        std::os::unix::fs::symlink(&elsewhere, s.0.join(STATE_FILE)).unwrap();
        let got = UpdateStore::new(&s.0, pk, PRODUCT).load();
        assert_eq!(got.source, StateSource::Default, "state must not be read through a symlink");
    }

    #[cfg(unix)]
    #[test]
    fn a_planted_temp_symlink_cannot_redirect_the_write() {
        let s = Scratch::new();
        let (pk, sk) = generate_keypair();
        fs::create_dir_all(&s.0).unwrap();
        let victim = s.0.join("victim.txt");
        fs::write(&victim, b"precious").unwrap();
        // The naive temp name from the previous design.
        std::os::unix::fs::symlink(&victim, s.0.join(format!("{STATE_FILE}.tmp"))).unwrap();
        let st = UpdateStore::new(&s.0, pk, PRODUCT);
        st.apply_patch_bytes(&signed(&sk, 1, &rules_with_block_at(110.0))).unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"precious", "victim must be untouched");
        assert!(fs::symlink_metadata(s.0.join(STATE_FILE)).unwrap().file_type().is_file());
        assert_eq!(st.load().version, 1);
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_at_the_state_path_does_not_hang_load() {
        let s = Scratch::new();
        let (pk, _) = generate_keypair();
        fs::create_dir_all(&s.0).unwrap();
        let fifo = s.0.join(STATE_FILE);
        let made = std::process::Command::new("mkfifo").arg(&fifo).status();
        if !matches!(made, Ok(st) if st.success()) {
            eprintln!("mkfifo unavailable; skipping");
            return;
        }
        let dir = s.0.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(UpdateStore::new(&dir, pk, PRODUCT).load());
        });
        let got = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("load() hung on a FIFO");
        assert_eq!(got.source, StateSource::Default);
    }

    #[test]
    fn a_directory_at_a_state_path_fails_cleanly_without_changes() {
        let s = Scratch::new();
        let (pk, sk) = generate_keypair();
        let st = UpdateStore::new(&s.0, pk, PRODUCT);
        st.apply_patch_bytes(&signed(&sk, 1, &rules_with_block_at(110.0))).unwrap();
        fs::remove_file(s.0.join(PREV_FILE)).ok();
        fs::create_dir_all(s.0.join(PREV_FILE)).unwrap(); // hostile directory
        let res = st.apply_patch_bytes(&signed(&sk, 2, &rules_with_block_at(120.0)));
        assert!(matches!(res, Err(ApplyError::Io(_))), "got {res:?}");
        assert_eq!(st.load().version, 1, "current rules unchanged");
    }

    #[test]
    fn stale_temp_files_are_cleaned_up() {
        let s = Scratch::new();
        let (pk, sk) = generate_keypair();
        fs::create_dir_all(&s.0).unwrap();
        let stale = s.0.join(format!("{STATE_FILE}.123.456.0.tmp"));
        fs::write(&stale, b"half-written").unwrap();
        let keep = s.0.join("unrelated.tmp");
        fs::write(&keep, b"not ours").unwrap();
        UpdateStore::new(&s.0, pk, PRODUCT)
            .apply_patch_bytes(&signed(&sk, 1, &rules_with_block_at(110.0)))
            .unwrap();
        assert!(!stale.exists(), "our stale temp is removed");
        assert!(keep.exists(), "unrelated files are left alone");
    }
}
