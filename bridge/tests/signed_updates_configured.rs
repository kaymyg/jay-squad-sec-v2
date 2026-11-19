//! Happy-path and rejection tests for signed rules updates through the bridge,
//! in a build that embeds a builder key.
//!
//! These run only when the library was compiled with the TEST key below:
//!
//!   JSS_ANDROID_BUILDER_PUBLIC_KEY_HEX=<test_public_key_hex()> \
//!   JSS_ANDROID_MIN_RULES_VERSION=0 JSS_EXPECT_CONFIGURED_TESTS=1 \
//!   cargo test --manifest-path bridge/Cargo.toml --test signed_updates_configured
//!
//! Without that configuration they skip, unless JSS_EXPECT_CONFIGURED_TESTS
//! is set, in which case they FAIL, so CI cannot silently skip them.
//!
//! The seed below is a published TEST-ONLY key. Never embed its public key in
//! a release build.

use ed25519_compact::{KeyPair, Seed};
use jay_squad_sec::event::EventKind;
use jay_squad_sec::rules::{kind_index, RulesConfig, DEFAULT_RULES};
use jay_squad_sec_bridge::*;
use jay_squad_sec_update::{signing_message, PatchManifest, SignedPatch, PATCH_SCHEMA_VERSION};
use std::path::PathBuf;
use std::sync::Mutex;

const TEST_ONLY_SEED: [u8; 32] = [0x4a; 32];
static LOCK: Mutex<()> = Mutex::new(());

fn keypair(seed: [u8; 32]) -> KeyPair {
    KeyPair::from_seed(Seed::new(seed))
}

fn test_public_key_hex() -> String {
    keypair(TEST_ONLY_SEED)
        .pk
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// True when this build embeds the test key; otherwise skip (or fail if CI
/// asked for these tests to run).
fn configured() -> bool {
    let ok = option_env!("JSS_ANDROID_BUILDER_PUBLIC_KEY_HEX")
        == Some(test_public_key_hex().as_str())
        && option_env!("JSS_ANDROID_MIN_RULES_VERSION") == Some("0");
    if !ok && std::env::var_os("JSS_EXPECT_CONFIGURED_TESTS").is_some() {
        panic!(
            "configured-update tests were required but the bridge was not built with the test key \
             ({}) and JSS_ANDROID_MIN_RULES_VERSION=0",
            test_public_key_hex()
        );
    }
    if !ok {
        eprintln!("skipping: bridge not built with the test builder key");
    }
    ok
}

/// Sign a rules payload with ed25519 deterministic signing (no RNG).
fn patch(seed: [u8; 32], product: &str, version: u64, rules: &RulesConfig) -> Vec<u8> {
    let payload = rules.encode();
    let manifest = PatchManifest {
        schema_version: PATCH_SCHEMA_VERSION,
        product_id: product.into(),
        patch_version: version,
        payload_len: payload.len() as u64,
    };
    let sig = keypair(seed)
        .sk
        .sign(signing_message(&manifest, &payload), None);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(sig.as_ref());
    SignedPatch {
        manifest,
        payload,
        signature,
    }
    .encode()
}

struct Dir(PathBuf);
impl Dir {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!("jss-bridge-upd-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        Dir(p)
    }
    fn bytes(&self) -> Vec<u8> {
        self.0.to_str().unwrap().as_bytes().to_vec()
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn alerts(h: JssHandle) -> String {
    String::from_utf8(take_alerts(h, 1 << 20).unwrap()).unwrap()
}

/// Thresholds tight enough that a single credential-access event (weight 40)
/// reaches Block, whereas under the defaults it only reaches Monitor.
fn strict_rules() -> RulesConfig {
    let mut r = DEFAULT_RULES;
    r.monitor_at = 10.0;
    r.restrict_at = 20.0;
    r.suspend_at = 30.0;
    r.block_at = 40.0;
    r
}

#[test]
fn genuine_patch_installs_activates_and_persists() {
    let _g = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    if !configured() {
        return;
    }
    let dir = Dir::new("genuine");
    let h = engine_new(1);
    assert_eq!(
        load_signed_rules(h, &dir.bytes()),
        Ok(0),
        "fresh: compiled-in defaults"
    );

    let p = patch(TEST_ONLY_SEED, ANDROID_PRODUCT_ID, 1, &strict_rules());
    assert_eq!(apply_signed_rules(h, &dir.bytes(), &p), Ok(1));
    assert!(alerts(h).contains("rules v1 verified, installed and activated"));

    // The new rules are live: one credential access now blocks.
    assert_eq!(
        submit(h, 50, 1, b"com.x:sha256:01", b"credential_access", b"", 1),
        OK
    );
    assert!(
        alerts(h).contains("BLOCKED"),
        "patched rules must drive decisions"
    );

    // A fresh engine (app restart) loads the same verified rules.
    let h2 = engine_new(2);
    assert_eq!(load_signed_rules(h2, &dir.bytes()), Ok(1));
    assert_eq!(
        submit(h2, 60, 1, b"com.y:sha256:02", b"credential_access", b"", 1),
        OK
    );
    assert!(
        alerts(h2).contains("BLOCKED"),
        "persisted rules must survive restart"
    );
    engine_free(h);
    engine_free(h2);
}

#[test]
fn defaults_do_not_block_on_a_single_credential_access() {
    // Control for the test above: proves the BLOCKED alert came from the patch.
    let _g = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    if !configured() {
        return;
    }
    let h = engine_new(3);
    assert_eq!(
        submit(h, 70, 1, b"com.z:sha256:03", b"credential_access", b"", 1),
        OK
    );
    assert!(!alerts(h).contains("BLOCKED"));
    engine_free(h);
}

#[test]
fn forged_wrong_product_rollback_and_unsafe_rules_are_rejected() {
    let _g = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    if !configured() {
        return;
    }
    let dir = Dir::new("reject");
    let h = engine_new(4);
    let d = dir.bytes();

    let forged = patch([0x99; 32], ANDROID_PRODUCT_ID, 1, &strict_rules());
    assert_eq!(apply_signed_rules(h, &d, &forged), Err(ERR_UPDATE_REJECTED));
    assert!(alerts(h).contains("signature verification failed"));

    let desktop = patch(TEST_ONLY_SEED, "jay-squad-sec-agent", 1, &strict_rules());
    assert_eq!(
        apply_signed_rules(h, &d, &desktop),
        Err(ERR_UPDATE_REJECTED)
    );
    assert!(alerts(h).contains("different product"));

    let mut unsafe_rules = DEFAULT_RULES;
    unsafe_rules.weights[kind_index(EventKind::CredentialAccess)] = 0.0;
    let disabling = patch(TEST_ONLY_SEED, ANDROID_PRODUCT_ID, 1, &unsafe_rules);
    assert_eq!(
        apply_signed_rules(h, &d, &disabling),
        Err(ERR_UPDATE_REJECTED)
    );
    assert!(alerts(h).contains("cannot be silenced"));

    assert_eq!(
        apply_signed_rules(
            h,
            &d,
            &patch(TEST_ONLY_SEED, ANDROID_PRODUCT_ID, 2, &strict_rules())
        ),
        Ok(2)
    );
    let older = patch(TEST_ONLY_SEED, ANDROID_PRODUCT_ID, 1, &DEFAULT_RULES);
    assert_eq!(apply_signed_rules(h, &d, &older), Err(ERR_UPDATE_REJECTED));
    assert!(alerts(h).contains("not newer"));
    assert_eq!(
        load_signed_rules(h, &d),
        Ok(2),
        "rejections never changed installed rules"
    );
    engine_free(h);
}

#[test]
fn relative_storage_path_is_refused() {
    let _g = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    if !configured() {
        return;
    }
    let h = engine_new(5);
    assert_eq!(load_signed_rules(h, b"relative/dir"), Err(ERR_INVALID));
    engine_free(h);
}
